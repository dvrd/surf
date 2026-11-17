package surf_async

import surf ".."
import runtime_async "../../async"
import "core:sync"
import http "../../http"
import "core:mem"
import charged "core:mem/budget"
import stream_api "stream"
import h1 "../../http/v1"

@(private)
redirect_status_error :: proc(error: surf.HTTP_Error, status: int) -> surf.HTTP_Error {
	result := error

	if result.status == 0 {
		result.status = status
	}

	if status != 0 && result.write_effect == .Not_Sent {
		result.write_effect = .Response_Received
	}

	return result
}

// Match Root's logical-request error context: never replace Unknown from an
// ambiguous later-hop write merely because an earlier response was received.
@(private)
redirect_error_context :: proc(a: ^Session_Actor, error: surf.HTTP_Error) -> surf.HTTP_Error {
	status := 0
	h := a.request

	if a.redirect.phase == .Ready {
		status = a.redirect.last_status

		if h == (Request_Handle{}) {
			h = a.redirect.request
		}
	}

	if status == 0 && h != (Request_Handle{}) {
		s := a.owner
		sync.lock(&s.mu)

		if h.owner_id == s.kernel.owner_id && h.slot > 0 && u64(h.slot) <= u64(len(s.requests)) {
			metadata := &s.requests[int(h.slot) - 1]

			if metadata.generation == h.generation {
				status = metadata.last_status
			}
		}

		sync.unlock(&s.mu)
	}

	return redirect_status_error(error, status)
}

@(private)
redirect_client_error :: proc(error: Client_Error) -> surf.HTTP_Error {
	if error.http.kind != .None {
		return error.http
	}

	if error.kind == .Closed {
		return {kind = .IO_Failed, transport = {kind = .Cancelled}, phase = .Cancellation, write_effect = .Not_Sent}
	}

	// HTTP_Error has no local admission Capacity category. Initial submission
	// returns Client_Error.Capacity; an accepted target reports only the honest
	// broad inability to establish that hop, without inventing OOM/Scope causes.
	if error.kind == .Capacity {
		return {kind = .Dial_Failed, phase = .Connect, write_effect = .Not_Sent}
	}

	if error.kind == .Runtime_Error {
		return session_runtime_error(error.runtime, .Connect)
	}

	return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
}

// Return true only when this response is consumed by redirect processing.
// A disabled policy returns the original successful3xx to its caller unchanged.
@(private)
redirect_response :: proc(a: ^Session_Actor, response: ^surf.Response) -> bool {
	if a.owner.config.config.http.max_redirects == 0 {
		return false
	}

	status := response.status

	if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
		return false
	}

	s := a.owner
	sync.lock(&s.mu)
	metadata := s.requests[int(a.request.slot) - 1]
	sync.unlock(&s.mu)
	current, _, borrow := session_borrow(a)
	cause := borrow

	if metadata.generation != a.request.generation {
		cause = {
			kind = .Invalid_State,
		}
	}

	if cause.kind == .None {
		cause = redirect_prepare(
			&a.redirect,
			&s.profile,
			a.request,
			current,
			response,
			metadata.redirects,
			metadata.query_budget_left,
			s.resources.allocator,
		)
	}

	// Preflight errors can preserve Response ownership; every handled path must
	// dispose any remainder before its next fresh deadline/cancellation barrier.
	surf.response_destroy(response)

	if cause.kind != .None {
		session_error(a, redirect_status_error(redirect_client_error(cause), status))
		return true
	}

	now, clock := network_clock(s)

	if clock.kind != .None {
		session_error(a, redirect_client_error(clock))
		return true
	}

	if failure := redirect_live_error(a, a.redirect.request, now); failure.kind != .None {
		session_error(a, failure)
		return true
	}

	// Even same-origin redirects retire the old physical stream before requeue.
	a.phase = .Retiring

	return true
}

// Called only after old close/app callbacks and adapter quiescence. On Begin
// rejection the old request remains Active and normal closed-stream completion
// handles it. On success the handoff becomes its sole actor custody across reset.
@(private)
redirect_closed_begin :: proc(a: ^Session_Actor) {
	if a.redirect.phase != .Ready {
		return
	}

	s := a.owner
	h := a.redirect.request
	status := a.redirect.last_status

	if a.request == (Request_Handle{}) {
		return
	} // Begin already owns Returning.
	assert(a.request == h)
	primary := a.error
	now, clock := network_clock(s)

	if primary.kind == .None && clock.kind != .None {
		primary = redirect_client_error(clock)
	}

	disposal: Request_Disposal

	if primary.kind == .None {
		sync.lock(&s.mu)
		next, cause := kernel_redirect_begin(&s.kernel, h, now)

		if cause.kind == .None {
			disposal = next
			s.returning_calls += 1
			network_queue_forget_locked(s, h)
			a.request = {}
		} else {
			primary = redirect_client_error(cause)
		}

		sync.unlock(&s.mu)
	}

	if primary.kind != .None {
		primary = redirect_status_error(primary, status)
		redirect_handoff_destroy(&a.redirect)
		session_error(a, primary)
		return
	}

	redirect_dispose(s, &disposal)
}

// After old model retirement, all remaining ledger and physical cleanup is
// synchronous and bounded by the owned input/origin limits. Keep running until
// the accepted request is Queued or Completed, including global close paths.
@(private)
redirect_closed_resolve :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	assert(a.redirect.phase == .Ready && a.request == (Request_Handle{}) && a.model.slot == 0)
	redirect_requeue(a)
	assert(a.redirect.phase == .Empty)
	session_notify_coordinator(a)

	if session_stopping(a) {
		a.owner_drained = true
		a.phase = .Done
		return .Done
	}

	a.phase = .Idle

	return .Yield
}

@(private)
Redirect_Grant :: struct {
	storage:   []u8,
	alignment: int,
}
@(private)
Redirect_Allocator :: struct {
	backing: mem.Allocator,
	binding: charged.Binding,
	grants:  [2]Redirect_Grant,
	failure: Client_Error,
}
@(private)
redirect_allocator_failure :: proc(state: ^Redirect_Allocator, error: Client_Error) {
	if state.failure.kind == .None {
		state.failure = error
	}
}

// Root redirect_url makes at most two simultaneously live URL grants. After it
// returns, the surviving URL and one origin grant share this same finite ledger.
// No pointer to this stack allocator may appear in a published owner.
@(private)
redirect_allocator_proc :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Redirect_Allocator)data
	switch mode {
	case .Query_Features:
		if old_memory == nil {
			return nil, .Invalid_Argument
		}

		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		return nil, nil
	case .Alloc, .Alloc_Non_Zeroed:
		if state.failure.kind != .None {
			return nil, .Out_Of_Memory
		}

		if size < 0 || size > http.MAX_HEADER_SIZE || alignment < 1 || alignment & (alignment - 1) != 0 {
			redirect_allocator_failure(state, {kind = .Invalid_Config, http = {kind = .Invalid_Config}})
			return nil, .Invalid_Argument
		}

		if size == 0 {
			return nil, nil
		}

		index := -1

		for grant, i in state.grants {
			if raw_data(grant.storage) == nil {
				index = i
				break
			}
		}

		if index < 0 {
			redirect_allocator_failure(
				state,
				{kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = .Out_Of_Memory}},
			)
			return nil, .Out_Of_Memory
		}

		storage: []u8
		cause: mem.Allocator_Error

		if state.binding != (charged.Binding{}) {
			grant, error := charged.allocate(state.binding, size, alignment)
			storage = grant

			if error.kind != .None {
				redirect_allocator_failure(state, resource_allocation_failure(error))
				return nil, .Out_Of_Memory
			}
		} else {
			storage, cause = state.backing.procedure(state.backing.data, mode, size, alignment, nil, 0, location)
		}

		// Validate before Root make can construct/copy into any sized view. Even a
		// failed grant may report storage; free its full reported extent and alignment.
		if cause != nil ||
		   raw_data(storage) == nil ||
		   len(storage) != size ||
		   uintptr(raw_data(storage)) % uintptr(alignment) != 0 {
			if raw_data(storage) != nil {
				_, _ = state.backing.procedure(
					state.backing.data,
					.Free,
					0,
					alignment,
					raw_data(storage),
					len(storage),
					location,
				)
			}
			if cause == nil {
				cause = .Out_Of_Memory
			}
			redirect_allocator_failure(
				state,
				{kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = cause}},
			)
			return nil, cause
		}

		state.grants[index] = {
			storage   = storage,
			alignment = alignment,
		}

		return storage, nil
	case .Free:
		if old_memory == nil {
			return nil, nil
		}

		for &grant in state.grants {
			if raw_data(grant.storage) == old_memory {
				// Odin delete/free use alignment0; unsized free also uses old_size0.
				// A known base pointer authorizes only this recorded whole grant. Never
				// forward those sentinels or a caller-provided extent to the backing.
				if old_size != 0 && len(grant.storage) != old_size || alignment != 0 && grant.alignment != alignment {
					break
				}

				old := grant
				grant = {}
				return state.backing.procedure(
					state.backing.data,
					.Free,
					0,
					old.alignment,
					raw_data(old.storage),
					len(old.storage),
					location,
				)
			}
		}

		redirect_allocator_failure(
			state,
			{kind = .Invalid_Config, http = {kind = .Invalid_Config, allocation = .Invalid_Pointer}},
		)
		return nil, .Invalid_Pointer
	case .Free_All, .Resize, .Resize_Non_Zeroed, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, .Mode_Not_Implemented
}

@(private)
redirect_allocator_init :: proc(state: ^Redirect_Allocator, backing: mem.Allocator) -> Client_Error {
	if backing.procedure == nil || .Free not_in mem.query_features(backing) {
		return {kind = .Invalid_Config}
	}

	state.backing = backing

	if charged.is_managed_allocator(backing) {
		binding, error := charged.retain_allocator(backing)

		if error.kind != .None {
			return resource_allocation_failure(error)
		}

		state.binding = binding
	}

	return {}
}

// Transfer one exact origin allocation to its permanent allocator provenance.
// This removes the temporary ledger's ownership without releasing the bytes.
@(private)
redirect_allocator_detach :: proc(state: ^Redirect_Allocator, storage: []u8, alignment: int) -> bool {
	for &grant in state.grants {
		if raw_data(grant.storage) == raw_data(storage) &&
		   len(grant.storage) == len(storage) &&
		   grant.alignment == alignment {
			grant = {}
			return true
		}
	}

	return false
}
@(private)
redirect_allocator_destroy :: proc(state: ^Redirect_Allocator) {
	old := state^
	state^ = {}

	for grant in old.grants {
		if raw_data(grant.storage) != nil {
			_, _ = old.backing.procedure(
				old.backing.data,
				.Free,
				0,
				grant.alignment,
				raw_data(grant.storage),
				len(grant.storage),
			)
		}
	}

	charged.release(&old.binding)
}

// Kernel.mu is held. The owner samples now after its physical work; this pure
// ledger has no Runtime/transport pointer and cannot certify callback drainage.
@(private)
redirect_cutoff_locked :: proc(k: ^Kernel, r: ^Request_Slot, now: runtime_async.Deadline) -> Client_Error {
	if now.epoch != r.deadline.epoch || now.at <= 0 {
		return {kind = .Invalid_Config, http = {kind = .Invalid_Config, phase = .Configuration}}
	}

	if k.closed {
		return {kind = .Closed}
	}

	if r.cancel_requested {
		return {
			kind = .Request_Error,
			http = {
				kind = .IO_Failed,
				transport = {kind = .Cancelled},
				phase = .Cancellation,
				write_effect = .Not_Sent,
			},
		}
	}

	if now.at >= r.deadline.at {
		return {kind = .Request_Error, http = {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}}
	}

	return {}
}

// Caller certifies that all old accepted IO callbacks and the physical stream
// close have completed. Retiring model metadata alone is not that proof.
// The returned disposal deliberately contains NO stream lease: the same lease
// remains in the accepted request until final success/failure, across all hops.
kernel_redirect_begin :: proc(
	k: ^Kernel,
	h: Request_Handle,
	now: runtime_async.Deadline,
) -> (
	Request_Disposal,
	Client_Error,
) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)
	if r == nil {
		return {}, {kind = .Invalid_Handle}
	}
	if r.state != .Active ||
	   r.error.kind != .None ||
	   !completion_empty(&r.response) ||
	   r.completion_queued ||
	   r.session.slot == 0 ||
	   r.origin.slot == 0 ||
	   k.counters.active_requests < 1 ||
	   k.returning < 0 ||
	   k.returning == max(int) ||
	   k.counters.returning_requests == max(int) ||
	   k.references < 1 ||
	   k.references >= max(int) - 2 {
		return {}, {kind = .Invalid_State}
	}
	if error := redirect_cutoff_locked(k, r, now); error.kind != .None {
		return {}, error
	}
	model := pool_session_locked(k, r.session)
	origin := admission_origin_locked(k, r.origin)
	if model == nil ||
	   model.state != .Retiring ||
	   model.request != h ||
	   model.origin != r.origin ||
	   origin == nil ||
	   origin.requests < 1 ||
	   origin.sessions < 1 ||
	   origin.preparing < 0 ||
	   origin.waiters < 0 ||
	   k.counters.retiring_connections < 1 ||
	   k.counters.origins < 1 {
		return {}, {kind = .Invalid_State}
	}
	old_origin := r.origin
	if error := admission_detach_claim_locked(k, h, r); error.kind != .None {
		return {}, error
	}
	detached, error := kernel_origin_release_locked(k, old_origin, .Request)
	// The old physical model still holds its Origin.Session reference. Thus this
	// release cannot retire that origin or invoke any allocator callback.
	assert(error.kind == .None && detached.origin.slot == 0)
	disposal := Request_Disposal {
		request      = h,
		returning_to = .Preparing,
		input        = r.input,
		origin       = detached,
	}
	r.input = {}
	r.origin = {}
	r.state = .Returning
	r.returning_to = .Preparing
	r.stage = .Redirecting
	k.counters.active_requests -= 1
	k.returning += 1
	k.counters.returning_requests += 1
	k.references += 1
	k.dispatch_dirty = true
	k.idle_dirty = true
	return disposal, {}
}

// The owner has disposed the Begin input/origin and physically retired the old
// model before calling Ready. Transfer the SAME ledger reference and lease;
// never recycle the request generation or append an intermediate completion.
kernel_redirect_ready :: proc(k: ^Kernel, h: Request_Handle, now: runtime_async.Deadline) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)

	if r == nil {
		return {kind = .Invalid_Handle}
	}

	if r.state != .Returning ||
	   r.returning_to != .Preparing ||
	   r.stage != .Redirecting ||
	   r.input.storage != nil ||
	   r.origin.slot != 0 ||
	   r.session.slot != 0 ||
	   !completion_empty(&r.response) ||
	   r.error.kind != .None ||
	   r.completion_queued ||
	   k.returning < 1 ||
	   k.counters.returning_requests < 1 ||
	   k.references <= 1 ||
	   k.preparing == max(int) ||
	   k.counters.preparing_requests == max(int) {
		return {kind = .Invalid_State}
	}

	if error := redirect_cutoff_locked(k, r, now); error.kind != .None {
		return error
	}

	r.state = .Preparing
	r.returning_to = .Free
	// Redirecting distinguishes an already accepted Preparing ticket from an
	// original producer reservation; only the accepted form may use Fail below.
	k.returning -= 1
	k.counters.returning_requests -= 1
	k.preparing += 1
	k.counters.preparing_requests += 1
	k.dispatch_dirty = true

	return {}
}

// Resolve a previously accepted hop, including failure before a new claim or
// after a Reserved/Waiter claim. Ordinary kernel_rollback would lose the public
// request and silently retire its handle, so it is never used on this path.
kernel_redirect_fail :: proc(
	k: ^Kernel,
	h: Request_Handle,
	primary: surf.HTTP_Error,
) -> (
	Request_Disposal,
	Client_Error,
) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}
	if primary.kind == .None {
		return {}, {kind = .Invalid_Config}
	}
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)
	if r == nil {
		return {}, {kind = .Invalid_Handle}
	}
	returning := r.state == .Returning && r.returning_to == .Preparing
	preparing := r.state == .Preparing
	if (!returning && !preparing) ||
	   r.stage != .Redirecting ||
	   r.error.kind != .None ||
	   !completion_empty(&r.response) ||
	   r.completion_queued ||
	   k.references <= 1 {
		return {}, {kind = .Invalid_State}
	}
	if returning &&
	   (r.origin.slot != 0 ||
			   r.session.slot != 0 ||
			   r.input.storage != nil ||
			   k.returning < 1 ||
			   k.counters.returning_requests < 1) {
		return {}, {kind = .Invalid_State}
	}
	if preparing &&
	   (k.preparing < 1 ||
			   k.counters.preparing_requests < 1 ||
			   k.returning == max(int) ||
			   k.counters.returning_requests == max(int) ||
			   k.references == max(int)) {
		return {}, {kind = .Invalid_State}
	}
	disposal := Request_Disposal {
		request      = h,
		returning_to = .Completed,
		input        = r.input,
		lease        = r.lease,
	}
	if r.stream != nil {
		assert(stream_api.retain(r.stream))
		disposal.stream_finish = r.stream
		disposal.stream_error = primary
	}
	if preparing {
		if error := admission_detach_claim_locked(k, h, r); error.kind != .None {
			return {}, error
		}

		if r.origin.slot != 0 {
			origin, error := kernel_origin_release_locked(k, r.origin, .Request)
			assert(error.kind == .None)
			disposal.origin = origin
		}

		k.preparing -= 1
		k.counters.preparing_requests -= 1
		k.returning += 1
		k.counters.returning_requests += 1
	}
	// Preparing and Returning both already own one Kernel bookkeeping reference.
	// Transfer it to terminal Returning without adding or dropping another one.
	r.input = {}
	r.origin = {}
	r.session = {}
	r.lease = {}
	r.error = primary
	r.state = .Returning
	r.returning_to = .Completed
	r.stage = .Retiring
	k.dispatch_dirty = true
	k.idle_dirty = true
	return disposal, {}
}

@(private)
redirect_dispose :: proc(s: ^Client_State, disposal: ^Request_Disposal) {
	origin := disposal.origin.origin
	request_disposal_destroy(disposal)

	if origin.slot != 0 {
		assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
	}
}

// Fresh monotonic sample supplied after each synchronous prefix destructor.
// The accepted request stays exclusively actor-owned until terminal/requeue.
@(private)
redirect_live_error :: proc(a: ^Session_Actor, h: Request_Handle, now: runtime_async.Deadline) -> surf.HTTP_Error {
	s := a.owner
	network_lock_both(s)
	r := admission_request_locked(&s.kernel, h)
	result: surf.HTTP_Error

	if r == nil || now.epoch != r.deadline.epoch || now.at <= 0 {
		result = {
			kind         = .Invalid_Config,
			phase        = .Configuration,
			write_effect = .Not_Sent,
		}
	} else if now.at >= r.deadline.at {
		result = {
			kind = .Deadline_Failed,
			transport = {kind = .Timeout},
			phase = .Deadline,
			write_effect = .Not_Sent,
		}
	} else if s.phase != .Published || s.kernel.closed || r.cancel_requested || runtime_async.cancelled(&a.task) {
		result = {
			kind = .IO_Failed,
			transport = {kind = .Cancelled},
			phase = .Cancellation,
			write_effect = .Not_Sent,
		}
	}

	network_unlock_both(s)

	return result
}

@(private)
redirect_terminal :: proc(a: ^Session_Actor, error: surf.HTTP_Error) {
	s := a.owner
	h := a.redirect.request
	primary := redirect_status_error(error, a.redirect.last_status)
	assert(primary.kind != .None)
	// Snapshot scalar custody before destruction clears the move-only target.
	// This prefix may call close/stats/cancel and must precede final publication.
	redirect_handoff_destroy(&a.redirect)
	sync.lock(&s.mu)
	disposal, cause := kernel_redirect_fail(&s.kernel, h, primary)
	assert(cause.kind == .None)
	network_queue_forget_locked(s, h)
	sync.unlock(&s.mu)

	for {
		redirect_dispose(s, &disposal)
		now, clock := network_clock(s)
		assert(clock.kind == .None)
		next, done, finish := kernel_cleanup_finish(&s.kernel, h, now)
		assert(finish.kind == .None)
		disposal = next

		if done {
			break
		}
	}

	sync.lock(&s.mu)
	assert(s.returning_calls > 0)
	s.returning_calls -= 1
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
}

@(private)
redirect_requeue :: proc(a: ^Session_Actor) {
	s := a.owner
	h := a.redirect.request
	now, clock := network_clock(s)

	if clock.kind != .None {
		redirect_terminal(a, redirect_client_error(clock))
		return
	}

	if error := redirect_live_error(a, h, now); error.kind != .None {
		redirect_terminal(a, error)
		return
	}

	sync.lock(&s.mu)
	ready := kernel_redirect_ready(&s.kernel, h, now)
	sync.unlock(&s.mu)

	if ready.kind != .None {
		redirect_terminal(a, redirect_client_error(ready))
		return
	}

	_, claim := network_queue_claim_budget(s, {request = h}, &a.redirect.origin, now.at, a.redirect.queries_remaining)

	if claim.kind != .None {
		redirect_terminal(a, redirect_client_error(claim))
		return
	}

	// A pre-existing origin leaves the prepared candidate with us. Release it
	// before the final fresh-clock commit barrier, outside every owner mutex.
	origin_destroy(&a.redirect.origin)
	fresh, sample := network_clock(s)

	if sample.kind != .None {
		redirect_terminal(a, redirect_client_error(sample))
		return
	}

	if error := redirect_live_error(a, h, fresh); error.kind != .None {
		redirect_terminal(a, error)
		return
	}

	sync.lock(&s.mu)
	metadata := &s.requests[int(h.slot) - 1]
	assert(metadata.generation == h.generation)
	metadata.redirects = a.redirect.next_hop
	metadata.last_status = a.redirect.last_status
	commit := network_queue_committed_locked(s, {request = h}, &a.redirect.input, fresh)

	if commit.kind == .None {
		assert(a.redirect.input.storage == nil && a.redirect.origin.storage == nil)
		a.redirect = {}
		assert(s.returning_calls > 0)
		s.returning_calls -= 1
		network_queue_changed_locked(s)
	}

	sync.unlock(&s.mu)

	if commit.kind != .None {
		redirect_terminal(a, redirect_client_error(commit))
		return
	}
}

@(private)
redirect_empty :: proc(h: ^Redirect_Handoff) -> bool {
	return(
		h.phase == .Empty &&
		h.request == (Request_Handle{}) &&
		raw_data(h.input.storage) == nil &&
		h.input.allocator.procedure == nil &&
		raw_data(h.input.request.url) == nil &&
		raw_data(h.input.request.headers) == nil &&
		raw_data(h.input.request.body) == nil &&
		raw_data(h.origin.storage) == nil &&
		h.origin.allocator.procedure == nil &&
		raw_data(h.origin.key.host) == nil &&
		len(h.input.storage) == 0 &&
		len(h.input.request.url) == 0 &&
		len(h.input.request.headers) == 0 &&
		len(h.input.request.body) == 0 &&
		len(h.origin.storage) == 0 &&
		len(h.origin.key.host) == 0 &&
		h.origin.key.profile_id == 0 &&
		h.origin.key.port == 0 &&
		!h.origin.key.secure &&
		h.next_hop == 0 &&
		h.queries_remaining == 0 &&
		h.last_status == 0 \
	)
}
@(private)
redirect_request_shape :: proc(request: http.Request) -> bool {
	if len(request.url) < 0 ||
	   len(request.body) < 0 ||
	   len(request.headers) < 0 ||
	   len(request.headers) > http.MAX_HEADERS ||
	   len(request.url) > 0 && raw_data(request.url) == nil ||
	   len(request.body) > 0 && raw_data(request.body) == nil ||
	   len(request.headers) > 0 && raw_data(request.headers) == nil {
		return false
	}

	for field in request.headers {
		if len(field.name) < 0 ||
		   len(field.value) < 0 ||
		   len(field.name) > 0 && raw_data(field.name) == nil ||
		   len(field.value) > 0 && raw_data(field.value) == nil {
			return false
		}
	}

	return true
}
@(private)
redirect_request_overlaps :: proc(request: http.Request, p: rawptr, n: int) -> bool {
	if ranges_overlap(raw_data(request.url), len(request.url), p, n) ||
	   ranges_overlap(raw_data(request.body), len(request.body), p, n) ||
	   ranges_overlap(raw_data(request.headers), len(request.headers) * size_of(http.Header), p, n) {
		return true
	}

	for field in request.headers {
		if ranges_overlap(raw_data(field.name), len(field.name), p, n) ||
		   ranges_overlap(raw_data(field.value), len(field.value), p, n) {
			return true
		}
	}

	return false
}
@(private)
redirect_preparation_error :: proc(error: Client_Error, status: int) -> Client_Error {
	result := error
	result.http = surf.http_error_classify(result.http, .Protocol, .Response_Received, status)

	return result
}

// Caller keeps Profile/current immutable and independently alive through this
// synchronous borrowed call, outside all State/Kernel locks. Before Preparing,
// malformed/reentrant/alias rejection preserves the caller's Response. Once
// Preparing is installed, the Response is moved+cleared and consumed on EVERY
// subsequent policy/allocation outcome. No intermediate bytes escape to Ready.
// This function does not sample time; its caller rechecks the original cutoff
// and cancellation after all preparation and physical cleanup have returned.
redirect_prepare :: proc(
	target: ^Redirect_Handoff,
	profile: ^Profile,
	handle: Request_Handle,
	current: http.Request,
	response: ^surf.Response,
	redirects, queries_remaining: int,
	allocator: mem.Allocator,
) -> Client_Error {
	if target == nil || !redirect_empty(target) {
		return {kind = .Invalid_State}
	}
	if !profile_valid(profile) ||
	   response == nil ||
	   handle.owner_id == 0 ||
	   handle.slot == 0 ||
	   handle.generation == 0 ||
	   redirects < 0 ||
	   redirects > http.MAX_REDIRECTS ||
	   queries_remaining < 0 ||
	   queries_remaining > DNS_TOTAL_QUERY_LIMIT ||
	   allocator.procedure == nil {
		return {kind = .Invalid_Config}
	}
	status := response.status
	if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
		return {kind = .Invalid_Config}
	}
	if !redirect_request_shape(current) {
		return {kind = .Invalid_Config}
	}
	if len(response.headers) < 0 ||
	   len(response.headers) > http.MAX_HEADERS ||
	   len(response.headers) > 0 && raw_data(response.headers) == nil ||
	   len(response.header_storage) < 0 ||
	   len(response.body) < 0 ||
	   len(response.body_storage) < 0 ||
	   cap(response.body_storage) < len(response.body_storage) {
		return {kind = .Invalid_Config}
	}
	for field in response.headers {
		if len(field.name) < 0 ||
		   len(field.value) < 0 ||
		   len(field.name) > 0 && raw_data(field.name) == nil ||
		   len(field.value) > 0 && raw_data(field.value) == nil {
			return {kind = .Invalid_Config}
		}
	}
	if ranges_overlap(target, size_of(Redirect_Handoff), response, size_of(surf.Response)) ||
	   ranges_overlap(target, size_of(Redirect_Handoff), profile, size_of(Profile)) ||
	   ranges_overlap(target, size_of(Redirect_Handoff), raw_data(profile.storage), len(profile.storage)) ||
	   redirect_request_overlaps(current, target, size_of(Redirect_Handoff)) ||
	   redirect_request_overlaps({headers = response.headers}, target, size_of(Redirect_Handoff)) ||
	   ranges_overlap(target, size_of(Redirect_Handoff), raw_data(response.body), len(response.body)) ||
	   ranges_overlap(
		   target,
		   size_of(Redirect_Handoff),
		   raw_data(response.header_storage),
		   len(response.header_storage),
	   ) ||
	   ranges_overlap(target, size_of(Redirect_Handoff), raw_data(response.body_storage), cap(response.body_storage)) {
		return {kind = .Invalid_Config, http = {kind = .Overlapping_Buffers}}
	}
	// Root execute_redirect consumes response storage before target cloning, so
	// current input must not borrow any of that independently disposed backing.
	if redirect_request_overlaps(current, raw_data(response.headers), len(response.headers) * size_of(http.Header)) ||
	   redirect_request_overlaps(current, raw_data(response.header_storage), len(response.header_storage)) ||
	   redirect_request_overlaps(current, raw_data(response.body_storage), cap(response.body_storage)) {
		return {kind = .Invalid_Config, http = {kind = .Overlapping_Buffers}}
	}
	header: [http.MAX_HEADER_SIZE]u8
	if _, error := h1.request_encode_content(header[:], current, .Keep_Alive, .Identity); error.kind != .None {
		return {kind = .Request_Error, http = {kind = error.kind}}
	}
	base, parse_error := http.url_parse(current.url)
	if parse_error.kind != .None {
		return {kind = .Request_Error, http = {kind = parse_error.kind}}
	}
	target.phase = .Preparing
	consumed := response^
	response^ = {}
	checked: Redirect_Allocator
	input: Request_Owner
	origin: Prepared_Origin
	success := false
	// Keep the Preparing guard through every arbitrary prefix destructor. The
	// final commit/reset follows all callbacks; no allocator pointer outlives us.
	defer {
		if !success {
			request_owner_destroy(&input)
			origin_destroy(&origin)
		}

		redirect_allocator_destroy(&checked)
		surf.response_destroy(&consumed)

		if success {
			target^ = {
				phase             = .Ready,
				request           = handle,
				input             = input,
				origin            = origin,
				next_hop          = redirects + 1,
				queries_remaining = queries_remaining,
				last_status       = status,
			}
		} else {
			target^ = {}
		}
	}
	if error := redirect_allocator_init(&checked, allocator); error.kind != .None {
		return redirect_preparation_error(error, status)
	}
	temporary := mem.Allocator{redirect_allocator_proc, &checked}
	url, error := surf.execute_redirect(&consumed, current, base, profile.config.http, redirects, temporary)
	if checked.failure.kind != .None {
		return redirect_preparation_error(checked.failure, status)
	}
	if error.kind != .None {
		return redirect_preparation_error({kind = .Request_Error, http = error}, status)
	}
	next := current
	next.url = url
	cloned, clone_error := request_clone(next, allocator)
	if clone_error.kind != .None {
		return redirect_preparation_error(clone_error, status)
	}
	input = cloned
	prepared, origin_error := origin_prepare(profile, url, temporary)
	if checked.failure.kind != .None {
		return redirect_preparation_error(checked.failure, status)
	}
	if origin_error.kind != .None {
		return redirect_preparation_error(origin_error, status)
	}
	// origin_prepare used the checked stack adapter for typed allocation causes.
	// Detach the exact whole grant before replacing its allocator with permanent
	// provenance. Temporary cleanup then owns only the helper's surviving URL.
	assert(redirect_allocator_detach(&checked, prepared.storage, 1))
	prepared.allocator = allocator
	origin = prepared
	success = true
	return {}
}

// Preparing is an outstanding borrowed construction, so reentrant destruction
// rejects by doing nothing. Ready destruction clears before the first physical
// free; that callback may destroy/free the public handoff header itself.
redirect_handoff_destroy :: proc(target: ^Redirect_Handoff) {
	if target == nil || target.phase == .Preparing {
		return
	}

	old := target^
	target^ = {}
	request_owner_destroy(&old.input)
	origin_destroy(&old.origin)
}

// Internal accepted-request handoff. Preparing is a construction/reentry guard,
// not permission to publish a Kernel request or move an incomplete target.
Redirect_Phase :: enum {
	Empty,
	Preparing,
	Ready,
}

// Move-only target custody at a stable address across physical close callbacks.
// The original Request_Handle, Scope stream lease and total deadline belong to
// the Kernel. Only the handle is copied here: no second lease is admitted.
//
// Preparing must be installed before the first arbitrary allocator callback or
// intermediate Response disposal. Ready owns both input and origin; its target
// slices never borrow the consumed Response, temporary URL or caller request.
// A destructor snapshots and clears the whole handoff before physical frees.
// Do not relocate this value while Preparing, nor copy its Ready owners.
Redirect_Handoff :: struct {
	phase:             Redirect_Phase,
	// Survives session_reset_io clearing actor.request. Never use a later actor
	// mailbox's handle to resolve this already accepted request's ledger ticket.
	request:           Request_Handle,
	input:             Request_Owner,
	origin:            Prepared_Origin,
	// First followed redirect is1; Ready is bounded by http.MAX_REDIRECTS (5).
	next_hop:          int,
	// Original request's remaining finite DNS draw allowance, before reserving
	// the next hop's block. Moving a block to an actor deducts exactly once.
	queries_remaining: int,
	// Most recent validated redirect response. Fill missing error status only;
	// an ambiguous later-hop Unknown write effect must remain Unknown.
	last_status:       int,
}
