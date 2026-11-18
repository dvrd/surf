package surf_async

import surf ".."
import runtime_async "shared:async"
import signal "shared:async/signal"
import "core:sync"
import http "shared:http"
import h1 "shared:http/v1"
import "core:bytes"
import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"
import "core:strings"
import stream_api "stream"
import exchange_api "exchange"
import "core:net"
import "core:os"

network_coordinator_wake :: proc(notification: signal.Signal) {
	owner, valid := signal.retain(notification)

	if valid {
		_ = signal.wake(owner)
		signal.release(&owner)
	}
}

// Idempotent whole-State close. The caller owns a State reference. Snapshot
// retained producer handles while State.mu protects registration metadata; no
// scheduler notification or physical release executes under either owner lock.
network_close_state :: proc(s: ^Client_State) {
	if !network_valid(s) {
		return
	}

	notifications: [MAX_CONNECTIONS + 1]signal.Signal
	count := 0
	sync.lock(&s.mu)

	if s.phase == .Disposing {
		sync.unlock(&s.mu)
		return
	}

	sync.lock(&s.kernel.mu)
	first := s.phase != .Closing || !s.kernel.closed
	sync.unlock(&s.kernel.mu)

	if first {
		s.phase = .Closing
		assert(kernel_close(&s.kernel).kind == .None)
		network_queue_changed_locked(s)

		if s.coordinator.registered && !s.coordinator.detached {
			owner, valid := signal.retain(s.coordinator.wake)

			if valid {
				notifications[count] = owner
				count += 1
			}
		}

		for actor in s.actors {
			if actor.registered && !actor.detached {
				owner, valid := signal.retain(actor.wake)

				if valid {
					notifications[count] = owner
					count += 1
				}
			}
		}
	}

	sync.unlock(&s.mu)

	for &notification in notifications[:count] {
		_ = signal.wake(notification)
		signal.release(&notification)
	}
}

// The caller's registration reference keeps State alive through arbitrary input
// and lease disposal callbacks. No physical callback runs under either mutex.
network_coordinator_complete :: proc(
	s: ^Client_State,
	handle: Request_Handle,
	error: surf.HTTP_Error,
) -> Client_Error {
	sync.lock(&s.mu)
	response: surf.Response
	disposal, failure := kernel_begin_complete(&s.kernel, handle, &response, error)
	if failure.kind == .None {
		network_queue_forget_locked(s, handle)
	}
	s.returning_calls += 1
	sync.unlock(&s.mu)
	if failure.kind == .None {
		for {
			origin := disposal.origin.origin
			request_disposal_destroy(&disposal)

			if origin.slot != 0 {
				assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
			}

			now, clock_error := network_clock(s)
			assert(clock_error.kind == .None)
			next, done, finish_error := kernel_cleanup_finish(&s.kernel, handle, now)
			assert(finish_error.kind == .None)
			disposal = next

			if done {
				break
			}
		}
	}
	sync.lock(&s.mu)
	assert(s.returning_calls > 0)
	s.returning_calls -= 1
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
	return failure
}

// One request-capacity inspection. Active request completion belongs solely to
// its actor; the coordinator only delivers a cancellation mailbox notification.
network_coordinator_request_step :: proc(s: ^Client_State, now: runtime_async.Deadline) -> bool {
	sync.lock(&s.mu)

	if s.coordinator.scan_remaining == 0 {
		sync.unlock(&s.mu)
		return false
	}

	index := int(s.coordinator.request_cursor) % len(s.requests)
	s.coordinator.request_cursor = u32((index + 1) % len(s.requests))
	s.coordinator.scan_remaining -= 1
	sync.lock(&s.kernel.mu)
	request := &s.kernel.requests[index]
	handle := Request_Handle {
		owner_id   = s.kernel.owner_id,
		slot       = u32(index + 1),
		generation = request.generation,
	}

	closing := s.phase == .Closing || s.kernel.closed
	cancellation := closing || request.cancel_requested
	failed := cancellation || (request.deadline.at != 0 && now.at >= request.deadline.at)
	complete := request.state == .Queued && failed
	notification: signal.Signal

	if request.state == .Active && failed && request.session.slot != 0 {
		actor := &s.actors[int(request.session.slot) - 1]
		// An expired Active cutoff remains the actor's Deadline result. Do not
		// turn it into an explicit cancellation merely because we also wake its owner.
		if cancellation {
			actor.command.cancel = true
		}

		notification = actor.wake
	}

	if request.state == .Queued && !failed && request.deadline.at > 0 {
		next := &s.coordinator.next_deadline

		if next.at == 0 || request.deadline.at < next.at {
			next^ = request.deadline
		}
	}

	network_unlock_both(s)
	network_coordinator_wake(notification)

	if complete {
		error := surf.HTTP_Error {
			kind         = .Deadline_Failed,
			phase        = .Deadline,
			write_effect = .Not_Sent,
		}

		if cancellation {
			error = {
				kind = .IO_Failed,
				transport = {kind = .Cancelled},
				phase = .Cancellation,
				write_effect = .Not_Sent,
			}
		}

		assert(network_coordinator_complete(s, handle, error).kind == .None)
		return true
	}

	return false
}

// One request metadata cell and at most one finite16-ID transfer. Only the
// unassigned origin FIFO head is unparked; no later waiter bypasses that head.
// Lock order: s.mu, then s.kernel.mu. Release in reverse.
network_lock_both :: proc(s: ^Client_State) {
	sync.lock(&s.mu)
	sync.lock(&s.kernel.mu)
}

network_unlock_both :: proc(s: ^Client_State) {
	sync.unlock(&s.kernel.mu)
	sync.unlock(&s.mu)
}

network_coordinator_dns_step :: proc(s: ^Client_State) -> bool {
	sync.lock(&s.mu)
	index := int(s.coordinator.dns_cursor) % len(s.requests)
	s.coordinator.dns_cursor = u32((index + 1) % len(s.requests))
	sync.lock(&s.kernel.mu)
	request := &s.kernel.requests[index]
	metadata := &s.requests[index]
	handle := Request_Handle {
		owner_id   = s.kernel.owner_id,
		slot       = u32(index + 1),
		generation = request.generation,
	}

	origin := admission_origin_locked(&s.kernel, request.origin)
	eligible :=
		s.phase == .Published &&
		request.state == .Queued &&
		request.session.slot == 0 &&
		!request.cancel_requested &&
		metadata.generation == request.generation &&
		metadata.awaiting_ids &&
		metadata.ids.count == 0 &&
		metadata.query_budget_left > 0 &&
		origin != nil &&
		origin.queue_head == handle.slot
	maximum := min(DNS_IDS_PER_QUERY, metadata.query_budget_left)
	network_unlock_both(s)

	if !eligible {
		return false
	}

	block, error := network_dns_reserve(s, maximum)

	if error.kind != .None {
		return false
	}

	installed := false
	network_lock_both(s)
	request = admission_request_locked(&s.kernel, handle)
	metadata = &s.requests[index]
	if s.phase == .Published &&
	   request != nil &&
	   request.state == .Queued &&
	   request.session.slot == 0 &&
	   !request.cancel_requested &&
	   metadata.generation == handle.generation &&
	   metadata.awaiting_ids &&
	   metadata.ids.count == 0 {
		origin = admission_origin_locked(&s.kernel, request.origin)
		if origin != nil && origin.queue_head == handle.slot {
			metadata.ids = block
			block = {}
			metadata.awaiting_ids = false
			request.stage = .Queued
			s.kernel.dispatch_dirty = true
			network_queue_changed_locked(s)
			installed = true
		}
	}

	network_unlock_both(s)
	network_dns_burn(s, &block)

	return installed
}

network_coordinator_dispatch_step :: proc(s: ^Client_State, now: i64) -> bool {
	sync.lock(&s.mu)

	if s.phase != .Published {
		sync.unlock(&s.mu)
		return true
	}

	assignment, _, error := pool_dispatch(&s.kernel, 1, now)
	notification: signal.Signal

	if assignment.request.slot != 0 {
		actor := &s.actors[int(assignment.session.slot) - 1]
		assert(!actor.command.pending)
		actor.command = {
			assignment = assignment,
			pending    = true,
		}

		notification = actor.wake
	}

	sync.unlock(&s.mu)
	network_coordinator_wake(notification)

	return error.kind != .Pending && assignment.request.slot == 0
}

network_coordinator_idle_step :: proc(s: ^Client_State, now: i64) -> bool {
	network_lock_both(s)
	needs_scan :=
		s.kernel.idle_dirty ||
		s.kernel.idle_remaining > 0 ||
		(s.kernel.idle_deadline > 0 && now >= s.kernel.idle_deadline)
	sync.unlock(&s.kernel.mu)

	if !needs_scan {
		sync.unlock(&s.mu)
		return true
	}

	candidate, _, error := pool_idle_candidate(&s.kernel, 1, now)
	notification: signal.Signal

	if candidate.slot != 0 {
		assert(pool_session_state(&s.kernel, candidate, .Retiring, now).kind == .None)
		actor := &s.actors[int(candidate.slot) - 1]
		actor.command.retire = true
		notification = actor.wake
	}

	sync.lock(&s.kernel.mu)
	stable := s.kernel.idle_remaining == 0 && !s.kernel.idle_dirty
	network_unlock_both(s)
	network_coordinator_wake(notification)

	return error.kind != .Pending && candidate.slot == 0 && stable
}

network_coordinator_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	coordinator := cast(^Coordinator_State)data

	if coordinator == nil || !network_valid(coordinator.owner) {
		return .Done
	}

	s := coordinator.owner
	now, error := network_clock(s)
	assert(error.kind == .None)
	sync.lock(&s.mu)
	lifetime := s.config.config.lifetime
	closing_at_entry := s.phase == .Closing
	sync.unlock(&s.mu)

	if closing_at_entry || lifetime.epoch != 0 && now.at >= lifetime.at {
		network_close_state(s)
	}

	sync.lock(&s.mu)

	if coordinator.scan_remaining == 0 {
		network_queue_changed_locked(s)
	}

	work := s.config.config.capacities.work_per_resume
	sync.unlock(&s.mu)
	dispatch_stable, idle_stable := false, false
	// Each unit is a documented COMPOSITE upper bound: one request inspection,
	// one DNS cell+at most16 copied IDs, one charged pool dispatch inspection and
	// one charged Idle inspection. Parser/I/O/entropy and unbounded scans are absent.
	for _ in 0 ..< work {
		if network_coordinator_request_step(s, now) {
			return .Yield
		}

		_ = network_coordinator_dns_step(s)
		dispatch_stable = network_coordinator_dispatch_step(s, now.at)
		idle_stable = network_coordinator_idle_step(s, now.at)
	}

	network_lock_both(s)
	closing := s.phase == .Closing || s.kernel.closed
	done :=
		closing &&
		s.kernel.preparing == 0 &&
		s.kernel.returning == 0 &&
		s.kernel.counters.queued_requests == 0 &&
		s.kernel.counters.active_requests == 0 &&
		s.kernel.counters.reserved_connections == 0 &&
		s.kernel.counters.idle_connections == 0 &&
		s.producer_calls == 0 &&
		s.returning_calls == 0

	if done {
		coordinator.done = true
	}

	scanned := coordinator.scan_remaining == 0
	deadline := coordinator.next_deadline

	if s.kernel.idle_deadline > 0 && (deadline.at == 0 || s.kernel.idle_deadline < deadline.at) {
		deadline = {
			epoch = s.runtime_epoch,
			at    = s.kernel.idle_deadline,
		}
	}

	if !closing && lifetime.epoch != 0 && (deadline.at == 0 || lifetime.at < deadline.at) {
		deadline = lifetime
	}

	runtime := s.runtime
	network_unlock_both(s)

	if done {
		return .Done
	}

	if closing || !scanned || !dispatch_stable || !idle_stable {
		return .Yield
	}

	if deadline.at > 0 {
		failure := runtime_async.sleep_until(runtime, deadline)

		if failure.kind != .Pending {
			return .Yield
		}
	}

	return .Waiting
}

network_coordinator_cancel :: proc(data: rawptr) -> runtime_async.Resume_Result {
	coordinator := cast(^Coordinator_State)data

	if coordinator == nil || !network_valid(coordinator.owner) {
		return .Done
	}

	s := coordinator.owner
	network_close_state(s)

	return network_coordinator_resume(data)
}
network_coordinator_done :: proc(data: rawptr) {
	coordinator := cast(^Coordinator_State)data

	if coordinator == nil || !network_valid(coordinator.owner) {
		return
	}

	s := coordinator.owner
	sync.lock(&s.mu)
	drained := coordinator.done
	sync.unlock(&s.mu)
	network_task_done(s, 0, drained)
}

admission_request_locked :: proc(k: ^Kernel, h: Request_Handle) -> ^Request_Slot {
	if h.owner_id != k.owner_id || h.slot == 0 || u64(h.slot) > u64(len(k.requests)) || h.generation == 0 {
		return nil
	}

	r := &k.requests[int(h.slot) - 1]

	if r.generation != h.generation || r.state == .Free || r.state == .Retired {
		return nil
	}

	return r
}
admission_origin_locked :: proc(k: ^Kernel, h: Cell_Handle) -> ^Origin_Slot {
	if h.slot == 0 || u64(h.slot) > u64(len(k.origins)) || h.generation == 0 {
		return nil
	}

	o := &k.origins[int(h.slot) - 1]

	if o.generation != h.generation || o.state != .Occupied {
		return nil
	}

	return o
}
admission_alias :: proc(k: ^Kernel, p: rawptr, size: int) -> bool {
	region := mem.byte_slice(p, size)

	if bytes.alias(region, mem.byte_slice(k, size_of(Kernel))) {
		return true
	}

	for storage in ([6][]u8 {
			mem.slice_to_bytes(k.requests),
			mem.slice_to_bytes(k.origins),
			mem.slice_to_bytes(k.sessions),
			mem.slice_to_bytes(k.request_free),
			mem.slice_to_bytes(k.origin_free),
			mem.slice_to_bytes(k.session_free),
		}) {
		if bytes.alias(region, storage) {
			return true
		}
	}

	return false
}
admission_region :: proc(storage: []u8, p: rawptr, size: int) -> bool {
	if size == 0 {
		return true
	}

	if p == nil || size < 0 {
		return false
	}

	start, at := uintptr(raw_data(storage)), uintptr(p)

	return at >= start && at - start <= uintptr(len(storage)) && uintptr(size) <= uintptr(len(storage)) - (at - start)
}
admission_input :: proc(k: ^Kernel, input: ^Request_Owner) -> (http.URL, Client_Error) {
	if input == nil ||
	   admission_alias(k, input, size_of(Request_Owner)) ||
	   input.allocator.procedure == nil ||
	   len(input.storage) == 0 ||
	   raw_data(input.storage) == nil {
		return {}, {kind = .Invalid_Config}
	}

	if bytes.alias(mem.byte_slice(input, size_of(Request_Owner)), input.storage) ||
	   admission_alias(k, raw_data(input.storage), len(input.storage)) ||
	   uintptr(raw_data(input.storage)) % align_of(http.Header) != 0 {
		return {}, {kind = .Invalid_Config}
	}

	r := input.request
	if len(r.headers) > http.MAX_HEADERS ||
	   !admission_region(input.storage, raw_data(r.headers), len(r.headers) * size_of(http.Header)) ||
	   len(r.headers) > 0 && uintptr(raw_data(r.headers)) % align_of(http.Header) != 0 ||
	   !admission_region(input.storage, raw_data(r.url), len(r.url)) ||
	   !admission_region(input.storage, raw_data(r.body), len(r.body)) {
		return {}, {kind = .Invalid_Config}
	}

	for header in r.headers {
		if !admission_region(input.storage, raw_data(header.name), len(header.name)) ||
		   !admission_region(input.storage, raw_data(header.value), len(header.value)) {
			return {}, {kind = .Invalid_Config}
		}
	}

	wire: [http.MAX_HEADER_SIZE]u8
	_, validation := h1.request_encode_content(wire[:], r, .Keep_Alive, .Identity)

	if validation.kind != .None {
		return {}, {kind = .Request_Error, http = {kind = validation.kind}}
	}

	if k.resources.scope != (scopes.Scope{}) {
		covered := false
		// A physical-free wrapper can forward a real managed allocation without
		// itself being a managed allocator. Query only known Binding registries.
		for allocator in ([2]mem.Allocator{input.allocator, k.resources.allocator}) {
			info, valid := charged.allocation_info(allocator, raw_data(input.storage))

			if valid && info.size == len(input.storage) && scopes.covers(info.scope, k.resources.scope) {
				covered = true
				break
			}
		}

		if !covered {
			return {}, {kind = .Invalid_Config, http = {kind = .Invalid_Config, budget = .Foreign_Root}}
		}
	}

	url, error := http.url_parse(r.url)

	if error.kind != .None {
		return {}, {kind = .Request_Error, http = {kind = error.kind}}
	}

	return url, {}
}

kernel_reserve :: proc(
	k: ^Kernel,
	deadline: runtime_async.Deadline,
	lease: ^scopes.Lease,
) -> (
	Preparing_Request,
	Client_Error,
) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}
	if lease == nil || admission_alias(k, lease, size_of(scopes.Lease)) || deadline.epoch == 0 || deadline.at <= 0 {
		return {}, {kind = .Invalid_Config}
	}
	selected := deadline
	if lifetime := k.config.lifetime; lifetime.epoch != 0 {
		if lifetime.epoch != deadline.epoch {
			return {}, {kind = .Invalid_Config}
		}

		selected.at = min(selected.at, lifetime.at)
	}
	scope := k.resources.scope
	if scope == (scopes.Scope{}) {
		if lease^ != (scopes.Lease{}) {
			return {}, {kind = .Invalid_Config}
		}
	} else {
		actual := scopes.scope_of(lease^)

		if actual == (scopes.Scope{}) || !scopes.covers(actual, scope) {
			cause := scopes.Error.Invalid_Config

			if actual != (scopes.Scope{}) && !scopes.same_root(actual, scope) {
				cause = .Foreign_Root
			}

			return {}, {kind = .Invalid_Config, http = {kind = .Invalid_Config, budget = cause}}
		}

		if scopes.cost_of(lease^) != (scopes.Cost{streams = 1}) || scopes.phase_of(lease^) != .None {
			return {}, {kind = .Invalid_Config}
		}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	if k.closed {
		return {}, {kind = .Closed}
	}
	if k.request_free_count == 0 {
		return {}, {kind = .Capacity}
	}
	if k.request_free_count < 0 ||
	   k.request_free_count > len(k.request_free) ||
	   k.references < 1 ||
	   k.references == max(int) ||
	   k.preparing == max(int) {
		return {}, {kind = .Invalid_State}
	}
	index := k.request_free[k.request_free_count - 1]
	if index == 0 || u64(index) > u64(len(k.requests)) {
		return {}, {kind = .Invalid_State}
	}
	r := &k.requests[int(index) - 1]
	if r.state != .Free || r.generation == 0 {
		return {}, {kind = .Invalid_State}
	}
	generation := r.generation
	r^ = {
		generation = generation,
		state      = .Preparing,
		stage      = .Queued,
		deadline   = selected,
		lease      = lease^,
	}
	lease^ = {}
	k.request_free_count -= 1
	k.request_free[k.request_free_count] = 0
	k.preparing += 1
	k.references += 1
	k.counters.preparing_requests += 1
	k.dispatch_dirty = true
	return {request = {owner_id = k.owner_id, slot = index, generation = generation}}, {}
}

kernel_commit :: proc(
	k: ^Kernel,
	p: Preparing_Request,
	input: ^Request_Owner,
	now: runtime_async.Deadline,
) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}
	url, validation := admission_input(k, input)
	if validation.kind != .None {
		return validation
	}
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, p.request)
	if r == nil {
		return {kind = .Invalid_Handle}
	}
	if r.state != .Preparing {
		return {kind = .Invalid_State}
	}
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
	o := admission_origin_locked(k, r.origin)
	if o == nil || o.requests < 1 || o.preparing < 1 || k.preparing < 1 || k.references <= 1 {
		return {kind = .Invalid_State}
	}
	if o.owner.key.profile_id != k.profile.owner_id ||
	   o.owner.key.secure != url.secure ||
	   int(o.owner.key.port) != url.port ||
	   !strings.equal_fold(o.owner.key.host, url.host) {
		return {kind = .Invalid_Config}
	}
	if r.session.slot != 0 {
		if u64(r.session.slot) > u64(len(k.sessions)) {
			return {kind = .Invalid_State}
		}

		s := &k.sessions[int(r.session.slot) - 1]
		if s.generation != r.session.generation ||
		   s.state != .Reserved ||
		   s.request != p.request ||
		   s.origin != r.origin ||
		   (s.reserved_from != .Free && s.reserved_from != .Idle) {
			return {kind = .Invalid_State}
		}
	} else {
		if o.waiters < 1 || (o.queue_head == 0) != (o.queue_tail == 0) {
			return {kind = .Invalid_State}
		}

		if o.queue_tail != 0 {
			if u64(o.queue_tail) > u64(len(k.requests)) {
				return {kind = .Invalid_State}
			}

			tail := &k.requests[int(o.queue_tail) - 1]

			if tail.state != .Queued || tail.origin != r.origin || tail.session.slot != 0 || tail.queue_next != 0 {
				return {kind = .Invalid_State}
			}
		}
	}
	disposal, error := kernel_origin_release_locked(k, r.origin, .Preparing)
	assert(error.kind == .None && disposal.origin.slot == 0)
	if r.session.slot == 0 {
		r.queue_previous = o.queue_tail

		if o.queue_tail != 0 {
			k.requests[int(o.queue_tail) - 1].queue_next = p.request.slot
		} else {
			o.queue_head = p.request.slot
		}

		o.queue_tail = p.request.slot
	}
	r.input = input^
	input^ = {}
	r.state = .Queued
	r.stage = .Queued
	k.preparing -= 1
	k.references -= 1
	k.counters.preparing_requests -= 1
	k.counters.queued_requests += 1
	k.dispatch_dirty = true
	return {}
}

admission_unlink_waiter_locked :: proc(k: ^Kernel, index: u32, r: ^Request_Slot, o: ^Origin_Slot) -> Client_Error {
	previous, next := r.queue_previous, r.queue_next

	if previous == 0 {
		if o.queue_head != index {
			return {kind = .Invalid_State}
		}
	} else {
		if u64(previous) > u64(len(k.requests)) ||
		   k.requests[int(previous) - 1].queue_next != index ||
		   k.requests[int(previous) - 1].origin != r.origin {
			return {kind = .Invalid_State}
		}
	}

	if next == 0 {
		if o.queue_tail != index {
			return {kind = .Invalid_State}
		}
	} else {
		if u64(next) > u64(len(k.requests)) ||
		   k.requests[int(next) - 1].queue_previous != index ||
		   k.requests[int(next) - 1].origin != r.origin {
			return {kind = .Invalid_State}
		}
	}

	if previous != 0 {
		k.requests[int(previous) - 1].queue_next = next
	} else {
		o.queue_head = next
	}

	if next != 0 {
		k.requests[int(next) - 1].queue_previous = previous
	} else {
		o.queue_tail = previous
	}

	r.queue_previous, r.queue_next = 0, 0

	return {}
}

// Detach a Preparing/accepted session claim using only verified07 origin
// bookkeeping. The caller preflights all fields before this mutation phase.
admission_detach_claim_locked :: proc(k: ^Kernel, h: Request_Handle, r: ^Request_Slot) -> Client_Error {
	if r.origin.slot == 0 {
		if r.session.slot != 0 {
			return {kind = .Invalid_State}
		}

		return {}
	}

	o := admission_origin_locked(k, r.origin)

	if o == nil || o.requests < 1 || o.sessions < 0 || o.preparing < 0 || o.waiters < 0 || k.counters.origins < 1 {
		return {kind = .Invalid_State}
	}

	if r.state == .Preparing && o.preparing < 1 {
		return {kind = .Invalid_State}
	}

	if r.session.slot == 0 {
		if o.waiters < 1 {
			return {kind = .Invalid_State}
		}

		if r.state == .Queued {
			if error := admission_unlink_waiter_locked(k, h.slot, r, o); error.kind != .None {
				return error
			}
		}

		disposal, error := kernel_origin_release_locked(k, r.origin, .Waiter)
		assert(error.kind == .None && disposal.origin.slot == 0)
	} else {
		if u64(r.session.slot) > u64(len(k.sessions)) {
			return {kind = .Invalid_State}
		}

		s := &k.sessions[int(r.session.slot) - 1]

		if s.generation != r.session.generation || s.origin != r.origin || s.request != h {
			return {kind = .Invalid_State}
		}

		if s.state == .Reserved {
			if (r.state != .Preparing && r.state != .Queued) ||
			   (s.reserved_from != .Idle && s.reserved_from != .Free) ||
			   k.counters.reserved_connections < 1 {
				return {kind = .Invalid_State}
			}

			if s.reserved_from == .Free &&
			   (o.sessions < 1 || s.generation != max(u64) && k.session_free_count >= len(k.session_free)) {
				return {kind = .Invalid_State}
			}

			k.counters.reserved_connections -= 1

			if s.reserved_from == .Idle {
				s.state = .Idle
				s.reserved_from = .Free
				s.request = {}
				k.counters.idle_connections += 1
				k.idle_dirty = true
			} else {
				index, generation := r.session.slot, s.generation
				s^ = {
					generation = generation,
					state      = .Retired,
				}

				if generation != max(u64) {
					s.generation += 1
					s.state = .Free
					k.session_free[k.session_free_count] = index
					k.session_free_count += 1
				}

				disposal, error := kernel_origin_release_locked(k, r.origin, .Session)
				assert(error.kind == .None && disposal.origin.slot == 0)
			}
		} else if r.state == .Active && (s.state == .Connecting || s.state == .Busy || s.state == .Retiring) {
			s.request = {}
		} else {
			return {kind = .Invalid_State}
		}

		r.session = {}
	}

	if r.state == .Preparing {
		disposal, error := kernel_origin_release_locked(k, r.origin, .Preparing)
		assert(error.kind == .None && disposal.origin.slot == 0)
	}

	k.dispatch_dirty = true

	return {}
}

kernel_rollback :: proc(k: ^Kernel, p: Preparing_Request) -> (Request_Disposal, Client_Error) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, p.request)

	if r == nil {
		return {}, {kind = .Invalid_Handle}
	}

	if r.state != .Preparing || k.preparing < 1 || k.references <= 1 || k.references == max(int) {
		return {}, {kind = .Invalid_State}
	}

	if error := admission_detach_claim_locked(k, p.request, r); error.kind != .None {
		return {}, error
	}

	result := Request_Disposal {
		request      = p.request,
		returning_to = .Free,
		input        = r.input,
		response     = r.response,
		lease        = r.lease,
		stream       = r.stream,
	}

	r.stream = nil

	if r.origin.slot != 0 {
		disposal, error := kernel_origin_release_locked(k, r.origin, .Request)
		assert(error.kind == .None)
		result.origin = disposal
	}

	r.input = {}
	r.response = {}
	r.lease = {}
	r.origin = {}
	r.state = .Returning
	r.returning_to = .Free
	r.stage = .Retiring
	k.preparing -= 1
	k.counters.preparing_requests -= 1
	k.returning += 1
	k.counters.returning_requests += 1
	k.dispatch_dirty = true

	return result, {}
}

kernel_cancel :: proc(k: ^Kernel, h: Request_Handle) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)

	if r == nil {
		return {kind = .Invalid_Handle}
	}

	if r.state == .Completed {
		return {}
	}

	if r.state == .Returning && r.returning_to == .Free {
		return {kind = .Invalid_State}
	}

	if !r.cancel_requested {
		r.cancel_requested = true

		if k.counters.cancel_count != max(u64) {
			k.counters.cancel_count += 1
		}
	}

	k.dispatch_dirty = true

	return {}
}

kernel_close :: proc(k: ^Kernel) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	k.closed = true
	k.dispatch_dirty = true
	k.idle_dirty = true

	for &r in k.requests {
		if r.state == .Preparing ||
		   r.state == .Queued ||
		   r.state == .Active ||
		   r.state == .Returning && r.returning_to == .Completed {
			if !r.cancel_requested {
				r.cancel_requested = true

				if k.counters.cancel_count != max(u64) {
					k.counters.cancel_count += 1
				}
			}
		}
	}

	return {}
}
kernel_stage :: proc(k: ^Kernel, h: Request_Handle) -> (Request_Stage, Client_Error) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)

	if r == nil {
		return {}, {kind = .Invalid_Handle}
	}

	return r.stage, {}
}

network_valid :: proc(s: ^Client_State) -> bool {
	return s != nil && s.self == s
}
network_snapshot_error :: proc(error: net.Resolver_Snapshot_Error) -> Client_Error {
	if error.kind == .Allocation_Failed {
		return {kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = error.allocation}}
	}

	if error.kind == .Unsupported {
		return {
			kind = .Runtime_Error,
			runtime = {kind = .Unsupported},
			http = {kind = .Dial_Failed, network = net.DNS_Error.Unsupported},
		}
	}

	if error.kind == .Read_Failed {
		code, _ := os.is_platform_error(error.io)
		return {
			kind = .Runtime_Error,
			runtime = {kind = .System_Error, system_code = code},
			http = {kind = .Dial_Failed, network = net.DNS_Error.Invalid_Resolv_Config_Error},
		}
	}

	return {
		kind = .Invalid_Config,
		http = {kind = .Invalid_Config, network = net.DNS_Error.Invalid_Resolv_Config_Error},
	}
}
network_scope_probe :: proc(scope: scopes.Scope) -> Client_Error {
	if scope == (scopes.Scope{}) {
		return {}
	}

	lease, error := scopes.reserve(scope, {})

	if error != .None {
		return resource_failure(error)
	}

	scopes.release(&lease)

	return {}
}
network_backing :: proc(scope: scopes.Scope, allocator: mem.Allocator) -> (State_Backing, Client_Error) {
	if allocator.procedure == nil || .Free not_in mem.query_features(allocator) {
		return {}, {kind = .Invalid_Config}
	}

	source_scope, managed := charged.allocator_scope(allocator)

	if managed && scope != (scopes.Scope{}) && !scopes.covers(source_scope, scope) {
		cause := scopes.Error.Invalid_Config

		if !scopes.same_root(source_scope, scope) {
			cause = .Foreign_Root
		}

		return {}, {kind = .Invalid_Config, http = {kind = .Invalid_Config, budget = cause}}
	}

	if error := network_scope_probe(scope); error.kind != .None {
		return {}, error
	}

	if managed {
		if error := network_scope_probe(source_scope); error.kind != .None {
			return {}, error
		}
	}

	lease: scopes.Lease

	if !managed && scope != (scopes.Scope{}) {
		owner, error := scopes.reserve(scope, {bytes = u64(size_of(Client_State))})

		if error != .None {
			return {}, resource_failure(error)
		}

		lease = owner
	}

	storage, error := kernel_grant(size_of(Client_State), align_of(Client_State), allocator)

	if error.kind != .None {
		scopes.release(&lease)
		return {}, error
	}

	for &byte in storage {
		byte = 0
	}

	return {storage = storage, allocator = allocator, lease = lease}, {}
}

// No Task registration or protocol I/O. Runtime/controller and certificate
// objects remain caller-owned through this preparation and every later close.
network_prepare :: proc(
	runtime: ^runtime_async.Runtime,
	config: Normalized_Config,
	allocator: mem.Allocator,
) -> (
	^Client_State,
	Client_Error,
) {
	if runtime == nil {
		return nil, {kind = .Invalid_Config}
	}
	options, error := network_config_normalize(config)
	if error.kind != .None {
		return nil, error
	}
	if options.dns_preparation != .Numeric_Only && runtime_async.worker_thread_active() {
		return nil, {kind = .Runtime_Error, runtime = {kind = .Current_Worker_Active}}
	}
	now := runtime_async.deadline_after(runtime, 0)
	if now.epoch == 0 || now.at <= 0 {
		return nil, {kind = .Runtime_Error, runtime = {kind = .Not_Initialized}}
	}
	if config.lifetime.epoch != 0 && config.lifetime.epoch != now.epoch {
		return nil, {kind = .Invalid_Config}
	}
	if config.lifetime.epoch != 0 && config.lifetime.at <= now.at {
		return nil, {kind = .Runtime_Error, runtime = {kind = .Timeout}}
	}
	backing, allocation := network_backing(config.http.scope, allocator)
	if allocation.kind != .None {
		return nil, allocation
	}
	s := cast(^Client_State)raw_data(backing.storage)
	s^ = {
		self           = s,
		config         = options,
		backing        = backing,
		references     = 1,
		base_owned     = true,
		runtime        = runtime,
		runtime_epoch  = now.epoch,
		last_clock     = now,
		producer_calls = 1,
	}
	success := false
	defer if !success {
		s.references = 0
		s.base_owned = false
		s.producer_calls = 0
		network_cleanup_storage(s)
	}
	error = resources_init(&s.resources, config.http.scope, allocator)
	if error.kind != .None {
		return nil, error
	}
	error = profile_init(&s.profile, config, s.resources.allocator)
	if error.kind != .None {
		return nil, error
	}
	// Only owned Profile views survive preparation; original resolver intent was
	// already captured by options before Profile canonicalized empty slices.
	s.config.config = s.profile.config
	if limits, enabled := config.streaming.?; enabled {
		bank, error := stream_api.bank_create(limits, s.resources.allocator)

		if error.kind != .None {
			return nil, stream_client_error(error)
		}

		s.stream_bank = bank
	}
	error = kernel_init(&s.kernel, &s.profile, &s.resources)
	if error.kind != .None {
		return nil, error
	}
	s.actors, error = kernel_array(Session_Actor, config.capacities.connections, s.resources.allocator)
	if error.kind != .None {
		return nil, error
	}
	for &actor in s.actors {
		actor = {}
	}
	s.requests, error = kernel_array(Request_Network, config.capacities.requests, s.resources.allocator)
	if error.kind != .None {
		return nil, error
	}
	for &request, index in s.requests {
		request = {
			generation        = s.kernel.requests[index].generation,
			query_budget_left = DNS_TOTAL_QUERY_LIMIT,
		}
	}
	s.task_index, error = kernel_array(^runtime_async.Task, options.task_count, s.resources.allocator)
	if error.kind != .None {
		return nil, error
	}
	s.dns_ids, error = kernel_array(u16, config.capacities.dns_ids, s.resources.allocator)
	if error.kind != .None {
		return nil, error
	}
	if options.dns_preparation != .Numeric_Only {
		prepared := net.resolver_snapshot_prepare(
			&s.resolver,
			{name_servers = s.profile.config.http.resolver.name_servers, limits = options.resolver_limits},
			s.resources.allocator,
		)

		if prepared.kind != .None {
			return nil, network_snapshot_error(prepared)
		}

		if entropy := runtime_async.prepare_dns_ids(s.dns_ids); entropy.kind != .None {
			return nil, {kind = .Runtime_Error, runtime = entropy}
		}

		s.dns_count = len(s.dns_ids)
	}
	s.coordinator.owner = s
	s.coordinator.task.data = &s.coordinator
	s.task_index[0] = &s.coordinator.task
	wake, ready := signal.create(runtime, &s.coordinator.task)
	if !ready {
		return nil, {kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = .Out_Of_Memory}}
	}
	s.coordinator.wake = wake
	s.signal_cells += 1
	for &actor, index in s.actors {
		actor.owner = s
		actor.index = u32(index + 1)
		actor.task.data = &actor
		s.task_index[index + 1] = &actor.task
		if init := exchange_api.exchange_init(
			&actor.exchange,
			{body_limit = config.response_body_limit},
			s.resources.allocator,
		); init.kind != .None {
			return nil, {kind = .Invalid_Config, http = init}
		}

		notification, created := signal.create(runtime, &actor.task)

		if !created {
			return nil, {kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = .Out_Of_Memory}}
		}

		actor.wake = notification
		s.signal_cells += 1
	}
	// Synchronous preparation may have taken time or raced Scope.close. No
	// expired/closed constructor is published merely because its first check won.
	now = runtime_async.deadline_after(runtime, 0)
	if config.lifetime.epoch != 0 && now.at >= config.lifetime.at {
		return nil, {kind = .Runtime_Error, runtime = {kind = .Timeout}}
	}
	if probe := network_scope_probe(s.resources.scope); probe.kind != .None {
		return nil, probe
	}
	source, managed := charged.allocator_scope(s.resources.allocator)
	if managed {
		if probe := network_scope_probe(source); probe.kind != .None {
			return nil, probe
		}
	}
	s.last_clock = now
	s.producer_calls = 0
	success = true
	return s, {}
}

// Destroy stable subowners IN PLACE. The last raw free can physically destroy
// State; its independent bootstrap lease is released afterward from locals only.
network_cleanup_storage :: proc(s: ^Client_State) {
	assert(network_valid(s))
	s.phase = .Disposing

	if s.kernel.self == &s.kernel {
		assert(kernel_destroy(&s.kernel).kind == .None)
	}

	signal.detach(s.coordinator.wake)
	signal.release(&s.coordinator.wake)

	for &actor in s.actors {
		signal.detach(actor.wake)
		signal.release(&actor.wake)

		if actor.exchange._self == &actor.exchange {
			assert(exchange_api.exchange_destroy(&actor.exchange).kind == .None)
		}
	}

	stream_api.bank_close(&s.stream_bank)
	net.resolver_snapshot_destroy(&s.resolver)
	profile_destroy(&s.profile)
	allocator := s.resources.allocator
	actors, requests, tasks, ids := s.actors, s.requests, s.task_index, s.dns_ids
	s.actors = nil
	s.requests = nil
	s.task_index = nil
	s.dns_ids = nil
	kernel_free_array(actors, allocator)
	kernel_free_array(requests, allocator)
	kernel_free_array(tasks, allocator)
	kernel_free_array(ids, allocator)
	resources_destroy(&s.resources)
	backing := s.backing
	s.backing = {}
	s.self = nil
	kernel_free(backing.storage, align_of(Client_State), backing.allocator)
	scopes.release(&backing.lease)
}

network_dispose_prepared :: proc(s: ^Client_State) -> Client_Error {
	if !network_valid(s) {
		return {kind = .Invalid_State}
	}

	sync.lock(&s.mu)
	if s.phase != .Constructing ||
	   s.references != 1 ||
	   !s.base_owned ||
	   s.registered_tasks != 0 ||
	   s.producer_calls != 0 ||
	   s.returning_calls != 0 {
		sync.unlock(&s.mu)
		return {kind = .Pending}
	}

	// Kernel destroy is a no-mutation rejection when live children remain. Mark
	// this private State unavailable before any arbitrary raw destructor callback.
	s.phase = .Disposing
	sync.unlock(&s.mu)

	if error := kernel_destroy(&s.kernel); error.kind != .None {
		sync.lock(&s.mu)
		s.phase = .Constructing
		sync.unlock(&s.mu)
		return error
	}

	s.base_owned = false
	s.references = 0
	network_cleanup_storage(s)

	return {}
}

completion_empty :: proc(response: ^surf.Response) -> bool {
	return(
		response != nil &&
		response.status == 0 &&
		response.headers == nil &&
		response.body == nil &&
		response.header_storage == nil &&
		raw_data(response.body_storage) == nil &&
		response.allocator.procedure == nil &&
		response._allocator_scope == (scopes.Scope{}) \
	)
}
completion_queue_unlink_locked :: proc(k: ^Kernel, index: u32, r: ^Request_Slot) {
	if !r.completion_queued {
		return
	}

	previous, next := r.completion_previous, r.completion_next

	if previous == 0 {
		k.completion_head = next
	} else {
		k.requests[int(previous) - 1].completion_next = next
	}

	if next == 0 {
		k.completion_tail = previous
	} else {
		k.requests[int(next) - 1].completion_previous = previous
	}

	r.completion_previous, r.completion_next = 0, 0
	r.completion_queued = false
}
completion_queue_append_locked :: proc(k: ^Kernel, index: u32, r: ^Request_Slot) {
	assert(!r.completion_queued)
	r.completion_previous = k.completion_tail
	r.completion_next = 0

	if k.completion_tail == 0 {
		k.completion_head = index
	} else {
		k.requests[int(k.completion_tail) - 1].completion_next = index
	}

	k.completion_tail = index
	r.completion_queued = true
}

kernel_begin_complete :: proc(
	k: ^Kernel,
	h: Request_Handle,
	response: ^surf.Response,
	error: surf.HTTP_Error,
) -> (
	Request_Disposal,
	Client_Error,
) {
	if k == nil || k.self != k {
		return {}, {kind = .Invalid_State}
	}
	if response == nil || admission_alias(k, response, size_of(surf.Response)) {
		return {}, {kind = .Invalid_Config}
	}
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)
	if r == nil {
		return {}, {kind = .Invalid_Handle}
	}
	if r.state != .Queued && r.state != .Active {
		return {}, {kind = .Pending}
	}
	if k.references < 1 || k.references == max(int) || k.returning == max(int) {
		return {}, {kind = .Invalid_State}
	}
	if cause := admission_detach_claim_locked(k, h, r); cause.kind != .None {
		return {}, cause
	}
	result := Request_Disposal {
		request      = h,
		returning_to = .Completed,
		input        = r.input,
		lease        = r.lease,
	}
	if error.kind != .None && r.stream != nil {
		assert(stream_api.retain(r.stream))
		result.stream_finish = r.stream
		result.stream_error = error
	}
	// A primary failure stays authoritative. Even an accidentally supplied owned
	// Response on that path must be detached and physically released, not hidden.
	if error.kind == .None {
		r.response = response^
	} else {
		result.response = response^
		r.response = {}
	}
	response^ = {}
	r.input = {}
	r.lease = {}
	r.error = error
	if r.state == .Queued {
		k.counters.queued_requests -= 1
	} else {
		k.counters.active_requests -= 1
	}
	r.state = .Returning
	r.returning_to = .Completed
	r.stage = .Retiring
	k.returning += 1
	k.references += 1
	k.counters.returning_requests += 1
	k.dispatch_dirty = true
	return result, {}
}

completion_late_failure :: proc(k: ^Kernel, r: ^Request_Slot, now: runtime_async.Deadline) -> surf.HTTP_Error {
	effect := surf.HTTP_Write_Effect.Unknown

	if r.response.status != 0 {
		effect = .Response_Received
	}

	if now.epoch != r.deadline.epoch || now.at <= 0 {
		return {kind = .Invalid_Config, phase = .Configuration, status = r.response.status, write_effect = effect}
	}

	if r.cancel_requested || k.closed {
		return {
			kind = .IO_Failed,
			transport = {kind = .Cancelled},
			phase = .Cancellation,
			status = r.response.status,
			write_effect = effect,
		}
	}

	if now.at >= r.deadline.at {
		return {kind = .Deadline_Failed, phase = .Deadline, status = r.response.status, write_effect = effect}
	}

	return {}
}

kernel_cleanup_finish :: proc(
	k: ^Kernel,
	h: Request_Handle,
	now: runtime_async.Deadline,
) -> (
	Request_Disposal,
	bool,
	Client_Error,
) {
	if k == nil || k.self != k {
		return {}, false, {kind = .Invalid_State}
	}
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	r := admission_request_locked(k, h)
	if r == nil {
		return {}, false, {kind = .Invalid_Handle}
	}
	if r.state != .Returning ||
	   (r.returning_to != .Free && r.returning_to != .Completed) ||
	   k.returning < 1 ||
	   k.references <= 1 {
		return {}, false, {kind = .Invalid_State}
	}
	if r.returning_to == .Completed {
		if r.error.kind == .None {
			error := completion_late_failure(k, r, now)

			if error.kind != .None {
				disposal := Request_Disposal {
					request      = h,
					returning_to = .Completed,
					response     = r.response,
				}

				if r.stream != nil {
					assert(stream_api.retain(r.stream))
					disposal.stream_finish = r.stream
					disposal.stream_error = error
				}

				r.response = {}
				r.error = error
				// Keep the same Returning reference and withhold publication until the
				// detached successful payload's final physical free has returned.
				return disposal, false, {}
			}
		}

		r.state = .Completed
		r.stage = .Completed
		r.returning_to = .Free
		k.returning -= 1
		k.references -= 1
		k.counters.returning_requests -= 1
		k.counters.completed_requests += 1

		if (r.error.kind == .Deadline_Failed || r.error.phase == .Deadline) && k.counters.deadline_count != max(u64) {
			k.counters.deadline_count += 1
		}

		completion_queue_append_locked(k, h.slot, r)
		return {}, true, {}
	}
	if r.origin.slot != 0 ||
	   r.session.slot != 0 ||
	   r.input.storage != nil ||
	   !completion_empty(&r.response) ||
	   r.lease != (scopes.Lease{}) {
		return {}, false, {kind = .Invalid_State}
	}
	if r.generation != max(u64) && (k.request_free_count < 0 || k.request_free_count >= len(k.request_free)) {
		return {}, false, {kind = .Invalid_State}
	}
	generation := r.generation
	r^ = {
		generation = generation,
		state      = .Retired,
	}
	if generation != max(u64) {
		r.generation += 1
		r.state = .Free
		k.request_free[k.request_free_count] = h.slot
		k.request_free_count += 1
	}
	k.returning -= 1
	k.references -= 1
	k.counters.returning_requests -= 1
	k.dispatch_dirty = true
	return {}, true, {}
}

kernel_poll :: proc(k: ^Kernel) -> (Completion, bool) {
	if k == nil || k.self != k {
		return {}, false
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	index := k.completion_head

	if index == 0 || u64(index) > u64(len(k.requests)) {
		return {}, false
	}

	r := &k.requests[int(index) - 1]

	if r.state != .Completed || !r.completion_queued {
		return {}, false
	}

	completion_queue_unlink_locked(k, index, r)

	return {request = {owner_id = k.owner_id, slot = index, generation = r.generation}, error = r.error}, true
}

// Both synchronous consumers use the same Returning machinery as asynchronous
// cleanup. No generation is recycled until Response/origin callbacks finish.
completion_detach_locked :: proc(k: ^Kernel, h: Request_Handle, r: ^Request_Slot) -> (Request_Disposal, Client_Error) {
	if r.state != .Completed {
		return {}, {kind = .Pending}
	}

	if k.references < 1 ||
	   k.references >= max(int) - 1 ||
	   k.returning == max(int) ||
	   k.counters.completed_requests < 1 {
		return {}, {kind = .Invalid_State}
	}

	if r.origin.slot != 0 {
		origin := admission_origin_locked(k, r.origin)

		if origin == nil || origin.requests < 1 {
			return {}, {kind = .Invalid_State}
		}
	}

	result := Request_Disposal {
		request      = h,
		returning_to = .Free,
		input        = r.input,
		response     = r.response,
		lease        = r.lease,
		stream       = r.stream,
	}

	r.stream = nil

	if r.origin.slot != 0 {
		disposal, error := kernel_origin_release_locked(k, r.origin, .Request)

		if error.kind != .None {
			return {}, error
		}

		result.origin = disposal
	}

	completion_queue_unlink_locked(k, h.slot, r)
	r.origin = {}
	r.session = {}
	r.input = {}
	r.response = {}
	r.lease = {}
	r.state = .Returning
	r.returning_to = .Free
	r.stage = .Retiring
	k.references += 1
	k.returning += 1
	k.counters.returning_requests += 1
	k.counters.completed_requests -= 1
	k.dispatch_dirty = true

	return result, {}
}
completion_dispose_and_finish :: proc(k: ^Kernel, h: Request_Handle, disposal: ^Request_Disposal) -> Client_Error {
	origin := disposal.origin.origin
	request_disposal_destroy(disposal)

	if origin.slot != 0 {
		if error := kernel_origin_cleanup_finish(k, origin); error.kind != .None {
			return error
		}
	}

	next, done, error := kernel_cleanup_finish(k, h, {})
	assert(next.input.storage == nil && next.response.body_storage == nil)

	if error.kind != .None {
		return error
	}

	if !done {
		return {kind = .Invalid_State}
	}

	return {}
}

kernel_take :: proc(k: ^Kernel, h: Request_Handle, destination: ^surf.Response) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	if destination == nil || admission_alias(k, destination, size_of(surf.Response)) {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	r := admission_request_locked(k, h)

	if r == nil {
		sync.unlock(&k.mu)
		return {kind = .Invalid_Handle}
	}

	if r.stream != nil {
		sync.unlock(&k.mu)
		return {kind = .Invalid_State}
	}

	if r.state != .Completed {
		sync.unlock(&k.mu)
		return {kind = .Pending}
	}

	if !completion_empty(destination) {
		sync.unlock(&k.mu)
		return {kind = .Invalid_State}
	}

	if r.error.kind != .None {
		error := Client_Error {
			kind = .Request_Error,
			http = r.error,
		}

		sync.unlock(&k.mu)
		return error
	}

	// Preflight/detach can fail without changing destination or the stored result.
	saved := r.response
	disposal, error := completion_detach_locked(k, h, r)

	if error.kind != .None {
		sync.unlock(&k.mu)
		return error
	}

	destination^ = saved
	disposal.response = {}
	sync.unlock(&k.mu)

	return completion_dispose_and_finish(k, h, &disposal)
}

kernel_release :: proc(k: ^Kernel, h: Request_Handle) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	r := admission_request_locked(k, h)

	if r == nil {
		sync.unlock(&k.mu)
		return {kind = .Invalid_Handle}
	}

	disposal, error := completion_detach_locked(k, h, r)
	sync.unlock(&k.mu)

	if error.kind != .None {
		return error
	}

	return completion_dispose_and_finish(k, h, &disposal)
}

client_drained_locked :: proc(s: ^Client_State, own_call: bool) -> bool {
	callers := s.producer_calls

	if own_call {
		callers -= 1
	}

	return(
		s.phase == .Closing &&
		s.registered_tasks == 0 &&
		callers == 0 &&
		s.returning_calls == 0 &&
		s.kernel.preparing == 0 &&
		s.kernel.returning == 0 &&
		s.kernel.counters.active_requests == 0 &&
		s.kernel.counters.queued_requests == 0 \
	)
}
client_close :: proc(c: ^Client) -> Client_Error {
	s, error := client_enter(c)

	if error.kind != .None {
		return error
	}

	defer client_leave(s)
	network_close_state(s)
	sync.lock(&s.mu)
	runtime := s.runtime
	registered := s.registered_tasks
	sync.unlock(&s.mu)
	// Runtime start/join/destroy and this prestart ownership return are controller
	// serialized. shutdown remains allowed to race ordinary operational methods.
	if registered > 0 && runtime != nil {
		retirement := runtime_async.retire_group_unstarted(runtime, s.task_index)

		if retirement.kind == .None {
			for index in 0 ..< len(s.task_index) {
				network_task_done(s, index, false)
			}
		} else if retirement.kind != .Already_Started && retirement.kind != .Not_Registered {
			return {kind = .Runtime_Error, runtime = retirement}
		}
	}

	network_lock_both(s)
	drained := client_drained_locked(s, true)
	network_unlock_both(s)

	if !drained {
		return {kind = .Pending}
	}

	return {}
}
client_quiescent :: proc(c: ^Client) -> bool {
	s, error := client_enter(c)

	if error.kind != .None {
		return false
	}

	defer client_leave(s)
	network_lock_both(s)
	drained := client_drained_locked(s, true)
	network_unlock_both(s)

	return drained
}
client_destroy :: proc(c: ^Client) -> Client_Error {
	if c == nil || c._self != c || c._state == nil {
		return {kind = .Invalid_State}
	}

	s := cast(^Client_State)c._state

	if !network_valid(s) {
		return {kind = .Invalid_State}
	}

	network_lock_both(s)
	ready :=
		client_drained_locked(s, false) &&
		s.references == 1 &&
		s.base_owned &&
		s.kernel.references == 1 &&
		s.kernel.counters.completed_requests == 0 &&
		s.kernel.counters.origins == 0 &&
		s.kernel.counters.reserved_connections == 0 &&
		s.kernel.counters.connecting_connections == 0 &&
		s.kernel.counters.active_connections == 0 &&
		s.kernel.counters.idle_connections == 0 &&
		s.kernel.counters.retiring_connections == 0

	if ready {
		s.base_owned = false
		c^ = {}
	}

	network_unlock_both(s)

	if !ready {
		return {kind = .Pending}
	}

	// Final backing callback may physically free the public header. Locals only.
	network_state_release(s)

	return {}
}

client_rollback :: proc(s: ^Client_State, preparing: Preparing_Request) {
	sync.lock(&s.mu)
	disposal, error := kernel_rollback(&s.kernel, preparing)
	assert(error.kind == .None)
	network_queue_forget_locked(s, preparing.request)
	s.returning_calls += 1
	sync.unlock(&s.mu)
	origin := disposal.origin.origin
	request_disposal_destroy(&disposal)

	if origin.slot != 0 {
		assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
	}

	now, _ := network_clock(s)
	next, done, finish := kernel_cleanup_finish(&s.kernel, preparing.request, now)
	assert(finish.kind == .None && done)
	request_disposal_destroy(&next)
	sync.lock(&s.mu)
	s.returning_calls -= 1
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
}

client_submit :: proc(
	c: ^Client,
	request: http.Request,
	deadline: runtime_async.Deadline = {},
) -> (
	Request_Handle,
	Client_Error,
) {
	s, error := client_enter(c)

	if error.kind != .None {
		return {}, error
	}

	defer client_leave(s)
	selected, cause := submission_budget(s, deadline)
	if cause.kind != .None {
		return {}, cause
	}
	return client_submit_state(s, request, selected, nil)
}

client_submit_state :: proc(
	s: ^Client_State,
	request: http.Request,
	selected: Submission_Budget,
	input_stream: ^stream_api.Channel,
) -> (
	Request_Handle,
	Client_Error,
) {
	stream := input_stream
	defer if stream != nil {
		stream_api.release_request(stream)
	}
	now, cutoff := selected.now, selected.cutoff
	if stream != nil {
		sync.lock(&s.mu)
		published := s.phase == .Published
		sync.unlock(&s.mu)

		if !published {
			return {}, {kind = .Closed}
		}

		fresh, clock := network_clock(s)

		if clock.kind != .None {
			return {}, clock
		}

		if fresh.at >= cutoff.at {
			return {}, {
				kind = .Request_Error,
				http = {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent},
			}
		}

		now = fresh
	}
	if len(request.url) < 0 || len(request.url) > 0 && raw_data(request.url) == nil {
		return {}, {kind = .Request_Error, http = {kind = .Invalid_URL}}
	}
	if len(request.body) < 0 || len(request.body) > 0 && raw_data(request.body) == nil {
		return {}, {kind = .Request_Error, http = {kind = .Invalid_Config}}
	}
	if len(request.headers) < 0 || len(request.headers) > http.MAX_HEADERS {
		return {}, {kind = .Request_Error, http = {kind = .Header_Limit}}
	}
	if len(request.headers) > 0 && raw_data(request.headers) == nil {
		return {}, {kind = .Request_Error, http = {kind = .Invalid_Header}}
	}
	for field in request.headers {
		if len(field.name) < 0 ||
		   len(field.value) < 0 ||
		   len(field.name) > 0 && raw_data(field.name) == nil ||
		   len(field.value) > 0 && raw_data(field.value) == nil {
			return {}, {kind = .Request_Error, http = {kind = .Invalid_Header}}
		}
	}
	// Pure descriptor/wire validation precedes any source traversal or allocation.
	header: [http.MAX_HEADER_SIZE]u8
	if _, validation := h1.request_encode_content(header[:], request, .Keep_Alive, .Identity); validation.kind != .None {
		return {}, {kind = .Request_Error, http = {kind = validation.kind}}
	}
	lease, admission := resources_request_lease(&s.resources)
	if admission.kind != .None {
		return {}, admission
	}
	defer scopes.release(&lease)
	sync.lock(&s.mu)
	if s.phase != .Published {
		sync.unlock(&s.mu)
		return {}, {kind = .Closed}
	}
	preparing, reserve := kernel_reserve(&s.kernel, cutoff, &lease)
	sync.unlock(&s.mu)
	if reserve.kind != .None {
		return {}, reserve
	}
	if stream != nil {
		sync.lock(&s.kernel.mu)
		slot := admission_request_locked(&s.kernel, preparing.request)
		assert(slot != nil)
		slot.stream = stream
		stream_api.adopt_lease(stream, &slot.lease)
		stream = nil
		sync.unlock(&s.kernel.mu)
	}
	committed := false
	defer if !committed {
		client_rollback(s, preparing)
	}
	origin, prepare := origin_prepare(&s.profile, request.url, s.resources.allocator)
	if prepare.kind != .None {
		return {}, prepare
	}
	defer origin_destroy(&origin)
	if _, claim := network_queue_claim(s, preparing, &origin, now.at); claim.kind != .None {
		return {}, claim
	}
	input, clone := request_clone(request, s.resources.allocator)
	if clone.kind != .None {
		return {}, clone
	}
	defer request_owner_destroy(&input)
	fresh, sample := network_clock(s)
	if sample.kind != .None {
		return {}, sample
	}
	sync.lock(&s.mu)
	commit := network_queue_committed_locked(s, preparing, &input, fresh)
	sync.unlock(&s.mu)
	if commit.kind != .None {
		return {}, commit
	}
	committed = true
	_ = signal.wake(s.coordinator.wake)
	return preparing.request, {}
}

Submission_Budget :: struct {
	now, cutoff: runtime_async.Deadline,
}

// Select the immutable total cutoff before validation or any owned allocation.
submission_budget :: proc(s: ^Client_State, deadline: runtime_async.Deadline) -> (Submission_Budget, Client_Error) {
	sync.lock(&s.mu)
	published := s.phase == .Published
	sync.unlock(&s.mu)

	if !published {
		return {}, {kind = .Closed}
	}

	now, clock := network_clock(s)

	if clock.kind != .None {
		return {}, clock
	}

	if (deadline.epoch == 0 && deadline.at != 0) ||
	   deadline.epoch != 0 && (deadline.epoch != now.epoch || deadline.at <= 0) {
		return {}, {kind = .Invalid_Config}
	}

	cutoff := runtime_async.Deadline {
		epoch = now.epoch,
		at    = now.at + min(i64(s.config.config.request_timeout), max(i64) - now.at),
	}

	if deadline.epoch != 0 {
		cutoff.at = min(cutoff.at, deadline.at)
	}

	if life := s.config.config.lifetime; life.epoch != 0 {
		cutoff.at = min(cutoff.at, life.at)
	}

	if now.at >= cutoff.at {
		return {}, {
			kind = .Request_Error,
			http = {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent},
		}
	}

	return {now = now, cutoff = cutoff}, {}
}
