package surf_async

import surf ".."
import http "shared:async/http"
import runtime_async "shared:async"
import adapter "shared:async/connection"
import signal "shared:async/signal"
import exchange_api "exchange"
import tls_api "shared:async/tls"
import "core:net"
import "core:sync"
import "core:time"
import "core:strings"
import stream_api "stream"
import h1 "shared:async/http/v1"
import "core:mem"
import scopes "shared:async/sync/budget"

session_valid :: proc(a: ^Session_Actor) -> bool {
	return(
		a != nil &&
		network_valid(a.owner) &&
		a.index != 0 &&
		u64(a.index) <= u64(len(a.owner.actors)) &&
		a == &a.owner.actors[int(a.index) - 1] \
	)
}
session_notify :: proc(data: rawptr) {
	a := cast(^Session_Actor)data
	_ = signal.wake(a.wake)
}
session_notify_coordinator :: proc(a: ^Session_Actor) {
	_ = signal.wake(a.owner.coordinator.wake)
}
session_borrow :: proc(a: ^Session_Actor) -> (http.Request, Origin_Key, Client_Error) {
	s := a.owner
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)
	sync.lock(&s.kernel.mu)
	defer sync.unlock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, a.request)

	if request == nil || request.state != .Active || request.session != a.model {
		return {}, {}, {kind = .Invalid_Handle}
	}

	origin := admission_origin_locked(&s.kernel, request.origin)

	if origin == nil {
		return {}, {}, {kind = .Invalid_State}
	}

	return request.input.request, origin.owner.key, {}
}
session_stopping :: proc(a: ^Session_Actor) -> bool {
	s := a.owner
	sync.lock(&s.mu)
	closing := s.phase == .Closing || s.phase == .Disposing
	sync.unlock(&s.mu)

	return closing || runtime_async.cancelled(&a.task)
}
session_cancelled :: proc(a: ^Session_Actor) -> bool {
	s := a.owner
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	if s.phase == .Closing || s.phase == .Disposing || a.command.cancel || a.command.retire {
		return true
	}

	if a.request == (Request_Handle{}) {
		return false
	}

	sync.lock(&s.kernel.mu)
	defer sync.unlock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, a.request)

	return request == nil || request.cancel_requested || s.kernel.closed
}
session_tls_network :: proc(error: tls_api.Error) -> net.Network_Error {
	#partial switch cause in error {
	case net.TCP_Recv_Error:
		return cause
	case net.TCP_Send_Error:
		return cause
	case net.Dial_Error:
		return cause
	}

	return nil
}
session_runtime_error :: proc(error: runtime_async.Error, phase: surf.HTTP_Phase) -> surf.HTTP_Error {
	if error.kind == .Timeout {
		return {kind = .Deadline_Failed, transport = net.TCP_Recv_Error.Timeout, phase = .Deadline, write_effect = .Not_Sent}
	}

	if error.kind == .Cancelled || error.kind == .Stopping {
		return {kind = .IO_Failed, transport = net.Connection_Error.Cancelled, phase = .Cancellation, write_effect = .Not_Sent}
	}

	if error.allocation_cause != nil {
		return {
			kind = .Allocation_Failed,
			allocation = error.allocation_cause,
			phase = phase,
			write_effect = .Not_Sent,
		}
	}

	if error.network_cause != nil {
		return {kind = .IO_Failed, network = error.network_cause, phase = phase, write_effect = .Not_Sent}
	}

	if error.kind == .Closed || error.kind == .Peer_Closed {
		return {kind = .IO_Failed, transport = net.Connection_Error.Peer_Closed, phase = phase, write_effect = .Not_Sent}
	}

	if error.kind == .Task_Busy || error.kind == .Pending {
		return {kind = .IO_Failed, transport = net.Connection_Error.Operation_Pending, phase = phase, write_effect = .Not_Sent}
	}

	return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
}
session_error :: proc(a: ^Session_Actor, error: surf.HTTP_Error) {
	if a.error.kind == .None {
		a.error = redirect_error_context(a, error)
	}

	a.phase = .Retiring
}
session_before_http :: proc(a: ^Session_Actor, now: runtime_async.Deadline) -> bool {
	if session_cancelled(a) || runtime_async.cancelled(&a.task) {
		session_error(
			a,
			{kind = .IO_Failed, transport = net.Connection_Error.Cancelled, phase = .Cancellation, write_effect = .Not_Sent},
		)
		return false
	}

	if now.at >= a.cutoff.at {
		session_error(
			a,
			{kind = .Deadline_Failed, transport = net.TCP_Recv_Error.Timeout, phase = .Deadline, write_effect = .Not_Sent},
		)
		return false
	}

	return true
}

// A pending mailbox can already represent an Active Kernel assignment even if
// the actor never took it. Cancellation must complete that handle without I/O.
session_take_cancelled_mailbox :: proc(a: ^Session_Actor) {
	s := a.owner
	sync.lock(&s.mu)

	if a.request != (Request_Handle{}) || !a.command.pending {
		sync.unlock(&s.mu)
		return
	}

	assignment := a.command.assignment
	sync.lock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, assignment.request)
	if request != nil &&
	   request.state == .Active &&
	   request.session == assignment.session &&
	   assignment.session.slot == a.index {
		a.request = assignment.request
		a.model = assignment.session
		a.cutoff = request.deadline
		a.command.pending = false
	}

	network_unlock_both(s)
}

network_assignment_finish :: proc(
	a: ^Session_Actor,
	response: ^surf.Response,
	error: surf.HTTP_Error,
) -> Client_Error {
	if !session_valid(a) || a.request == (Request_Handle{}) || response == nil {
		return {kind = .Invalid_State}
	}
	s := a.owner
	handle := a.request
	sync.lock(&s.mu)
	sync.lock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, handle)
	returning := request != nil && request.state == .Returning && request.returning_to == .Completed
	sync.unlock(&s.kernel.mu)
	disposal: Request_Disposal
	if !returning {
		// Terminal metadata cleanup is one transaction with begin-complete. An
		// untaken mailbox may still own a reserved DNS block in Request_Network.
		next, cause := kernel_begin_complete(&s.kernel, handle, response, error)

		if cause.kind != .None {
			sync.unlock(&s.mu)
			return cause
		}

		disposal = next
		network_queue_forget_locked(s, handle)
		s.returning_calls += 1
	}
	sync.unlock(&s.mu)
	for {
		origin := disposal.origin.origin
		request_disposal_destroy(&disposal)

		if origin.slot != 0 {
			if cleanup := kernel_origin_cleanup_finish(&s.kernel, origin); cleanup.kind != .None {
				return cleanup
			}
		}

		now, clock := network_clock(s)

		if clock.kind != .None {
			return clock
		}

		// A late failure can have detached the successful Response on a previous
		// resume. It stays Returning until the physical transport is retired.
		sync.lock(&s.kernel.mu)
		current := admission_request_locked(&s.kernel, handle)
		failure: surf.HTTP_Error

		if current != nil && current.state == .Returning {
			failure = current.error
		}

		sync.unlock(&s.kernel.mu)

		if failure.kind != .None && a.transport_initialized && !a.close_done {
			if a.error.kind == .None {
				a.error = failure
			}

			a.phase = .Retiring
			return {kind = .Pending}
		}

		next, done, finish := kernel_cleanup_finish(&s.kernel, handle, now)

		if finish.kind != .None {
			return finish
		}

		if !done {
			// Destroy the returned move-owning disposal synchronously. Only the Kernel
			// Returning ticket/error/ref persists across the asynchronous close.
			request_disposal_destroy(&next)
			sync.lock(&s.kernel.mu)
			current = admission_request_locked(&s.kernel, handle)
			failure = {}

			if current != nil {
				failure = current.error
			}

			sync.unlock(&s.kernel.mu)

			if a.error.kind == .None {
				a.error = failure
			}

			if a.transport_initialized && !a.close_done {
				a.phase = .Retiring
				return {kind = .Pending}
			}

			disposal = {}
			continue
		}

		break
	}
	sync.lock(&s.mu)
	assert(s.returning_calls > 0)
	s.returning_calls -= 1
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
	a.request = {}
	session_notify_coordinator(a)
	return {}
}

session_assign :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	snapshot, error := network_assignment_take(a)

	if error.kind != .None {
		if error.kind == .Pending {
			return .Waiting
		}

		session_take_cancelled_mailbox(a)

		if a.request != (Request_Handle{}) {
			failure := error.http

			if failure.kind == .None {
				failure = {
					kind = .IO_Failed,
					transport = net.Connection_Error.Cancelled,
					phase = .Cancellation,
					write_effect = .Not_Sent,
				}
			}

			session_error(a, failure)
			return .Yield
		}

		return .Waiting
	}

	a.request = snapshot.assignment.request
	a.model = snapshot.assignment.session
	a.cutoff = snapshot.cutoff
	a.setup_cutoff = snapshot.setup_cutoff
	a.secure = snapshot.secure
	a.ids = snapshot.ids
	a.prepared_addresses = snapshot.addresses
	a.prepared_address_count = snapshot.address_count
	a.prepared_address_at = 0
	// A waiter may have reserved IDs before a healthy Idle became available.
	// Reuse needs no query; burn that moved block instead of overwriting it later.
	if a.transport_initialized {
		network_dns_burn(a.owner, &a.ids)
	}

	a.error = {}
	a.phase = .Assigned

	return .Yield
}

session_exchange_step :: proc(a: ^Session_Actor, now: runtime_async.Deadline) -> runtime_async.Resume_Result {
	if a.stream_exchange != nil {
		return session_stream_step(a, now)
	}

	// The selected absolute cutoff has priority once expired. Let the Engine
	// classify Deadline with its received status and write-effect context.
	cancelled := (session_cancelled(a) || runtime_async.cancelled(&a.task)) && now.at < a.cutoff.at
	result := exchange_api.exchange_drive(
		&a.exchange,
		now.at,
		cancelled,
		a.owner.config.config.capacities.work_per_resume,
	)

	if result.error.kind != .None {
		error := result.error

		if a.tls_initialized {
			error.tls_error = tls_api.async_failure(&a.tls)
		}

		session_error(a, error)
		return .Yield
	}

	if result.status != .Done {
		return .Waiting if result.status == .Waiting else .Yield
	}

	response: surf.Response

	if error := exchange_api.exchange_take(&a.exchange, &response); error.kind != .None {
		session_error(a, error)
		return .Yield
	}

	// A full buffered response is not permission to publish after a late owner
	// cancellation, monotonic timeout or synchronous allocator callback.
	fresh, clock := network_clock(a.owner)
	failure: surf.HTTP_Error

	if clock.kind != .None {
		failure = {
			kind  = .Invalid_Config,
			phase = .Configuration,
		}
	} else {
		if session_cancelled(a) || runtime_async.cancelled(&a.task) {
			failure = {
				kind = .IO_Failed,
				transport = net.Connection_Error.Cancelled,
				phase = .Cancellation,
			}
		}

		if failure.kind == .None {
			if budget := adapter.budget_error(&a.executor); budget != nil {
				failure = surf.http_error_classify(
					{kind = .IO_Failed, transport = budget},
					.Read,
					.Response_Received,
					response.status,
				)
			}
		}

		if failure.kind == .None && fresh.at >= a.cutoff.at {
			failure = {
				kind  = .Deadline_Failed,
				phase = .Deadline,
			}
		}
	}

	if failure.kind != .None {
		failure.status = response.status
		failure.write_effect = .Response_Received
		surf.response_destroy(&response)
		session_error(a, failure)
		return .Yield
	}

	if redirect_response(a, &response) {
		return .Yield
	}

	if error := network_assignment_finish(a, &response, {}); error.kind != .None {
		surf.response_destroy(&response)
		session_error(a, {kind = .Invalid_Config, phase = .Configuration})
		return .Yield
	}

	if reset := exchange_api.exchange_reset(&a.exchange); reset.kind != .None {
		session_error(a, reset)
		return .Yield
	}

	return session_finish_reuse(a, result.reuse_eligible)
}

session_finish_reuse :: proc(a: ^Session_Actor, eligible: bool) -> runtime_async.Resume_Result {
	reusable := eligible && !session_stopping(a) && !session_cancelled(a)

	if reusable && a.secure {
		reusable = tls_api.async_idle_state(&a.tls) == .Ready
	}

	if reusable {
		reusable = adapter.set_request_budget(&a.executor, a.cutoff).kind == .None
	}

	if reusable {
		observation, error := adapter.probe_stream(&a.transport)
		reusable = error.kind == .None && observation == .Empty
	}

	if reusable {
		now, _ := network_clock(a.owner)
		sync.lock(&a.owner.mu)
		idle := a.owner.phase == .Published && !a.command.cancel && !a.command.retire

		if idle {
			idle = pool_session_state(&a.owner.kernel, a.model, .Idle, now.at).kind == .None
		}

		if idle {
			a.phase = .Idle
		}

		sync.unlock(&a.owner.mu)

		if idle {
			session_notify_coordinator(a)
			return .Waiting
		}
	}

	a.phase = .Retiring

	return .Yield
}

network_session_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	return session_resume(cast(^Session_Actor)data, false)
}
network_session_cancel :: proc(data: rawptr) -> runtime_async.Resume_Result {
	return session_resume(cast(^Session_Actor)data, true)
}

// Owner-thread observation after provider jobs have run. Public readers touch
// only this synchronized Kernel metadata, never TLS/Exchange/actor internals.
// Returning/Preparing redirect tickets retain the ledger's Redirecting stage.
session_publish_stage :: proc(a: ^Session_Actor) {
	h := a.request

	if h == (Request_Handle{}) {
		return
	}

	stage: Request_Stage

	switch a.phase {
	case .Assigned:
		stage = .Writing if a.transport_initialized else .Connecting
	case .Resolving_A, .Resolving_AAAA, .Connecting:
		stage = .Connecting
	case .Handshaking:
		stage = .Handshaking
	case .Exchanging:
		phase, valid := exchange_api.exchange_phase(&a.exchange)

		if a.stream_exchange != nil {
			phase, valid = exchange_api.exchange_phase(&a.stream_exchange.base)
		}

		if !valid {
			return
		}

		switch phase {
		case .Writing_Head, .Writing_Body:
			stage = .Writing
		case .Reading_Head, .Copying_Head, .Reading_Body:
			stage = .Reading
		case .Draining, .Done:
			stage = .Retiring
		case .Idle:
			return
		}
	case .Retiring:
		stage = .Retiring
	case .Prepared, .Idle, .Done:
		return
	}

	s := a.owner
	network_lock_both(s)
	request := admission_request_locked(&s.kernel, h)
	model := pool_session_locked(&s.kernel, a.model)
	if request != nil &&
	   request.state == .Active &&
	   request.session == a.model &&
	   a.model.slot == a.index &&
	   model != nil &&
	   model.request == h {
		request.stage = stage
	}

	network_unlock_both(s)
}

session_resume :: proc(a: ^Session_Actor, force: bool) -> runtime_async.Resume_Result {
	if !session_valid(a) {
		return .Done
	}

	// DNS/TCP state is thread-confined too: pin before its first operation,
	// rather than waiting until a later successful adapter initialization.
	_, pin := runtime_async.pin_current_task()
	assert(pin.kind == .None)

	if force {
		network_close_state(a.owner)
	}

	now, clock := network_clock(a.owner)
	// Registered actor ownership pins the Runtime clock witness until on_done.
	// Losing it cannot certify physical I/O drainage.
	assert(clock.kind == .None)
	lifetime := a.owner.config.config.lifetime

	if lifetime.epoch != 0 && now.at >= lifetime.at {
		network_close_state(a.owner)

		if a.request != (Request_Handle{}) && a.phase != .Exchanging {
			session_error(
				a,
				{kind = .Deadline_Failed, transport = net.TCP_Recv_Error.Timeout, phase = .Deadline, write_effect = .Not_Sent},
			)
		}
	}

	stopping := force || session_stopping(a)

	if a.phase != .Exchanging && a.phase != .Retiring && a.phase != .Done && (stopping || session_cancelled(a)) {
		session_take_cancelled_mailbox(a)

		if a.request != (Request_Handle{}) {
			session_error(
				a,
				{kind = .IO_Failed, transport = net.Connection_Error.Cancelled, phase = .Cancellation, write_effect = .Not_Sent},
			)
		} else {
			a.phase = .Retiring
		}
	}

	result: runtime_async.Resume_Result

	switch a.phase {
	case .Prepared, .Idle:
		sync.lock(&a.owner.mu)
		pending := a.command.pending
		retire := a.command.retire
		sync.unlock(&a.owner.mu)

		if pending {
			result = session_assign(a)
		} else if retire || stopping {
			a.phase = .Retiring
			result = .Yield
		} else {
			a.phase = .Idle
			result = .Waiting
		}
	case .Assigned:
		if !session_before_http(a, now) {
			result = .Yield
		} else if a.transport_initialized {
			result = session_reuse(a)
		} else {
			result = session_dial_begin(a)
		}
	case .Resolving_A, .Resolving_AAAA, .Connecting:
		result = session_dial_step(a, now)
	case .Handshaking:
		result = session_tls_step(a, now)
	case .Exchanging:
		result = session_exchange_step(a, now)
	case .Retiring:
		result = session_close_step(a)
	case .Done:
		a.owner_drained = true; return .Done
	}

	// Once Idle, do not run the expired PREVIOUS request cap. A future request
	// installs its own cap before any drive/write. Closing runs through callbacks.
	if a.executor_initialized && a.transport_initialized && a.phase != .Idle && a.phase != .Done {
		driven := adapter.drive(&a.executor)

		if driven == .Yield {
			result = .Yield
		}
	}

	session_publish_stage(a)

	return result
}
network_session_done :: proc(data: rawptr) {
	a := cast(^Session_Actor)data

	if !session_valid(a) {
		return
	}

	s, index, drained := a.owner, int(a.index), a.owner_drained
	network_task_done(s, index, drained)
}

session_close_done :: proc(op: ^net.Async_Operation) {
	a := cast(^Session_Actor)op.user_data
	a.close_done = true
	session_notify(a)
}
session_mark_retiring :: proc(a: ^Session_Actor) {
	if a.model.slot == 0 {
		return
	}

	now, _ := network_clock(a.owner)
	k := &a.owner.kernel
	sync.lock(&a.owner.mu)
	defer sync.unlock(&a.owner.mu)
	sync.lock(&k.mu)
	model := pool_session_locked(k, a.model)
	state := Session_State.Free

	if model != nil {
		state = model.state
	}

	sync.unlock(&k.mu)

	if state == .Idle || state == .Connecting || state == .Busy {
		assert(pool_session_state(k, a.model, .Retiring, now.at).kind == .None)
	}
}

// Reset only a fully closed transport generation. Task, Signal, owner/index and
// the cross-thread mailbox and redirect custody MUST survive: coordinator may already have queued
// the next generation as soon as pool_retire made the model slot available.
session_reset_io :: proc(a: ^Session_Actor) {
	session_stream_dispose(a)
	assert(exchange_api.exchange_reset(&a.exchange).kind == .None)
	network_dns_burn(a.owner, &a.ids)
	a.executor = {}
	a.transport = {}
	a.tls = {}
	a.handshake = {}
	a.close = {}
	a.query = {}
	a.dial = {}
	a.cutoff = {}
	a.setup_cutoff = {}
	a.request = {}
	a.prepared_address_count = 0
	a.prepared_address_at = 0
	a.dns_server_count = 0
	a.secure = false
	a.executor_initialized = false
	a.transport_initialized = false
	a.tls_initialized = false
	a.handshake_started = false
	a.handshake_done = false
	a.close_started = false
	a.close_done = false
	a.error = {}
}

session_close_step :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	session_mark_retiring(a)
	// Consume only flags attached to this old generation before freeing its pool
	// model. Never clear a new pending assignment during I/O field reset.
	sync.lock(&a.owner.mu)

	if !a.command.pending {
		a.command.cancel = false
		a.command.retire = false
	}

	sync.unlock(&a.owner.mu)
	_ = runtime_async.close_dns_connect(&a.dial)
	_ = runtime_async.close_dns(&a.query)

	if a.tls_initialized && a.handshake_started && !a.handshake_done {
		_ = tls_api.async_cancel_handshake(&a.tls)
	}

	if a.transport_initialized && !a.close_started {
		stream := adapter.stream(&a.transport)

		if a.tls_initialized {
			stream = tls_api.async_connection(&a.tls)
		}

		a.close = {
			callback  = session_close_done,
			user_data = a,
		}

		error := net.async_close(stream, &a.close)

		if error == nil {
			a.close_started = true
		} else {
			// Owned validated streams normally accept exactly one close. Keep driving
			// the owner rather than treating a rejection as callback/FD retirement.
			adapter.abort(&a.executor)
			return .Yield
		}
	}

	if a.transport_initialized {
		if a.error.kind != .None || session_stopping(a) {
			adapter.abort(&a.executor)
		}

		// Engine cancellation must also observe every app callback emitted by TLS
		// shutdown; a raw close alone is not permission to discard accepted buffers.
		if !session_engine_quiescent(a) {
			now, _ := network_clock(a.owner)
			result := session_engine_drive(a, now.at, true)

			if a.error.kind == .None && result.error.kind != .None {
				a.error = result.error
			}

			if result.status == .Progress {
				return .Yield
			}
		}

		if !a.close_done || !adapter.quiescent(&a.executor) || !session_engine_quiescent(a) {
			return .Waiting
		}
	}

	// Redirect begin happens only after actual old IO retirement, before normal
	// terminalization and before model retirement needs its request detached.
	if a.redirect.phase != .Empty {
		redirect_closed_begin(a)
	}

	if a.request != (Request_Handle{}) {
		response: surf.Response

		if a.stream_exchange == nil {
			_ = exchange_api.exchange_take(&a.exchange, &response)
		} else {
			response.status = a.stream_exchange.status
		}

		failure := a.error

		if failure.kind == .None {
			failure = {
				kind = .IO_Failed,
				transport = net.Connection_Error.Cancelled,
				phase = .Cancellation,
				write_effect = .Not_Sent,
			}
		}

		if response.status > 0 {
			failure.status = response.status
			failure.write_effect = .Response_Received
		}

		if error := network_assignment_finish(a, &response, failure); error.kind != .None {
			surf.response_destroy(&response)
			return .Yield
		}
	}

	// All old application operations/interfaces are now retired. Reset BEFORE
	// releasing model capacity, but preserve its handle for final pool retirement.
	model := a.model
	session_reset_io(a)

	if model.slot != 0 {
		if error := pool_retire(&a.owner.kernel, model); error.kind != .None {
			return .Yield
		}
	}

	a.model = {}
	session_notify_coordinator(a)
	// No Waiting/Idle/Done path may strand an accepted Returning/Preparing hop.
	if a.redirect.phase != .Empty {
		return redirect_closed_resolve(a)
	}

	if session_stopping(a) {
		a.owner_drained = true
		a.phase = .Done
		return .Done
	}

	a.phase = .Idle

	return .Waiting
}

session_handshake_done :: proc(op: ^tls_api.Async_Handshake_Operation) {
	a := cast(^Session_Actor)op.user_data
	a.handshake_done = true
	session_notify(a)
}
session_tls_begin :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	_, origin, borrow := session_borrow(a)

	if borrow.kind != .None {
		session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
		return .Yield
	}

	config := a.owner.profile.config.http.tls
	config.server_name = origin.host
	timeout := config.handshake_timeout

	if timeout == 0 {
		timeout = 10 * time.Second
	}

	now, clock := network_clock(a.owner)

	if clock.kind != .None {
		session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
		return .Yield
	}

	a.setup_cutoff.at = min(a.setup_cutoff.at, now.at + min(i64(timeout), max(i64) - now.at))

	if cap := adapter.set_request_budget(&a.executor, a.setup_cutoff); cap.kind != .None {
		session_error(a, session_runtime_error(cap, .TLS))
		return .Yield
	}

	if init := tls_api.async_client(
		&a.tls,
		adapter.stream(&a.transport),
		adapter.executor(&a.executor),
		config,
		a.owner.resources.allocator,
	); init != nil {
		session_error(
			a,
			{
				kind = .TLS_Failed,
				tls_error = init,
				phase = .TLS,
				write_effect = .Not_Sent,
			},
		)
		return .Yield
	}

	a.tls_initialized = true
	a.handshake = {
		callback  = session_handshake_done,
		user_data = a,
	}

	if error := tls_api.async_handshake(&a.tls, &a.handshake, adapter.wall_budget(&a.executor)); error != nil {
		session_error(a, {
			kind = .TLS_Failed,
			tls_error = error,
			transport = session_tls_network(error),
			phase = .TLS,
			write_effect = .Not_Sent,
		})
		return .Yield
	}

	a.handshake_started = true
	a.phase = .Handshaking

	return .Yield
}
session_tls_step :: proc(a: ^Session_Actor, now: runtime_async.Deadline) -> runtime_async.Resume_Result {
	if !session_before_http(a, now) {
		return .Yield
	}

	if now.at >= a.setup_cutoff.at {
		session_error(
			a,
			{kind = .Deadline_Failed, phase = .Deadline, transport = net.TCP_Recv_Error.Timeout, write_effect = .Not_Sent},
		)
		return .Yield
	}

	if !a.handshake_done {
		return .Waiting
	}

	handshake_error := tls_api.async_handshake_error(&a.handshake)
	if handshake_error != nil {
		transport := a.handshake.err
		if transport == nil {
			transport = session_tls_network(handshake_error)
		}
		session_error(
			a,
			{
				kind = .TLS_Failed,
				transport = transport,
				tls_error = handshake_error,
				phase = .TLS,
				write_effect = .Not_Sent,
			},
		)
		return .Yield
	}

	state := tls_api.async_idle_state(&a.tls)

	if state == .Busy {
		return .Yield
	}

	if state != .Ready {
		session_error(
			a,
			{kind = .TLS_Failed, tls_error = tls_api.General_Error.Invalid_State, phase = .TLS, write_effect = .Not_Sent},
		)
		return .Yield
	}

	// No handshake callback/accepted raw slot can be rebudgeted while live.
	cap := adapter.set_request_budget(&a.executor, a.cutoff)

	if cap.kind == .Task_Busy {
		return .Yield
	}

	if cap.kind != .None {
		session_error(a, session_runtime_error(cap, .TLS))
		return .Yield
	}

	return session_begin_exchange(a, true)
}

session_reuse :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	if !exchange_api.exchange_quiescent(&a.exchange) {
		session_error(
			a,
			{kind = .IO_Failed, transport = net.Connection_Error.Protocol_Failed, phase = .Protocol, write_effect = .Not_Sent},
		)
		return .Yield
	}

	if a.secure && tls_api.async_idle_state(&a.tls) != .Ready {
		session_error(
			a,
			{kind = .IO_Failed, transport = net.Connection_Error.Protocol_Failed, phase = .Protocol, write_effect = .Not_Sent},
		)
		return .Yield
	}

	if cap := adapter.set_request_budget(&a.executor, a.cutoff); cap.kind != .None {
		session_error(a, session_runtime_error(cap, .TLS))
		return .Yield
	}

	observed, error := adapter.probe_stream(&a.transport)

	if error.kind != .None {
		session_error(a, session_runtime_error(error, .Read))
		return .Yield
	}

	if observed != .Empty {
		session_error(
			a,
			{
				kind = .IO_Failed,
				transport = net.Connection_Error.Peer_Closed if observed == .Closed else net.Connection_Error.Protocol_Failed,
				phase = .Read,
				write_effect = .Not_Sent,
			},
		)
		return .Yield
	}

	return session_begin_exchange(a, false)
}
session_begin_exchange :: proc(a: ^Session_Actor, fresh: bool) -> runtime_async.Resume_Result {
	request, _, borrow := session_borrow(a)

	if borrow.kind != .None {
		session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
		return .Yield
	}

	now, clock := network_clock(a.owner)

	if clock.kind != .None || !session_before_http(a, now) {
		return .Yield
	}

	if !a.secure {
		cap := adapter.set_request_budget(&a.executor, a.cutoff)

		if cap.kind == .Task_Busy {
			return .Yield
		}

		if cap.kind != .None {
			session_error(a, session_runtime_error(cap, .TLS))
			return .Yield
		}
	}

	if fresh {
		if error := pool_session_state(&a.owner.kernel, a.model, .Busy, now.at); error.kind != .None {
			session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
			return .Yield
		}
	}

	stream := adapter.stream(&a.transport)

	if a.secure {
		stream = tls_api.async_connection(&a.tls)
	}

	budget := exchange_api.Budget {
		at   = a.cutoff.at,
		wall = adapter.wall_budget(&a.executor),
	}

	if cell := session_stream_channel(a); cell != nil {
		if error := session_stream_begin(a, cell, stream, request, budget); error.kind != .None {
			session_error(a, error)
			return .Yield
		}

		a.phase = .Exchanging
		return .Yield
	}

	if error := exchange_api.exchange_begin(&a.exchange, stream, request, budget, {data = a, wake = session_notify});
	   error.kind != .None {
		session_error(a, error)
		return .Yield
	}

	a.phase = .Exchanging

	return .Yield
}

session_dns_error :: proc(error: runtime_async.DNS_Error) -> surf.HTTP_Error {
	result := surf.HTTP_Error {
		kind         = .Dial_Failed,
		phase        = .DNS,
		write_effect = .Not_Sent,
		network      = net.Resolve_Error.Unable_To_Resolve,
	}

	if error.cause.network_cause != nil {
		result.network = error.cause.network_cause
	}

	if error.cause.allocation_cause != nil {
		return {
			kind = .Allocation_Failed,
			allocation = error.cause.allocation_cause,
			phase = .DNS,
			write_effect = .Not_Sent,
		}
	}

	if error.status == .Timeout || error.cause.kind == .Timeout {
		return {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent, transport = net.TCP_Recv_Error.Timeout}
	}

	if error.status == .Cancelled || error.cause.kind == .Cancelled {
		return {kind = .IO_Failed, phase = .Cancellation, write_effect = .Not_Sent, transport = net.Connection_Error.Cancelled}
	}

	return result
}
session_dns_block :: proc(a: ^Session_Actor) -> (bool, Client_Error) {
	s := a.owner
	sync.lock(&s.mu)
	metadata := &s.requests[int(a.request.slot) - 1]
	remaining := metadata.query_budget_left

	if metadata.generation != a.request.generation {
		remaining = 0
	}

	sync.unlock(&s.mu)

	if remaining <= 0 {
		return false, {}
	}

	block, error := network_dns_reserve(s, min(DNS_IDS_PER_QUERY, remaining))

	if error.kind != .None {
		return false, error
	}

	sync.lock(&s.mu)
	metadata = &s.requests[int(a.request.slot) - 1]
	valid := metadata.generation == a.request.generation && metadata.query_budget_left >= block.count

	if valid {
		metadata.query_budget_left -= block.count
	}

	sync.unlock(&s.mu)

	if !valid {
		network_dns_burn(s, &block)
		return false, {}
	}

	a.ids = block

	return true, {}
}
session_query_begin :: proc(
	a: ^Session_Actor,
	host: string,
	port: int,
	family: runtime_async.DNS_Family,
	connect: bool,
) -> runtime_async.DNS_Error {
	s := a.owner
	config := runtime_async.DNS_Config {
		nameservers     = a.dns_servers[:a.dns_server_count],
		ids             = a.ids.values[:a.ids.count],
		max_queries     = a.ids.count,
		rounds          = DNS_ROUNDS,
		attempt_timeout = DNS_ATTEMPT_TIMEOUT,
		max_messages    = DNS_MESSAGE_LIMIT,
	}
	workspace := runtime_async.DNS_Workspace {
		tx      = a.dns_tx[:],
		rx      = a.dns_rx[:],
		aliases = a.dns_aliases[:],
		results = a.dns_results[:],
	}
	error := runtime_async.begin_dns(
		s.runtime,
		&a.task,
		&a.query,
		host,
		port,
		family,
		config,
		workspace,
		a.setup_cutoff,
	)
	if error.status != .Success {
		return error
	}
	// An address policy must see the resolved set before TCP. The dial step
	// starts connect after that check. Numeric callers already checked.
	if !connect {
		return {}
	}
	return runtime_async.begin_dns_connect(&a.dial, &a.query)
}
session_numeric_begin :: proc(a: ^Session_Actor) -> runtime_async.DNS_Error {
	endpoint := a.prepared_addresses[a.prepared_address_at]
	storage: [64]u8
	builder := strings.builder_from_bytes(storage[:])
	text := net.address_to_string(endpoint.address, &builder)

	if text == "" {
		return {status = .Invalid_Config}
	}

	// begin_dns copies the numeric address into exclusive actor workspace before
	// this stack string dies. DNS_Connect then performs actual nonblocking TCP.
	return session_query_begin(a, text, endpoint.port, .Both_A_First, true)
}

session_dial_begin :: proc(a: ^Session_Actor) -> runtime_async.Resume_Result {
	_, origin, borrow := session_borrow(a)

	if borrow.kind != .None {
		session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
		return .Yield
	}

	if a.prepared_address_count > 0 {
		// These endpoints are the ones numeric connect will dial, including an
		// IP literal and a resolver-snapshot hit. Check them before any socket.
		if rejected := surf.address_policy_check(
			a.owner.profile.config.http,
			origin.host,
			a.prepared_addresses[:a.prepared_address_count],
		); rejected.kind != .None {
			session_error(a, rejected)
			return .Yield
		}

		error := session_numeric_begin(a)

		if error.status != .Success {
			session_error(a, session_dns_error(error))
			return .Yield
		}

		a.phase = .Connecting
		return .Yield
	}

	servers, ready := net.resolver_snapshot_name_servers(&a.owner.resolver)

	if !ready || len(servers) == 0 || a.ids.count == 0 {
		session_error(
			a,
			{
				kind = .Dial_Failed,
				phase = .DNS,
				network = net.Resolve_Error.Unable_To_Resolve,
				write_effect = .Not_Sent,
			},
		)
		return .Yield
	}

	a.dns_server_count = copy(a.dns_servers[:], servers)
	error := session_query_begin(
		a,
		origin.host,
		int(origin.port),
		.A_Only,
		a.owner.profile.config.http.address_policy == nil,
	)

	if error.status != .Success {
		session_error(a, session_dns_error(error))
		return .Yield
	}

	a.phase = .Resolving_A

	return .Yield
}

// Hostname lookups with an address policy stay unconnected until the resolved
// set is accepted. begin_dns_connect then dials that same query. Numeric dials
// are checked in session_dial_begin. A nil policy, or a dial already started,
// continues straight into connect.
session_policy_gate :: proc(a: ^Session_Actor) -> (ready: bool, result: runtime_async.Resume_Result) {
	if a.owner.profile.config.http.address_policy == nil || a.dial._self == &a.dial {
		return true, {}
	}

	state, error := runtime_async.finish_dns(&a.query)
	if state != .Done {
		return false, state
	}
	if error.status != .Success {
		return false, session_dial_unresolved(a, error)
	}

	results := runtime_async.dns_results(&a.query)
	_, origin, borrow := session_borrow(a)
	if borrow.kind != .None {
		_ = runtime_async.close_dns(&a.query)
		network_dns_burn(a.owner, &a.ids)
		session_error(a, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent})
		return false, .Yield
	}
	if rejected := surf.address_policy_check(a.owner.profile.config.http, origin.host, results);
	   rejected.kind != .None {
		_ = runtime_async.close_dns(&a.query)
		network_dns_burn(a.owner, &a.ids)
		session_error(a, rejected)
		return false, .Yield
	}
	if begin := runtime_async.begin_dns_connect(&a.dial, &a.query); begin.status != .Success {
		_ = runtime_async.close_dns(&a.query)
		network_dns_burn(a.owner, &a.ids)
		session_error(a, session_dns_error(begin))
		return false, .Yield
	}
	return true, {}
}

session_dial_unresolved :: proc(a: ^Session_Actor, error: runtime_async.DNS_Error) -> runtime_async.Resume_Result {
	cause := error
	_ = runtime_async.close_dns(&a.query)
	network_dns_burn(a.owner, &a.ids)
	if a.phase == .Resolving_A &&
	   cause.status != .Timeout &&
	   cause.status != .Cancelled &&
	   cause.status != .Limit {
		drew, draw_error := session_dns_block(a)

		if draw_error.kind != .None {
			session_error(a, network_dns_bank_exhausted().http)
			return .Yield
		}

		if drew {
			_, origin, borrow := session_borrow(a)

			if borrow.kind == .None {
				a.query = {}
				a.dial = {}
				next := session_query_begin(
					a,
					origin.host,
					int(origin.port),
					.AAAA_Only,
					a.owner.profile.config.http.address_policy == nil,
				)

				if next.status == .Success {
					a.phase = .Resolving_AAAA
					return .Yield
				}

				cause = next
			}
		}
	}

	session_error(a, session_dns_error(cause))
	return .Yield
}

session_dial_step :: proc(a: ^Session_Actor, now: runtime_async.Deadline) -> runtime_async.Resume_Result {
	if !session_before_http(a, now) {
		return .Yield
	}

	if now.at >= a.setup_cutoff.at {
		session_error(
			a,
			{kind = .Deadline_Failed, transport = net.TCP_Recv_Error.Timeout, phase = .Deadline, write_effect = .Not_Sent},
		)
		return .Yield
	}

	ready, gated := session_policy_gate(a)
	if !ready {
		return gated
	}

	socket, status, error := runtime_async.finish_dns_connect(&a.dial)

	if status != .Done {
		return status
	}

	_ = runtime_async.close_dns_connect(&a.dial)
	_ = runtime_async.close_dns(&a.query)
	network_dns_burn(a.owner, &a.ids)

	if error.status != .Success {
		if a.phase == .Connecting &&
		   a.prepared_address_at + 1 < a.prepared_address_count &&
		   error.status != .Timeout &&
		   error.status != .Cancelled {
			a.prepared_address_at += 1
			a.query = {}
			a.dial = {}
			if next := session_numeric_begin(a); next.status == .Success {
				return .Yield
			} else {
				error = next
			}
		} else if a.phase == .Resolving_A &&
		   error.status != .Timeout &&
		   error.status != .Cancelled &&
		   error.status != .Limit {
			drew, draw_error := session_dns_block(a)

			if draw_error.kind != .None {
				session_error(a, network_dns_bank_exhausted().http)
				return .Yield
			}

			if drew {
				_, origin, borrow := session_borrow(a)

				if borrow.kind == .None {
					a.query = {}
					a.dial = {}
					next := session_query_begin(
						a,
						origin.host,
						int(origin.port),
						.AAAA_Only,
						a.owner.profile.config.http.address_policy == nil,
					)

					if next.status == .Success {
						a.phase = .Resolving_AAAA
						return .Yield
					}

					error = next
				}
			}
		}

		session_error(a, session_dns_error(error))
		return .Yield
	}

	// Socket ownership transfers immediately into the actor's adapter; no raw
	// Socket needs to be retained in the frozen actor schema.
	if init := adapter.init_executor(&a.executor, a.owner.runtime, &a.task, a.owner.config.config.lifetime);
	   init.kind != .None {
		_ = runtime_async.close(socket)
		session_error(a, session_runtime_error(init, .Connect))
		return .Yield
	}

	a.executor_initialized = true

	if init := adapter.init_transport(&a.transport, &a.executor, socket); init.kind != .None {
		_ = runtime_async.close(socket)
		session_error(a, session_runtime_error(init, .Connect))
		return .Yield
	}

	a.transport_initialized = true

	if cap := adapter.set_request_budget(&a.executor, a.setup_cutoff); cap.kind != .None {
		session_error(a, session_runtime_error(cap, .Connect))
		return .Yield
	}

	if a.secure {
		return session_tls_begin(a)
	}

	return session_begin_exchange(a, true)
}

kernel_identity_mu: sync.Mutex
kernel_identity_serial: u64

request_clone :: proc(request: http.Request, allocator: mem.Allocator) -> (Request_Owner, Client_Error) {
	header: [http.MAX_HEADER_SIZE]u8
	_, error := h1.request_encode_content(header[:], request, .Keep_Alive, .Identity)

	if error.kind != .None {
		return {}, {kind = .Request_Error, http = {kind = error.kind}}
	}

	total := len(request.headers) * size_of(http.Header)

	for size in ([2]int{len(request.url), len(request.body)}) {
		if size > max(int) - total {
			return {}, {kind = .Invalid_Config}
		}

		total += size
	}

	for field in request.headers {
		for size in ([2]int{len(field.name), len(field.value)}) {
			if size > max(int) - total {
				return {}, {kind = .Invalid_Config}
			}

			total += size
		}
	}

	storage, failure := kernel_grant(total, align_of(http.Header), allocator)

	if failure.kind != .None {
		return {}, failure
	}

	result := Request_Owner {
		storage = storage,
		allocator = allocator,
		request = {method = request.method},
	}

	at := len(request.headers) * size_of(http.Header)
	result.request.headers = (cast([^]http.Header)raw_data(storage))[:len(request.headers)]
	n := copy(storage[at:], request.url)
	result.request.url = cast(string)storage[at:at + n]
	at += n

	for field, index in request.headers {
		n = copy(storage[at:], field.name)
		result.request.headers[index].name = cast(string)storage[at:at + n]
		at += n
		n = copy(storage[at:], field.value)
		result.request.headers[index].value = cast(string)storage[at:at + n]
		at += n
	}

	n = copy(storage[at:], request.body)
	result.request.body = storage[at:at + n]

	return result, {}
}
request_owner_destroy :: proc(owner: ^Request_Owner) {
	if owner == nil {
		return
	}
	old := owner^
	owner^ = {}
	kernel_free(old.storage, align_of(http.Header), old.allocator)
}

kernel_init :: proc(k: ^Kernel, profile: ^Profile, resources: ^Kernel_Resources) -> Client_Error {
	if k == nil ||
	   profile == nil ||
	   profile.self != profile ||
	   profile.owner_id == 0 ||
	   resources == nil ||
	   resources.self != resources {
		return {kind = .Invalid_Config}
	}

	if k.self != nil {
		return {kind = .Invalid_State}
	}

	normalized, error := config_normalize(
		{
			http = profile.config.http,
			capacities = profile.config.capacities,
			idle_timeout = profile.config.idle_timeout,
			max_age = profile.config.max_age,
			lifetime = profile.config.lifetime,
			streaming = profile.config.streaming,
		},
	)
	if error.kind != .None {
		return error
	}
	if normalized.capacities != profile.config.capacities ||
	   normalized.request_timeout != profile.config.request_timeout ||
	   normalized.response_body_limit != profile.config.response_body_limit ||
	   normalized.idle_timeout != profile.config.idle_timeout ||
	   normalized.max_age != profile.config.max_age {
		return {kind = .Invalid_Config}
	}

	temporary := Kernel {
		config     = profile.config,
		resources  = resources,
		profile    = profile,
		references = 1,
		allocator  = resources.allocator,
	}

	success := false

	defer if !success {
		kernel_free_arrays(&temporary)
	}

	capacities := profile.config.capacities
	temporary.requests, error = kernel_array(Request_Slot, capacities.requests, temporary.allocator)
	if error.kind != .None {
		return error
	}
	temporary.origins, error = kernel_array(Origin_Slot, capacities.origins, temporary.allocator)
	if error.kind != .None {
		return error
	}
	temporary.sessions, error = kernel_array(Session_Model, capacities.connections, temporary.allocator)
	if error.kind != .None {
		return error
	}
	temporary.request_free, error = kernel_array(u32, capacities.requests, temporary.allocator)
	if error.kind != .None {
		return error
	}
	temporary.origin_free, error = kernel_array(u32, capacities.origins, temporary.allocator)
	if error.kind != .None {
		return error
	}
	temporary.session_free, error = kernel_array(u32, capacities.connections, temporary.allocator)
	if error.kind != .None {
		return error
	}

	for &slot, index in temporary.requests {
		slot.generation = 1
		temporary.request_free[index] = u32(len(temporary.requests) - index)
	}

	for &slot, index in temporary.origins {
		slot.generation = 1
		temporary.origin_free[index] = u32(len(temporary.origins) - index)
	}

	for &slot, index in temporary.sessions {
		slot.generation = 1
		temporary.session_free[index] = u32(len(temporary.sessions) - index)
	}

	temporary.request_free_count = len(temporary.requests)
	temporary.origin_free_count = len(temporary.origins)
	temporary.session_free_count = len(temporary.sessions)
	temporary.counters.capacities = capacities
	// A fresh kernel domain prevents stale handles from aliasing another Kernel,
	// including later reuse of the same immutable Profile and slot generations.
	identity, available := profile_identity_next(&kernel_identity_serial, &kernel_identity_mu)

	if !available {
		return {kind = .Capacity}
	}

	temporary.owner_id = identity
	temporary.self = k
	k^ = temporary
	success = true

	return {}
}
kernel_free_arrays :: proc(k: ^Kernel) {
	// Locals only after clearing the owner: arbitrary backing frees may reenter.
	old := k^
	k^ = {}
	kernel_free_array(old.requests, old.allocator)
	kernel_free_array(old.origins, old.allocator)
	kernel_free_array(old.sessions, old.allocator)
	kernel_free_array(old.request_free, old.allocator)
	kernel_free_array(old.origin_free, old.allocator)
	kernel_free_array(old.session_free, old.allocator)
}
kernel_destroy :: proc(k: ^Kernel) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	busy :=
		k.references != 1 || k.preparing != 0 || k.returning != 0 || k.completion_head != 0 || k.completion_tail != 0

	for slot in k.requests {
		if slot.state != .Free && slot.state != .Retired {
			busy = true
		}
	}

	for slot in k.origins {
		if slot.state != .Free && slot.state != .Retired {
			busy = true
		}
	}

	for slot in k.sessions {
		if slot.state != .Free && slot.state != .Retired {
			busy = true
		}
	}

	sync.unlock(&k.mu)

	if busy {
		return {kind = .Pending}
	}

	kernel_free_arrays(k)

	return {}
}

// Disposal snapshots never contain the Kernel, Client, Runtime or an active Task.
// Only the scalar cleanup tickets survive, copied separately by the caller.
origin_disposal_destroy :: proc(disposal: ^Origin_Disposal) {
	if disposal == nil {
		return
	}
	old := disposal^
	disposal^ = {}
	kernel_free(old.owner.storage, 1, old.owner.allocator)
}
request_disposal_destroy :: proc(disposal: ^Request_Disposal) {
	if disposal == nil {
		return
	}
	old := disposal^
	disposal^ = {}

	if old.stream_finish != nil {
		stream_api.complete(old.stream_finish, old.stream_error)
		stream_api.release(old.stream_finish)
	}

	stream_api.release_request(old.stream)
	request_owner_destroy(&old.input)
	surf.response_destroy(&old.response)
	scopes.release(&old.lease)
	origin_disposal_destroy(&old.origin)
}

kernel_origin_cell_locked :: proc(k: ^Kernel, handle: Cell_Handle) -> ^Origin_Slot {
	if k == nil ||
	   k.self != k ||
	   handle.slot == 0 ||
	   u64(handle.slot) > u64(len(k.origins)) ||
	   handle.generation == 0 {
		return nil
	}

	slot := &k.origins[int(handle.slot) - 1]

	if slot.generation != handle.generation {
		return nil
	}

	return slot
}
origin_reference_counter :: proc(slot: ^Origin_Slot, reference: Origin_Reference) -> ^int {
	switch reference {
	case .Request:
		return &slot.requests
	case .Session:
		return &slot.sessions
	case .Preparing:
		return &slot.preparing
	case .Waiter:
		return &slot.waiters
	case:
		return nil
	}
}
kernel_origin_retain_locked :: proc(k: ^Kernel, origin: Cell_Handle, reference: Origin_Reference) -> Client_Error {
	slot := kernel_origin_cell_locked(k, origin)

	if slot == nil || slot.state != .Occupied {
		return {kind = .Invalid_Handle}
	}

	counter := origin_reference_counter(slot, reference)

	if counter == nil {
		return {kind = .Invalid_Config}
	}

	if counter^ < 0 || counter^ == max(int) {
		return {kind = .Capacity}
	}

	counter^ += 1

	return {}
}
kernel_origin_release_locked :: proc(
	k: ^Kernel,
	origin: Cell_Handle,
	reference: Origin_Reference,
) -> (
	Origin_Disposal,
	Client_Error,
) {
	slot := kernel_origin_cell_locked(k, origin)
	if slot == nil || slot.state != .Occupied {
		return {}, {kind = .Invalid_Handle}
	}
	counter := origin_reference_counter(slot, reference)
	if counter == nil {
		return {}, {kind = .Invalid_Config}
	}
	if counter^ <= 0 {
		return {}, {kind = .Invalid_State}
	}
	// Preflight retirement before changing even the reference being released.
	final := counter^ == 1
	for other in ([4]^int{&slot.requests, &slot.sessions, &slot.preparing, &slot.waiters}) {
		if other^ < 0 {
			return {}, {kind = .Invalid_State}
		}

		if other != counter && other^ != 0 {
			final = false
		}
	}
	if final &&
	   (slot.queue_head != 0 ||
			   slot.queue_tail != 0 ||
			   k.counters.origins < 1 ||
			   k.references < 1 ||
			   k.references == max(int)) {
		return {}, {kind = .Invalid_State}
	}
	counter^ -= 1
	if slot.requests != 0 || slot.sessions != 0 || slot.preparing != 0 || slot.waiters != 0 {
		return {}, {}
	}
	result := Origin_Disposal {
		origin = origin,
		owner  = slot.owner,
	}
	slot.owner = {}
	slot.state = .Returning
	k.references += 1
	return result, {}
}
kernel_origin_cleanup_finish :: proc(k: ^Kernel, origin: Cell_Handle) -> Client_Error {
	if k == nil || k.self != k {
		return {kind = .Invalid_State}
	}

	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	slot := kernel_origin_cell_locked(k, origin)

	if slot == nil || slot.state != .Returning {
		return {kind = .Invalid_Handle}
	}

	if slot.requests != 0 ||
	   slot.sessions != 0 ||
	   slot.preparing != 0 ||
	   slot.waiters != 0 ||
	   slot.queue_head != 0 ||
	   slot.queue_tail != 0 ||
	   k.counters.origins < 1 ||
	   k.references <= 1 {
		return {kind = .Invalid_State}
	}

	if slot.generation != max(u64) && k.origin_free_count >= len(k.origin_free) {
		return {kind = .Invalid_State}
	}

	generation := slot.generation
	slot^ = {
		generation = generation,
		state      = .Retired,
	}

	if generation != max(u64) {
		slot.generation += 1
		slot.state = .Free
		k.origin_free[k.origin_free_count] = origin.slot
		k.origin_free_count += 1
	}

	k.counters.origins -= 1
	k.references -= 1

	return {}
}

network_state_retain :: proc(s: ^Client_State) -> bool {
	if !network_valid(s) {
		return false
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	if s.phase == .Disposing || s.references == 0 || s.references == max(u64) {
		return false
	}

	s.references += 1

	return true
}
network_state_release :: proc(s: ^Client_State) {
	if !network_valid(s) {
		return
	}

	sync.lock(&s.mu)
	assert(s.references > 0 && (s.references > 1 || !s.base_owned))
	s.references -= 1
	last := s.references == 0

	if last {
		assert(!s.base_owned && s.registered_tasks == 0 && s.producer_calls == 0 && s.returning_calls == 0)
		s.phase = .Disposing
	}

	sync.unlock(&s.mu)

	if last {
		network_cleanup_storage(s)
	}
}

network_clock :: proc(s: ^Client_State) -> (runtime_async.Deadline, Client_Error) {
	if !network_valid(s) {
		return {}, {kind = .Invalid_State}
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	if s.phase == .Disposing || s.registered_tasks == 0 || s.runtime == nil {
		return {}, {kind = .Closed}
	}

	now := runtime_async.deadline_after(s.runtime, 0)

	if now.epoch != s.epoch || now.at <= 0 {
		return {}, {kind = .Invalid_State}
	}

	s.last_clock = now

	return now, {}
}

// Bounded metadata-only transfer used by the actor implementation. Borrowed
// input/host views remain held by Kernel Request/Session refs through cleanup.
network_assignment_take :: proc(actor: ^Session_Actor) -> (Session_Assignment, Client_Error) {
	if actor == nil || !network_valid(actor.owner) {
		return {}, {kind = .Invalid_State}
	}

	s := actor.owner

	if actor.index == 0 || u64(actor.index) > u64(len(s.actors)) || actor != &s.actors[int(actor.index) - 1] {
		return {}, {kind = .Invalid_Handle}
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	if s.phase != .Published {
		return {}, {kind = .Closed}
	}

	if !actor.command.pending {
		return {}, {kind = .Pending}
	}

	assignment := actor.command.assignment
	sync.lock(&s.kernel.mu)
	defer sync.unlock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, assignment.request)
	if request == nil ||
	   request.state != .Active ||
	   request.session != assignment.session ||
	   assignment.session.slot != actor.index ||
	   assignment.session.generation == 0 {
		return {}, {kind = .Invalid_Handle}
	}

	model := &s.kernel.sessions[int(actor.index) - 1]
	if model.generation != assignment.session.generation ||
	   model.request != assignment.request ||
	   (model.state != .Busy && model.state != .Connecting) {
		return {}, {kind = .Invalid_State}
	}

	origin := admission_origin_locked(&s.kernel, request.origin)

	if origin == nil || model.origin != request.origin {
		return {}, {kind = .Invalid_State}
	}

	metadata := &s.requests[int(assignment.request.slot) - 1]
	if metadata.generation != assignment.request.generation ||
	   metadata.ids.count < 0 ||
	   metadata.ids.count > DNS_IDS_PER_QUERY ||
	   metadata.prepared_address_count < 0 ||
	   metadata.prepared_address_count > DNS_RESULT_CAPACITY ||
	   metadata.query_budget_left < metadata.ids.count {
		return {}, {kind = .Invalid_State}
	}

	if model.state == .Connecting && metadata.prepared_address_count == 0 && metadata.ids.count == 0 {
		return {}, {kind = .Pending}
	}

	if s.registered_tasks == 0 || s.runtime == nil {
		return {}, {kind = .Closed}
	}

	now := runtime_async.deadline_after(s.runtime, 0)

	if now.epoch != request.deadline.epoch || now.at <= 0 {
		return {}, {kind = .Invalid_State}
	}

	s.last_clock = now

	if request.cancel_requested || actor.command.cancel || actor.command.retire || s.kernel.closed {
		return {}, {kind = .Closed}
	}

	if now.at >= request.deadline.at {
		return {}, {kind = .Request_Error, http = {kind = .Deadline_Failed, phase = .Deadline}}
	}

	setup := request.deadline
	duration := s.config.config.http.setup_timeout

	if duration > 0 {
		setup.at = min(setup.at, now.at + min(i64(duration), max(i64) - now.at))
	}

	result := Session_Assignment {
		assignment    = assignment,
		request       = request.input.request,
		cutoff        = request.deadline,
		setup_cutoff  = setup,
		secure        = origin.owner.key.secure,
		host          = origin.owner.key.host,
		port          = origin.owner.key.port,
		ids           = metadata.ids,
		addresses     = metadata.prepared_addresses,
		address_count = metadata.prepared_address_count,
	}

	metadata.query_budget_left -= metadata.ids.count
	metadata.ids = {}
	metadata.awaiting_ids = false
	actor.command.pending = false

	return result, {}
}

network_unstarted_cancel :: proc(s: ^Client_State) {
	assert(kernel_close(&s.kernel).kind == .None)

	for index in 0 ..< len(s.kernel.requests) {
		sync.lock(&s.mu)
		sync.lock(&s.kernel.mu)
		request := &s.kernel.requests[index]
		queued := request.state == .Queued
		handle := Request_Handle {
			owner_id   = s.kernel.owner_id,
			slot       = u32(index + 1),
			generation = request.generation,
		}

		if queued {
			network_queue_forget_locked(s, handle)
		}

		sync.unlock(&s.kernel.mu)
		sync.unlock(&s.mu)

		if !queued {
			continue
		}

		response: surf.Response
		disposal, error := kernel_begin_complete(
			&s.kernel,
			handle,
			&response,
			{kind = .IO_Failed, transport = net.Connection_Error.Cancelled, phase = .Cancellation, write_effect = .Not_Sent},
		)
		assert(error.kind == .None)

		for {
			origin := disposal.origin.origin
			request_disposal_destroy(&disposal)

			if origin.slot != 0 {
				assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
			}

			now, clock_error := network_clock(s)
			assert(clock_error.kind == .None) // This callback still owns its registered witness.
			next, done, failure := kernel_cleanup_finish(&s.kernel, handle, now)
			assert(failure.kind == .None)
			disposal = next

			if done {
				break
			}
		}
	}
}

// No Task/TLS/adapter API is valid here: _current_task was cleared before the
// runtime invokes on_done. False certifies the caller's unstarted/no-I/O path.
network_task_done :: proc(s: ^Client_State, actor_index: int, owner_drained: bool) {
	if !network_valid(s) || actor_index < 0 || actor_index > len(s.actors) {
		return
	}

	sync.lock(&s.mu)
	registered: ^bool
	done: ^bool
	detached: ^bool
	notification: signal.Signal

	if actor_index == 0 {
		registered = &s.coordinator.registered
		done = &s.coordinator.done
		detached = &s.coordinator.detached
		notification = s.coordinator.wake
	} else {
		actor := &s.actors[actor_index - 1]
		registered = &actor.registered
		done = &actor.done
		detached = &actor.detached
		notification = actor.wake
	}

	if !registered^ {
		sync.unlock(&s.mu); return
	}

	assert(s.registered_tasks > 0 && s.references > 1)

	if !owner_drained {
		for actor in s.actors {
			assert(
				!actor.executor_initialized &&
				!actor.transport_initialized &&
				!actor.tls_initialized &&
				!actor.handshake_started &&
				!actor.close_started,
			)
		}
	}

	registered^ = false
	done^ = true
	s.phase = .Closing
	cleanup := !owner_drained && !s.unstarted_cleanup_started

	if cleanup {
		s.unstarted_cleanup_started = true
	}

	sync.unlock(&s.mu)
	signal.detach(notification)

	if cleanup {
		network_unstarted_cancel(s)
		sync.lock(&s.mu)
		s.unstarted_cleanup_done = true
		sync.unlock(&s.mu)
	}

	sync.lock(&s.mu)
	detached^ = true
	s.registered_tasks -= 1

	if s.registered_tasks == 0 {
		s.runtime = nil
	}

	sync.unlock(&s.mu)
	network_state_release(s) // FINAL State access; last release may physically free.
}
