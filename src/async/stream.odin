package surf_async

import surf ".."
import stream_api "stream"
import exchange_api "exchange"
import http "shared:async/http"
import runtime_async "shared:async"
import adapter "shared:async/connection"
import tls_api "shared:async/tls"
import "core:net"
import "core:sync"
import "core:io"
import "shared:async/mem/owned"

session_stream_channel :: proc(a: ^Session_Actor) -> ^stream_api.Channel {
	sync.lock(&a.owner.kernel.mu)
	defer sync.unlock(&a.owner.kernel.mu)
	request := admission_request_locked(&a.owner.kernel, a.request)

	if request == nil || request.stream == nil {
		return nil
	}

	assert(stream_api.retain(request.stream))

	return request.stream
}

session_stream_begin :: proc(
	a: ^Session_Actor,
	cell: ^stream_api.Channel,
	stream: net.Async_Connection,
	request: http.Request,
	budget: exchange_api.Budget,
) -> surf.HTTP_Error {
	storage, cause := kernel_grant(
		size_of(exchange_api.Stream_Exchange),
		align_of(exchange_api.Stream_Exchange),
		a.owner.resources.allocator,
	)
	if cause.kind != .None {
		stream_api.release(cell)
		return cause.http
	}
	engine := cast(^exchange_api.Stream_Exchange)raw_data(storage)
	now, clock := network_clock(a.owner)
	if clock.kind != .None || !session_before_http(a, now) {
		kernel_free(storage, align_of(exchange_api.Stream_Exchange), a.owner.resources.allocator)
		stream_api.release(cell)
		return a.error
	}
	error := exchange_api.stream_exchange_begin(
		engine,
		stream,
		request,
		budget,
		{data = a, wake = session_notify},
		cell,
		a.owner.config.config.http.max_redirects > 0,
		a.owner.resources.allocator,
	)
	if error.kind != .None {
		kernel_free(storage, align_of(exchange_api.Stream_Exchange), a.owner.resources.allocator)
		stream_api.release(cell)
		return error
	}
	a.stream_exchange = engine
	stream_api.set_notify(cell, a.wake)
	return {}
}

session_stream_dispose :: proc(a: ^Session_Actor) {
	engine := a.stream_exchange

	if engine == nil {
		return
	}

	assert(exchange_api.stream_exchange_destroy(engine).kind == .None)
	cell := engine.channel
	a.stream_exchange = nil
	storage := (cast([^]u8)engine)[:size_of(exchange_api.Stream_Exchange)]
	kernel_free(storage, align_of(exchange_api.Stream_Exchange), a.owner.resources.allocator)
	stream_api.release(cell)
}

session_engine_quiescent :: proc(a: ^Session_Actor) -> bool {
	if a.stream_exchange != nil {
		return exchange_api.stream_exchange_quiescent(a.stream_exchange)
	}

	return exchange_api.exchange_quiescent(&a.exchange)
}

session_engine_drive :: proc(a: ^Session_Actor, now: i64, cancelled: bool) -> exchange_api.Drive_Result {
	if a.stream_exchange != nil {
		return exchange_api.stream_exchange_drive(
			a.stream_exchange,
			now,
			cancelled,
			a.owner.config.config.capacities.work_per_resume,
		)
	}

	return exchange_api.exchange_drive(&a.exchange, now, cancelled, a.owner.config.config.capacities.work_per_resume)
}

session_stream_step :: proc(a: ^Session_Actor, now: runtime_async.Deadline) -> runtime_async.Resume_Result {
	engine := a.stream_exchange
	cancelled := (session_cancelled(a) || runtime_async.cancelled(&a.task)) && now.at < a.cutoff.at
	result := exchange_api.stream_exchange_drive(
		engine,
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
		if result.status != .Waiting {
			return .Yield
		}

		sleep := runtime_async.sleep_until_earlier(a.owner.runtime, a.cutoff)

		if sleep.kind == .None {
			return .Yield
		}

		if sleep.kind != .Pending {
			session_error(a, {kind = .IO_Failed, phase = .Cancellation, transport = net.Connection_Error.Cancelled})
			return .Yield
		}

		return .Waiting
	}

	response: surf.Response

	if exchange_api.stream_exchange_take_redirect(engine, &response) {
		if redirect_response(a, &response) {
			return .Yield
		}

		surf.response_destroy(&response)
		session_error(a, {kind = .Invalid_Config, phase = .Protocol})
		return .Yield
	}

	fresh, clock := network_clock(a.owner)
	failure: surf.HTTP_Error

	if clock.kind != .None {
		failure = {
			kind  = .Invalid_Config,
			phase = .Configuration,
		}
	} else if session_cancelled(a) || runtime_async.cancelled(&a.task) {
		failure = {
			kind = .IO_Failed,
			transport = net.Connection_Error.Cancelled,
			phase = .Cancellation,
		}
	} else if fresh.at >= a.cutoff.at {
		failure = {
			kind  = .Deadline_Failed,
			phase = .Deadline,
		}
	} else if budget := adapter.budget_error(&a.executor); budget != nil {
		failure = {
			kind      = .IO_Failed,
			transport = budget,
			phase     = .Read,
		}
	}

	response.status = engine.status

	if failure.kind != .None {
		failure.status = engine.status
		failure.write_effect = .Response_Received
		session_error(a, failure)
		return .Yield
	}

	if error := network_assignment_finish(a, &response, {}); error.kind != .None {
		if error.kind != .Pending {
			session_error(a, {kind = .Invalid_Config, phase = .Configuration})
		}

		return .Yield
	}

	stream_api.complete(engine.channel, {})
	session_stream_dispose(a)

	return session_finish_reuse(a, result.reuse_eligible)
}

stream_client_error :: proc(cause: stream_api.Error) -> Client_Error {
	if cause.kind == .Allocation_Failed {
		return {kind = .Allocation_Failed, http = cause.http}
	}

	if cause.http.kind != .None {
		return {kind = .Request_Error, http = cause.http}
	}

	switch cause.kind {
	case .None:
		return {}
	case .Invalid:
		return {kind = .Invalid_State}
	case .Closed:
		return {kind = .Closed}
	case .Pending:
		return {kind = .Pending}
	case .Capacity:
		return {kind = .Capacity}
	case .Allocation_Failed:
		return {kind = .Allocation_Failed, http = cause.http}
	}

	unreachable()
}

client_submit_stream :: proc(
	c: ^Client,
	request: http.Request,
	options: Stream_Options,
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
	selected, selection := submission_budget(s, deadline)
	if selection.kind != .None {
		return {}, selection
	}
	if s.stream_bank == nil {
		return {}, {kind = .Invalid_Config}
	}
	normalized, valid := stream_api.options_normalize(options, s.config.config.response_body_limit)
	if !valid {
		return {}, {kind = .Invalid_Config}
	}
	if length, upload := normalized.upload_length.?; upload {
		limits, _ := s.config.config.streaming.?

		if length > 0 && limits.max_retained_bytes_per_stream <= limits.response_chunks * limits.max_chunk_bytes {
			return {}, {kind = .Invalid_Config}
		}

		if len(request.body) != 0 || s.config.config.http.max_redirects > 0 {
			return {}, {kind = .Invalid_Config}
		}
	}
	cell, cause := stream_api.channel_create(s.stream_bank, normalized)
	if cause.kind != .None {
		return {}, stream_client_error(cause)
	}
	return client_submit_state(s, request, selected, cell)
}

client_stream_ref :: proc(s: ^Client_State, handle: Request_Handle) -> (^stream_api.Channel, Client_Error) {
	sync.lock(&s.kernel.mu)
	defer sync.unlock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, handle)

	if request == nil {
		return nil, {kind = .Invalid_Handle}
	}

	if request.stream == nil || !stream_api.retain(request.stream) {
		return nil, {kind = .Invalid_State}
	}

	return request.stream, {}
}

client_stream_take_head :: proc(c: ^Client, handle: Request_Handle, destination: ^Stream_Head) -> Client_Error {
	s, error := client_enter(c)

	if error.kind != .None {
		return error
	}

	defer client_leave(s)

	if destination == nil || client_stream_destination_alias(s, c, destination, size_of(Stream_Head)) {
		return {kind = .Invalid_State}
	}

	cell, cause := client_stream_ref(s, handle)

	if cause.kind != .None {
		return cause
	}

	defer stream_api.release(cell)

	return stream_client_error(stream_api.take_head(cell, destination))
}

client_stream_next :: proc(
	c: ^Client,
	handle: Request_Handle,
	destination: ^owned.Chunk,
) -> (
	Stream_Read_Status,
	Client_Error,
) {
	s, error := client_enter(c)

	if error.kind != .None {
		return .Pending, error
	}

	defer client_leave(s)
	if destination == nil || client_stream_destination_alias(s, c, destination, size_of(owned.Chunk)) {
		return .Pending, {kind = .Invalid_State}
	}
	cell, cause := client_stream_ref(s, handle)

	if cause.kind != .None {
		return .Pending, cause
	}
	defer stream_api.release(cell)
	status, next := stream_api.next(cell, destination)
	return status, stream_client_error(next)
}

client_upload_submit :: proc(
	c: ^Client,
	handle: Request_Handle,
	source: ^owned.Chunk,
) -> (
	Upload_Submit_Status,
	Client_Error,
) {
	s, error := client_enter(c)

	if error.kind != .None {
		return .Closed, error
	}

	defer client_leave(s)
	if source == nil || client_stream_destination_alias(s, c, source, size_of(owned.Chunk)) {
		return .Invalid, {kind = .Invalid_State}
	}
	if gate := client_upload_gate(s, handle); gate.kind != .None {
		return .Closed, gate
	}
	cell, cause := client_stream_ref(s, handle)

	if cause.kind != .None {
		return .Invalid, cause
	}
	defer stream_api.release(cell)
	status, next := stream_api.upload_submit(cell, source)
	return status, stream_client_error(next)
}

client_upload_finish :: proc(c: ^Client, handle: Request_Handle, source_error: io.Error = nil) -> Client_Error {
	s, error := client_enter(c)

	if error.kind != .None {
		return error
	}

	defer client_leave(s)

	if gate := client_upload_gate(s, handle); gate.kind != .None {
		return gate
	}

	cell, cause := client_stream_ref(s, handle)

	if cause.kind != .None {
		return cause
	}

	defer stream_api.release(cell)

	return stream_client_error(stream_api.upload_finish(cell, source_error))
}

client_stream_destination_alias :: proc(s: ^Client_State, c: ^Client, destination: rawptr, size: int) -> bool {
	if client_state_alias(s, c, destination, size) {
		return true
	}

	k := &s.kernel

	return(
		ranges_overlap(destination, size, raw_data(k.requests), len(k.requests) * size_of(Request_Slot)) ||
		ranges_overlap(destination, size, raw_data(k.sessions), len(k.sessions) * size_of(Session_Model)) ||
		ranges_overlap(destination, size, raw_data(k.origins), len(k.origins) * size_of(Origin_Slot)) \
	)
}

// Sample through the registered-task witness before producer ownership moves.
// No user allocator/destructor or injected clock executes under ledger locks.
client_upload_gate :: proc(s: ^Client_State, handle: Request_Handle) -> Client_Error {
	now, clock := network_clock(s)

	if clock.kind != .None {
		return clock
	}

	sync.lock(&s.kernel.mu)
	defer sync.unlock(&s.kernel.mu)
	request := admission_request_locked(&s.kernel, handle)

	if request == nil {
		return {kind = .Invalid_Handle}
	}

	if request.state != .Queued && request.state != .Active {
		return {kind = .Closed}
	}

	if request.cancel_requested || s.kernel.closed {
		return {
			kind = .Request_Error,
			http = {kind = .IO_Failed, transport = net.Connection_Error.Cancelled, phase = .Cancellation},
		}
	}

	if now.epoch != request.deadline.epoch {
		return {kind = .Invalid_Config}
	}

	if now.at >= request.deadline.at {
		return {
			kind = .Request_Error,
			http = {kind = .Deadline_Failed, transport = net.TCP_Recv_Error.Timeout, phase = .Deadline},
		}
	}

	return {}
}

Stream_Client_Limits :: stream_api.Limits
Stream_Options :: stream_api.Options
Stream_Head :: stream_api.Head
Content_Decoding :: stream_api.Content_Decoding
Stream_Read_Status :: stream_api.Read_Status
Upload_Submit_Status :: stream_api.Upload_Status
Stream_Stats :: stream_api.Stats

stream_head_destroy :: stream_api.head_destroy
