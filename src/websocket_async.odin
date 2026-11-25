package surf

import "base:intrinsics"
import rt "base:runtime"
import "core:crypto"
import "core:crypto/x509"
import "core:mem"
import "core:net"
import "core:time"
import "shared:async"
import adapter "shared:async/connection"
import "shared:async/tls"
import "shared:websocket"

// Asynchronous RFC 6455 client over the task-owned TCP bridge and, when roots
// are set, the existing async TLS client. This is not HTTP/2 or QUIC.
// Caller-owned read/write buffers stay borrowed until that operation's callback.
// Close copies its short reason into fixed session storage. One task drives the
// session; cancel may be requested from another thread and only wakes it.

WebSocket_Async_QUEUE_CAP :: 8
WebSocket_Async_MAX_FRAME_PAYLOAD :: 4096
WebSocket_Async_DEFAULT_MESSAGE_SIZE :: 1 << 20
WebSocket_Async_MESSAGE_LIMIT :: 64 << 20
WebSocket_Async_DEFAULT_FRAME_PAYLOAD :: 1024
WebSocket_Async_DEFAULT_QUEUED_MESSAGES :: 4
WebSocket_Async_DEFAULT_QUEUED_BYTES :: 1 << 20
WebSocket_Async_DEFAULT_FRAGMENTS :: 1024
WebSocket_Async_MAX_CONTROL_WITHOUT_MESSAGE :: 1024

WebSocket_Async_Kind :: enum {
	Upgrade,
	Read,
	Write,
	Close,
}

WebSocket_Async_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Cancelled,
	Timeout,
	Queue_Full,
	Busy,
	Upgrade_Failed,
	TLS_Failed,
	IO_Failed,
	Protocol_Failed,
	Closed,
	EOF,
	Peer_Close,
	Message_Oversized,
	Invalid_UTF8,
	Invalid_Frame,
	Allocation_Failed,
	Destination_Undersized,
	Entropy_Unavailable,
	Address_Rejected,
}

WebSocket_Async_Error :: struct {
	kind:       WebSocket_Async_Error_Kind,
	upgrade:    websocket.Upgrade_Error,
	frame:      websocket.Frame_Error,
	message:    websocket.Message_Error_Kind,
	transport:  net.Network_Error,
	tls_error:  tls.Error,
	x509_error: x509.Error,
	close_code: u16,
	n:          int,
}

// Stable until callback. Do not copy or reuse while pending.
WebSocket_Async_Op :: struct {
	callback:    proc(op: ^WebSocket_Async_Op),
	user_data:   rawptr,
	kind:        WebSocket_Async_Kind,
	opcode:      websocket.Opcode,
	buffer:      []u8,
	close_code:  u16,
	reason:      string,
	pending:     bool,
	cancel_flag: int,
	n:           int,
	error:       WebSocket_Async_Error,
}

// Borrowed host, target, origin, subprotocols, server_name and roots must
// outlive the session. Empty roots select plain ws. A zero limit or timeout
// selects the documented default. Endpoint is numeric; this session does not
// resolve DNS.
WebSocket_Async_Config :: struct {
	endpoint:            net.Endpoint,
	host:                string,
	target:              string,
	origin:              string,
	server_name:         string,
	subprotocols:        []string,
	roots:               []^x509.Certificate,
	max_message_size:    int,
	max_frame_payload:   int,
	max_queued_messages: int,
	max_queued_bytes:    int,
	max_fragments:       int,
	handshake_timeout:   time.Duration,
	io_timeout:          time.Duration,
	close_timeout:       time.Duration,
	// Nil allows endpoint. Checked with host before connect. host is not resolved.
	address_policy:      Address_Policy,
	address_policy_data: rawptr,
}

// Caller-owned, stable address, not copied. user is untouched by bind and is
// available to the on_done procedure. Free the session only after on_done.
WebSocket_Async :: struct {
	user:                                                                   rawptr,
	runtime:                                                                ^async.Runtime,
	task:                                                                   async.Task,
	config:                                                                 WebSocket_Async_Config,
	loop:                                                                   adapter.Executor,
	transport:                                                              adapter.Transport,
	secure_conn:                                                            tls.Async_Conn,
	hs:                                                                     tls.Async_Handshake_Operation,
	net_read, net_write, net_close:                                         net.Async_Operation,
	connecting:                                                             async.Connecting_Socket,
	connect_deadline:                                                       async.Deadline,
	allocator:                                                              mem.Allocator,
	failure:                                                                WebSocket_Async_Error,
	handshake_error:                                                        tls.Error,
	selected_protocol:                                                      [websocket.MAX_SUBPROTOCOL_SIZE]u8,
	selected_protocol_size:                                                 int,
	upgrade_key:                                                            [16]u8,
	request_buf:                                                            [websocket.MAX_UPGRADE_HEADER_SIZE]u8,
	upgrade_buf:                                                            [websocket.MAX_UPGRADE_HEADER_SIZE]u8,
	inbox:                                                                  [2048]u8,
	wire:                                                                   [14 + WebSocket_Async_MAX_FRAME_PAYLOAD]u8,
	header_raw:                                                             [14]u8,
	control_out:                                                            [125]u8,
	control_in:                                                             [125]u8,
	close_body:                                                             [125]u8,
	peer_close_body:                                                        [125]u8,
	message:                                                                websocket.Message_State,
	upgrade_op, read_op, close_op:                                          ^WebSocket_Async_Op,
	queue:                                                                  [WebSocket_Async_QUEUE_CAP]^WebSocket_Async_Op,
	phase:                                                                  WebSocket_Async_Phase,
	read_state, write_state, close_state:                                   WebSocket_Async_IO,
	writer:                                                                 WebSocket_Async_Writer,
	header:                                                                 websocket.Frame_Header,
	read_error, write_error:                                                net.Network_Error,
	read_deadline, write_deadline, close_deadline:                          time.Time,
	request_len, upgrade_len, inbox_at, inbox_len, wire_len:                int,
	header_have, payload_have, payload_need:                                int,
	write_offset, fragment_len, queue_head, queue_count, queue_bytes:       int,
	control_len, close_len, peer_close_len, fragments, controls:            int,
	upgrade_read_armed:                                                     int,
	handshake_transport:                                                    net.Network_Error,
	bound, secure, tls_ready, executor_ready, connected, connect_started:   bool,
	handshake_ready, read_cancel_sent:                                      bool,
	running, request_sent, upgrade_open, released, ops_finished:            bool,
	control_pending, control_is_close, close_sent, peer_closed, echo_close: bool,
	local_close, fail_quiet, task_cancelled, clean, close_started:          bool,
}

WebSocket_Async_Phase :: enum {
	Bound,
	Connecting,
	Securing,
	Upgrade,
	Open,
	Closing,
	Failed,
	Terminal,
}

WebSocket_Async_IO :: enum {
	Idle,
	Pending,
	Done,
}

WebSocket_Async_Writer :: enum {
	None,
	Request,
	Frame,
	Control,
}

websocket_async_limits :: proc(
	config: WebSocket_Async_Config,
) -> (
	WebSocket_Async_Config,
	WebSocket_Async_Error,
) {
	settings := config
	if settings.target == "" {
		settings.target = "/"
	}
	if settings.max_message_size == 0 {
		settings.max_message_size = WebSocket_Async_DEFAULT_MESSAGE_SIZE
	}
	if settings.max_frame_payload == 0 {
		settings.max_frame_payload = WebSocket_Async_DEFAULT_FRAME_PAYLOAD
	}
	if settings.max_queued_messages == 0 {
		settings.max_queued_messages = WebSocket_Async_DEFAULT_QUEUED_MESSAGES
	}
	if settings.max_queued_bytes == 0 {
		settings.max_queued_bytes = WebSocket_Async_DEFAULT_QUEUED_BYTES
	}
	if settings.max_fragments == 0 {
		settings.max_fragments = WebSocket_Async_DEFAULT_FRAGMENTS
	}
	if settings.handshake_timeout == 0 {
		settings.handshake_timeout = 10 * time.Second
	}
	if settings.io_timeout == 0 {
		settings.io_timeout = 10 * time.Second
	}
	if settings.close_timeout == 0 {
		settings.close_timeout = time.Second
	}
	if settings.host == "" ||
	   settings.endpoint.port <= 0 ||
	   settings.endpoint.port > 65535 ||
	   settings.endpoint.address == nil ||
	   settings.max_message_size < 0 ||
	   settings.max_message_size > WebSocket_Async_MESSAGE_LIMIT ||
	   settings.max_frame_payload < 1 ||
	   settings.max_frame_payload > WebSocket_Async_MAX_FRAME_PAYLOAD ||
	   settings.max_queued_messages < 1 ||
	   settings.max_queued_messages > WebSocket_Async_QUEUE_CAP ||
	   settings.max_queued_bytes < 1 ||
	   settings.max_queued_bytes > WebSocket_Async_MESSAGE_LIMIT ||
	   settings.max_fragments < 1 ||
	   settings.max_fragments > 65536 ||
	   settings.handshake_timeout < 0 ||
	   settings.io_timeout < 0 ||
	   settings.close_timeout < 0 ||
	   len(settings.roots) > 0 &&
		   settings.server_name == "" &&
		   websocket_async_name(settings.host) == "" {
		return {}, {kind = .Invalid_Config}
	}

	scratch: [websocket.MAX_UPGRADE_HEADER_SIZE]u8
	_, encode_error := websocket.upgrade_request_encode(
		scratch[:],
		{
			host = settings.host,
			target = settings.target,
			origin = settings.origin,
			subprotocols = settings.subprotocols,
		},
		{},
	)

	if encode_error != .None {
		return {}, {kind = .Invalid_Config, upgrade = encode_error}
	}

	return settings, {}
}

websocket_async_name :: proc(host: string) -> string {
	if len(host) == 0 || host[0] == '[' {
		return ""
	}
	colon := 0
	for colon < len(host) && host[colon] != ':' {
		colon += 1
	}
	if colon == 0 {
		return ""
	}

	return host[:colon]
}

// Installs resume and on_cancel. The caller registers or spawns the task.
// on_done may be nil. A rejected bind leaves the session unchanged.
websocket_async_bind :: proc(
	session: ^WebSocket_Async,
	runtime: ^async.Runtime,
	config: WebSocket_Async_Config,
	on_done: proc(_: rawptr) = nil,
) -> WebSocket_Async_Error {
	if session == nil || runtime == nil || session.bound {
		return {kind = .Invalid_Config}
	}
	settings, limit_error := websocket_async_limits(config)
	if limit_error.kind != .None {
		return limit_error
	}
	user := session.user
	session^ = {
		user = user,
	}
	session.runtime = runtime
	session.config = settings
	session.secure = len(settings.roots) > 0
	session.allocator = context.allocator
	if session.allocator.procedure == nil {
		session.allocator = rt.heap_allocator()
	}
	session.task = {
		data      = session,
		resume    = websocket_async_resume,
		on_cancel = websocket_async_on_cancel,
		on_done   = on_done,
	}
	session.phase = .Bound
	session.bound = true
	return {}
}

websocket_async_owner_ok :: proc(session: ^WebSocket_Async) -> bool {
	if session == nil || !session.bound {
		return false
	}
	if !session.running {
		return true
	}

	return async.is_current_task(&session.task)
}

websocket_async_upgrade :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	if session.upgrade_op != nil ||
	   session.upgrade_open ||
	   session.phase == .Failed ||
	   session.phase == .Terminal ||
	   session.phase == .Open ||
	   session.phase == .Closing {
		return {kind = .Invalid_State}
	}

	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Upgrade,
		pending   = true,
	}

	session.upgrade_op = op

	return {}
}

websocket_async_read :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	dst: []u8,
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	if session.phase != .Open || session.read_op != nil {
		return {kind = .Busy if session.read_op != nil else .Invalid_State}
	}

	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Read,
		buffer    = dst,
		pending   = true,
	}

	session.read_op = op
	session.read_deadline = time.time_add(time.now(), session.config.io_timeout)

	return {}
}

websocket_async_write :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	opcode: websocket.Opcode,
	src: []u8,
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}
	if session.phase != .Open || session.local_close {
		return {kind = .Invalid_State}
	}
	if error := websocket.message_validate(opcode, src, session.config.max_message_size);
	   error.kind != .None {
		return websocket_async_message_error(error)
	}
	if len(src) > session.config.max_queued_bytes ||
	   session.queue_count >= session.config.max_queued_messages ||
	   session.queue_bytes > session.config.max_queued_bytes - len(src) {
		return {kind = .Queue_Full}
	}
	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Write,
		opcode    = opcode,
		buffer    = src,
		pending   = true,
	}
	index := (session.queue_head + session.queue_count) % session.config.max_queued_messages
	session.queue[index] = op
	session.queue_count += 1
	session.queue_bytes += len(src)
	return {}
}

// reason is copied before return. code must be a wire close code.
websocket_async_close :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	code: u16 = 1000,
	reason: string = "",
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}
	if session.close_op != nil ||
	   session.local_close ||
	   session.phase == .Failed ||
	   session.phase == .Terminal ||
	   session.phase == .Closing {
		return {kind = .Invalid_State}
	}
	if session.phase != .Open {
		return {kind = .Invalid_State}
	}
	body: [125]u8
	size, frame_error := websocket_close_payload(&body, code, reason)
	if frame_error != .None {
		return {kind = .Invalid_Frame, frame = frame_error}
	}
	copy(session.close_body[:], body[:size])
	session.close_len = size
	session.local_close = true
	op^ = {
		callback   = op.callback,
		user_data  = op.user_data,
		kind       = .Close,
		close_code = code,
		pending    = true,
	}
	session.close_op = op
	return {}
}

// Safe from another thread. The operation stays borrowed until its callback.
// Close cannot be cancelled. A repeated request while pending is harmless.
websocket_async_cancel :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || !op.pending {
		return {kind = .Invalid_State}
	}

	if op.kind == .Close {
		return {kind = .Invalid_State}
	}

	intrinsics.atomic_store(&op.cancel_flag, 1)

	if session.runtime != nil {
		async.wake(session.runtime, &session.task)
	}

	return {}
}

websocket_async_subprotocol :: proc(session: ^WebSocket_Async) -> string {
	if session == nil || !session.upgrade_open {
		return ""
	}

	return cast(string)session.selected_protocol[:session.selected_protocol_size]
}

websocket_async_cancelled :: proc(op: ^WebSocket_Async_Op) -> bool {
	return op != nil && op.pending && intrinsics.atomic_load(&op.cancel_flag) != 0
}

websocket_async_message_error :: proc(error: websocket.Message_Error) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.Protocol_Failed

	switch error.kind {
	case .None:
		kind = .None
	case .Message_Oversized:
		kind = .Message_Oversized
	case .Invalid_UTF8:
		kind = .Invalid_UTF8
	case .Allocation_Failed:
		kind = .Allocation_Failed
	case .Destination_Undersized:
		kind = .Destination_Undersized
	case .Unexpected_Continuation, .Interrupted_Message, .Invalid_Message_Type:
		kind = .Protocol_Failed
	}

	return {kind = kind, message = error.kind}
}

websocket_async_complete :: proc(op: ^WebSocket_Async_Op, error: WebSocket_Async_Error) {
	if op == nil || !op.pending {
		return
	}
	op.pending = false
	op.error = error
	op.n = error.n
	callback := op.callback
	if callback != nil {
		callback(op)
	}
}

websocket_async_resume :: proc(data: rawptr) -> async.Resume_Result {
	session := cast(^WebSocket_Async)data
	session.running = true
	if session.phase == .Terminal {
		return .Done
	}

	if !session.connected {
		result := websocket_async_connect(session)
		if !session.connected {
			return result
		}
		return .Yield
	}

	drive_result := async.Resume_Result.Waiting

	if session.executor_ready {
		drive_result = adapter.drive(&session.loop)
	}

	if websocket_async_pump(session) {
		return .Yield
	}
	if session.phase == .Terminal {
		return .Done
	}

	return drive_result
}

websocket_async_on_cancel :: proc(data: rawptr) -> async.Resume_Result {
	session := cast(^WebSocket_Async)data
	session.running = true
	session.task_cancelled = true

	if !session.ops_finished {
		websocket_async_fail_ops(session, {kind = .Cancelled})
		session.ops_finished = true
	}

	if !session.executor_ready {
		websocket_async_release(session)
		session.phase = .Terminal
		return .Done
	}

	adapter.abort(&session.loop)
	if !session.close_started {
		websocket_async_begin_transport_close(session)
	}
	result := adapter.drive(&session.loop)

	if session.close_state == .Done || adapter.quiescent(&session.loop) {
		websocket_async_release(session)
		session.phase = .Terminal
		return .Done
	}

	if result == .Done {
		return .Yield
	}

	return result
}

websocket_async_connect :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	if websocket_async_cancelled(session.upgrade_op) || session.task_cancelled {
		websocket_async_finish_early(session, {kind = .Cancelled})
		return .Done
	}

	if !session.connect_started {
		if session.config.address_policy != nil {
			endpoint := session.config.endpoint

			if !session.config.address_policy(
				session.config.host,
				[]net.Endpoint{endpoint},
				session.config.address_policy_data,
			) {
				websocket_async_finish_early(session, {kind = .Address_Rejected})
				return .Done
			}
		}

		session.connect_deadline = async.deadline_after(
			session.runtime,
			session.config.handshake_timeout,
		)
		pending, error := async.begin_connect(
			session.runtime,
			&session.task,
			session.config.endpoint,
			session.connect_deadline,
		)

		if error.kind != .None {
			websocket_async_finish_early(session, websocket_async_runtime_error(error))
			return .Done
		}

		session.connecting = pending
		session.connect_started = true
		session.phase = .Connecting
	}

	socket, error := async.finish_connect(session.connecting, session.connect_deadline)
	if error.kind == .Pending {
		return .Waiting
	}

	if error.kind != .None {
		websocket_async_finish_early(session, websocket_async_runtime_error(error))
		return .Done
	}

	if wrap_error := websocket_async_wrap(session, socket); wrap_error.kind != .None {
		websocket_async_fail(session, wrap_error)
		if !session.close_started {
			websocket_async_begin_transport_close(session)
		}
	}

	session.connected = true

	return .Yield
}

websocket_async_wrap :: proc(
	session: ^WebSocket_Async,
	socket: async.Socket,
) -> WebSocket_Async_Error {
	if error := adapter.init_executor(&session.loop, session.runtime, &session.task, {});
	   error.kind != .None {
		return websocket_async_runtime_error(error)
	}

	session.executor_ready = true

	if error := adapter.init_transport(&session.transport, &session.loop, socket);
	   error.kind != .None {
		return websocket_async_runtime_error(error)
	}

	session.net_read = {
		callback  = websocket_async_read_done,
		user_data = session,
	}

	session.net_write = {
		callback  = websocket_async_write_done,
		user_data = session,
	}

	session.net_close = {
		callback  = websocket_async_close_done,
		user_data = session,
	}

	if !session.secure {
		session.phase = .Upgrade
		return {}
	}

	name := session.config.server_name
	if name == "" {
		name = websocket_async_name(session.config.host)
	}
	if error := tls.async_client(
		&session.secure_conn,
		adapter.stream(&session.transport),
		adapter.executor(&session.loop),
		{
			server_name = name,
			root_cas = session.config.roots,
			handshake_timeout = session.config.handshake_timeout,
		},
		session.allocator,
	); error != nil {
		return {kind = .TLS_Failed, tls_error = error}
	}

	session.tls_ready = true
	deadline := async.deadline_after(session.runtime, session.config.handshake_timeout)

	if error := adapter.set_request_budget(&session.loop, deadline); error.kind != .None {
		return websocket_async_runtime_error(error)
	}

	session.hs = {
		callback  = websocket_async_handshake_done,
		user_data = session,
	}

	wall := time.time_add(time.now(), session.config.handshake_timeout)

	if error := tls.async_handshake(&session.secure_conn, &session.hs, wall); error != nil {
		return {kind = .TLS_Failed, tls_error = error, transport = tls_network(error)}
	}

	session.phase = .Securing

	return {}
}

websocket_async_handshake_done :: proc(op: ^tls.Async_Handshake_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.handshake_error = tls.async_handshake_error(op)
	session.handshake_transport = op.err
	session.handshake_ready = true
}

websocket_async_read_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.inbox_at = 0
	session.inbox_len = op.result.count
	session.read_error = op.result.err
	session.read_state = .Done
}

websocket_async_write_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.wire_len = op.result.count
	session.write_error = op.result.err
	session.write_state = .Done
}

websocket_async_close_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.read_error = op.result.err
	session.close_state = .Done
}

websocket_async_pump :: proc(session: ^WebSocket_Async) -> bool {
	progressed := false

	for _ in 0 ..< 32 {
		if !websocket_async_step(session) {
			break
		}
		progressed = true
		if session.phase == .Terminal {
			break
		}
	}

	return progressed
}

websocket_async_step :: proc(session: ^WebSocket_Async) -> bool {
	if session.phase == .Terminal {
		return false
	}

	if session.close_state == .Done && session.phase != .Terminal {
		if !session.ops_finished {
			if session.phase != .Failed &&
			   session.failure.kind == .None &&
			   session.close_op != nil {
				session.clean = session.close_sent && session.peer_closed
				op := session.close_op
				session.close_op = nil
				session.ops_finished = true
				websocket_async_complete(op, {})
			} else {
				error := session.failure
				if error.kind == .None {
					error.kind = .IO_Failed
				}
				websocket_async_fail_ops(session, error)
				session.ops_finished = true
			}
		}

		websocket_async_release(session)
		session.phase = .Terminal
		return true
	}

	if session.phase == .Failed {
		if !session.ops_finished {
			websocket_async_fail_ops(session, session.failure)
			session.ops_finished = true
			if !session.close_started {
				websocket_async_begin_transport_close(session)
			}
			return true
		}

		return false
	}

	if session.task_cancelled || websocket_async_cancelled(session.upgrade_op) {
		websocket_async_fail(session, {kind = .Cancelled})
		return true
	}

	if session.write_state == .Done {
		websocket_async_finish_write(session)
		return true
	}

	#partial switch session.phase {
	case .Securing:
		return websocket_async_secure_step(session)
	case .Upgrade:
		return websocket_async_upgrade_step(session)
	case .Open, .Closing:
		return websocket_async_open_step(session)
	}

	return false
}

websocket_async_secure_step :: proc(session: ^WebSocket_Async) -> bool {
	if !session.handshake_ready {
		return false
	}

	if session.handshake_transport != nil || session.handshake_error != nil {
		transport := session.handshake_transport
		if transport == nil {
			transport = tls_network(session.handshake_error)
		}
		websocket_async_fail(
			session,
			{kind = .TLS_Failed, transport = transport, tls_error = session.handshake_error},
		)
		return true
	}

	if budget := adapter.budget_error(&session.loop); budget != nil {
		websocket_async_fail(session, websocket_async_net_error(budget))
		return true
	}

	if !tls.async_connection_state(&session.secure_conn).handshake_complete {
		websocket_async_fail(
			session,
			{kind = .TLS_Failed, tls_error = tls.General_Error.Invalid_State},
		)
		return true
	}

	idle := tls.async_idle_state(&session.secure_conn)
	// Busy still has a handshake callback or socket op. Buffered is residual
	// handshake state after success; application reads drain it.
	if idle == .Busy {
		return true
	}

	if idle != .Ready && idle != .Buffered {
		websocket_async_fail(session, {kind = .TLS_Failed})
		return true
	}

	cleared := adapter.set_request_budget(&session.loop, {})
	if cleared.kind == .Task_Busy {
		return true
	}

	if cleared.kind != .None {
		websocket_async_fail(session, websocket_async_runtime_error(cleared))
		return true
	}

	session.phase = .Upgrade

	return true
}

websocket_async_upgrade_step :: proc(session: ^WebSocket_Async) -> bool {
	if session.upgrade_op == nil {
		return false
	}

	if !session.request_sent {
		if session.write_state != .Idle {
			return false
		}

		when !crypto.HAS_RAND_BYTES {
			websocket_async_fail(session, {kind = .Entropy_Unavailable})
			return true
		}

		crypto.rand_bytes(session.upgrade_key[:])
		size, encode_error := websocket.upgrade_request_encode(
			session.request_buf[:],
			{
				host = session.config.host,
				target = session.config.target,
				origin = session.config.origin,
				subprotocols = session.config.subprotocols,
			},
			session.upgrade_key,
		)

		if encode_error != .None {
			websocket_async_fail(session, {kind = .Upgrade_Failed, upgrade = encode_error})
			return true
		}

		session.request_len = size
		session.write_deadline = time.time_add(time.now(), session.config.handshake_timeout)
		if !websocket_async_arm_write(session, session.request_buf[:size], .Request) {
			return true
		}
		return true
	}

	if session.upgrade_len > 0 ||
	   session.inbox_at < session.inbox_len ||
	   session.read_state == .Done {
		if !websocket_async_take_upgrade(session) {
			return session.phase == .Failed
		}
		response, consumed, validate_error := websocket.upgrade_response_validate(
			session.upgrade_buf[:session.upgrade_len],
			session.upgrade_key,
			session.config.subprotocols,
		)

		if validate_error == .Header_Incomplete {
			if session.upgrade_len == len(session.upgrade_buf) {
				websocket_async_fail(
					session,
					{kind = .Upgrade_Failed, upgrade = .Header_Oversized},
				)
				return true
			}

			return websocket_async_arm_upgrade_read(session)
		}

		if validate_error != .None {
			websocket_async_fail(session, {kind = .Upgrade_Failed, upgrade = validate_error})
			return true
		}

		if budget := adapter.budget_error(&session.loop); budget != nil && session.secure {
			websocket_async_fail(session, websocket_async_net_error(budget))
			return true
		}

		copy(session.selected_protocol[:], transmute([]u8)response.subprotocol)
		session.selected_protocol_size = len(response.subprotocol)
		tail := session.upgrade_len - consumed
		copy(session.inbox[:], session.upgrade_buf[consumed:session.upgrade_len])
		session.inbox_at = 0
		session.inbox_len = tail
		session.upgrade_open = true
		session.phase = .Open
		op := session.upgrade_op
		session.upgrade_op = nil
		websocket_async_complete(op, {})
		return true
	}

	return websocket_async_arm_upgrade_read(session)
}

websocket_async_take_upgrade :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state == .Done {
		error := session.read_error
		got := session.inbox_len
		session.read_state = .Idle

		if got == 0 {
			if error == nil {
				error = .No_Progress
			}
			websocket_async_fail(session, websocket_async_upgrade_io(error))
			return false
		}
	}

	available := session.inbox_len - session.inbox_at
	if available <= 0 {
		return session.upgrade_len > 0
	}
	n := copy(
		session.upgrade_buf[session.upgrade_len:],
		session.inbox[session.inbox_at:session.inbox_len],
	)
	session.upgrade_len += n
	session.inbox_at += n

	return true
}

websocket_async_arm_upgrade_read :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state == .Pending {
		return false
	}
	if session.inbox_at < session.inbox_len {
		return true
	}
	session.read_deadline = time.time_add(time.now(), session.config.handshake_timeout)

	if websocket_async_arm_read(session) {
		intrinsics.atomic_add(&session.upgrade_read_armed, 1)
		return true
	}

	return session.phase == .Failed
}

websocket_async_open_step :: proc(session: ^WebSocket_Async) -> bool {
	if websocket_async_cancelled(session.read_op) {
		if session.read_state == .Pending {
			if !session.read_cancel_sent {
				_ = net.async_cancel(websocket_async_stream(session), &session.net_read)
				session.read_cancel_sent = true
				return true
			}
		} else {
			session.read_cancel_sent = false
			op := session.read_op
			session.read_op = nil
			mid :=
				session.header_have > 0 ||
				session.payload_have > 0 ||
				session.message.fragmented ||
				len(session.message.message) > 0
			websocket_async_complete(op, {kind = .Cancelled})
			if mid {
				websocket_async_fail(session, {kind = .Cancelled})
			}
			return true
		}
	}

	if session.read_state == .Done {
		session.read_cancel_sent = false

		if session.read_error == net.Connection_Error.Cancelled ||
		   (session.read_error == nil && session.inbox_len == 0) {
			empty := session.read_error == nil && session.inbox_len == 0
			session.read_state = .Idle

			if empty {
				websocket_async_fail(
					session,
					{kind = .IO_Failed, transport = net.Connection_Error.No_Progress},
				)
				return true
			}

			op := session.read_op
			session.read_op = nil
			websocket_async_complete(op, {kind = .Cancelled})
			return true
		}

		terminal_read :=
			session.phase == .Closing &&
			(session.read_error == net.Connection_Error.Peer_Closed ||
					session.read_error == net.Connection_Error.Closed ||
					session.read_error == net.Connection_Error.Cancelled)

		if session.read_error != nil && session.inbox_len == 0 && !terminal_read {
			websocket_async_fail(session, websocket_async_net_error(session.read_error))
			session.read_state = .Idle
			return true
		}

		session.read_state = .Idle

		if terminal_read && !session.close_started {
			websocket_async_begin_transport_close(session)
			return true
		}
	}

	if session.phase == .Closing &&
	   session.close_deadline != (time.Time{}) &&
	   time.diff(time.now(), session.close_deadline) <= 0 &&
	   !session.close_started {
		websocket_async_fail(session, {kind = .Timeout})
		return true
	}

	if session.close_sent && session.peer_closed && !session.close_started {
		session.clean = session.failure.kind == .None
		websocket_async_begin_transport_close(session)
		return true
	}

	if websocket_async_parse(session) {
		return true
	}
	if session.phase == .Failed {
		return true
	}
	if websocket_async_send_next(session) {
		return true
	}
	// Closing still reads so a peer close or control frame is observed. Application
	// data stays buffered until a caller read is submitted.
	closing_read := session.phase == .Closing && !session.peer_closed && !session.close_started
	if (session.read_op != nil || closing_read) &&
	   session.read_state == .Idle &&
	   session.inbox_at >= session.inbox_len &&
	   !session.message.message_ready {
		if closing_read && session.close_deadline != (time.Time{}) {
			if session.read_op == nil ||
			   time.diff(session.read_deadline, session.close_deadline) < 0 {
				session.read_deadline = session.close_deadline
			}
		}
		if !websocket_async_arm_read(session) {
			return session.phase == .Failed
		}
		return true
	}

	return false
}

websocket_async_parse :: proc(session: ^WebSocket_Async) -> bool {
	progressed := false

	for {
		if session.message.message_ready && session.read_op != nil {
			websocket_async_deliver(session)
			return true
		}

		if session.message.message_ready {
			return progressed
		}

		if session.payload_need > 0 {
			if !websocket_async_fill_payload(session) {
				return progressed
			}
			progressed = true
			continue
		}

		if session.header_have < 2 {
			if !websocket_async_pull_header(session, 2) {
				return progressed
			}
			progressed = true
		}

		need := websocket_async_header_need(session)

		if session.header_have < need {
			if !websocket_async_pull_header(session, need) {
				return progressed
			}
			progressed = true
		}

		header, _, frame_error := websocket.frame_header_decode(
			session.header_raw[:session.header_have],
			false,
		)

		if frame_error != .None {
			websocket_async_fail(session, {kind = .Invalid_Frame, frame = frame_error})
			return true
		}

		session.header = header
		session.header_have = 0

		if header.opcode == .Continuation || header.opcode == .Text || header.opcode == .Binary {
			session.controls = 0
			_, prepare_error := websocket.message_prepare(
				&session.message,
				header,
				session.config.max_message_size,
				session.allocator,
			)

			if prepare_error.kind != .None {
				websocket_async_fail(session, websocket_async_message_error(prepare_error))
				return true
			}

			session.fragments += 1

			if session.fragments > session.config.max_fragments {
				websocket_async_fail(session, {kind = .Message_Oversized})
				return true
			}

			session.payload_need = int(header.payload_length)
			session.payload_have = 0

			if session.payload_need == 0 {
				if finish_error := websocket.message_finish(&session.message, header.fin);
				   finish_error.kind != .None {
					websocket_async_fail(session, websocket_async_message_error(finish_error))
					return true
				}
			}

			progressed = true
			continue
		}

		session.controls += 1

		if session.controls > WebSocket_Async_MAX_CONTROL_WITHOUT_MESSAGE {
			websocket_async_fail(session, {kind = .Protocol_Failed})
			return true
		}

		session.payload_need = int(header.payload_length)
		session.payload_have = 0
		progressed = true

		if session.payload_need == 0 {
			if !websocket_async_finish_control(session, session.control_in[:0]) {
				return true
			}
		}
	}
}

websocket_async_fill_payload :: proc(session: ^WebSocket_Async) -> bool {
	if session.inbox_at >= session.inbox_len {
		return false
	}

	if websocket_async_control_opcode(session.header.opcode) {
		dst := session.control_in[session.payload_have:session.payload_need]
		n := copy(dst, session.inbox[session.inbox_at:session.inbox_len])
		session.inbox_at += n
		session.payload_have += n
		if session.payload_have < session.payload_need {
			return false
		}
		session.payload_need = 0
		return websocket_async_finish_control(session, session.control_in[:session.payload_have])
	}

	base := len(session.message.message) - int(session.header.payload_length)

	if base < 0 {
		websocket_async_fail(session, {kind = .Protocol_Failed})
		return false
	}

	dst := session.message.message[base + session.payload_have:]
	n := copy(dst, session.inbox[session.inbox_at:session.inbox_len])
	session.inbox_at += n
	session.payload_have += n
	if session.payload_have < int(session.header.payload_length) {
		return false
	}
	session.payload_need = 0

	if finish_error := websocket.message_finish(&session.message, session.header.fin);
	   finish_error.kind != .None {
		websocket_async_fail(session, websocket_async_message_error(finish_error))
		return false
	}

	return true
}

websocket_async_finish_control :: proc(session: ^WebSocket_Async, body: []u8) -> bool {
	session.payload_need = 0
	#partial switch session.header.opcode {
	case .Ping:
		if session.control_pending {
			websocket_async_fail(session, {kind = .Protocol_Failed})
			return false
		}
		copy(session.control_out[:], body)
		session.control_len = len(body)
		session.control_pending = true
		session.control_is_close = false
	case .Pong:
	case .Close:
		if frame_error := websocket.close_payload_validate(body); frame_error != .None {
			code := websocket_close_validation_code(frame_error)
			websocket_async_fail(
				session,
				{kind = .Invalid_Frame, frame = frame_error, close_code = code},
			)
			return false
		}
		copy(session.peer_close_body[:], body)
		session.peer_close_len = len(body)
		session.peer_closed = true
		code := websocket_close_code(body)
		kind := WebSocket_Async_Error_Kind.EOF
		if !websocket_close_code_normal(code) {
			kind = .Peer_Close
		}
		if !session.local_close && !session.close_sent {
			copy(session.close_body[:], body)
			session.close_len = len(body)
			session.echo_close = true
		}
		if session.read_op != nil {
			op := session.read_op
			session.read_op = nil
			websocket_async_complete(op, {kind = kind, close_code = code})
		}
	case:
		websocket_async_fail(session, {kind = .Invalid_Frame})
		return false
	}

	return true
}

websocket_async_deliver :: proc(session: ^WebSocket_Async) {
	op := session.read_op
	session.read_op = nil
	opcode, n, error := websocket.message_deliver(&session.message, op.buffer)
	session.fragments = 0

	if error.kind != .None {
		result := websocket_async_message_error(error)
		result.n = n

		if error.kind == .Destination_Undersized {
			session.fragments = 1
		}

		websocket_async_complete(op, result)
		return
	}

	op.opcode = opcode
	websocket_async_complete(op, {n = n})
}

websocket_async_control_opcode :: proc(opcode: websocket.Opcode) -> bool {
	#partial switch opcode {
	case .Close, .Ping, .Pong:
		return true
	}

	return false
}

websocket_async_pull_header :: proc(session: ^WebSocket_Async, need: int) -> bool {
	for session.header_have < need && session.inbox_at < session.inbox_len {
		session.header_raw[session.header_have] = session.inbox[session.inbox_at]
		session.header_have += 1
		session.inbox_at += 1
	}

	return session.header_have >= need
}

websocket_async_header_need :: proc(session: ^WebSocket_Async) -> int {
	if session.header_have < 2 {
		return 2
	}

	return websocket_frame_header_size(session.header_raw[1])
}

websocket_async_send_next :: proc(session: ^WebSocket_Async) -> bool {
	if session.write_state != .Idle || session.phase == .Failed {
		return false
	}

	if session.control_pending {
		if session.close_sent && !session.control_is_close {
			session.control_pending = false
			session.control_len = 0
		} else {
			opcode := websocket.Opcode.Pong
			if session.control_is_close {
				opcode = .Close
			}
			return websocket_async_arm_frame(
				session,
				opcode,
				session.control_out[:session.control_len],
				true,
				.Control,
			)
		}
	}

	if (session.local_close || session.echo_close) && !session.close_sent {
		return websocket_async_arm_frame(
			session,
			.Close,
			session.close_body[:session.close_len],
			true,
			.Control,
		)
	}

	if session.phase != .Open || session.queue_count == 0 {
		return false
	}
	op := session.queue[session.queue_head]
	remain := op.buffer[session.write_offset:]
	chunk := len(remain)
	if chunk > session.config.max_frame_payload {
		chunk = session.config.max_frame_payload
	}
	fin := session.write_offset + chunk == len(op.buffer)
	opcode := op.opcode if session.write_offset == 0 else websocket.Opcode.Continuation
	session.fragment_len = chunk

	return websocket_async_arm_frame(session, opcode, remain[:chunk], fin, .Frame)
}

websocket_async_arm_frame :: proc(
	session: ^WebSocket_Async,
	opcode: websocket.Opcode,
	payload: []u8,
	fin: bool,
	writer: WebSocket_Async_Writer,
) -> bool {
	when !crypto.HAS_RAND_BYTES {
		websocket_async_fail(session, {kind = .Entropy_Unavailable})
		return true
	}
	mask: [4]u8
	crypto.rand_bytes(mask[:])
	size, frame_error := websocket.frame_encode(session.wire[:], fin, opcode, payload, mask, true)
	if frame_error != .None {
		websocket_async_fail(session, {kind = .Invalid_Frame, frame = frame_error})
		return true
	}
	session.write_deadline = time.time_add(time.now(), session.config.io_timeout)
	if writer == .Control && opcode == .Close {
		session.control_is_close = true
		session.control_pending = true
		session.control_len = len(payload)
	}
	return websocket_async_arm_write(session, session.wire[:size], writer)
}

websocket_async_finish_write :: proc(session: ^WebSocket_Async) {
	writer := session.writer
	error := session.write_error
	count := session.wire_len
	session.write_state = .Idle
	session.writer = .None
	session.write_error = {}

	if error != nil {
		if error == net.Connection_Error.Cancelled {
			websocket_async_fail(session, {kind = .Cancelled, transport = error, n = count})
			return
		}

		websocket_async_fail(session, websocket_async_net_error(error))
		return
	}

	#partial switch writer {
	case .Request:
		session.request_sent = true
	case .Frame:
		session.write_offset += session.fragment_len
		session.fragment_len = 0
		op := session.queue[session.queue_head]
		if session.write_offset == len(op.buffer) {
			session.write_offset = 0
			websocket_async_dequeue(session)
			op.n = len(op.buffer)
			websocket_async_complete(op, {n = len(op.buffer)})
		}
	case .Control:
		sent_close := session.control_is_close
		session.control_pending = false
		session.control_is_close = false
		session.control_len = 0
		if sent_close {
			session.close_sent = true
			if session.phase == .Open {
				session.phase = .Closing
			}
			session.close_deadline = time.time_add(time.now(), session.config.close_timeout)
			websocket_async_discard_queue(session)
			if session.peer_closed {
				websocket_async_begin_transport_close(session)
			}
		}
	}
}

websocket_async_dequeue :: proc(session: ^WebSocket_Async) {
	if session.queue_count == 0 {
		return
	}
	op := session.queue[session.queue_head]
	session.queue[session.queue_head] = nil
	session.queue_head = (session.queue_head + 1) % session.config.max_queued_messages
	session.queue_count -= 1
	session.queue_bytes -= len(op.buffer)
}

websocket_async_discard_queue :: proc(session: ^WebSocket_Async) {
	for session.queue_count > 0 {
		op := session.queue[session.queue_head]
		websocket_async_dequeue(session)
		websocket_async_complete(op, {kind = .Closed})
	}

	session.write_offset = 0
	session.fragment_len = 0
}

// Socket deadlines are monotonic ticks. A zero wall time means no deadline.
// A time already reached must stay a deadline: the zero tick would disable it.
websocket_async_deadline_tick :: proc(deadline: time.Time) -> time.Tick {
	if deadline == {} {
		return {}
	}

	remain := time.diff(time.now(), deadline)
	if remain <= 0 {
		return time.tick_add(time.tick_now(), -time.Nanosecond)
	}

	tick := time.tick_add(time.tick_now(), remain)
	if tick == {} {
		return time.tick_add(time.tick_now(), time.Nanosecond)
	}

	return tick
}

websocket_async_arm_read :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state != .Idle || session.phase == .Failed || session.phase == .Terminal {
		return false
	}
	error := net.async_read(
		websocket_async_stream(session),
		&session.net_read,
		session.inbox[:],
		websocket_async_deadline_tick(session.read_deadline),
	)

	if error != nil {
		websocket_async_fail(session, websocket_async_net_error(error))
		return false
	}

	session.read_state = .Pending
	session.inbox_at = 0
	session.inbox_len = 0

	return true
}

websocket_async_arm_write :: proc(
	session: ^WebSocket_Async,
	src: []u8,
	writer: WebSocket_Async_Writer,
) -> bool {
	if session.write_state != .Idle {
		return false
	}
	error := net.async_write(
		websocket_async_stream(session),
		&session.net_write,
		src,
		websocket_async_deadline_tick(session.write_deadline),
	)

	if error != nil {
		websocket_async_fail(session, websocket_async_net_error(error))
		return false
	}

	session.write_state = .Pending
	session.writer = writer

	return true
}

websocket_async_stream :: proc(session: ^WebSocket_Async) -> net.Async_Connection {
	if session.tls_ready {
		return tls.async_connection(&session.secure_conn)
	}

	return adapter.stream(&session.transport)
}

websocket_async_finish_early :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	websocket_async_fail(session, error)

	if !session.ops_finished {
		websocket_async_fail_ops(session, session.failure)
		session.ops_finished = true
	}

	websocket_async_release(session)
	session.phase = .Terminal
}

websocket_async_fail :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	if session.phase == .Failed || session.phase == .Terminal {
		return
	}
	session.failure = error
	session.phase = .Failed
}

websocket_async_fail_ops :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	upgrade := session.upgrade_op
	read := session.read_op
	close := session.close_op
	session.upgrade_op = nil
	session.read_op = nil
	session.close_op = nil
	pending: [WebSocket_Async_QUEUE_CAP]^WebSocket_Async_Op
	count := session.queue_count

	for i in 0 ..< count {
		pending[i] = session.queue[(session.queue_head + i) % session.config.max_queued_messages]
	}

	session.queue_count = 0
	session.queue_bytes = 0
	session.queue_head = 0
	websocket_async_complete(upgrade, error)
	websocket_async_complete(read, error)

	for i in 0 ..< count {
		websocket_async_complete(pending[i], error)
	}

	websocket_async_complete(close, error)
}

websocket_async_begin_transport_close :: proc(session: ^WebSocket_Async) {
	if session.close_started {
		return
	}

	if !session.executor_ready {
		session.close_state = .Done
		return
	}

	session.close_started = true
	error := net.async_close(websocket_async_stream(session), &session.net_close)

	if error != nil {
		session.close_state = .Done
	}
}

websocket_async_release :: proc(session: ^WebSocket_Async) {
	if session.released {
		return
	}
	session.released = true
	websocket.message_release(&session.message)
}

websocket_async_runtime_error :: proc(error: async.Error) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.IO_Failed
	if error.kind == .Timeout {
		kind = .Timeout
	}
	if error.kind == .Cancelled || error.kind == .Stopping {
		kind = .Cancelled
	}
	if error.kind == .Invalid_Config || error.kind == .Wrong_Task {
		kind = .Invalid_Config
	}
	transport: net.Network_Error
	if kind == .Timeout {
		transport = net.TCP_Recv_Error.Timeout
	}
	if kind == .Cancelled {
		transport = net.Connection_Error.Cancelled
	}

	return {kind = kind, transport = transport}
}

websocket_async_net_error :: proc(error: net.Network_Error) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.IO_Failed
	if recv, ok := error.(net.TCP_Recv_Error); ok && recv == .Timeout {
		kind = .Timeout
	}
	if sent, ok := error.(net.TCP_Send_Error); ok && sent == .Timeout {
		kind = .Timeout
	}
	if dial, ok := error.(net.Dial_Error); ok && dial == .Timeout {
		kind = .Timeout
	}
	if error == net.Connection_Error.Cancelled {
		kind = .Cancelled
	}
	if error == net.Connection_Error.Peer_Closed {
		kind = .EOF
	}
	if error == net.Connection_Error.Protocol_Failed {
		kind = .Protocol_Failed
	}

	return {kind = kind, transport = error}
}

websocket_async_upgrade_io :: proc(error: net.Network_Error) -> WebSocket_Async_Error {
	mapped := websocket_async_net_error(error)
	if mapped.kind == .IO_Failed || mapped.kind == .EOF {
		mapped.kind = .Upgrade_Failed
	}

	return mapped
}
