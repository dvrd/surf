package surf

import websocket "../websocket"
import runtime_async "../async"
import adapter "../async/connection"

import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/tls"
import x509 "core:crypto/x509"
import "core:mem"
import "core:net"
import "core:time"

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
}

WebSocket_Async_Error :: struct {
	kind:       WebSocket_Async_Error_Kind,
	upgrade:    websocket.Upgrade_Error,
	frame:      websocket.Frame_Error,
	message:    websocket.Message_Error_Kind,
	transport:  net.Connection_Error,
	tls_kind:   tls.Handshake_Error_Kind,
	x509_error: x509.Error,
	close_code: u16,
	n:          int,
}

// Stable until callback. Do not copy or reuse while pending.
WebSocket_Async_Op :: struct {
	callback:     proc(op: ^WebSocket_Async_Op),
	user_data:    rawptr,
	kind:         WebSocket_Async_Kind,
	opcode:       websocket.Opcode,
	buffer:       []u8,
	close_code:   u16,
	reason:       string,
	pending:      bool,
	cancel_flag:  int,
	n:            int,
	error:        WebSocket_Async_Error,
}

// Borrowed host, target, origin, subprotocols, server_name and roots must
// outlive the session. Empty roots select plain ws. A zero limit or timeout
// selects the documented default. Endpoint is numeric; this session does not
// resolve DNS.
WebSocket_Async_Config :: struct {
	endpoint:             net.Endpoint,
	host:                 string,
	target:               string,
	origin:               string,
	server_name:          string,
	subprotocols:         []string,
	roots:                []^x509.Certificate,
	max_message_size:     int,
	max_frame_payload:    int,
	max_queued_messages:  int,
	max_queued_bytes:     int,
	max_fragments:        int,
	handshake_timeout:    time.Duration,
	io_timeout:           time.Duration,
	close_timeout:        time.Duration,
}

// Caller-owned, stable address, not copied. user is untouched by bind and is
// available to the on_done procedure. Free the session only after on_done.
WebSocket_Async :: struct {
	user:    rawptr,
	runtime: ^runtime_async.Runtime,
	task:    runtime_async.Task,
	config:  WebSocket_Async_Config,
	loop:    adapter.Executor,
	transport: adapter.Transport,
	secure_conn: tls.Async_Conn,
	hs:      tls.Async_Handshake_Operation,
	net_read, net_write, net_close: net.Async_Operation,
	connecting: runtime_async.Connecting_Socket,
	connect_deadline: runtime_async.Deadline,
	allocator: mem.Allocator,
	failure: WebSocket_Async_Error,
	handshake_error: tls.Handshake_Error,
	selected_protocol: [websocket.MAX_SUBPROTOCOL_SIZE]u8,
	selected_protocol_size: int,
	upgrade_key: [16]u8,
	request_buf: [websocket.MAX_UPGRADE_HEADER_SIZE]u8,
	upgrade_buf: [websocket.MAX_UPGRADE_HEADER_SIZE]u8,
	inbox: [2048]u8,
	wire: [14 + WebSocket_Async_MAX_FRAME_PAYLOAD]u8,
	header_raw: [14]u8,
	control_out: [125]u8,
	control_in: [125]u8,
	close_body: [125]u8,
	peer_close_body: [125]u8,
	message: websocket.Message_State,
	upgrade_op, read_op, close_op: ^WebSocket_Async_Op,
	queue: [WebSocket_Async_QUEUE_CAP]^WebSocket_Async_Op,
	phase: WebSocket_Async_Phase,
	read_state, write_state, close_state: WebSocket_Async_IO,
	writer: WebSocket_Async_Writer,
	header: websocket.Frame_Header,
	read_error, write_error: net.Connection_Error,
	read_deadline, write_deadline, close_deadline: time.Time,
	request_len, upgrade_len, inbox_at, inbox_len, wire_len: int,
	header_have, payload_have, payload_need: int,
	write_offset, fragment_len, queue_head, queue_count, queue_bytes: int,
	control_len, close_len, peer_close_len, fragments, controls: int,
	upgrade_read_armed: int,
	handshake_transport: net.Connection_Error,
	bound, secure, tls_ready, executor_ready, connected, connect_started: bool,
	handshake_ready, read_cancel_sent: bool,
	running, request_sent, upgrade_open, released, ops_finished: bool,
	control_pending, control_is_close, close_sent, peer_closed, echo_close: bool,
	local_close, fail_quiet, task_cancelled, clean, close_started: bool,
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

@(private)
WebSocket_Async_IO :: enum {
	Idle,
	Pending,
	Done,
}

@(private)
WebSocket_Async_Writer :: enum {
	None,
	Request,
	Frame,
	Control,
}

@(private)
websocket_async_limits :: proc(config: WebSocket_Async_Config) -> (WebSocket_Async_Config, WebSocket_Async_Error) {
	settings := config
	if settings.target == "" do settings.target = "/"
	if settings.max_message_size == 0 do settings.max_message_size = WebSocket_Async_DEFAULT_MESSAGE_SIZE
	if settings.max_frame_payload == 0 do settings.max_frame_payload = WebSocket_Async_DEFAULT_FRAME_PAYLOAD
	if settings.max_queued_messages == 0 do settings.max_queued_messages = WebSocket_Async_DEFAULT_QUEUED_MESSAGES
	if settings.max_queued_bytes == 0 do settings.max_queued_bytes = WebSocket_Async_DEFAULT_QUEUED_BYTES
	if settings.max_fragments == 0 do settings.max_fragments = WebSocket_Async_DEFAULT_FRAGMENTS
	if settings.handshake_timeout == 0 do settings.handshake_timeout = 10 * time.Second
	if settings.io_timeout == 0 do settings.io_timeout = 10 * time.Second
	if settings.close_timeout == 0 do settings.close_timeout = time.Second
	if settings.host == "" ||
	   settings.endpoint.port <= 0 || settings.endpoint.port > 65535 ||
	   settings.endpoint.address == nil ||
	   settings.max_message_size < 0 || settings.max_message_size > WebSocket_Async_MESSAGE_LIMIT ||
	   settings.max_frame_payload < 1 || settings.max_frame_payload > WebSocket_Async_MAX_FRAME_PAYLOAD ||
	   settings.max_queued_messages < 1 || settings.max_queued_messages > WebSocket_Async_QUEUE_CAP ||
	   settings.max_queued_bytes < 1 || settings.max_queued_bytes > WebSocket_Async_MESSAGE_LIMIT ||
	   settings.max_fragments < 1 || settings.max_fragments > 65536 ||
	   settings.handshake_timeout < 0 || settings.io_timeout < 0 || settings.close_timeout < 0 ||
	   len(settings.roots) > 0 && settings.server_name == "" && websocket_async_name(settings.host) == "" {
		return {}, {kind = .Invalid_Config}
	}
	scratch: [websocket.MAX_UPGRADE_HEADER_SIZE]u8
	_, encode_error := websocket.upgrade_request_encode(scratch[:], {
		host = settings.host,
		target = settings.target,
		origin = settings.origin,
		subprotocols = settings.subprotocols,
	}, {})
	if encode_error != .None {
		return {}, {kind = .Invalid_Config, upgrade = encode_error}
	}
	return settings, {}
}

@(private)
websocket_async_name :: proc(host: string) -> string {
	if len(host) == 0 || host[0] == '[' do return ""
	colon := 0
	for colon < len(host) && host[colon] != ':' do colon += 1
	if colon == 0 do return ""
	return host[:colon]
}

// Installs resume and on_cancel. The caller registers or spawns the task.
// on_done may be nil. A rejected bind leaves the session unchanged.
websocket_async_bind :: proc(
	session: ^WebSocket_Async,
	runtime: ^runtime_async.Runtime,
	config: WebSocket_Async_Config,
	on_done: proc(rawptr) = nil,
) -> WebSocket_Async_Error {
	if session == nil || runtime == nil || session.bound {
		return {kind = .Invalid_Config}
	}
	settings, limit_error := websocket_async_limits(config)
	if limit_error.kind != .None do return limit_error
	user := session.user
	session^ = {user = user}
	session.runtime = runtime
	session.config = settings
	session.secure = len(settings.roots) > 0
	session.allocator = context.allocator
	if session.allocator.procedure == nil {
		session.allocator = rt.heap_allocator()
	}
	session.task = {
		data = session,
		resume = websocket_async_resume,
		on_cancel = websocket_async_on_cancel,
		on_done = on_done,
	}
	session.phase = .Bound
	session.bound = true
	return {}
}

@(private)
websocket_async_owner_ok :: proc(session: ^WebSocket_Async) -> bool {
	if session == nil || !session.bound do return false
	if !session.running do return true
	return runtime_async.is_current_task(&session.task)
}

websocket_async_upgrade :: proc(
	session: ^WebSocket_Async, op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}
	if session.upgrade_op != nil || session.upgrade_open ||
	   session.phase == .Failed || session.phase == .Terminal || session.phase == .Open ||
	   session.phase == .Closing {
		return {kind = .Invalid_State}
	}
	op^ = {
		callback = op.callback,
		user_data = op.user_data,
		kind = .Upgrade,
		pending = true,
	}
	session.upgrade_op = op
	return {}
}

websocket_async_read :: proc(
	session: ^WebSocket_Async, op: ^WebSocket_Async_Op, dst: []u8,
) -> WebSocket_Async_Error {
	if !websocket_async_owner_ok(session) || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}
	if session.phase != .Open || session.read_op != nil {
		return {kind = .Busy if session.read_op != nil else .Invalid_State}
	}
	op^ = {
		callback = op.callback,
		user_data = op.user_data,
		kind = .Read,
		buffer = dst,
		pending = true,
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
	if error := websocket.message_validate(opcode, src, session.config.max_message_size); error.kind != .None {
		return websocket_async_message_error(error)
	}
	if len(src) > session.config.max_queued_bytes ||
	   session.queue_count >= session.config.max_queued_messages ||
	   session.queue_bytes > session.config.max_queued_bytes - len(src) {
		return {kind = .Queue_Full}
	}
	op^ = {
		callback = op.callback,
		user_data = op.user_data,
		kind = .Write,
		opcode = opcode,
		buffer = src,
		pending = true,
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
	if session.close_op != nil || session.local_close ||
	   session.phase == .Failed || session.phase == .Terminal || session.phase == .Closing {
		return {kind = .Invalid_State}
	}
	if session.phase != .Open {
		return {kind = .Invalid_State}
	}
	if len(reason) > 123 {
		return {kind = .Invalid_Frame, frame = .Control_Payload_Oversized}
	}
	body: [125]u8
	body[0], body[1] = u8(code >> 8), u8(code)
	copy(body[2:], transmute([]u8)reason)
	if frame_error := websocket.close_payload_validate(body[:2 + len(reason)]); frame_error != .None {
		return {kind = .Invalid_Frame, frame = frame_error}
	}
	copy(session.close_body[:], body[:2 + len(reason)])
	session.close_len = 2 + len(reason)
	session.local_close = true
	op^ = {
		callback = op.callback,
		user_data = op.user_data,
		kind = .Close,
		close_code = code,
		pending = true,
	}
	session.close_op = op
	return {}
}

// Safe from another thread. The operation stays borrowed until its callback.
// Close cannot be cancelled. A repeated request while pending is harmless.
websocket_async_cancel :: proc(
	session: ^WebSocket_Async, op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || !op.pending {
		return {kind = .Invalid_State}
	}
	if op.kind == .Close {
		return {kind = .Invalid_State}
	}
	intrinsics.atomic_store(&op.cancel_flag, 1)
	if session.runtime != nil {
		runtime_async.wake(session.runtime, &session.task)
	}
	return {}
}

websocket_async_subprotocol :: proc(session: ^WebSocket_Async) -> string {
	if session == nil || !session.upgrade_open do return ""
	return cast(string)session.selected_protocol[:session.selected_protocol_size]
}

@(private)
websocket_async_cancelled :: proc(op: ^WebSocket_Async_Op) -> bool {
	return op != nil && op.pending && intrinsics.atomic_load(&op.cancel_flag) != 0
}

@(private)
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

@(private)
websocket_async_complete :: proc(op: ^WebSocket_Async_Op, error: WebSocket_Async_Error) {
	if op == nil || !op.pending do return
	op.pending = false
	op.error = error
	op.n = error.n
	callback := op.callback
	if callback != nil do callback(op)
}
