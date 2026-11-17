package surf

import websocket "../websocket"
import tls_api "core:crypto/tls"
import "core:crypto"
import "core:fmt"
import "core:strings"
import "core:time"
import "core:mem"
import tcp_api "core:net"

WebSocket_DEFAULT_MAX_MESSAGE_SIZE :: 1 << 20
WebSocket_MAX_MESSAGE_SIZE_LIMIT :: 64 << 20

// Borrowed strings/slices must outlive the connection. Compression and other
// extensions are deliberately not offered, so received RSV bits must be zero.
WebSocket_Config :: struct {
	host:              string,
	target:            string,
	origin:            string,
	subprotocols:      []string,
	max_message_size:  int,
	handshake_timeout: time.Duration,
}

WebSocket_Client_Error :: enum {
	None,
	Nil_Connection,
	Already_Initialized,
	Invalid_Stream,
	Invalid_Upgrade_Options,
	Invalid_Message_Limit,
	Invalid_Timeout,
}

websocket_client :: proc(
	conn: ^WebSocket_Conn,
	stream: WebSocket_Stream,
	config: WebSocket_Config,
) -> WebSocket_Client_Error {
	if conn == nil do return .Nil_Connection

	if conn.phase != .Uninitialized {
		return .Already_Initialized
	}

	if !websocket_stream_valid(stream) do return .Invalid_Stream

	if config.max_message_size < 0 ||
	   config.max_message_size > WebSocket_MAX_MESSAGE_SIZE_LIMIT {
		return .Invalid_Message_Limit
	}

	if config.handshake_timeout < 0 {
		return .Invalid_Timeout
	}

	settings := config

	if settings.target == "" do settings.target = "/"

	if settings.max_message_size == 0 {
		settings.max_message_size = WebSocket_DEFAULT_MAX_MESSAGE_SIZE
	}

	storage: [websocket.MAX_UPGRADE_HEADER_SIZE]u8

	_, err := websocket.upgrade_request_encode(
		storage[:],
		{
			host = settings.host,
			target = settings.target,
			origin = settings.origin,
			subprotocols = settings.subprotocols,
		},
		{},
	)
	if err != .None do return .Invalid_Upgrade_Options

	conn.stream = stream
	conn.config = settings
	conn.phase = .Upgrade_Pending
	conn.allocator = context.allocator

	return .None
}

// Sends HTTP Upgrade, validates the response, and retains any WebSocket bytes
// coalesced with its final header. Failure consumes the connection and closes
// the stream; successful repeated calls are no-ops.
websocket_upgrade :: proc(conn: ^WebSocket_Conn) -> WebSocket_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Open do return {}

	if conn.phase == .Failed do return conn.last_error

	if conn.phase != .Upgrade_Pending {
		return {kind = .Invalid_State}
	}

	when !crypto.HAS_RAND_BYTES {
		return websocket_upgrade_fail(conn, {kind = .Entropy_Unavailable})
	}

	deadlines_set, deadline_error := websocket_upgrade_deadline_start(conn)
	if deadline_error.kind != .None do return deadline_error

	defer {
		if deadlines_set && !conn.transport_closed {
			conn.stream.set_read_deadline(conn.stream.data, {})
			conn.stream.set_write_deadline(conn.stream.data, {})
		}

	}
	key: [16]u8
	crypto.rand_bytes(key[:])
	if request_error := websocket_upgrade_request_send(conn, key);
	   request_error.kind != .None do return request_error
	if response_error := websocket_upgrade_response_receive(conn, key);
	   response_error.kind != .None do return response_error
	if deadlines_set {
		if clear_error := websocket_upgrade_deadline_clear(conn); clear_error.kind != .None {
			return clear_error
		}
		deadlines_set = false
	}
	conn.phase = .Open
	return {}
}

websocket_upgrade_deadline_start :: proc(conn: ^WebSocket_Conn) -> (bool, WebSocket_Error) {
	has_read_n_write_deadline :=
		conn.stream.set_read_deadline != nil &&
		conn.stream.set_write_deadline != nil

	deadlines_set := false
	if has_read_n_write_deadline {

		timeout := conn.config.handshake_timeout
		if timeout == 0 do timeout = 10 * time.Second

		deadline := time.time_add(time.now(), timeout)
		if err := websocket_stream_set_deadlines(conn.stream, deadline); err.kind != .None {
			return false, websocket_upgrade_fail(conn, {kind = .Deadline_Failed, stream = err})
		}

		deadlines_set = true
	} else if conn.config.handshake_timeout > 0 {
		return false, websocket_upgrade_fail(
			conn,
			{
				kind = .Deadline_Failed,
				stream = {kind = .Deadline_Unsupported},
			},
		)
	}

	return deadlines_set, {}
}

websocket_upgrade_request_send :: proc(conn: ^WebSocket_Conn, key: [16]u8) -> WebSocket_Error {
	request: [websocket.MAX_UPGRADE_HEADER_SIZE]u8
	size, encode_err := websocket.upgrade_request_encode(
		request[:],
		{
			host = conn.config.host,
			target = conn.config.target,
			origin = conn.config.origin,
			subprotocols = conn.config.subprotocols,
		},
		key,
	)
	if encode_err != .None {
		return websocket_upgrade_fail(
			conn,
			{kind = .Upgrade_Failed, upgrade = encode_err},
		)
	}

	_, send_err := websocket_stream_write_all(conn.stream, request[:size])
	if send_err.kind != .None {
		return websocket_upgrade_fail(
			conn,
			{kind = .Frame_Write_Failed, stream = send_err},
		)
	}

	return {}
}

// Sets the read deadline, then the write deadline; stops at the first failure.
websocket_stream_set_deadlines :: proc(stream: WebSocket_Stream, deadline: time.Time) -> WebSocket_Stream_Error {
	err := stream.set_read_deadline(stream.data, deadline)
	if err.kind != .None {
		return err
	}

	return stream.set_write_deadline(stream.data, deadline)
}

websocket_upgrade_deadline_clear :: proc(conn: ^WebSocket_Conn) -> WebSocket_Error {
	if err := websocket_stream_set_deadlines(conn.stream, {}); err.kind != .None {
		return websocket_upgrade_fail(conn, {kind = .Deadline_Failed, stream = err})
	}

	return {}
}

websocket_upgrade_response_receive :: proc(conn: ^WebSocket_Conn, key: [16]u8) -> WebSocket_Error {
	used := 0
	for {
		response, consumed, response_err :=
			websocket.upgrade_response_validate(
				conn.prefetched[:used],
				key,
				conn.config.subprotocols,
			)
		if response_err == .None {
			copy(
				conn.selected_protocol[:],
				transmute([]u8)response.subprotocol,
			)
			conn.selected_protocol_size = len(response.subprotocol)
			copy(conn.prefetched[:], conn.prefetched[consumed:used])
			conn.prefetched_at, conn.prefetched_size =
				0, used - consumed


			return {}
		}

		if response_err != .Header_Incomplete {
			return websocket_upgrade_fail(
				conn,
				{kind = .Upgrade_Failed, upgrade = response_err},
			)
		}

		if used == len(conn.prefetched) {
			return websocket_upgrade_fail(
				conn,
				{
					kind = .Upgrade_Failed,
					upgrade = .Header_Oversized,
				},
			)
		}

		if progress_error := websocket_upgrade_response_progress(conn, key, &used);
		   progress_error.kind != .None do return progress_error

	}
}

websocket_upgrade_response_progress :: proc(
	conn: ^WebSocket_Conn, key: [16]u8, used: ^int,
) -> WebSocket_Error {
	count, read_err := conn.stream.read(
		conn.stream.data,
		conn.prefetched[used^:],
	)
	if count < 0 || count > len(conn.prefetched) - used^ {
		return websocket_upgrade_fail(
			conn,
			{
				kind = .Frame_Read_Failed,
				stream = {kind = .Invalid_Count},
			},
		)
	}

	used^ += count

	// Process bytes that accompany EOF before deciding the upgrade failed.
	if read_err.kind != .None {
		if read_err.kind != .EOF {
			return websocket_upgrade_fail(
				conn,
				{kind = .Frame_Read_Failed, stream = read_err},
			)
		}

		_, _, final_err := websocket.upgrade_response_validate(
			conn.prefetched[:used^],
			key,
			conn.config.subprotocols,
		)
		if final_err != .None {
			return websocket_upgrade_fail(
				conn,
				{kind = .Frame_Read_Failed, stream = read_err},
			)
		}

	} else if count == 0 {
		return websocket_upgrade_fail(
			conn,
			{
				kind = .Frame_Read_Failed,
				stream = {kind = .No_Progress},
			},
		)
	}

	return {}
}

websocket_upgrade_fail :: proc(conn: ^WebSocket_Conn, err: WebSocket_Error) -> WebSocket_Error {
	conn.phase = .Failed
	conn.last_error = err
	if !conn.transport_closed {
		conn.transport_closed = true
		if conn.stream.abort != nil {
			conn.stream.abort(conn.stream.data)
		} else {
			conn.stream.close(conn.stream.data)
		}

	}

	return err
}

WebSocket_Dial_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	TLS_Failed,
	Upgrade_Failed,
}

WebSocket_Dial_Error :: struct {
	kind:      WebSocket_Dial_Error_Kind,
	client:    WebSocket_Client_Error,
	tls:       tls_api.Dial_Error,
	websocket: WebSocket_Error,
}

// Opens a secure WebSocket (wss). config.host defaults to host[:port] and
// config.target to '/'. conn and all borrowed settings must remain alive and
// unchanged until close. No redirects, proxying, or extensions are negotiated.
websocket_dial :: proc(
	conn: ^WebSocket_Conn,
	host: string,
	port: int,
	config: WebSocket_Config,
	tls_config: tls_api.Config,
) -> WebSocket_Dial_Error {
	if conn == nil || conn.phase != .Uninitialized {
		return {kind = .Invalid_State}
	}

	settings := config
	host_storage: [512]u8
	if settings.host == "" {
		settings.host = websocket_dial_host(host_storage[:], host, port)
	}

	if len(settings.host) > len(conn.dial_host) {
		return {
			kind = .Invalid_Config,
			client = .Invalid_Upgrade_Options,
		}
	}

	// client only validates the callback shape, so using the stable embedded
	// TLS address before dialing performs no network I/O. Install it below.
	stream := websocket_stream_from_tls_address(&conn.tls_client)
	if err := websocket_client(conn, stream, settings); err != .None {
		return {kind = .Invalid_Config, client = err}
	}

	copy(conn.dial_host[:], transmute([]u8)settings.host)
	conn.config.host = cast(string)conn.dial_host[:len(
		settings.host,
	)]

	err := tls_api.dial(&conn.tls_client, host, port, tls_config)
	if err.kind != .None {
		conn.phase = .Failed
		conn.transport_closed = true // tls.dial closes sockets on handshake failure.
		conn.last_error = {
			kind = .Upgrade_Failed,
			stream = {kind = .TLS_Failed, tls_dial = err},
		}
		return {kind = .TLS_Failed, tls = err}
	}

	if err := websocket_upgrade(conn); err.kind != .None {
		return {kind = .Upgrade_Failed, websocket = err}
	}

	return {}
}

websocket_dial_host :: proc(host_storage: []u8, host: string, port: int) -> string {
	hostname := host
	if strings.contains(host, ":") {
		if port == 443 {
			hostname = fmt.bprintf(host_storage, "[%s]", host)
		} else {
			hostname = fmt.bprintf(
				host_storage,
				"[%s]:%d",
				host,
				port,
			)
		}

	} else if port != 443 {
		hostname = fmt.bprintf(
			host_storage,
			"%s:%d",
			host,
			port,
		)
	}

	return hostname
}

// Returns the negotiated subprotocol, borrowing connection-owned storage.
websocket_subprotocol :: proc(conn: ^WebSocket_Conn) -> string {
	if conn == nil do return ""

	return(
		cast(string)conn.selected_protocol[:conn.selected_protocol_size] \
	)
}

websocket_set_write_deadline :: proc(
	conn: ^WebSocket_Conn,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	if conn == nil || conn.phase != .Open {
		return {kind = .Invalid_Stream}
	}

	if conn.stream.set_write_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	return conn.stream.set_write_deadline(conn.stream.data, deadline)
}

websocket_set_deadline :: proc(
	conn: ^WebSocket_Conn,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	if conn == nil || conn.phase != .Open {
		return {kind = .Invalid_Stream}
	}

	if conn.stream.set_read_deadline == nil ||
	   conn.stream.set_write_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	return websocket_stream_set_deadlines(conn.stream, deadline)
}

WebSocket_MAX_CONTROL_FRAMES_WITHOUT_MESSAGE :: 1024

@(private)
WebSocket_STACK_FRAME_PAYLOAD :: 2048

WebSocket_Conn_Phase :: enum {
	Uninitialized,
	Upgrade_Pending,
	Open,
	Closing,
	Closed,
	Failed,
}

WebSocket_Error_Kind :: enum {
	None,
	EOF,
	Closed,
	Invalid_State,
	Invalid_Config,
	Upgrade_Failed,
	Deadline_Failed,
	Destination_Undersized,
	Message_Oversized,
	Frame_Read_Failed,
	Frame_Write_Failed,
	Invalid_Frame,
	Unexpected_Continuation,
	Interrupted_Message,
	Invalid_Message_Type,
	Invalid_UTF8,
	Peer_Close_Error,
	Entropy_Unavailable,
	Invalid_Close,
	Stream_Close_Failed,
	Allocation_Failed,
	No_Progress,
}

WebSocket_Error :: struct {
	kind:        WebSocket_Error_Kind,
	frame:       websocket.Frame_Error,
	stream:      WebSocket_Stream_Error,
	upgrade:     websocket.Upgrade_Error,
	allocation:  mem.Allocator_Error,
	close_code:  u16,
	transferred: int,
}

// Caller-owned and serialized: do not copy a live Conn or use it concurrently.
// Upgrade's trailing bytes are consumed before reading from the stream.
WebSocket_Conn :: struct {
	stream:                         WebSocket_Stream,
	config:                         WebSocket_Config,
	phase:                          WebSocket_Conn_Phase,
	allocator:                      mem.Allocator,
	prefetched:                     [websocket.MAX_UPGRADE_HEADER_SIZE]u8,
	prefetched_at, prefetched_size: int,
	selected_protocol:              [websocket.MAX_SUBPROTOCOL_SIZE]u8,
	selected_protocol_size:         int,
	tls_client:                     tls_api.Conn,
	dial_host:                      [512]u8,
	using message_state: websocket.Message_State,
	last_error:                     WebSocket_Error,
	transport_closed:               bool,
}

// Reads one complete text or binary message; control frames are handled here.
// An undersized destination consumes the message from the wire but retains it
// for retry. n then reports the required destination size. On success n is the
// number copied, including zero for an empty message.
websocket_read_message :: proc(
	conn: ^WebSocket_Conn,
	dst: []u8,
) -> (
	opcode: websocket.Opcode,
	n: int,
	error: WebSocket_Error,
) {
	if err := websocket_ensure_open(conn); err.kind != .None {
		return {}, 0, err
	}

	if conn.message_ready {
		return websocket_deliver_message(conn, dst)
	}

	controls := 0
	for {
		header, header_err := websocket_frame_header_read(conn)
		if header_err.kind != .None {
			return {}, 0, header_err
		}

		#partial switch header.opcode {
		case .Ping, .Pong, .Close:
			if idle_error := websocket_idle_frame(conn, &controls); idle_error.kind != .None {
				return {}, 0, idle_error
			}

			if control_error := websocket_control_read(conn, header); control_error.kind != .None {
				return {}, 0, control_error
			}
		case .Text, .Binary, .Continuation:
			if header.payload_length == 0 {
				if idle_error := websocket_idle_frame(conn, &controls); idle_error.kind != .None {
					return {}, 0, idle_error
				}
			}

			if data_error := websocket_data_read(conn, header); data_error.kind != .None {
				return {}, 0, data_error
			}

			if conn.message_ready {
				return websocket_deliver_message(conn, dst)
			}

		case:
			return {}, 0, websocket_fail(
				conn,
				{kind = .Invalid_Frame},
				1002,
			)
		}
	}
}

// Counts a frame that carries no message payload. A peer sending only such
// frames is failed with 1008 instead of stalling the read forever.
websocket_idle_frame :: proc(conn: ^WebSocket_Conn, idle: ^int) -> WebSocket_Error {
	idle^ += 1
	if idle^ > WebSocket_MAX_CONTROL_FRAMES_WITHOUT_MESSAGE {
		return websocket_fail(conn, {kind = .No_Progress}, 1008)
	}

	return {}
}

websocket_control_read :: proc(
	conn: ^WebSocket_Conn, header: websocket.Frame_Header,
) -> WebSocket_Error {
	payload: [125]u8
	body := payload[:cast(int)header.payload_length]
	count, read_err := websocket_read_exact(conn, body)
	if read_err.kind != .None {
		return websocket_fail(
			conn,
			{
				kind = .Frame_Read_Failed,
				stream = read_err,
				transferred = count,
			},
		)
	}

	#partial switch header.opcode {
	case .Ping:
		if err := websocket_frame_write(conn, .Pong, body);
		   err.kind != .None {
			return websocket_fail(conn, err)
		}

	case .Pong:
	case .Close:
		return websocket_peer_close(conn, body)
	case:
	}
	return {}
}

websocket_peer_close :: proc(conn: ^WebSocket_Conn, body: []u8) -> WebSocket_Error {
	if frame_err := websocket.close_payload_validate(body);
	   frame_err != .None {
		return websocket_fail(
			conn,
			{kind = .Invalid_Close, frame = frame_err},
			websocket_close_validation_code(frame_err),
		)
	}

	code := websocket_close_code(body)
	deadline_err := websocket_close_deadline(conn)
	// Echo a valid peer close once, with a fresh client mask.
	write_err := deadline_err
	if deadline_err.kind == .None {
		write_err = websocket_frame_write(
			conn,
			.Close,
			body,
		)
	}

	conn.phase = .Closed
	websocket_release_message(conn)
	websocket_stream_close(conn, write_err.kind != .None)
	if write_err.kind != .None {
		write_err.close_code = code
		conn.last_error = write_err
		return write_err
	}

	err := WebSocket_Error {
		kind       = .EOF,
		close_code = code,
	}
	if !websocket_close_code_normal(code) {
		err.kind = .Peer_Close_Error
	}

	conn.last_error = err
	return err
}

// Protocol errors become connection failures here; the protocol owns no stream.
websocket_message_error :: proc(error: websocket.Message_Error) -> WebSocket_Error {
	kind: WebSocket_Error_Kind
	switch error.kind {
	case .None: kind = .None
	case .Unexpected_Continuation: kind = .Unexpected_Continuation
	case .Interrupted_Message: kind = .Interrupted_Message
	case .Invalid_Message_Type: kind = .Invalid_Message_Type
	case .Message_Oversized: kind = .Message_Oversized
	case .Invalid_UTF8: kind = .Invalid_UTF8
	case .Allocation_Failed: kind = .Allocation_Failed
	case .Destination_Undersized: kind = .Destination_Undersized
	}
	return {kind = kind, allocation = error.allocation}
}

websocket_message_fail :: proc(
	conn: ^WebSocket_Conn, error: websocket.Message_Error,
) -> WebSocket_Error {
	code: u16 = 1002
	#partial switch error.kind {
	case .Message_Oversized: code = 1009
	case .Invalid_UTF8: code = 1007
	case .Allocation_Failed: code = 1011
	}
	return websocket_fail(conn, websocket_message_error(error), code)
}

websocket_data_read :: proc(
	conn: ^WebSocket_Conn, header: websocket.Frame_Header,
) -> WebSocket_Error {
	allocator := conn.allocator
	if allocator.procedure == nil {allocator = context.allocator}
	body, prepare_error := websocket.message_prepare(
		&conn.message_state, header, conn.config.max_message_size, allocator,
	)
	if prepare_error.kind != .None {return websocket_message_fail(conn, prepare_error)}
	count, read_error := websocket_read_exact(conn, body)
	if read_error.kind != .None {
		return websocket_fail(conn, {
			kind = .Frame_Read_Failed, stream = read_error, transferred = count,
		})
	}
	if finish_error := websocket.message_finish(&conn.message_state, header.fin);
	   finish_error.kind != .None {return websocket_message_fail(conn, finish_error)}
	return {}
}

websocket_write_message :: proc(
	conn: ^WebSocket_Conn,
	opcode: websocket.Opcode,
	payload: []u8,
) -> WebSocket_Error {
	if err := websocket_ensure_open(conn); err.kind != .None {
		return err
	}

	if error := websocket.message_validate(opcode, payload, conn.config.max_message_size);
	   error.kind != .None {return websocket_message_error(error)}

	if err := websocket_frame_write(conn, opcode, payload);
	   err.kind != .None {
		return websocket_fail(conn, err)
	}

	return {}
}

websocket_ping :: proc(conn: ^WebSocket_Conn, payload: []u8) -> WebSocket_Error {
	if err := websocket_ensure_open(conn); err.kind != .None {
		return err
	}

	if len(payload) > 125 {
		return {
			kind = .Invalid_Frame,
			frame = .Control_Payload_Oversized,
		}
	}

	if err := websocket_frame_write(conn, .Ping, payload);
	   err.kind != .None {
		return websocket_fail(conn, err)
	}

	return {}
}

// Sends close and then closes the underlying stream without an endless wait
// for a peer response. Close also releases any retained oversized-dst message.
websocket_close :: proc(
	conn: ^WebSocket_Conn,
	code: u16 = 1000,
	reason: string = "",
) -> WebSocket_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if conn.phase == .Closed || conn.phase == .Failed {
		websocket_release_message(conn)
		websocket_stream_close(conn, conn.phase == .Failed)
		return {}
	}

	payload: [125]u8
	size, frame_err := websocket_close_payload(&payload, code, reason)
	if frame_err != .None {
		return {kind = .Invalid_Close, frame = frame_err}
	}
	body := payload[:size]

	err: WebSocket_Error
	abort_stream := conn.phase != .Open
	if conn.phase == .Open {
		conn.phase = .Closing
		err = websocket_close_deadline(conn)
		if err.kind == .None {
			err = websocket_frame_write(conn, .Close, body)
		}

	}

	conn.phase = .Closed
	websocket_release_message(conn)
	stream_err := websocket_stream_close(
		conn,
		abort_stream || err.kind != .None,
	)
	if err.kind == .None && stream_err.kind != .None {
		err = {
			kind   = .Stream_Close_Failed,
			stream = stream_err,
		}
	}

	return err
}

// Shared failure path for upgrade and framed I/O. close_code=0 suppresses a
// best-effort protocol close (e.g. transport failure before frames are usable).
websocket_fail :: proc(
	conn: ^WebSocket_Conn,
	err: WebSocket_Error,
	close_code: u16 = 0,
) -> WebSocket_Error {
	if conn == nil do return err

	if close_code != 0 &&
	   conn.phase == .Open &&
	   !conn.transport_closed {
		if deadline_err := websocket_close_deadline(conn);
		   deadline_err.kind == .None {
			payload := [?]u8 {
				cast(u8)(close_code >> 8),
				cast(u8)close_code,
			}
			websocket_frame_write(conn, .Close, payload[:])
		}

	}

	conn.phase = .Failed
	conn.last_error = err
	websocket_release_message(conn)
	websocket_stream_close(conn, true)
	return err
}

websocket_ensure_open :: proc(conn: ^WebSocket_Conn) -> WebSocket_Error {
	if conn == nil do return {kind = .Invalid_State}

	if conn.phase == .Failed do return conn.last_error

	if conn.phase == .Closed {
		if conn.last_error.kind != .None {
			return conn.last_error
		}

		return {kind = .Closed}
	}

	if conn.phase == .Upgrade_Pending {
		if err := websocket_upgrade(conn); err.kind != .None {
			return err
		}

	}

	if conn.phase != .Open || conn.config.max_message_size <= 0 {
		return {kind = .Invalid_State}
	}

	return {}
}

websocket_read_exact :: proc(
	conn: ^WebSocket_Conn,
	dst: []u8,
) -> (
	received: int,
	error: WebSocket_Stream_Error,
) {
	if conn.prefetched_at < conn.prefetched_size {
		received = copy(
			dst,
			conn.prefetched[conn.prefetched_at:conn.prefetched_size],
		)
		conn.prefetched_at += received
	}

	if received == len(dst) do return received, {}

	count, stream_err := websocket_stream_read_exact(
		conn.stream,
		dst[received:],
	)
	return received + count, stream_err
}

websocket_frame_header_read :: proc(
	conn: ^WebSocket_Conn,
) -> (
	header: websocket.Frame_Header,
	error: WebSocket_Error,
) {
	wire: [websocket.MAX_FRAME_HEADER_SIZE]u8
	count, read_err := websocket_read_exact(conn, wire[:2])
	if read_err.kind != .None {
		return {}, websocket_fail(
			conn,
			{
				kind = .Frame_Read_Failed,
				stream = read_err,
				transferred = count,
			},
		)
	}

	decoded, _, frame_err := websocket.frame_header_decode(wire[:2], false)
	if frame_err == .Header_Incomplete {
		size := websocket_frame_header_size(wire[1])
		count, read_err = websocket_read_exact(conn, wire[2:size])
		if read_err.kind != .None {
			return {}, websocket_fail(
				conn,
				{
					kind = .Frame_Read_Failed,
					stream = read_err,
					transferred = count + 2,
				},
			)
		}

		decoded, _, frame_err = websocket.frame_header_decode(
			wire[:size],
			false,
		)
	}

	if frame_err != .None {
		return {}, websocket_fail(
			conn,
			{kind = .Invalid_Frame, frame = frame_err},
			1002,
		)
	}

	return decoded, {}
}

websocket_frame_write :: proc(
	conn: ^WebSocket_Conn,
	opcode: websocket.Opcode,
	payload: []u8,
) -> WebSocket_Error {
	when !crypto.HAS_RAND_BYTES do return {kind = .Entropy_Unavailable}
	mask: [4]u8
	crypto.rand_bytes(mask[:])
	// Control frames and short messages are masked on the stack, so replying to
	// a ping or closing never depends on the allocator.
	small: [websocket.MAX_FRAME_HEADER_SIZE + WebSocket_STACK_FRAME_PAYLOAD]u8
	wire := small[:]
	allocator := conn.allocator
	if allocator.procedure == nil {
		allocator = context.allocator
	}

	heap: []u8
	defer delete(heap, allocator)
	if len(payload) > WebSocket_STACK_FRAME_PAYLOAD {
		allocation_err: mem.Allocator_Error
		heap, allocation_err = make([]u8, websocket.MAX_FRAME_HEADER_SIZE + len(payload), allocator)
		if allocation_err != nil {
			return {kind = .Allocation_Failed, allocation = allocation_err}
		}
		wire = heap
	}

	size, frame_err := websocket.frame_encode(
		wire,
		true,
		opcode,
		payload,
		mask,
	)
	if frame_err != .None {
		return {kind = .Invalid_Frame, frame = frame_err}
	}

	count, stream_err := websocket_stream_write_all(conn.stream, wire[:size])
	if stream_err.kind != .None {
		return {
			kind = .Frame_Write_Failed,
			stream = stream_err,
			transferred = count,
		}
	}

	return {}
}

websocket_deliver_message :: proc(
	conn: ^WebSocket_Conn, dst: []u8,
) -> (websocket.Opcode, int, WebSocket_Error) {
	opcode, count, error := websocket.message_deliver(&conn.message_state, dst)
	return opcode, count, websocket_message_error(error)
}

websocket_release_message :: proc(conn: ^WebSocket_Conn) {
	websocket.message_release(&conn.message_state)
}

// Wire size of a frame header, known from its second byte.
@(private)
websocket_frame_header_size :: proc(second: u8) -> int {
	size := 2
	switch second & 0x7f {
	case 126:
		size += 2
	case 127:
		size += 8
	}
	if second & 0x80 != 0 do size += 4
	return size
}

// Writes code and reason into dst and validates the result as a close payload.
@(private)
websocket_close_payload :: proc(dst: ^[125]u8, code: u16, reason: string) -> (int, websocket.Frame_Error) {
	if len(reason) > 123 do return 0, .Control_Payload_Oversized
	dst[0], dst[1] = u8(code >> 8), u8(code)
	copy(dst[2:], reason)
	size := 2 + len(reason)
	return size, websocket.close_payload_validate(dst[:size])
}

// Close code sent for a peer close payload that failed validation.
@(private)
websocket_close_validation_code :: proc(frame_err: websocket.Frame_Error) -> u16 {
	if frame_err == .Invalid_UTF8 {
		return 1007
	}

	return 1002
}

// 1005 means no status was present; it is never sent as a wire code.
@(private)
websocket_close_code :: proc(body: []u8) -> u16 {
	if len(body) < 2 do return 1005
	return u16(body[0]) << 8 | u16(body[1])
}

// Close codes that end a connection without reporting a peer error.
@(private)
websocket_close_code_normal :: proc(code: u16) -> bool {
	switch code {
	case 1000, 1001, 1005:
		return true
	}
	return false
}

websocket_stream_close :: proc(
	conn: ^WebSocket_Conn,
	abort_stream: bool = false,
) -> WebSocket_Stream_Error {
	if conn.transport_closed do return {}

	conn.transport_closed = true
	if abort_stream && conn.stream.abort != nil {
		return conn.stream.abort(conn.stream.data)
	}

	// Custom streams without abort must make close an immediate resource
	// release. TLS adapters provide abort to avoid an unbounded close_notify.
	if conn.stream.close == nil {
		return {kind = .Invalid_Stream}
	}

	return conn.stream.close(conn.stream.data)
}

websocket_close_deadline :: proc(conn: ^WebSocket_Conn) -> WebSocket_Error {
	if conn.stream.set_write_deadline == nil {
		return {
			kind = .Deadline_Failed,
			stream = {kind = .Deadline_Unsupported},
		}
	}

	if err := conn.stream.set_write_deadline(
		conn.stream.data,
		time.time_add(time.now(), time.Second),
	); err.kind != .None {
		return {kind = .Deadline_Failed, stream = err}
	}

	return {}
}

WebSocket_Stream_Error_Kind :: enum {
	None,
	EOF,
	Invalid_Stream,
	No_Progress,
	Invalid_Count,
	TLS_Failed,
	TCP_Failed,
	Deadline_Unsupported,
}

WebSocket_Stream_Error :: struct {
	kind:      WebSocket_Stream_Error_Kind,
	tls:       tls_api.IO_Error,
	tls_dial:  tls_api.Dial_Error,
	transport: tcp_api.Connection_Error,
}

// A blocking byte stream. Callbacks may return bytes together with an error.
// The underlying TLS/TCP connection must remain at a stable address.
WebSocket_Stream :: struct {
	data:               rawptr,
	read:               proc(
		data: rawptr,
		dst: []u8,
	) -> (
		int,
		WebSocket_Stream_Error,
	),
	write:              proc(
		data: rawptr,
		src: []u8,
	) -> (
		int,
		WebSocket_Stream_Error,
	),
	close:              proc(data: rawptr) -> WebSocket_Stream_Error,
	// Optional non-writing cleanup. When absent, close must release resources
	// without blocking on peer traffic, including on failure paths.
	abort:              proc(data: rawptr) -> WebSocket_Stream_Error,
	set_read_deadline:  proc(
		data: rawptr,
		deadline: time.Time,
	) -> WebSocket_Stream_Error,
	set_write_deadline: proc(
		data: rawptr,
		deadline: time.Time,
	) -> WebSocket_Stream_Error,
}

websocket_stream_valid :: proc(stream: WebSocket_Stream) -> bool {
	return(
		stream.read != nil &&
		stream.write != nil &&
		stream.close != nil \
	)
}

websocket_stream_read_exact :: proc(
	stream: WebSocket_Stream,
	dst: []u8,
) -> (
	received: int,
	err: WebSocket_Stream_Error,
) {
	if !websocket_stream_valid(stream) {
		return 0, {kind = .Invalid_Stream}
	}

	return tcp_api.read_exact_callback(
		WebSocket_Stream_Error, stream.data, dst, stream.read,
	)
}

websocket_stream_write_all :: proc(
	stream: WebSocket_Stream,
	src: []u8,
) -> (
	written: int,
	err: WebSocket_Stream_Error,
) {
	if !websocket_stream_valid(stream) {
		return 0, {kind = .Invalid_Stream}
	}

	return tcp_api.write_all_callback(
		WebSocket_Stream_Error, stream.data, src, stream.write,
	)
}

websocket_stream_from_tls_address :: proc(conn: ^tls_api.Conn) -> WebSocket_Stream {
	return {
		data = conn,
		read = websocket_stream_tls_read,
		write = websocket_stream_tls_write,
		close = websocket_stream_tls_close,
		abort = websocket_stream_tls_abort,
		set_read_deadline = websocket_stream_tls_read_deadline,
		set_write_deadline = websocket_stream_tls_write_deadline,
	}
}

websocket_tcp_stream :: proc(conn: ^tcp_api.TCP_Connection) -> WebSocket_Stream {
	if conn == nil do return {}

	return {
		data = conn,
		read = websocket_stream_tcp_read,
		write = websocket_stream_tcp_write,
		close = websocket_stream_tcp_close,
		abort = websocket_stream_tcp_close,
		set_read_deadline = websocket_stream_tcp_read_deadline,
		set_write_deadline = websocket_stream_tcp_write_deadline,
	}
}

websocket_stream_tls_read :: proc(
	data: rawptr,
	dst: []u8,
) -> (
	int,
	WebSocket_Stream_Error,
) {
	count, err := tls_api.read(cast(^tls_api.Conn)data, dst)
	if err.kind == .EOF {
		return count, {kind = .EOF, tls = err}
	}

	if err.kind != .None {
		return count, {kind = .TLS_Failed, tls = err}
	}

	return count, {}
}

websocket_stream_tls_write :: proc(
	data: rawptr,
	src: []u8,
) -> (
	int,
	WebSocket_Stream_Error,
) {
	count, err := tls_api.write(cast(^tls_api.Conn)data, src)
	if err.kind != .None {
		return count, {kind = .TLS_Failed, tls = err}
	}

	return count, {}
}

websocket_stream_tls_close :: proc(data: rawptr) -> WebSocket_Stream_Error {
	if err := tls_api.close(cast(^tls_api.Conn)data);
	   err.kind != .None {
		return {kind = .TLS_Failed, tls = err}
	}

	return {}
}

websocket_stream_tls_abort :: proc(data: rawptr) -> WebSocket_Stream_Error {
	if err := tls_api.abort(cast(^tls_api.Conn)data);
	   err.kind != .None {
		return {kind = .TLS_Failed, tls = err}
	}

	return {}
}

websocket_stream_tls_read_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	if err := tls_api.set_read_deadline(
		cast(^tls_api.Conn)data,
		deadline,
	); err.kind != .None {
		return {kind = .TCP_Failed, transport = err}
	}

	return {}
}

websocket_stream_tls_write_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	if err := tls_api.set_write_deadline(
		cast(^tls_api.Conn)data,
		deadline,
	); err.kind != .None {
		return {kind = .TCP_Failed, transport = err}
	}

	return {}
}

websocket_stream_tcp_read :: proc(
	data: rawptr,
	dst: []u8,
) -> (
	int,
	WebSocket_Stream_Error,
) {
	conn := tcp_api.tcp_connection(cast(^tcp_api.TCP_Connection)data)
	count, err := conn.read(conn.data, dst)
	if err.kind == .Peer_Closed {
		return count, {kind = .EOF, transport = err}
	}

	if err.kind != .None {
		return count, {kind = .TCP_Failed, transport = err}
	}

	return count, {}
}

websocket_stream_tcp_write :: proc(
	data: rawptr,
	src: []u8,
) -> (
	int,
	WebSocket_Stream_Error,
) {
	conn := tcp_api.tcp_connection(cast(^tcp_api.TCP_Connection)data)
	count, err := conn.write(conn.data, src)
	if err.kind != .None {
		return count, {kind = .TCP_Failed, transport = err}
	}

	return count, {}
}

websocket_stream_tcp_close :: proc(data: rawptr) -> WebSocket_Stream_Error {
	conn := tcp_api.tcp_connection(cast(^tcp_api.TCP_Connection)data)
	if err := conn.close(conn.data); err.kind != .None {
		return {kind = .TCP_Failed, transport = err}
	}

	return {}
}

websocket_stream_tcp_read_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	conn := tcp_api.tcp_connection(cast(^tcp_api.TCP_Connection)data)
	if err := tcp_api.set_read_deadline(conn, deadline);
	   err.kind != .None {
		return {kind = .TCP_Failed, transport = err}
	}

	return {}
}

websocket_stream_tcp_write_deadline :: proc(
	data: rawptr,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	conn := tcp_api.tcp_connection(cast(^tcp_api.TCP_Connection)data)
	if err := tcp_api.set_write_deadline(conn, deadline);
	   err.kind != .None {
		return {kind = .TCP_Failed, transport = err}
	}

	return {}
}
