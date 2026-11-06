package client

import websocket "../websocket"
import tls_api "core:crypto/tls"
import "core:crypto"
import "core:fmt"
import "core:strings"
import "core:time"

// WebSocket initialization and upgrade execution

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
		err := conn.stream.set_read_deadline(
			conn.stream.data,
			deadline,
		)
		if err.kind != .None {
			return false, websocket_upgrade_fail(
				conn,
				{kind = .Deadline_Failed, stream = err},
			)
		}

		err = conn.stream.set_write_deadline(
			conn.stream.data,
			deadline,
		)
		if err.kind != .None {
			return false, websocket_upgrade_fail(
				conn,
				{kind = .Deadline_Failed, stream = err},
			)
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

websocket_upgrade_deadline_clear :: proc(conn: ^WebSocket_Conn) -> WebSocket_Error {
	err := conn.stream.set_read_deadline(
		conn.stream.data,
		{},
	)
	if err.kind != .None {
		return websocket_upgrade_fail(
			conn,
			{kind = .Deadline_Failed, stream = err},
		)
	}

	err = conn.stream.set_write_deadline(
		conn.stream.data,
		{},
	)
	if err.kind != .None {
		return websocket_upgrade_fail(
			conn,
			{kind = .Deadline_Failed, stream = err},
		)
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

// Secure dialing and connection configuration

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

websocket_set_read_deadline :: proc(
	conn: ^WebSocket_Conn,
	deadline: time.Time,
) -> WebSocket_Stream_Error {
	if conn == nil || conn.phase != .Open {
		return {kind = .Invalid_Stream}
	}

	if conn.stream.set_read_deadline == nil {
		return {kind = .Deadline_Unsupported}
	}

	return conn.stream.set_read_deadline(conn.stream.data, deadline)
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

	err := conn.stream.set_read_deadline(conn.stream.data, deadline)
	if err.kind != .None do return err

	return conn.stream.set_write_deadline(conn.stream.data, deadline)
}
