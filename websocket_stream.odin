package surf

import tls_api "core:crypto/tls"
import tcp_api "core:net"
import "core:time"

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

// Complete TLS first so its handshake cannot replace the WebSocket upgrade's
// deadline. dial performs this sequencing automatically.
websocket_tls_stream :: proc(conn: ^tls_api.Conn) -> WebSocket_Stream {
	if conn == nil || conn.phase != .Established {
		return {}
	}

	return websocket_stream_from_tls_address(conn)
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
