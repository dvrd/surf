package surf

import "base:intrinsics"
import "core:net"
import "core:strings"
import "core:time"
import "shared:async/http"
import http2 "shared:async/http/v2"
import hpack "shared:async/http/v2/hpack"
import owned "shared:async/mem/owned"
import tls "shared:async/tls"

// A caller-owned, stable HTTP2 stream. All operations on its HTTP_Client,
// including ordinary HTTP requests, are serialized by the caller. Closing one
// WebSocket closes only this stream. Keep Tunnel alive until the client closes
// or its WebSocket is closed/aborted. Do not copy a live Tunnel. Client close
// safely detaches live tunnels.
HTTP2_Tunnel :: struct {
	_client:                         ^HTTP_Client,
	_lane:                           ^HTTP_Lane,
	_handle:                         http2.Stream_Handle,
	_response:                       Response,
	_status:                         int,
	_ended, _closed, _reset:         bool,
	_read_deadline, _write_deadline: time.Time,
	_inputs:                         [HTTP_STREAM_SLOTS]HTTP2_Tunnel_Input,
	_head, _count:                   int,
}
HTTP2_Tunnel_Input :: struct {
	owner:  http2.Incoming_Data,
	credit: http2.Data_Token,
	offset: int,
}

// RFC8441 Extended CONNECT uses status200, :protocol and SETTINGS negotiation;
// it never sends an HTTP1 Upgrade or Sec-WebSocket-Key/Accept exchange.
// The HTTP_Client TLS configuration must offer h2 through ALPN.
websocket_http2_open :: proc(
	client: ^HTTP_Client,
	tunnel: ^HTTP2_Tunnel,
	conn: ^WebSocket_Conn,
	url: string,
	config: WebSocket_Config,
	headers: []http.Header = nil,
) -> HTTP_Error {
	if client == nil ||
	   client._self != client ||
	   tunnel == nil ||
	   tunnel._lane != nil ||
	   conn == nil ||
	   conn.phase != .Uninitialized {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	intrinsics.atomic_store(&client.cancel, 0)
	parsed, pe := http.url_parse(url)
	if pe.kind != .None || !parsed.secure {
		return {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent}
	}
	options := config
	options.host = parsed.authority
	options.target = parsed.target
	if options.target == "" {
		options.target = "/"
	}
	stream := WebSocket_Stream {
		data               = tunnel,
		read               = h2_tunnel_read,
		write              = h2_tunnel_write,
		close              = h2_tunnel_close,
		abort              = h2_tunnel_abort,
		set_read_deadline  = h2_tunnel_read_deadline,
		set_write_deadline = h2_tunnel_write_deadline,
	}
	if websocket_client(conn, stream, options) != .None {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	success := false
	defer if !success {
		conn^ = {}
	}
	fields: [64]hpack.Field
	fields[0] = {":method", "CONNECT", false}
	fields[1] = {":protocol", "websocket", false}
	fields[2] = {":scheme", "https", false}
	fields[3] = {":authority", parsed.authority, false}
	fields[4] = {":path", options.target, false}
	fields[5] = {"sec-websocket-version", "13", false}
	count := 6
	if options.origin != "" {
		fields[count] = {"origin", options.origin, false}
		count += 1
	}
	protocols: [1024]u8
	if len(options.subprotocols) > 0 {
		offered, fits := websocket_protocols_join(protocols[:], options.subprotocols)

		if !fits {
			return {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}

		fields[count] = {"sec-websocket-protocol", offered, false}
		count += 1
	}
	names: [4096]u8
	name_n := 0
	for header in headers {
		if count == len(fields) {
			return {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}

		name, fits := field_name_lower(names[:], &name_n, header.name)

		if !fits {
			return {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}

		sensitive := name == "authorization" ||
			name == "proxy-authorization" ||
			name == "cookie" ||
			name == "set-cookie"
		fields[count] = {name, header.value, sensitive}
		count += 1
	}

	if _, e := http2.headers_validate(
		fields[:count],
		.Request,
		{max_fields = 64, max_list_bytes = 8192, extended_connect_enabled = true},
	); e.kind != .None {
		return {kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}
	}
	deadline := websocket_tunnel_deadline(client.config, options.handshake_timeout)
	lane, reused, e := http_lane_prepare(client, parsed, deadline)
	if e.kind != .None {
		return e
	}
	if lane.protocol != .HTTP2 {
		http_lane_close(client, lane)
		return {kind = .Invalid_Config, phase = .Protocol, write_effect = .Not_Sent}
	}
	if de := tls.set_deadline(lane.tls, deadline); de != nil {
		http_lane_close(client, lane)
		return {
			kind = .IO_Failed,
			phase = .Deadline,
			write_effect = .Not_Sent,
			tls_error = de,
			transport = tls_network(de),
		}
	}
	if !reused {
		if e = h2_boot(lane, deadline, &client.cancel); e.kind != .None {
			http_lane_close(client, lane)
			return e
		}
	}
	allowed, _, valid := http2.connection_connect_protocol(&lane.engine)
	if !valid || !allowed {
		http_lane_close(client, lane)
		return {kind = .Invalid_Config, phase = .Protocol, write_effect = .Not_Sent}
	}
	index := -1

	for slot, i in lane.tunnels {
		if slot == nil {
			index = i
			break
		}
	}
	if index < 0 {
		http_lane_close(client, lane)
		return {kind = .Invalid_Config, phase = .Admission, write_effect = .Not_Sent}
	}
	handle, opened := http2.connection_open(&lane.engine, fields[:count], false)
	if opened.kind != .None {
		http_lane_close(client, lane)
		return h2_map_error(opened, .Not_Sent, 0)
	}
	tunnel^ = {
		_client         = client,
		_lane           = lane,
		_handle         = handle,
		_read_deadline  = deadline,
		_write_deadline = deadline,
	}
	lane.tunnels[index] = tunnel
	defer if !success {
		_ = h2_tunnel_abort(tunnel)
		http_lane_close(client, lane)
	}
	for tunnel._status == 0 && !tunnel._closed {
		if e = h2_tunnel_progress(tunnel, true); e.kind != .None {
			return e
		}
	}
	if tunnel._status < 200 || tunnel._status >= 300 {
		return {
			kind = .Invalid_Status,
			phase = .Protocol,
			status = tunnel._status,
			write_effect = .Response_Received,
		}
	}
	selected, present := response_header(&tunnel._response, "sec-websocket-protocol")
	protocols_received := 0
	for header in tunnel._response.headers {
		if strings.equal_fold(header.name, "sec-websocket-protocol") {
			protocols_received += 1
		}
	}
	if protocols_received > 1 {
		return {kind = .Invalid_Header, phase = .Protocol, write_effect = .Response_Received}
	}
	if present && !websocket_subprotocol_accept(conn, options.subprotocols, selected) {
		return {kind = .Invalid_Header, phase = .Protocol, write_effect = .Response_Received}
	}
	if extension, _ := response_header(&tunnel._response, "sec-websocket-extensions");
	   extension != "" {
		return {kind = .Invalid_Header, phase = .Protocol, write_effect = .Response_Received}
	}
	response_destroy(&tunnel._response)
	conn.phase = .Open
	tunnel._read_deadline = {}
	tunnel._write_deadline = {}
	success = true
	return {}
}

h2_tunnel_find :: proc(lane: ^HTTP_Lane, handle: http2.Stream_Handle) -> ^HTTP2_Tunnel {
	for stream in lane.tunnels {
		if stream != nil && stream._handle == handle {
			return stream
		}
	}

	return nil
}
h2_tunnel_event :: proc(
	lane: ^HTTP_Lane,
	event: http2.Event_View,
) -> (
	handled, taken: bool,
	error: HTTP_Error,
) {
	#partial switch value in event.payload {
	case http2.Headers_Event:
		stream := h2_tunnel_find(lane, value.stream)

		if stream == nil {
			return false, false, {}
		}
		if value.summary.status < 200 {
			return true, false, {}
		}
		if stream._status != 0 || value.kind == .Trailers {
			stream._closed = true
			stream._reset = true
			return true, false, {}
		}
		stream._status = int(value.summary.status)
		job := H2_Job {
			status = stream._status,
		}
		e := h2_copy_headers(&job, value.summary.fields, lane.allocator)
		stream._response = job.response
		stream._ended = value.end_stream
		return true, false, e
	case http2.Data_Event:
		stream := h2_tunnel_find(lane, value.stream)
		if stream == nil {
			if h2_tunnel_retired(lane, value.stream) {
				return true, false, {}
			}; return false, false, {}
		}
		if stream._count == len(stream._inputs) {
			_ = http2.connection_reset(&lane.engine, value.stream, .Cancel)
			stream._closed = true
			stream._reset = true
			return true, false, {}
		}
		at := (stream._head + stream._count) % len(stream._inputs)
		entry := &stream._inputs[at]
		e := http2.connection_data_take(&lane.engine, event.token, &entry.owner)
		if e.kind != .None {
			return true, false, h2_map_error(e, .Response_Received, stream._status)
		}
		entry.credit = value.consumption
		stream._count += 1
		stream._ended = stream._ended || value.end_stream
		return true, true, {}
	case http2.Stream_End_Event:
		if h2_tunnel_retired(lane, value.stream) {
			return true, false, {}
		}
		if stream := h2_tunnel_find(lane, value.stream); stream != nil {
			stream._ended = true
			return true, false, {}
		}
	case http2.Reset_Event:
		if h2_tunnel_retired(lane, value.stream) {
			return true, false, {}
		}
		if stream := h2_tunnel_find(lane, value.stream); stream != nil {
			stream._closed = true
			stream._reset = true
			return true, false, {}
		}
	case http2.Goaway_Event:
		for stream in lane.tunnels {
			if stream != nil && stream._handle.stream_id > value.last_stream_id {
				stream._closed = true
				stream._reset = true
			}
		}
	case http2.Terminal_Event:
		for stream in lane.tunnels {
			if stream != nil {
				stream._closed = true
				stream._reset = true
			}
		}
	}

	return false, false, {}
}
h2_tunnel_progress :: proc(
	stream: ^HTTP2_Tunnel,
	read: bool,
	force_read: bool = false,
) -> HTTP_Error {
	lane := stream._lane

	if lane == nil || stream._closed {
		return {kind = .IO_Failed, phase = .Read, write_effect = .Response_Received}
	}

	opening := stream._status == 0
	deadline := stream._read_deadline if read && !force_read else stream._write_deadline

	if deadline == {} {
		deadline = time.time_add(time.now(), effective_timeout(stream._client.config))
	}

	if time.diff(time.now(), deadline) <= 0 {
		return {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Response_Received}
	}

	http_arm_socket(stream._client, lane.tls.tcp.socket)

	if de := tls.set_deadline(lane.tls, deadline); de != nil {
		return {
			kind = .IO_Failed,
			phase = .Deadline,
			write_effect = .Response_Received,
			tls_error = de,
			transport = tls_network(de),
		}
	}

	if h2_cancelled(&stream._client.cancel) {
		return {kind = .IO_Failed, phase = .Cancellation, write_effect = .Response_Received}
	}

	empty: [0]H2_Job
	_, e := h2_service(lane, empty[:])

	if e.kind != .None {
		return e
	}

	_, e = h2_write_all(lane, empty[:])

	if e.kind != .None {
		return e
	}

	if opening && stream._status != 0 {
		return {}
	}

	if !read ||
	   !force_read && stream._count > 0 ||
	   stream._ended ||
	   stream._closed ||
	   stream._status != 0 && stream._status != 200 {
		return {}
	}

	n, re := h2_read(lane)

	if re.kind != .None {
		return re
	}

	return h2_feed(lane, empty[:], lane.read_buf[:n])
}
h2_tunnel_read :: proc(data: rawptr, destination: []u8) -> (int, WebSocket_Stream_Error) {
	stream := cast(^HTTP2_Tunnel)data

	if len(destination) == 0 {
		return 0, {}
	}

	for {
		for stream._count == 0 && !stream._closed && !stream._ended {
			if e := h2_tunnel_progress(stream, true); e.kind != .None {
				return 0, h2_tunnel_stream_error(e)
			}
		}

		if stream._count == 0 {
			return 0, {kind = .TCP_Failed if stream._reset else .EOF}
		}

		entry := &stream._inputs[stream._head]
		bytes, ok := http2.incoming_data_bytes(&entry.owner)

		if !ok {
			return 0, {kind = .Invalid_Stream}
		}

		n := copy(destination, bytes[entry.offset:])
		entry.offset += n

		if n > 0 {
			_ = http2.connection_consume(&stream._lane.engine, entry.credit, u32(n))
		}

		if entry.offset == len(bytes) {
			if len(bytes) == 0 {
				_ = http2.connection_discard(&stream._lane.engine, entry.credit)
			}

			http2.incoming_data_destroy(&entry.owner)
			entry^ = {}
			stream._head = (stream._head + 1) % len(stream._inputs)
			stream._count -= 1
		}

		if n > 0 {
			return n, {}
		}
	}
}
h2_tunnel_write :: proc(data: rawptr, source: []u8) -> (int, WebSocket_Stream_Error) {
	stream := cast(^HTTP2_Tunnel)data

	if stream._lane == nil || stream._closed {
		return 0, {kind = .Invalid_Stream}
	}

	n := min(len(source), 16384)
	chunk, e := owned.copy_bounded(source[:n], 16384, stream._lane.allocator)

	if e.kind != .None {
		return 0, {kind = .Invalid_Stream}
	}

	defer owned.destroy(&chunk)

	for {
		sent := http2.connection_send_data(&stream._lane.engine, stream._handle, &chunk, false)

		if sent.kind == .None {
			if pe := h2_tunnel_progress(stream, false); pe.kind != .None {
				return n, h2_tunnel_stream_error(pe)
			}; return n, {}
		}

		if sent.kind != .Limit_Exceeded {
			return 0, {kind = .Invalid_Stream}
		}

		if pe := h2_tunnel_progress(stream, true, true); pe.kind != .None {
			return 0, h2_tunnel_stream_error(pe)
		}
	}
}
h2_tunnel_detach :: proc(stream: ^HTTP2_Tunnel) {
	lane := stream._lane

	if lane == nil {
		return
	}

	for &entry in stream._inputs {
		if entry.credit != (http2.Data_Token{}) {
			_ = http2.connection_discard(&lane.engine, entry.credit)
		}

		http2.incoming_data_destroy(&entry.owner)
		entry = {}
	}

	response_destroy(&stream._response)

	for &slot in lane.tunnels {
		if slot == stream {
			slot = nil
			break
		}
	}

	stored := false

	for &slot in lane.closed_tunnels {
		if slot == {} {
			slot = stream._handle
			stored = true
			break
		}
	}

	if !stored {
		lane.reusable = false
	}

	stream._lane = nil
	stream._client = nil
	stream._closed = true
	stream._count = 0
}
h2_tunnel_abort :: proc(data: rawptr) -> WebSocket_Stream_Error {
	stream := cast(^HTTP2_Tunnel)data

	if stream._lane == nil {
		return {}
	}

	// Failure cleanup never blocks on TLS/peer traffic. The engine owns the
	// queued reset and a later lane pump flushes it independently of this owner.
	_ = http2.connection_reset(&stream._lane.engine, stream._handle, .Cancel)
	h2_tunnel_detach(stream)

	return {}
}
h2_tunnel_close :: proc(data: rawptr) -> WebSocket_Stream_Error {
	stream := cast(^HTTP2_Tunnel)data

	if stream._lane == nil {
		return {}
	}

	empty, allocation := owned.allocate(0, stream._lane.allocator)

	if allocation.kind != .None {
		_ = h2_tunnel_abort(data)
		return {kind = .Invalid_Stream}
	}

	e := http2.connection_send_data(&stream._lane.engine, stream._handle, &empty, true)

	if e.kind != .None {
		owned.destroy(&empty)
		_ = h2_tunnel_abort(data)
		return {kind = .Invalid_Stream}
	}

	progress := h2_tunnel_progress(stream, false)
	_ = http2.connection_reap(&stream._lane.engine, stream._handle)
	h2_tunnel_detach(stream)

	if progress.kind != .None {
		return h2_tunnel_stream_error(progress)
	}

	return {}
}
h2_tunnel_read_deadline :: proc(data: rawptr, deadline: time.Time) -> WebSocket_Stream_Error {
	stream := cast(^HTTP2_Tunnel)data
	stream._read_deadline = deadline

	return {}
}
h2_tunnel_write_deadline :: proc(data: rawptr, deadline: time.Time) -> WebSocket_Stream_Error {
	stream := cast(^HTTP2_Tunnel)data
	stream._write_deadline = deadline

	return {}
}

h2_tunnel_retired :: proc(lane: ^HTTP_Lane, handle: http2.Stream_Handle) -> bool {
	for retired in lane.closed_tunnels {
		if retired == handle {
			return true
		}
	}

	return false
}
h2_tunnel_reap :: proc(lane: ^HTTP_Lane) {
	if lane == nil || !lane.engine_up {
		return
	}

	for &retired in lane.closed_tunnels {
		if retired == {} {
			continue
		}

		e := http2.connection_reap(&lane.engine, retired)

		if e.kind == .None || e.kind == .Invalid_Input {
			retired = {}
		}
	}
}

h2_tunnel_stream_error :: proc(error: HTTP_Error) -> WebSocket_Stream_Error {
	if error.tls_error != nil {
		return {kind = .TLS_Failed, tls = error.tls_error}
	}

	transport := error.transport

	if error.kind == .Deadline_Failed {
		transport = net.TCP_Recv_Error.Timeout
	}

	if error.phase == .Cancellation {
		transport = net.Connection_Error.Cancelled
	}

	return {kind = .TCP_Failed, transport = transport}
}

// Shared by the HTTP/2 and HTTP/3 Extended CONNECT openers.

// The client timeout bounds the open; a shorter handshake timeout wins.
websocket_tunnel_deadline :: proc(config: Config, handshake_timeout: time.Duration) -> time.Time {
	now := time.now()
	timeout := effective_timeout(config)

	if handshake_timeout > 0 && handshake_timeout < timeout {
		timeout = handshake_timeout
	}

	return time.time_add(now, timeout)
}

// Comma-joined sec-websocket-protocol value; false when it does not fit dst.
websocket_protocols_join :: proc(dst: []u8, subprotocols: []string) -> (string, bool) {
	used := 0

	for protocol, i in subprotocols {
		if i > 0 {
			if used + 2 > len(dst) {
				return "", false
			}

			used += copy(dst[used:], ", ")
		}

		if len(protocol) > len(dst) - used {
			return "", false
		}

		used += copy(dst[used:], protocol)
	}

	return string(dst[:used]), true
}

// Records the peer-selected subprotocol; false unless it was offered and fits.
websocket_subprotocol_accept :: proc(
	conn: ^WebSocket_Conn,
	offered: []string,
	selected: string,
) -> bool {
	found := false

	for candidate in offered {
		if candidate == selected {
			found = true
		}
	}

	if !found || len(selected) > len(conn.selected_protocol) {
		return false
	}

	conn.selected_protocol_size = copy(conn.selected_protocol[:], selected)

	return true
}
