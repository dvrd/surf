package surf

import http "../http"
import x509 "core:crypto/x509"
import tls_api "core:crypto/tls"
import "core:io"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

@(private)
buffered_http_validate :: proc(
	method, url: string,
	headers: []string,
	allow_http: bool,
	timeout_ms, upload_size: i64,
	managed: bool,
) -> HTTP_Error {
	error := HTTP_Error {
		kind         = .Invalid_Config,
		phase        = .Configuration,
		write_effect = .Not_Sent,
	}
	parsed, parse_error := http.url_parse(url)
	if parse_error.kind != .None {
		error.kind = parse_error.kind; return error
	}
	if !allow_http && !parsed.secure {
		error.kind = .Insecure_URL; return error
	}
	if !http.header_name_valid(method) {
		error.kind = .Invalid_Method; return error
	}
	if timeout_ms <= 0 || timeout_ms > 120000 || upload_size < 0 do return error
	if managed && len(headers) > http.MAX_HEADERS {
		error.kind = .Header_Limit; return error
	}
	bytes := 0
	for header in headers {
		if strings.contains_any(header, "\r\n\x00") {
			error.kind = .Invalid_Header; return error
		}
		if managed {
			if len(header) > http.MAX_HEADER_SIZE - bytes {
				error.kind = .Header_Oversized; return error
			}
			bytes += len(header)
		}
	}
	return {}
}

@(private)
buffered_http_perform :: proc(
	method, url: string,
	body: []byte,
	headers: []string,
	ca_file: string,
	timeout_ms: i64,
	upload_file: ^os.File,
	upload_size: i64,
	reply: ^Buffered_HTTP_Reply,
) -> (
	result: Buffered_HTTP_Result,
) {
	// The provider fixture fails the first temporary allocation before any socket.
	_, allocation_error := strings.clone_to_cstring(url, context.temp_allocator)
	if allocation_error != nil {
		result.error = buffered_http_allocation_error(allocation_error); return
	}
	parsed, parse_error := http.url_parse(url)
	if parse_error.kind != .None {
		result.error = {kind = parse_error.kind, phase = .Configuration, write_effect = .Not_Sent}
		return
	}
	timeout := time.Duration(timeout_ms) * time.Millisecond
	total := time.time_add(time.now(), timeout)
	if time.diff(time.now(), total) <= 0 {
		result.error = {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
		return
	}
	alpn := [?]string{"http/1.1", "h2"}
	config := Config {
		tls = {alpn_protocols = alpn[:]},
		timeout = timeout,
		setup_timeout = min(timeout, 5 * time.Second),
		allow_http = !parsed.secure,
		max_redirects = 0,
		max_body_size = len(reply.data),
	}
	// Nil roots fail before dial. A non-nil empty slice loads platform anchors.
	platform_anchor: [1]^x509.Certificate
	if ca_file == "" {
		config.tls.root_cas = platform_anchor[:0]
	}
	// A defer inside the load branch runs when that branch ends and nils the
	// roots before dial. Keep the pool until this procedure returns.
	pool: ^tls_api.Root_Pool
	defer if pool != nil {
		tls_api.root_pool_destroy(pool)
		free(pool)
	}
	if ca_file != "" {
		allocated, pool_error := new(tls_api.Root_Pool)
		if pool_error != nil || allocated == nil {
			if pool_error == nil do pool_error = .Out_Of_Memory
			result.error = buffered_http_allocation_error(pool_error)
			return
		}
		pool = allocated
		loaded := tls_api.root_pool_load_file(pool, ca_file)
		if loaded.kind != .None {
			result.error = {kind = .TLS_Failed, phase = .TLS, write_effect = .Not_Sent}
			return
		}
		config.tls.root_cas = pool.roots[:pool.count]
	}
	if !parsed.secure {
		socket, setup_error := bounded_socket(parsed, config, connection_setup_deadline(config, total))
		if setup_error.kind != .None {
			result.error = setup_error; return
		}
		defer net.close(socket)
		tcp := net.TCP_Connection{socket = socket}
		stream := net.tcp_connection(&tcp)
		if deadline_error := net.set_deadline(stream, total); deadline_error.kind != .None {
			result.error = buffered_tcp_timeout({
				kind = .Deadline_Failed, phase = .Deadline, transport = deadline_error, write_effect = .Not_Sent,
			})
			return
		}
		result = buffered_http_exchange(stream, method, parsed, body, headers, upload_file, upload_size, total, reply)
		result.error = buffered_tcp_timeout(result.error)
		return
	}
	connection, setup_error := http_tls_connect(parsed, config, total, context.allocator, nil)
	if setup_error.kind != .None {
		result.error = buffered_tcp_timeout(setup_error); return
	}
	defer {
		tls_api.abort(connection)
		free(connection, context.allocator)
	}
	if deadline_error := tls_api.set_deadline(connection, total); deadline_error.kind != .None {
		result.error = buffered_tcp_timeout({
			kind = .Deadline_Failed, phase = .Deadline, transport = deadline_error, write_effect = .Not_Sent,
		})
		return
	}
	selected := tls_api.connection_state(connection).negotiated_protocol
	if selected == "h2" {
		result = buffered_http_h2(connection, method, url, body, upload_file, upload_size, config, total, reply)
		result.error = buffered_tcp_timeout(result.error)
		return
	}
	if selected != "" && selected != "http/1.1" {
		result.error = {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
		return
	}
	adapter := TLS_Adapter{connection = connection}
	stream := net.Connection{data = &adapter, read = tls_read, write = tls_write, close = tls_close}
	result = buffered_http_exchange(stream, method, parsed, body, headers, upload_file, upload_size, total, reply)
	if result.error.kind == .IO_Failed {result.error.tls_io = adapter.last_error}
	result.error = buffered_tcp_timeout(result.error)
	return
}

// A timeout after the TCP connection exists is Unknown even when no HTTP request
// bytes were written. Unknown is the zero effect and is never replay-safe.
// Dial and certificate failures stay Not_Sent.
@(private)
buffered_tcp_timeout :: proc(error: HTTP_Error) -> HTTP_Error {
	result := error
	if result.kind == .None || result.kind == .Dial_Failed || result.write_effect != .Not_Sent {
		return result
	}
	if result.phase == .DNS || result.phase == .Connect || result.phase == .Configuration || result.phase == .TLS {
		return result
	}
	if result.phase == .Deadline {result.write_effect = .Unknown}
	return result
}

@(private)
buffered_http_method :: proc(method: string) -> (http.Method, bool) {
	switch method {
	case "GET": return .GET, true
	case "POST": return .POST, true
	case "PATCH": return .PATCH, true
	case "HEAD": return .HEAD, true
	case "PUT": return .PUT, true
	case "DELETE": return .DELETE, true
	case "OPTIONS": return .OPTIONS, true
	}
	return {}, false
}

@(private)
buffered_http_h2 :: proc(
	connection: ^tls_api.Conn, method, url: string, body: []byte,
	file: ^os.File, upload_size: i64, config: Config, deadline: time.Time, reply: ^Buffered_HTTP_Reply,
) -> Buffered_HTTP_Result {
	mapped, ok := buffered_http_method(method)
	if !ok {
		return {error = {kind = .Invalid_Method, phase = .Protocol, write_effect = .Not_Sent}}
	}
	request := http.Request{method = mapped, url = url}
	upload: Upload_Source
	upload_ptr: ^Upload_Source
	if file != nil {
		if !http.request_body_allowed(mapped) {
			return {error = {kind = .Invalid_Method, phase = .Protocol, write_effect = .Not_Sent}}
		}
		upload = {stream = os.to_stream(file), content_length = upload_size}
		upload_ptr = &upload
	} else if method == "PUT" || method == "POST" {
		request.body = body
	}
	response, error := h2_exchange_once(connection, request, upload_ptr, config, deadline, context.allocator, nil)
	defer response_destroy(&response)
	return buffered_http_from_response(&response, error, reply)
}

@(private)
buffered_http_from_response :: proc(response: ^Response, error: HTTP_Error, reply: ^Buffered_HTTP_Reply) -> Buffered_HTTP_Result {
	status := response.status
	if status == 0 {status = error.status}
	if error.kind == .None {
		if len(response.body) > len(reply.data) {
			return {
				status = status,
				error = {kind = .Body_Oversized, phase = .Body_Limit, status = status, write_effect = .Response_Received},
			}
		}
		copy(reply.data[:], response.body)
		reply.used = len(response.body)
		return {status = status, ok = status >= 200 && status < 300, transport_ok = true}
	}
	call := error
	if call.status == 0 {call.status = status}
	if call.phase == .Unknown || call.write_effect == .Not_Sent {
		effect := HTTP_Write_Effect.Unknown
		if status != 0 {effect = .Response_Received}
		call = http_error_classify(call, .Read, effect, status)
	}
	if call.kind == .Body_Oversized {
		call.phase = .Body_Limit
		if status != 0 {call.write_effect = .Response_Received}
	}
	return {status = status, error = call}
}

@(private)
buffered_http_exchange :: proc(
	stream: net.Connection, method: string, parsed: http.URL, body: []byte, headers: []string,
	file: ^os.File, upload_size: i64, deadline: time.Time, reply: ^Buffered_HTTP_Reply,
) -> Buffered_HTTP_Result {
	encoded: [http.MAX_HEADER_SIZE]u8
	count, encode_error := buffered_http_encode(encoded[:], method, parsed, body, headers, file, upload_size)
	if encode_error.kind != .None {return {error = encode_error}}
	outcome: HTTP_Exchange_Outcome
	outcome.write_started = true
	if _, write_error := net.write_all(stream, encoded[:count]); write_error.kind != .None {
		return {error = buffered_http_io(write_error, true, outcome)}
	}
	if file != nil {
		if read_error := buffered_http_upload(stream, file, upload_size, deadline); read_error.kind != .None {
			return {error = read_error}
		}
	} else if method == "PUT" || method == "POST" {
		if _, write_error := net.write_all(stream, body); write_error.kind != .None {
			return {error = buffered_http_io(write_error, true, outcome)}
		}
	}
	return buffered_http_read(stream, reply, &outcome)
}

@(private)
buffered_http_upload :: proc(stream: net.Connection, file: ^os.File, size: i64, deadline: time.Time) -> HTTP_Error {
	remaining := size
	buffer: [UPLOAD_BUFFER_SIZE]u8
	for remaining > 0 {
		if deadline != {} && time.diff(time.now(), deadline) <= 0 {
			return {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Unknown}
		}
		wanted := int(min(remaining, i64(len(buffer))))
		n, read_error := os.read(file, buffer[:wanted])
		if n < 0 || n > wanted {
			return {kind = .IO_Failed, phase = .Write, write_effect = .Unknown, source_io = buffered_source_io(read_error)}
		}
		if read_error != nil && read_error != io.Error.EOF {
			return {kind = .IO_Failed, phase = .Write, write_effect = .Unknown, source_io = buffered_source_io(read_error)}
		}
		if n == 0 {
			return {kind = .Unexpected_EOF, phase = .Write, write_effect = .Unknown, source_io = .EOF}
		}
		if _, write_error := net.write_all(stream, buffer[:n]); write_error.kind != .None {
			return buffered_http_io(write_error, true, {write_started = true})
		}
		remaining -= i64(n)
		if read_error == io.Error.EOF && remaining > 0 {
			return {kind = .Unexpected_EOF, phase = .Write, write_effect = .Unknown, source_io = .EOF}
		}
	}
	return {}
}

@(private)
buffered_http_read :: proc(stream: net.Connection, reply: ^Buffered_HTTP_Reply, outcome: ^HTTP_Exchange_Outcome) -> Buffered_HTTP_Result {
	response: Response
	response.allocator = context.allocator
	defer response_destroy(&response)
	reader := Reader{stream = stream}
	storage: [http.MAX_HEADER_SIZE]u8
	used, header_error := response_read_header(&reader, storage[:], &outcome.status)
	if header_error.kind != .None {
		return {status = outcome.status, error = buffered_http_read_error(header_error, outcome^)}
	}
	limit := len(reply.data)
	head, init_error := response_initialize(&response, storage[:used], limit, context.allocator)
	if init_error.kind != .None {
		if response.status != 0 {outcome.status = response.status}
		return {status = outcome.status, error = buffered_http_read_error(init_error, outcome^)}
	}
	outcome.status = head.status
	// Curl's custom request reads a HEAD body. Do not apply the native HEAD exception.
	if body_error := response_read_body(&reader, &response, head, limit); body_error.kind != .None {
		return {status = outcome.status, error = buffered_http_read_error(body_error, outcome^)}
	}
	// body_read fills body_storage. response.body is the published view.
	response.body = response.body_storage[:]
	if len(response.body) > len(reply.data) {
		reply.limit_exceeded = true
		return {
			status = outcome.status,
			error = {kind = .Body_Oversized, phase = .Body_Limit, status = outcome.status, write_effect = .Response_Received},
		}
	}
	copy(reply.data[:], response.body)
	reply.used = len(response.body)
	return {status = outcome.status, ok = outcome.status >= 200 && outcome.status < 300, transport_ok = true}
}

@(private)
buffered_http_read_error :: proc(error: HTTP_Error, outcome: HTTP_Exchange_Outcome) -> HTTP_Error {
	call := error
	if call.kind == .Body_Oversized {call.phase = .Body_Limit}
	effect := HTTP_Write_Effect.Unknown
	if outcome.status != 0 {effect = .Response_Received}
	fallback := HTTP_Phase.Read
	if call.phase != .Unknown {fallback = call.phase}
	call = http_error_classify(call, fallback, effect, outcome.status)
	if outcome.status != 0 {call.write_effect = .Response_Received}
	return call
}

@(private)
buffered_http_io :: proc(transport: net.Connection_Error, during_write: bool, outcome: HTTP_Exchange_Outcome) -> HTTP_Error {
	error := HTTP_Error {
		kind = .IO_Failed,
		transport = transport,
		phase = .Write if during_write else .Read,
	}
	effect := HTTP_Write_Effect.Unknown
	if outcome.status != 0 {effect = .Response_Received}
	return http_error_classify(error, error.phase, effect, outcome.status)
}

@(private)
buffered_source_io :: proc(error: os.Error) -> io.Error {
	if value, ok := error.(io.Error); ok do return value
	if error == nil do return .None
	return .Unknown
}

@(private)
buffered_http_append :: proc(dst: []u8, used: int, text: string) -> (int, bool) {
	if used > len(dst) || len(text) > len(dst) - used do return used, false
	copy(dst[used:], text)
	return used + len(text), true
}

// Method bytes are copied unchanged. A body buffer is sent only for the exact
// tokens PUT and POST; a file upload sends exactly upload_size bytes for any method.
@(private)
buffered_http_encode :: proc(
	dst: []u8, method: string, parsed: http.URL, body: []byte, headers: []string, file: ^os.File, upload_size: i64,
) -> (int, HTTP_Error) {
	Host_State :: struct {on: bool, value: string}
	host := Host_State{on = true, value = parsed.authority}
	accept := Host_State{on = true, value = "*/*"}
	length_on := file != nil || method == "PUT" || method == "POST"
	length_text: string
	digits: [32]u8
	if file != nil {
		length_text = strconv.write_int(digits[:], upload_size, 10)
	} else if length_on {
		length_text = strconv.write_int(digits[:], i64(len(body)), 10)
	}
	Custom :: struct {name, value: string, colon_only: bool}
	custom: [http.MAX_HEADERS]Custom
	custom_count := 0
	for header in headers {
		colon := strings.index_byte(header, ':')
		semi := strings.index_byte(header, ';')
		if colon < 0 && semi < 0 do continue
		name := header[:colon] if colon >= 0 else header[:semi]
		if !http.header_name_valid(name) {
			return 0, {kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}
		}
		suppress := colon >= 0 && len(strings.trim(header[colon + 1:], " \t")) == 0
		value := ""
		colon_only := false
		if colon < 0 {
			colon_only = true
		} else if !suppress {
			value = strings.trim(header[colon + 1:], " \t")
		}
		if strings.equal_fold(name, "Host") {
			host.on = !suppress
			if !suppress {host.value = value}
			continue
		}
		if strings.equal_fold(name, "Accept") {
			accept.on = !suppress
			if !suppress {accept.value = value}
			continue
		}
		if strings.equal_fold(name, "Content-Length") {
			length_on = !suppress && (file != nil || method == "PUT" || method == "POST" || !suppress)
			if suppress {length_on = false}
			if !suppress {length_text = value}
			continue
		}
		if suppress do continue
		if custom_count == len(custom) {
			return 0, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}
		custom[custom_count] = {name, value, colon_only}
		custom_count += 1
	}
	target := parsed.target
	prefix := ""
	if target == "" || target[0] == '?' do prefix = "/"
	used := 0
	ok := false
	parts := [?]string{method, " ", prefix, target, " HTTP/1.1\r\n"}
	for part in parts {
		used, ok = buffered_http_append(dst, used, part)
		if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
	}
	if host.on {
		for part in ([?]string{"Host: ", host.value, "\r\n"}) {
			used, ok = buffered_http_append(dst, used, part)
			if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
		}
	}
	if accept.on {
		for part in ([?]string{"Accept: ", accept.value, "\r\n"}) {
			used, ok = buffered_http_append(dst, used, part)
			if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
		}
	}
	for item in custom[:custom_count] {
		used, ok = buffered_http_append(dst, used, item.name)
		if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
		if item.colon_only {
			used, ok = buffered_http_append(dst, used, ":\r\n")
		} else {
			for part in ([?]string{": ", item.value, "\r\n"}) {
				used, ok = buffered_http_append(dst, used, part)
				if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
			}
		}
		if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
	}
	if length_on {
		for part in ([?]string{"Content-Length: ", length_text, "\r\n"}) {
			used, ok = buffered_http_append(dst, used, part)
			if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
		}
	}
	used, ok = buffered_http_append(dst, used, "\r\n")
	if !ok do return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
	return used, {}
}
