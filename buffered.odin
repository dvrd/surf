package surf

import "core:mem"
import "core:os"
import "core:strings"
import resources "core:sync/budget"
import http "../http"
import x509 "core:crypto/x509"
import tls_api "core:crypto/tls"
import "core:io"
import "core:net"
import "core:strconv"
import "core:time"

// Native TCP/TLS client. No redirects or proxies. The method token is sent
// unchanged on HTTP/1. Response bytes borrow the caller's temporary allocator,
// bounded to 64 KiB. provider_code stays zero.
Buffered_HTTP_Result :: struct {
	status:       int,
	ok:           bool,
	// A complete HTTP response can be non-2xx without a transport failure.
	transport_ok: bool,
	error:        HTTP_Error,
}

Buffered_HTTP_Reply :: struct {
	data: [64 * 1024]byte,
	used: int,
}

// Preserve the original procedure type for injected AWS/S3 HTTP callbacks.
buffered_http_execute :: proc(
	method, url: string,
	body: []byte,
	headers: []string,
	ca_file: string,
	allow_http := false,
	timeout_ms: i64 = 15000,
	upload_file: ^os.File = nil,
	upload_size: i64 = 0,
) -> (
	[]byte,
	Buffered_HTTP_Result,
) {
	return buffered_http_execute_managed(
		method,
		url,
		body,
		headers,
		ca_file,
		allow_http,
		timeout_ms,
		upload_file,
		upload_size,
	)
}

buffered_http_execute_managed :: proc(
	method, url: string,
	body: []byte,
	headers: []string,
	ca_file: string,
	allow_http := false,
	timeout_ms: i64 = 15000,
	upload_file: ^os.File = nil,
	upload_size: i64 = 0,
	scope: resources.Scope = {},
	allocator_scope: resources.Scope = {},
) -> (
	data: []byte,
	result: Buffered_HTTP_Result,
) {
	validation := buffered_http_validate(
		method,
		url,
		headers,
		allow_http,
		timeout_ms,
		upload_size,
		scope != (resources.Scope{}),
	)
	if validation.kind != .None do return nil, {error = validation}
	// Borrowed output has no independent destructor: managed mode requires an
	// explicit host promise about the temporary allocator's covered lifetime.
	if scope != (resources.Scope{}) && allocator_scope == (resources.Scope{}) {
		return nil, {error = budget_error(.Invalid_Config)}
	}
	ctx, output, admission := budget_begin(scope, allocator_scope, context.temp_allocator)
	if admission.kind != .None do return nil, {error = admission}
	defer budget_cleanup(&ctx)
	scratch, denied := buffered_http_scratch(scope)
	if denied.kind != .None do return nil, {error = denied}
	defer resources.release(&scratch)
	reply: Buffered_HTTP_Reply
	result = buffered_http_perform(method, url, body, headers, ca_file, timeout_ms, upload_file, upload_size, &reply)
	if !result.transport_ok do return
	copied, ae := make([]byte, reply.used, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae)
		return
	}
	copy(copied, reply.data[:reply.used])
	return copied, result
}

@(private)
buffered_http_allocation_error :: proc(error: mem.Allocator_Error) -> HTTP_Error {
	return {kind = .Allocation_Failed, phase = .Configuration, write_effect = .Not_Sent, allocation = error}
}

// Owned alternative to the borrowed temporary result. The allocator must outlive
// the Response or transferred body. A managed heap Binding supplies independent
// ownership; an explicitly covered caller arena still retains its own lifetime.
buffered_http_execute_owned :: proc(
	method, url: string,
	body: []byte,
	headers: []string,
	ca_file: string,
	allow_http := false,
	timeout_ms: i64 = 15000,
	upload_file: ^os.File = nil,
	upload_size: i64 = 0,
	allocator := context.allocator,
	scope: resources.Scope = {},
	allocator_scope: resources.Scope = {},
) -> (
	response: Response,
	result: Buffered_HTTP_Result,
) {
	validation := buffered_http_validate(
		method,
		url,
		headers,
		allow_http,
		timeout_ms,
		upload_size,
		scope != (resources.Scope{}),
	)
	if validation.kind != .None do return {}, {error = validation}
	ctx, output, admission := budget_begin(scope, allocator_scope, allocator)
	if admission.kind != .None do return {}, {error = admission}
	defer budget_cleanup(&ctx)
	scratch, denied := buffered_http_scratch(scope)
	if denied.kind != .None do return {}, {error = denied}
	defer resources.release(&scratch)
	// Setup cstrings are call-owned rather than leaked through a temporary heap
	// alias. Both arena backings use the already selected charged allocator.
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = output,
		array_allocator = output,
		block_size = 1024,
		out_band_size = 2048,
	)
	defer mem.dynamic_arena_destroy(&arena)
	previous := context.temp_allocator
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	defer context.temp_allocator = previous
	reply: Buffered_HTTP_Reply
	result = buffered_http_perform(method, url, body, headers, ca_file, timeout_ms, upload_file, upload_size, &reply)
	if !result.transport_ok do return
	copied, ae := buffered_http_owned_copy(&reply, result.status, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae)
		return
	}
	response = copied
	budget_response(&ctx, &response)
	return
}

@(private)
buffered_http_scratch :: proc(scope: resources.Scope) -> (resources.Lease, HTTP_Error) {
	if scope == (resources.Scope{}) do return {}, {}
	lease, denied := resources.reserve(scope, {bytes = 64 * 1024})
	if denied != .None do return {}, budget_error(denied)

	return lease, {}
}
@(private)
buffered_http_copy_error :: proc(previous: Buffered_HTTP_Result, error: mem.Allocator_Error) -> Buffered_HTTP_Result {
	result := previous
	result.ok, result.transport_ok = false, false
	result.error = {
		kind         = .Allocation_Failed,
		phase        = .Read,
		allocation   = error,
		status       = result.status,
		write_effect = .Response_Received,
	}

	return result
}

@(private)
buffered_http_owned_copy :: proc(
	reply: ^Buffered_HTTP_Reply,
	status: int,
	allocator: mem.Allocator,
) -> (
	Response,
	mem.Allocator_Error,
) {
	storage, error := make([dynamic]u8, reply.used, reply.used, allocator)
	if error != nil do return {}, error
	copy(storage[:], reply.data[:reply.used])
	return {status = status, body = storage[:], body_storage = storage, allocator = allocator}, nil
}

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
		error.kind = parse_error.kind
		return error
	}
	if !allow_http && !parsed.secure {
		error.kind = .Insecure_URL
		return error
	}
	if !http.header_name_valid(method) {
		error.kind = .Invalid_Method
		return error
	}
	if timeout_ms <= 0 || timeout_ms > 120000 || upload_size < 0 do return error
	if managed && len(headers) > http.MAX_HEADERS {
		error.kind = .Header_Limit
		return error
	}
	bytes := 0
	for header in headers {
		if strings.contains_any(header, "\r\n\x00") {
			error.kind = .Invalid_Header
			return error
		}

		if managed {
			if len(header) > http.MAX_HEADER_SIZE - bytes {
				error.kind = .Header_Oversized
				return error
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
		result.error = buffered_http_allocation_error(allocation_error)
		return
	}
	parsed, parse_error := http.url_parse(url)
	if parse_error.kind != .None {
		result.error = {
			kind         = parse_error.kind,
			phase        = .Configuration,
			write_effect = .Not_Sent,
		}

		return
	}
	timeout := time.Duration(timeout_ms) * time.Millisecond
	total := time.time_add(time.now(), timeout)
	if time.diff(time.now(), total) <= 0 {
		result.error = {
			kind         = .Deadline_Failed,
			phase        = .Deadline,
			write_effect = .Not_Sent,
		}

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
			result.error = {
				kind         = .TLS_Failed,
				phase        = .TLS,
				write_effect = .Not_Sent,
			}

			return
		}

		config.tls.root_cas = pool.roots[:pool.count]
	}
	if !parsed.secure {
		socket, setup_error := bounded_socket(parsed, config, connection_setup_deadline(config, total))

		if setup_error.kind != .None {
			result.error = setup_error
			return
		}

		defer net.close(socket)
		tcp := net.TCP_Connection {
			socket = socket,
		}

		stream := net.tcp_connection(&tcp)

		if deadline_error := net.set_deadline(stream, total); deadline_error.kind != .None {
			result.error = buffered_tcp_timeout(
				{kind = .Deadline_Failed, phase = .Deadline, transport = deadline_error, write_effect = .Not_Sent},
			)
			return
		}

		result = buffered_http_exchange(stream, method, parsed, body, headers, upload_file, upload_size, total, reply)
		result.error = buffered_tcp_timeout(result.error)
		return
	}
	connection, setup_error := http_tls_connect(parsed, config, total, context.allocator, nil)
	if setup_error.kind != .None {
		result.error = buffered_tcp_timeout(setup_error)
		return
	}
	defer {
		tls_api.abort(connection)
		free(connection, context.allocator)
	}
	if deadline_error := tls_api.set_deadline(connection, total); deadline_error.kind != .None {
		result.error = buffered_tcp_timeout(
			{kind = .Deadline_Failed, phase = .Deadline, transport = deadline_error, write_effect = .Not_Sent},
		)
		return
	}
	selected := tls_api.connection_state(connection).negotiated_protocol
	if selected == "h2" {
		result = buffered_http_h2(
			connection,
			method,
			url,
			body,
			headers,
			upload_file,
			upload_size,
			config,
			total,
			reply,
		)
		result.error = buffered_tcp_timeout(result.error)
		return
	}
	if selected != "" && selected != "http/1.1" {
		result.error = {
			kind         = .IO_Failed,
			phase        = .Protocol,
			write_effect = .Not_Sent,
		}

		return
	}
	adapter := TLS_Adapter {
		connection = connection,
	}
	stream := net.Connection {
		data  = &adapter,
		read  = tls_read,
		write = tls_write,
		close = tls_close,
	}
	result = buffered_http_exchange(stream, method, parsed, body, headers, upload_file, upload_size, total, reply)
	if result.error.kind == .IO_Failed {
		result.error.tls_io = adapter.last_error
	}
	result.error = buffered_tcp_timeout(result.error)
	return
}

// A timeout after the TCP connection exists is Unknown even when no HTTP request
// bytes were written. Unknown is the zero effect and is never replay-safe.
// Dial and certificate failures stay Not_Sent.
@(private)
buffered_tcp_timeout :: proc(error: HTTP_Error) -> HTTP_Error {
	result := error
	if result.kind != .None &&
	   result.kind != .Dial_Failed &&
	   result.phase == .Deadline &&
	   result.write_effect == .Not_Sent {
		result.write_effect = .Unknown
	}

	return result
}

@(private)
buffered_http_method :: proc(method: string) -> (http.Method, bool) {
	switch method {
	case "GET":
		return .GET, true
	case "POST":
		return .POST, true
	case "PATCH":
		return .PATCH, true
	case "HEAD":
		return .HEAD, true
	case "PUT":
		return .PUT, true
	case "DELETE":
		return .DELETE, true
	case "OPTIONS":
		return .OPTIONS, true
	}

	return {}, false
}

@(private)
buffered_http_h2 :: proc(
	connection: ^tls_api.Conn,
	method, url: string,
	body: []byte,
	headers: []string,
	file: ^os.File,
	upload_size: i64,
	config: Config,
	deadline: time.Time,
	reply: ^Buffered_HTTP_Reply,
) -> Buffered_HTTP_Result {
	mapped, ok := buffered_http_method(method)
	if !ok {
		return {error = {kind = .Invalid_Method, phase = .Protocol, write_effect = .Not_Sent}}
	}
	request := http.Request {
		method = mapped,
		url    = url,
	}
	fields: [http.MAX_HEADERS]http.Header
	parsed_headers, header_error := buffered_http_h2_headers(headers, fields[:])
	if header_error.kind != .None {
		return {error = header_error}
	}
	request.headers = parsed_headers
	upload: Upload_Source
	upload_ptr: ^Upload_Source
	if file != nil {
		if !http.request_body_allowed(mapped) {
			return {error = {kind = .Invalid_Method, phase = .Protocol, write_effect = .Not_Sent}}
		}

		upload = {
			stream         = os.to_stream(file),
			content_length = upload_size,
		}

		upload_ptr = &upload
	} else if method == "PUT" || method == "POST" {
		request.body = body
	}
	response, error := h2_exchange_once(connection, request, upload_ptr, config, deadline, context.allocator, nil)
	defer response_destroy(&response)
	return buffered_http_from_response(&response, error, reply)
}

// The buffered header-list convention: "Name: value" sends the value, "Name:"
// suppresses the field and "Name;" sends it with an empty value. A line with
// neither separator is not present.
@(private)
buffered_http_header :: proc(header: string) -> (name, value: string, suppress, present: bool) {
	if colon := strings.index_byte(header, ':'); colon >= 0 {
		value = strings.trim(header[colon + 1:], " \t")
		return header[:colon], value, value == "", true
	}

	semi := strings.index_byte(header, ';')
	if semi < 0 do return

	return header[:semi], "", false, true
}

// Passes application fields through the shared HTTP/2 encoder.
@(private)
buffered_http_h2_headers :: proc(headers: []string, storage: []http.Header) -> ([]http.Header, HTTP_Error) {
	count := 0

	for header in headers {
		name, value, suppress, present := buffered_http_header(header)
		if !present do continue

		if !http.header_name_valid(name) {
			return nil, {kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}
		}

		if suppress do continue

		if !http.header_value_valid(value) {
			return nil, {kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}
		}

		if count == len(storage) {
			return nil, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}

		storage[count] = {
			name  = name,
			value = value,
		}

		count += 1
	}

	return storage[:count], {}
}

@(private)
buffered_http_from_response :: proc(
	response: ^Response,
	error: HTTP_Error,
	reply: ^Buffered_HTTP_Reply,
) -> Buffered_HTTP_Result {
	status := response.status
	if status == 0 {
		status = error.status
	}
	if error.kind == .None {
		if len(response.body) > len(reply.data) {
			return {
				status = status,
				error = {
					kind = .Body_Oversized,
					phase = .Body_Limit,
					status = status,
					write_effect = .Response_Received,
				},
			}
		}

		copy(reply.data[:], response.body)
		reply.used = len(response.body)
		return {status = status, ok = status >= 200 && status < 300, transport_ok = true}
	}
	call := error
	if call.status == 0 {
		call.status = status
	}
	if call.phase == .Unknown || call.write_effect == .Not_Sent {
		effect := HTTP_Write_Effect.Unknown

		if status != 0 {
			effect = .Response_Received
		}

		call = http_error_classify(call, .Read, effect, status)
	}
	if call.kind == .Body_Oversized {
		call.phase = .Body_Limit

		if status != 0 {
			call.write_effect = .Response_Received
		}
	}
	return {status = status, error = call}
}

@(private)
buffered_http_exchange :: proc(
	stream: net.Connection,
	method: string,
	parsed: http.URL,
	body: []byte,
	headers: []string,
	file: ^os.File,
	upload_size: i64,
	deadline: time.Time,
	reply: ^Buffered_HTTP_Reply,
) -> Buffered_HTTP_Result {
	encoded: [http.MAX_HEADER_SIZE]u8
	count, encode_error := buffered_http_encode(encoded[:], method, parsed, body, headers, file, upload_size)
	if encode_error.kind != .None {
		return {error = encode_error}
	}
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
			return {
				kind = .IO_Failed,
				phase = .Write,
				write_effect = .Unknown,
				source_io = buffered_source_io(read_error),
			}
		}

		if read_error != nil && read_error != io.Error.EOF {
			return {
				kind = .IO_Failed,
				phase = .Write,
				write_effect = .Unknown,
				source_io = buffered_source_io(read_error),
			}
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
buffered_http_read :: proc(
	stream: net.Connection,
	reply: ^Buffered_HTTP_Reply,
	outcome: ^HTTP_Exchange_Outcome,
) -> Buffered_HTTP_Result {
	response: Response
	response.allocator = context.allocator
	defer response_destroy(&response)
	reader := Reader {
		stream = stream,
	}
	storage: [http.MAX_HEADER_SIZE]u8
	used, header_error := response_read_header(&reader, storage[:], &outcome.status)
	if header_error.kind != .None {
		return {status = outcome.status, error = buffered_http_read_error(header_error, outcome^)}
	}
	limit := len(reply.data)
	head, init_error := response_initialize(&response, storage[:used], limit, context.allocator)
	if init_error.kind != .None {
		if response.status != 0 {
			outcome.status = response.status
		}

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
		return {
			status = outcome.status,
			error = {
				kind = .Body_Oversized,
				phase = .Body_Limit,
				status = outcome.status,
				write_effect = .Response_Received,
			},
		}
	}
	copy(reply.data[:], response.body)
	reply.used = len(response.body)
	return {status = outcome.status, ok = outcome.status >= 200 && outcome.status < 300, transport_ok = true}
}

@(private)
buffered_http_read_error :: proc(error: HTTP_Error, outcome: HTTP_Exchange_Outcome) -> HTTP_Error {
	call := error

	if call.kind == .Body_Oversized {
		call.phase = .Body_Limit
	}

	effect := HTTP_Write_Effect.Unknown

	if outcome.status != 0 {
		effect = .Response_Received
	}

	fallback := HTTP_Phase.Read

	if call.phase != .Unknown {
		fallback = call.phase
	}

	call = http_error_classify(call, fallback, effect, outcome.status)

	if outcome.status != 0 {
		call.write_effect = .Response_Received
	}

	return call
}

@(private)
buffered_http_io :: proc(
	transport: net.Connection_Error,
	during_write: bool,
	outcome: HTTP_Exchange_Outcome,
) -> HTTP_Error {
	error := HTTP_Error {
		kind      = .IO_Failed,
		transport = transport,
		phase     = .Write if during_write else .Read,
	}
	effect := HTTP_Write_Effect.Unknown
	if outcome.status != 0 {
		effect = .Response_Received
	}
	return http_error_classify(error, error.phase, effect, outcome.status)
}

@(private)
buffered_source_io :: proc(error: os.Error) -> io.Error {
	if value, ok := error.(io.Error); ok do return value
	if error == nil do return .None

	return .Unknown
}

@(private)
Buffered_HTTP_Writer :: struct {
	dst:      []u8,
	used:     int,
	overflow: bool,
}

@(private)
buffered_http_put :: proc(w: ^Buffered_HTTP_Writer, parts: ..string) {
	for part in parts {
		if len(part) > len(w.dst) - w.used {
			w.overflow = true
			return
		}

		w.used += copy(w.dst[w.used:], part)
	}
}

// Method bytes are copied unchanged. A body buffer is sent only for the exact
// tokens PUT and POST; a file upload sends exactly upload_size bytes for any method.
@(private)
buffered_http_encode :: proc(
	dst: []u8,
	method: string,
	parsed: http.URL,
	body: []byte,
	headers: []string,
	file: ^os.File,
	upload_size: i64,
) -> (
	int,
	HTTP_Error,
) {
	Default :: struct {
		on:    bool,
		value: string,
	}
	host := Default {
		on    = true,
		value = parsed.authority,
	}
	accept := Default {
		on    = true,
		value = "*/*",
	}
	length_on := file != nil || method == "PUT" || method == "POST"
	length_text: string
	digits: [32]u8
	if file != nil {
		length_text = strconv.write_int(digits[:], upload_size, 10)
	} else if length_on {
		length_text = strconv.write_int(digits[:], i64(len(body)), 10)
	}
	custom: [http.MAX_HEADERS]http.Header
	custom_count := 0
	for header in headers {
		name, value, suppress, present := buffered_http_header(header)
		if !present do continue

		if !http.header_name_valid(name) {
			return 0, {kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}
		}

		if strings.equal_fold(name, "Host") {
			host.on = !suppress

			if !suppress {
				host.value = value
			}

			continue
		}

		if strings.equal_fold(name, "Accept") {
			accept.on = !suppress

			if !suppress {
				accept.value = value
			}

			continue
		}

		if strings.equal_fold(name, "Content-Length") {
			length_on = !suppress

			if !suppress {
				length_text = value
			}

			continue
		}

		if suppress do continue

		if custom_count == len(custom) {
			return 0, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
		}

		custom[custom_count] = {
			name  = name,
			value = value,
		}

		custom_count += 1
	}
	target := parsed.target
	prefix := ""
	if target == "" || target[0] == '?' do prefix = "/"
	w := Buffered_HTTP_Writer {
		dst = dst,
	}
	buffered_http_put(&w, method, " ", prefix, target, " HTTP/1.1\r\n")
	if host.on do buffered_http_put(&w, "Host: ", host.value, "\r\n")
	if accept.on do buffered_http_put(&w, "Accept: ", accept.value, "\r\n")
	for item in custom[:custom_count] {
		// Only the "Name;" form reaches here with an empty value.
		if item.value == "" {
			buffered_http_put(&w, item.name, ":\r\n")
		} else {
			buffered_http_put(&w, item.name, ": ", item.value, "\r\n")
		}
	}
	if length_on do buffered_http_put(&w, "Content-Length: ", length_text, "\r\n")
	buffered_http_put(&w, "\r\n")
	if w.overflow {
		return 0, {kind = .Header_Oversized, phase = .Configuration, write_effect = .Not_Sent}
	}
	return w.used, {}
}
