package surf


import http "../http"
import http1 "../http/v1"
import tls_api "core:crypto/tls"
import trans "core:net"
import "core:mem"
import "core:net"
import "core:slice"
import "core:strings"
import "core:time"



HTTP_Error :: struct {
	kind:       http.Error_Kind,
	transport:  trans.Connection_Error,
	network:    net.Network_Error,
	tls_dial:   tls_api.Dial_Error,
	tls_io:     tls_api.IO_Error,
	allocation: mem.Allocator_Error,
}

Config :: struct {
	tls:           tls_api.Config,
	// Zero selects 8 MiB. All responses, including redirect bodies, are bounded.
	max_body_size: int,
	// Zero disables automatic redirects; maximum5. POST follows only307/308.
	max_redirects: int,
	// Zero selects30s for the entire I/O/redirect budget. DNS/TCP connect
	// uses core:net's dial behavior; TLS handshake uses tls.handshake_timeout.
	timeout:       time.Duration,
	allow_http:    bool,
}


// Owns header strings/body. Do not copy and destroy twice. Destroy on success;
// errors return an empty response. Content-Encoding is not decompressed.
Response :: struct {
	status:         int,
	headers:        []http.Header,
	body:           []u8,
	allocator:      mem.Allocator,
	header_storage: []u8,
	body_storage:   [dynamic]u8,
}
response_destroy :: proc(response: ^Response) {
	if response == nil do return

	if response.allocator.procedure != nil {
		delete(response.headers, response.allocator)
		delete(response.header_storage, response.allocator)
		delete(response.body_storage)
	}

	response^ = {}
}
response_header :: proc(
	response: ^Response,
	name: string,
) -> (
	string,
	bool,
) {
	if response == nil do return "", false

	for h in response.headers do if strings.equal_fold(h.name, name) {
		return h.value, true
	}

	return "", false
}

// Single blocking request. HTTPS authentication always derives server_name
// from the URL rather than reusing a different host's TLS config. Roots borrow
// the caller's Root_Pool. Each redirect establishes a fresh connection.
execute :: proc(
	request: http.Request,
	config: Config,
	allocator := context.allocator,
) -> (
	response: Response,
	err: HTTP_Error,
) {
	if e := config_validate(config); e.kind != .None {
		return {}, e
	}

	current := request
	owned_url: string
	defer if len(owned_url) > 0 {
		delete(owned_url, allocator)
	}

	total_deadline := time.time_add(
		time.now(),
		effective_timeout(config),
	)
	for redirects := 0;; redirects += 1 {
		// Preflight before networking, including all caller-controlled headers.
		storage: [http.MAX_HEADER_SIZE]u8
		_, validation := http1.request_encode(storage[:], current)
		if validation.kind != .None do return {}, http_protocol_error(validation)

		u, e := http.url_parse(current.url)
		if e.kind != .None do return {}, http_protocol_error(e)

		if !u.secure && !config.allow_http {
			return {}, {kind = .Insecure_URL}
		}

		if time.diff(time.now(), total_deadline) <= 0 {
			return {}, {kind = .Deadline_Failed}
		}

		if u.secure {
			response, err = execute_tls(u, current, config, total_deadline, allocator)
		} else {
			response, err = execute_tcp(u, current, config, total_deadline, allocator)
		}

		if err.kind != .None do return {}, err

		redirect := slice.contains(
			[]type_of(response.status){301, 302, 303, 307, 308},
			response.status,
		)
		if !redirect || config.max_redirects == 0 {
			return response, {}
		}

		new_url, redirect_error := execute_redirect(
			&response, current, u, config, redirects, allocator,
		)
		if redirect_error.kind != .None {return {}, redirect_error}

		if len(owned_url) > 0 {
			delete(owned_url, allocator)
		}

		owned_url, current.url = new_url, new_url
	}
}

execute_tls :: proc(
	url: http.URL, request: http.Request, config: Config, total_deadline: time.Time,
	allocator: mem.Allocator,
) -> (response: Response, err: HTTP_Error) {
	connection, allocation_err := new(
		tls_api.Conn,
		allocator,
	)
	if allocation_err != nil {
		return {}, {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	settings := config.tls
	settings.server_name = url.host
	dial_err := tls_api.dial(
		connection,
		url.host,
		url.port,
		settings,
	)
	if dial_err.kind != .None {
		free(connection, allocator)
		return {}, {kind = .TLS_Failed, tls_dial = dial_err}
	}

	adapter := TLS_Adapter {
		connection = connection,
	}
	stream := trans.Connection {
		data  = &adapter,
		read  = tls_read,
		write = tls_write,
		close = tls_close,
	}
	deadline_err := tls_api.set_deadline(
		connection,
		total_deadline,
	)
	if deadline_err.kind == .None {
		response, err = exchange(
			stream,
			request,
			config.max_body_size,
			allocator,
		)
		if err.kind == .IO_Failed {
			err.tls_io = adapter.last_error
		}
	} else {
		err = {
			kind      = .Deadline_Failed,
			transport = deadline_err,
		}
	}

	tls_api.abort(connection)
	free(connection, allocator)

	return response, err
}

execute_tcp :: proc(
	url: http.URL, request: http.Request, config: Config, total_deadline: time.Time,
	allocator: mem.Allocator,
) -> (response: Response, err: HTTP_Error) {
	socket, dial_err := net.dial_tcp(url.host, url.port)
	if dial_err != nil {
		return {}, {kind = .Dial_Failed, network = dial_err}
	}

	connection := trans.TCP_Connection {
		socket = socket,
	}
	stream := trans.tcp_connection(&connection)
	deadline_err := trans.set_deadline(
		stream,
		total_deadline,
	)
	if deadline_err.kind == .None {
		response, err = exchange(
			stream,
			request,
			config.max_body_size,
			allocator,
		)
	} else {
		err = {
			kind      = .Deadline_Failed,
			transport = deadline_err,
		}
	}

	stream.close(stream.data)

	return response, err
}

execute_redirect :: proc(
	response: ^Response, current: http.Request, u: http.URL, config: Config,
	redirects: int, allocator: mem.Allocator,
) -> (string, HTTP_Error) {
	if redirects >= config.max_redirects {
		response_destroy(response)
		return "", {kind = .Redirect_Limit}
	}

	if current.method != .GET &&
	   !slice.contains(
			   []type_of(response.status){307, 308},
			   response.status,
		   ) {
		response_destroy(response)
		return "", {kind = .Unsafe_Redirect}
	}

	location, has_location := response_header(
		response,
		"Location",
	)
	locations := 0
	for h in response.headers do if strings.equal_fold(h.name, "Location") {
		locations += 1
	}

	if !has_location || locations != 1 {
		response_destroy(response)
		return "", {kind = .Invalid_Redirect}
	}

	new_url, resolve_err := redirect_url(u, location, allocator)
	response_destroy(response)
	if resolve_err.kind != .None {
		return "", resolve_err
	}

	new_parsed, parse_err := http.url_parse(new_url)
	if parse_err.kind != .None {
		delete(new_url, allocator)
		return "", {kind = .Invalid_Redirect}
	}

	if u.secure && !new_parsed.secure ||
	   !new_parsed.secure && !config.allow_http {
		delete(new_url, allocator)
		return "", {kind = .Insecure_URL}
	}

	if !redirect_origin_safe(current, u, new_parsed) {
		delete(new_url, allocator)
		return "", {kind = .Unsafe_Redirect}
	}
	return new_url, {}
}

redirect_origin_safe :: proc(request: http.Request, previous, next: http.URL) -> bool {
	cross_origin := previous.secure != next.secure || previous.port != next.port ||
	                !strings.equal_fold(previous.host, next.host)
	if !cross_origin {return true}
	// Only a GET with public media headers may cross origins automatically.
	if request.method != .GET {return false}
	for header in request.headers {
		safe := false
		for name in ([?]string{"Accept", "Content-Type", "Origin", "User-Agent"}) {
			if strings.equal_fold(header.name, name) {safe = true}
		}
		if !safe {return false}
	}
	return true
}

// Uses an already connected caller-owned stream, performs no redirect/TLS
// policy, does not close it, and consumes exactly one response. The caller must
// set deadlines. Any unconsumed bytes are discarded: do not reuse the stream.
exchange :: proc(
	stream: trans.Connection,
	request: http.Request,
	max_body_size: int = 0,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	response: Response
	if !trans.connection_valid(stream) {
		return {}, {kind = .Invalid_Config}
	}

	if max_body_size < 0 || max_body_size > http.MAX_BODY_SIZE {
		return {}, {kind = .Invalid_Config}
	}

	limit := max_body_size
	if limit == 0 do limit = http.DEFAULT_MAX_BODY_SIZE

	encoded: [http.MAX_HEADER_SIZE]u8
	n, e := http1.request_encode(encoded[:], request)
	if e.kind != .None do return {}, http_protocol_error(e)

	if _, write_err := trans.write_all(stream, encoded[:n]);
	   write_err.kind != .None {
		return {}, {kind = .IO_Failed, transport = write_err}
	}

	if _, write_err := trans.write_all(stream, request.body);
	   write_err.kind != .None {
		return {}, {kind = .IO_Failed, transport = write_err}
	}

	reader := Reader {
		stream = stream,
	}
	storage: [http.MAX_HEADER_SIZE]u8
	used, header_error := response_read_header(&reader, storage[:])
	if header_error.kind != .None {return {}, header_error}
	response.allocator = allocator
	success := false
	defer if !success do response_destroy(&response)

	head, initialize_error := response_initialize(&response, storage[:used], limit, allocator)
	if initialize_error.kind != .None {return {}, initialize_error}
	// HEAD describes the representation, but carries no response body.
	http1.response_apply_method(&head, request.method)
	if body_error := response_read_body(&reader, &response, head, limit); body_error.kind != .None {
		return {}, body_error
	}
	response.body = response.body_storage[:]
	success = true
	return response, {}
}

response_read_header :: proc(reader: ^Reader, storage: []u8) -> (int, HTTP_Error) {
	assert(len(storage) == http.MAX_HEADER_SIZE)
	used := 0
	for informational := 0;; informational += 1 {
		used = 0
		for {
			if used == http.MAX_HEADER_SIZE {
				return 0, {kind = .Header_Oversized}
			}

			v, read_err := reader_byte(reader)
			if read_err.kind != .None do return 0, read_err

			storage[used] = v
			used += 1
			if used >= 4 &&
			   storage[used - 4] == 13 &&
			   storage[used - 3] == 10 &&
			   storage[used - 2] == 13 &&
			   storage[used - 1] == 10 {
				break
			}
		}
		head, _, he := http1.response_header_decode(storage[:used])
		if he.kind != .None do return 0, http_protocol_error(he)

		if head.status == 101 {
			return 0, {kind = .Invalid_Status}
		}

		if head.status >= 200 do break

		if informational == 7 {
			return 0, {kind = .Too_Many_Informational}
		}
	}
	return used, {}
}

response_initialize :: proc(
	response: ^Response, storage: []u8, limit: int, allocator: mem.Allocator,
) -> (http1.Response_Head, HTTP_Error) {
	header_storage, ae := make([]u8, len(storage), allocator)
	if ae != nil {
		return http1.Response_Head{}, {kind = .Allocation_Failed, allocation = ae}
	}

	response.header_storage = header_storage
	copy(header_storage, storage)
	head, _, _ := http1.response_header_decode(header_storage)
	response.status = head.status
	headers, hae := make([]http.Header, head.header_count, allocator)
	if hae != nil {
		return http1.Response_Head{}, {kind = .Allocation_Failed, allocation = hae}
	}

	response.headers = headers
	copy(headers, head.headers[:head.header_count])
	body, bae := make([dynamic]u8, 0, min(4096, limit), allocator)
	if bae != nil {
		return http1.Response_Head{}, {kind = .Allocation_Failed, allocation = bae}
	}

	response.body_storage = body
	return head, {}
}

response_read_body :: proc(
	reader: ^Reader, response: ^Response, head: http1.Response_Head, limit: int,
) -> HTTP_Error {
	if head.framing == .Length &&
	   head.content_length > cast(u64)limit {
		return {kind = .Body_Oversized}
	}

	switch head.framing {
	case .None:
	case .Length:
		if operation_error := body_read(
			reader,
			&response.body_storage,
			cast(int)head.content_length,
			limit,
		); operation_error.kind != .None {
			return operation_error
		}

	case .EOF:
		return response_read_eof(reader, &response.body_storage, limit)
	case .Chunked:
		return response_read_chunked(reader, &response.body_storage, limit)
	}
	return {}
}

response_read_eof :: proc(reader: ^Reader, body: ^[dynamic]u8, limit: int) -> HTTP_Error {
	for {
		operation_error_2 := reader_fill(reader)
		if operation_error_2.kind != .None {
			if reader.pending.kind == .Peer_Closed {
				break
			}

			return operation_error_2
		}

		if operation_error := body_read(
			reader,
			body,
			reader.used - reader.at,
			limit,
		); operation_error.kind != .None {
			return operation_error
		}
	}
	return {}
}

response_read_chunked :: proc(reader: ^Reader, body: ^[dynamic]u8, limit: int) -> HTTP_Error {
	line: [http.MAX_HEADER_SIZE]u8
	metadata := 0
	for {
		read_count, operation_error_2 := reader_line(reader, line[:], &metadata)
		if operation_error_2.kind != .None do return operation_error_2

		size, se := http1.chunk_size_decode(cast(string)line[:read_count])
		if se.kind != .None do return http_protocol_error(se)

		if size == 0 do break

		if size > cast(u64)(limit - len(body^)) {
			return {kind = .Body_Oversized}
		}

		if operation_error := body_read(
			reader,
			body,
			cast(int)size,
			limit,
		); operation_error.kind != .None {
			return operation_error
		}

		for expected in ([?]u8{13, 10}) {
			v, re := reader_byte(reader)
			if re.kind != .None do return re

			if v != expected {
				return {kind = .Invalid_Chunk}
			}
		}
	}
	for {
		read_count, operation_error := reader_line(reader, line[:], &metadata)
		if operation_error.kind != .None do return operation_error

		if read_count == 0 do break

		h, he := http1.header_line_decode(cast(string)line[:read_count])
		if he.kind != .None || http1.forbidden_trailer(h.name) {
			return {kind = .Invalid_Trailer}
		}
	}
	return {}
}

Reader :: struct {
	stream:   trans.Connection,
	buffer:   [8192]u8,
	at, used: int,
	pending:  trans.Connection_Error,
}
HTTP_MAX_CHUNK_METADATA_SIZE :: 65536

reader_fill :: proc(r: ^Reader) -> HTTP_Error {
	if r.at < r.used do return {}

	if r.pending.kind != .None {
		if r.pending.kind == .Peer_Closed {
			return {kind = .Unexpected_EOF, transport = r.pending}
		}

		return {kind = .IO_Failed, transport = r.pending}
	}

	n, e := r.stream.read(r.stream.data, r.buffer[:])
	if n < 0 || n > len(r.buffer) {
		return {
			kind = .IO_Failed,
			transport = {kind = .Invalid_Count},
		}
	}

	r.at, r.used, r.pending = 0, n, e
	if n > 0 do return {}

	if e.kind == .None do return {kind = .No_Progress}

	if e.kind == .Peer_Closed {
		return {kind = .Unexpected_EOF, transport = e}
	}

	return {kind = .IO_Failed, transport = e}
}
reader_byte :: proc(r: ^Reader) -> (u8, HTTP_Error) {
	if e := reader_fill(r); e.kind != .None do return 0, e

	v := r.buffer[r.at]
	r.at += 1
	return v, {}
}
body_read :: proc(
	r: ^Reader,
	body: ^[dynamic]u8,
	count, limit: int,
) -> HTTP_Error {
	if count > limit - len(body^) {
		return {kind = .Body_Oversized}
	}

	remaining := count
	for remaining > 0 {
		if e := reader_fill(r); e.kind != .None do return e

		n := min(remaining, r.used - r.at)
		_, ae := append(body, ..r.buffer[r.at:r.at + n])
		if ae != nil {
			return {kind = .Allocation_Failed, allocation = ae}
		}

		r.at += n
		remaining -= n
	}
	return {}
}
reader_line :: proc(
	r: ^Reader,
	dst: []u8,
	metadata: ^int,
) -> (
	int,
	HTTP_Error,
) {
	at := 0
	for {
		if metadata^ >= HTTP_MAX_CHUNK_METADATA_SIZE {
			return 0, {kind = .Header_Oversized}
		}
		v, e := reader_byte(r)
		if e.kind != .None do return 0, e

		metadata^ += 1
		if at == len(dst) {
			return 0, {kind = .Header_Oversized}
		}

		if v == 13 {
			// CR and LF both consume the shared chunk/trailer metadata budget.
			if metadata^ >= HTTP_MAX_CHUNK_METADATA_SIZE {
				return 0, {kind = .Header_Oversized}
			}
			next, ne := reader_byte(r)
			if ne.kind != .None do return 0, ne

			metadata^ += 1
			if next != 10 {
				return 0, {kind = .Invalid_Chunk}
			}

			return at, {}
		}

		if v == 10 do return 0, {kind = .Invalid_Chunk}

		dst[at] = v
		at += 1
	}
}
config_validate :: proc(c: Config) -> HTTP_Error {
	if c.max_body_size < 0 ||
	   c.max_body_size > http.MAX_BODY_SIZE ||
	   c.max_redirects < 0 ||
	   c.max_redirects > http.MAX_REDIRECTS ||
	   c.timeout < 0 {
		return {kind = .Invalid_Config}
	}

	return {}
}
effective_timeout :: proc(c: Config) -> time.Duration {
	if c.timeout == 0 do return 30 * time.Second

	return c.timeout
}

TLS_Adapter :: struct {
	connection: ^tls_api.Conn,
	last_error: tls_api.IO_Error,
}
tls_read :: proc(data: rawptr, dst: []u8) -> (int, trans.Connection_Error) {
	a := cast(^TLS_Adapter)data
	n, e := tls_api.read(a.connection, dst)
	a.last_error = e
	if e.kind == .EOF do return n, {kind = .Peer_Closed}

	if e.kind != .None do return n, {kind = .Read_Failed}

	return n, {}
}
tls_write :: proc(data: rawptr, src: []u8) -> (int, trans.Connection_Error) {
	a := cast(^TLS_Adapter)data
	n, e := tls_api.write(a.connection, src)
	a.last_error = e
	if e.kind != .None do return n, {kind = .Write_Failed}

	return n, {}
}
tls_close :: proc(data: rawptr) -> trans.Connection_Error {
	a := cast(^TLS_Adapter)data
	e := tls_api.abort(a.connection)
	if e.kind != .None do return {kind = .Closed}

	return {}
}

// Resolve absolute, network-path, root-relative, query-only and relative paths.
// Dot segments are removed without decoding percent escapes (RFC3986 section5).
redirect_url :: proc(
	base: http.URL,
	location: string,
	allocator: mem.Allocator,
) -> (
	string,
	HTTP_Error,
) {
	if len(location) == 0 || len(location) > http.MAX_HEADER_SIZE {
		return "", {kind = .Invalid_Redirect}
	}

	parts: [5]string
	count := redirect_parts(base, location, &parts)

	size := 0
	for p in parts[:count] do size += len(p)
	if size > http.MAX_HEADER_SIZE {
		return "", {kind = .Invalid_Redirect}
	}

	storage, ae := make([]u8, size, allocator)
	if ae != nil {
		return "", {kind = .Allocation_Failed, allocation = ae}
	}

	at := 0
	for p in parts[:count] do at += copy(storage[at:], transmute([]u8)p)
	parsed, pe := http.url_parse(cast(string)storage)
	if pe.kind != .None {
		delete(storage, allocator)
		return "", {kind = .Invalid_Redirect}
	}

	if parsed.target == "" || parsed.target[0] == '?' {
		return cast(string)storage, {}
	}

	normalized: [http.MAX_HEADER_SIZE]u8
	n := redirect_path_normalize(normalized[:], parsed.target)
	prefix_size := len(storage) - len(parsed.target)
	copy(storage[prefix_size:], normalized[:n])
	// Return an allocation of exact length so deletion always frees the base.
	if n == len(parsed.target) {
		return cast(string)storage, {}
	}

	result, ae2 := make([]u8, prefix_size + n, allocator)
	if ae2 != nil {
		delete(storage, allocator)
		return "", {kind = .Allocation_Failed, allocation = ae2}
	}

	copy(result, storage[:prefix_size + n])
	delete(storage, allocator)
	return cast(string)result, {}
}
redirect_parts :: proc(base: http.URL, location: string, parts: ^[5]string) -> int {
	assert(len(location) > 0 && len(location) <= http.MAX_HEADER_SIZE)
	count := 0
	scheme_end := strings.index_byte(location, ':')
	path_end := len(location)
	for c, i in location {
		if slice.contains([]type_of(c){'/', '?'}, c) {
			path_end = i; break
		}
	}
	if scheme_end >= 0 && scheme_end < path_end {
		parts[0], count = location, 1
	} else if strings.has_prefix(location, "//") {
		parts[0], parts[1], parts[2], count =
			base.scheme, ":", location, 3
	} else if location[0] == '/' {
		parts[0], parts[1], parts[2], parts[3], count =
			base.scheme, "://", base.authority, location, 4
	} else if location[0] == '?' {
		target := base.target
		if target == "" || target[0] == '?' do target = "/"

		if i := strings.index_byte(target, '?'); i >= 0 {
			target = target[:i]
		}

		parts[0], parts[1], parts[2], parts[3], parts[4], count =
			base.scheme, "://", base.authority, target, location, 5
	} else {
		// RFC3986 relative path merging; normalize dot segments below.
		target := base.target
		if i := strings.index_byte(target, '?'); i >= 0 {
			target = target[:i]
		}

		if target == "" do target = "/"

		last := strings.last_index_byte(target, '/')
		target = target[:last + 1]
		parts[0], parts[1], parts[2], parts[3], parts[4], count =
			base.scheme, "://", base.authority, target, location, 5
	}

	return count
}

redirect_path_normalize :: proc(dst: []u8, target: string) -> int {
	path, query := target, ""
	if i := strings.index_byte(path, '?'); i >= 0 {
		path, query = path[:i], path[i:]
	}

	at := 0
	for len(path) > 0 {
		if strings.has_prefix(path, "../") {
			path = path[3:]; continue
		}

		if strings.has_prefix(path, "./") {
			path = path[2:]; continue
		}

		if strings.has_prefix(path, "/./") {
			path = path[2:]; continue
		}

		if path == "/." {
			path = "/"; continue
		}

		if strings.has_prefix(path, "/../") || path == "/.." {
			if path == "/.." {
				path = "/"
			} else {
				path = path[3:]
			}

			if i := strings.last_index_byte(
				cast(string)dst[:at],
				'/',
			); i >= 0 {
				at = i
			} else {
				at = 0
			}

			continue
		}

		if slice.contains([]string{".", ".."}, path) {
			break
		}

		end := len(path)
		start := 0
		if path[0] == '/' do start = 1

		if i := strings.index_byte(path[start:], '/'); i >= 0 {
			end = start + i
		}

		at += copy(dst[at:], transmute([]u8)path[:end])
		path = path[end:]
	}
	at += copy(dst[at:], transmute([]u8)query)
	return at
}

http_protocol_error :: proc(error: http.Error) -> HTTP_Error {
	return {kind = error.kind, allocation = error.allocation}
}
