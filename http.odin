package surf

import http "../http"
import h3 "../http/v3"
import "core:compress"
import http1 "../http/v1"
import tls_api "core:crypto/tls"
import trans "core:net"
import "core:mem"
import resources "core:sync/budget"
import "core:io"
import "core:slice"
import "core:strings"
import "core:time"
import owned "core:mem/owned"
import charged "core:mem/budget"

HTTP_Error :: struct {
	kind:       http.Error_Kind,
	transport:  trans.Connection_Error,
	network:    trans.Network_Error,
	tls_dial:   tls_api.Dial_Error,
	tls_io:     tls_api.IO_Error,
	allocation: mem.Allocator_Error,
	phase: HTTP_Phase,
	write_effect: HTTP_Write_Effect,
	// Last validated HTTP status, including failures while reading its body.
	status: int,
	// Numeric external-provider code only; native paths leave it zero.
	provider_code: int,
	// Source-stream failure during a request upload; no path/body is retained.
	source_io: io.Error,
	// Exact scope admission cause; allocator-enforced byte failures retain the
	// standard Allocation_Failed kind without guessing a concurrent cause.
	budget: resources.Error,
 decoding: compress.Decode_Error,
}

Config :: struct {
 _http3_cancel:proc(rawptr)->bool,
 _http3_cancel_data:rawptr,
	tls:           tls_api.Config,
	// Zero selects 8 MiB. All responses, including redirect bodies, are bounded.
	max_body_size: int,
	// Zero disables automatic redirects; maximum5. POST follows only307/308.
	max_redirects: int,
	// Zero selects30s for the entire setup/I/O/redirect budget.
	timeout:       time.Duration,
	allow_http:    bool,
	// Zero uses the remaining total budget. A positive value bounds DNS+TCP+TLS
	// together for each new connection, always capped by the total deadline.
	setup_timeout: time.Duration,
	resolver:      trans.Resolver_Options,
	// Zero preserves unmanaged compatibility. Host supplies an operation Scope
	// below its connection/global hierarchy.
	scope: resources.Scope,
	// Trusted coverage for a caller arena whose BOTH backings are charged.
	// This reference does not extend the arena/storage lifetime.
	allocator_scope: resources.Scope,
	// Explicit HTTP/3. Default off. Cleartext is refused. GET and HEAD may
	// fall back to TCP once; other methods are not sent again. Early data requires its explicit predicate.
	http3: bool,
	http3_qpack: h3.Qpack_Config,
 http3_ecn:bool,
 http3_early_data:proc(^http.Request)->bool,
	// Written only after an authenticated TLS response. Nil disables discovery.
	alt_svc: ^Alt_Svc_Cache,
	// Nil opens one HTTP/3 connection per call. A pool reuses an authenticated origin.
	http3_pool: ^h3.Pool,
}


// Owns header strings/body. Do not copy and destroy twice. Destroy on success;
// errors return an empty response. Content-Encoding is not decompressed.
Response :: struct {
 trailers:[]http.Header,
 trailer_storage:[]u8,
	status:         int,
	headers:        []http.Header,
	body:           []u8,
	allocator:      mem.Allocator,
	header_storage: []u8,
	body_storage:   [dynamic]u8,
	_allocator_scope: resources.Scope,
}
response_destroy :: proc(response: ^Response) {
	if response == nil do return
	old := response^; response^ = {}
	if old.allocator.procedure != nil {
		delete(old.trailers,old.allocator)
 delete(old.trailer_storage,old.allocator)
		delete(old.headers, old.allocator)
		delete(old.header_storage, old.allocator)
		delete(old.body_storage)
	}
	resources.release_scope(&old._allocator_scope)
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
execute :: proc(request: http.Request, config: Config, allocator := context.allocator) -> (Response, HTTP_Error) {
	return execute_with_upload(request, config, nil, allocator)
}

@(private)
execute_with_upload :: proc(
	request: http.Request,
	config: Config,
	upload: ^Upload_Source,
	allocator: mem.Allocator,
) -> (
	Response,
	HTTP_Error,
) {
	if validation := config_validate(config); validation.kind != .None {
		return {}, http_error_classify(validation, .Configuration, .Not_Sent)
	}
	ctx, call_allocator, admission := budget_begin(config.scope, config.allocator_scope, allocator)
	if admission.kind != .None do return {}, admission
	defer budget_cleanup(&ctx)
	previous_context := context
	next_context := context
	if resources.scope_of(ctx.stream) != (resources.Scope{}) {
		next_context.allocator = call_allocator
		next_context.temp_allocator = budget_temporary(&ctx, call_allocator)
	}
	context = next_context
	defer context = previous_context
	last_status := 0
	response, error := execute_internal(request, config, &last_status, call_allocator, upload)
	if error.kind != .None {
		if error.phase == .Unknown {
			error = http_error_classify(error, .Configuration, .Not_Sent)
		}
		if error.status == 0 {
			error.status = last_status
		}
		if last_status != 0 && error.write_effect == .Not_Sent {
			error.write_effect = .Response_Received
		}
	}
	if error.kind == .None do budget_response(&ctx, &response)
	return response, error
}

@(private)
execute_internal :: proc(
	request: http.Request,
	config: Config,
	last_status: ^int,
	allocator: mem.Allocator,
	upload: ^Upload_Source,
) -> (
	response: Response,
	err: HTTP_Error,
) {

	if e := config_validate(config); e.kind != .None {
		return {}, e
	}

 if config._http3_cancel!=nil && config._http3_cancel(config._http3_cancel_data) {return {},{kind=.IO_Failed,phase=.Cancellation,write_effect=.Not_Sent,transport={kind=.Cancelled}}}
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
		content_length: i64 = -1
		if upload != nil {content_length = upload.content_length}
        if config.http3 && !http3_request_trailers_valid(current.trailers) {return {},{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
		preflight:=current
 if config.http3 {preflight.trailers=nil}
 _, validation := http1.request_encode(storage[:], preflight, content_length)
		if validation.kind != .None {
			error := http_protocol_error(validation)
			error.phase = .Configuration
			if validation.kind == .Body_Oversized {error.phase = .Body_Limit}
			return {}, error
		}

		u, e := http.url_parse(current.url)
		if e.kind != .None do return {}, http_protocol_error(e)

		if !u.secure && !config.allow_http {
			return {}, {kind = .Insecure_URL}
		}

		if time.diff(time.now(), total_deadline) <= 0 {
			return {}, {kind = .Deadline_Failed}
		}

		if config.http3 {
			if !u.secure {
				return {}, {kind = .Insecure_URL, phase = .Configuration, write_effect = .Not_Sent}
			}
			response, err = execute_http3(u, current, config, total_deadline, allocator, upload)
			if err.kind != .None {
                if err.phase==.Cancellation {return {},err}
                if config._http3_cancel!=nil && config._http3_cancel(config._http3_cancel_data) {return {},{kind=.IO_Failed,phase=.Cancellation,write_effect=err.write_effect,transport={kind=.Cancelled}}}
				if time.diff(time.now(), total_deadline) <= 0 {
					err.kind = .Deadline_Failed
					err.phase = .Deadline
					return {}, err
				}
				// A datagram that already carried the request is not replayed on TCP.
				if err.write_effect != .Not_Sent {
					return {}, err
				}
				if upload != nil || len(current.trailers)>0 || !http3_fallback_allowed(current.method) {
					return {}, err
				}
				response, err = execute_tls(u, current, config, total_deadline, allocator, upload)
			}
		} else if u.secure {
			response, err = execute_tls(u, current, config, total_deadline, allocator, upload)
		} else {
			response, err = execute_tcp(u, current, config, total_deadline, allocator, upload)
		}

		if err.kind != .None do return {}, err
		if config.alt_svc != nil && u.secure {
			if value, found := response_header(&response, "Alt-Svc"); found {
				_ = alt_svc_note(config.alt_svc, u.host, value, true, true, time.now(), u.port)
			}
		}

		last_status^ = response.status
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
	allocator: mem.Allocator, upload: ^Upload_Source = nil,
) -> (response: Response, err: HTTP_Error) {
	connection: ^tls_api.Conn
	connection, err = http_tls_connect(url, config, total_deadline, allocator, nil)
	if err.kind != .None {return {}, err}
	defer {
		tls_api.abort(connection)
		free(connection, allocator)
	}

	deadline_err := tls_api.set_deadline(connection, total_deadline)
	if deadline_err.kind != .None {
		return {}, {kind = .Deadline_Failed, transport = deadline_err, phase = .Deadline, write_effect = .Not_Sent}
	}
	selected := tls_api.connection_state(connection).negotiated_protocol
	if selected == "h2" {
		return h2_exchange_once(connection, request, upload, config, total_deadline, allocator, nil)
	}
	if selected != "" && selected != "http/1.1" {
		return {}, {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
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
	if upload != nil {
		response, err = exchange_upload(stream, request, upload^, config.max_body_size, allocator, total_deadline)
	} else {
		response, err = exchange(stream, request, config.max_body_size, allocator)
	}
	if err.kind == .IO_Failed {
		err.tls_io = adapter.last_error
		err = http_error_classify(err, err.phase, err.write_effect, err.status)
	}
	if err.kind != .None && err.phase == .Unknown {err = http_error_classify(err, .TLS, .Not_Sent)}
	return response, err
}

execute_tcp :: proc(
	url: http.URL, request: http.Request, config: Config, total_deadline: time.Time,
	allocator: mem.Allocator, upload: ^Upload_Source = nil,
) -> (response: Response, err: HTTP_Error) {
	socket, setup_error := bounded_socket(url, config, connection_setup_deadline(config, total_deadline))
	if setup_error.kind != .None {return {}, setup_error}

	connection := trans.TCP_Connection {
		socket = socket,
	}
	stream := trans.tcp_connection(&connection)
	deadline_err := trans.set_deadline(
		stream,
		total_deadline,
	)
	if deadline_err.kind == .None {
		if upload != nil {
			response, err = exchange_upload(stream, request, upload^, config.max_body_size, allocator, total_deadline)
		} else {
			response, err = exchange(stream, request, config.max_body_size, allocator)
		}
	} else {
		err = {
			kind      = .Deadline_Failed,
			transport = deadline_err,
		}
	}

	stream.close(stream.data)

	if err.kind != .None && err.phase == .Unknown {err = http_error_classify(err, .Connect, .Not_Sent)}
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
	return exchange_scoped(stream, request, max_body_size, allocator)
}

// Explicit scoped variant preserves exchange's original injectable procedure type.
exchange_scoped :: proc(
	stream: trans.Connection,
	request: http.Request,
	max_body_size: int = 0,
	allocator := context.allocator,
	scope: resources.Scope = {},
	allocator_scope: resources.Scope = {},
) -> (
	Response,
	HTTP_Error,
) {
	ctx, call_allocator, admission := budget_begin(scope, allocator_scope, allocator)
	if admission.kind != .None do return {}, admission
	defer budget_cleanup(&ctx)
	previous_context := context
	next_context := context
	if resources.scope_of(ctx.stream) != (resources.Scope{}) {
		next_context.allocator = call_allocator
		next_context.temp_allocator = budget_temporary(&ctx, call_allocator)
	}
	context = next_context
	defer context = previous_context
	outcome: HTTP_Exchange_Outcome
	response, error := exchange_internal(stream, request, max_body_size, call_allocator, &outcome)
	if error.kind != .None {
		effect: HTTP_Write_Effect = .Not_Sent
		if outcome.write_started {
			effect = .Unknown
		}
		if outcome.status != 0 {
			effect = .Response_Received
		}
		error = http_error_classify(error, .Read, effect, outcome.status)
	}
	if error.kind == .None do budget_response(&ctx, &response)
	return response, error
}

@(private)
HTTP_Exchange_Outcome :: struct {write_started: bool, status: int}

@(private)
exchange_internal :: proc(
	stream: trans.Connection, request: http.Request, max_body_size: int,
	allocator: mem.Allocator, outcome: ^HTTP_Exchange_Outcome,
) -> (Response, HTTP_Error) {
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
	if e.kind != .None {
		error := http_protocol_error(e)
		error.phase = .Configuration
		if e.kind == .Body_Oversized {error.phase = .Body_Limit}
		return {}, error
	}

	outcome.write_started = true
	if _, write_err := trans.write_all(stream, encoded[:n]);
	   write_err.kind != .None {
		return {}, {kind = .IO_Failed, transport = write_err, phase = .Write}
	}

	if _, write_err := trans.write_all(stream, request.body);
	   write_err.kind != .None {
		return {}, {kind = .IO_Failed, transport = write_err, phase = .Write}
	}

	return exchange_read_response(stream, request, limit, allocator, outcome)
}

@(private)
exchange_read_response :: proc(stream: trans.Connection, request: http.Request, limit: int, allocator: mem.Allocator, outcome: ^HTTP_Exchange_Outcome) -> (Response, HTTP_Error) {
	response: Response
	reader := Reader {
		stream = stream,
	}
	storage: [http.MAX_HEADER_SIZE]u8
	used, header_error := response_read_header(&reader, storage[:], &outcome.status)
	if header_error.kind != .None {return {}, header_error}
	response.allocator = allocator
	success := false
	defer if !success do response_destroy(&response)

	head, initialize_error := response_initialize(&response, storage[:used], limit, allocator)
	if initialize_error.kind != .None {
		if response.status != 0 {outcome.status = response.status}
		return {}, initialize_error
	}
	outcome.status = head.status
	// HEAD describes the representation, but carries no response body.
	http1.response_apply_method(&head, request.method)
	if body_error := response_read_body(&reader, &response, head, limit); body_error.kind != .None {
		return {}, body_error
	}
	response.body = response.body_storage[:]
	success = true
	return response, {}
}

response_read_header :: proc(reader: ^Reader, storage: []u8, observed_status: ^int = nil) -> (int, HTTP_Error) {
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
		if observed_status != nil {observed_status^ = head.status}

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
	if !h3.qpack_config_valid(c.http3_qpack) {return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
	if c.max_body_size < 0 ||
	   c.max_body_size > http.MAX_BODY_SIZE ||
	   c.max_redirects < 0 ||
	   c.max_redirects > http.MAX_REDIRECTS ||
	   c.timeout < 0 || c.setup_timeout < 0 {
		return {kind = .Invalid_Config}
	}

	// TCP binding only. Missing ALPN stays HTTP/1 with no implicit h2/h3.
	// Offering h2 does not speak HTTP/2; that starts only after the peer
	// selects it. h3 is rejected here, before DNS, sockets or upload reads.
	// QUIC is not this stack.
	if tls_api.alpn_transport_offers(.TCP, c.tls.alpn_protocols) != .None {
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
	return {kind = error.kind, allocation = error.allocation, phase = .Protocol}
}

// Moves the response's complete body allocation into a separately releasable
// owner. Headers remain with response; response_destroy stays safe afterward.
// The allocator backing body_storage must survive until the chunk is released.
// Borrowed/manually constructed bodies are rejected without changing response.
response_take_body :: proc(response: ^Response) -> (chunk: owned.Chunk, error: owned.Error) {
	if response == nil || len(response.body) != len(response.body_storage) ||
	   raw_data(response.body) != raw_data(response.body_storage) {
		return {}, {kind=.Invalid_Input}
	}
	chunk, error = owned.take_dynamic(&response.body_storage)
	if error.kind == .None {response.body = nil}
	return
}

@(private)
connection_setup_deadline :: proc(config: Config, total: time.Time) -> time.Time {
	if config.setup_timeout <= 0 {return total}
	now := time.now()
	budget := min(config.setup_timeout, max(time.Duration(0), time.diff(now, total)))
	return time.time_add(now, budget)
}

@(private)
bounded_socket :: proc(url: http.URL, config: Config, deadline: time.Time) -> (trans.TCP_Socket, HTTP_Error) {
	endpoints, resolve_error := trans.resolve_endpoints_until(url.host, url.port, deadline, config.resolver)
	if resolve_error != nil {
		return 0, http_error_classify({kind = .Dial_Failed, network = resolve_error}, .DNS, .Not_Sent)
	}
	socket, connect_error := trans.dial_tcp_candidates_until(endpoints, deadline)
	if connect_error != nil {
		return 0, http_error_classify({kind = .Dial_Failed, network = connect_error}, .Connect, .Not_Sent)
	}
	return socket, {}
}

@(private)
Budget_Context :: struct {
	binding:               charged.Binding,
	stream:                resources.Lease,
	coverage:              resources.Scope,
	temporary:             mem.Dynamic_Arena,
	temporary_initialized: bool,
}

// Scope/coverage handles borrow host ownership during entry. An annotation is a
// trusted host promise about an arena's backing, not inference from its pointer.
@(private)
budget_begin :: proc(
	scope, coverage: resources.Scope,
	backing: mem.Allocator,
) -> (
	Budget_Context,
	mem.Allocator,
	HTTP_Error,
) {
	if scope == (resources.Scope{}) {
		if coverage != (resources.Scope{}) do return {}, {}, budget_error(.Invalid_Config)
		return {}, backing, {}
	}
	if coverage != (resources.Scope{}) && !resources.covers(coverage, scope) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	managed_scope, managed := charged.allocator_scope(backing)
	if managed && !resources.covers(managed_scope, scope) {
		reason: resources.Error = .Invalid_Config
		if !resources.same_root(managed_scope, scope) do reason = .Foreign_Root
		return {}, {}, budget_error(reason)
	}
	if !managed && coverage == (resources.Scope{}) && .Free not_in mem.query_features(backing) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	ctx: Budget_Context
	lease, admission := resources.reserve(scope, {streams = 1})
	if admission != .None do return {}, {}, budget_error(admission)
	ctx.stream = lease
	allocator := backing
	failure: HTTP_Error
	if managed {
		ctx.binding, failure = budget_retain_allocator(backing)
	} else if coverage == (resources.Scope{}) {
		ctx.binding, failure = budget_create_allocator(scope, backing)
		if failure.kind == .None do allocator = charged.allocator(ctx.binding)
	}
	if failure.kind == .None && coverage != (resources.Scope{}) {
		retained, error := resources.retain_scope(coverage)
		if error != .None do failure = budget_error(error)
		else do ctx.coverage = retained
	}
	if failure.kind != .None {
		budget_cleanup(&ctx); return {}, {}, failure
	}
	return ctx, allocator, {}
}

@(private)
budget_retain_allocator :: proc(source: mem.Allocator) -> (charged.Binding, HTTP_Error) {
	binding, error := charged.retain_allocator(source)
	return binding, budget_allocator_error(error)
}
@(private)
budget_create_allocator :: proc(
	scope: resources.Scope,
	backing: mem.Allocator,
) -> (
	charged.Binding,
	HTTP_Error,
) {
	binding, error := charged.create(scope, {backing = backing})
	return binding, budget_allocator_error(error)
}
@(private)
budget_allocator_error :: proc(error: charged.Error) -> HTTP_Error {
	if error.kind == .None do return {}
	result := budget_error(error.budget)
	result.allocation = error.allocation
	if error.kind == .Invalid_Config || error.kind == .Invalid_Handle {
		result.kind = .Invalid_Config
	}
	return result
}
@(private)
budget_error :: proc(reason: resources.Error) -> HTTP_Error {
	kind: http.Error_Kind = .Allocation_Failed
	if reason == .Invalid_Config || reason == .Invalid_Handle || reason == .Foreign_Root {
		kind = .Invalid_Config
	}
	return {kind = kind, budget = reason, phase = .Admission, write_effect = .Not_Sent}
}
@(private)
budget_cleanup :: proc(ctx: ^Budget_Context) {
	old := ctx^; ctx^ = {}
	if old.temporary_initialized do mem.dynamic_arena_destroy(&old.temporary)
	charged.release(&old.binding)
	resources.release_scope(&old.coverage)
	resources.release(&old.stream)
}
@(private)
budget_response :: proc(ctx: ^Budget_Context, response: ^Response) {
	response._allocator_scope = ctx.coverage
	ctx.coverage = {}
}

// Called only after the context has reached its final caller-owned stack address.
// Returned temporary allocator views must not escape the blocking operation.
@(private)
budget_temporary :: proc(ctx: ^Budget_Context, allocator: mem.Allocator) -> mem.Allocator {
	assert(!ctx.temporary_initialized)
	mem.dynamic_arena_init(
		&ctx.temporary,
		block_allocator = allocator,
		array_allocator = allocator,
		block_size = 16 * mem.Kilobyte,
		out_band_size = 8 * mem.Kilobyte,
	)
	ctx.temporary_initialized = true
	return mem.dynamic_arena_allocator(&ctx.temporary)
}

// Failure categories preserve observable distinctions without storing URLs,
// headers, tokens or response bodies. Unknown means the provider cannot say.
HTTP_Phase :: enum {
	Unknown,
	Configuration,
	DNS,
	Connect,
	TLS,
	Write,
	Read,
	Protocol,
	Body_Limit,
	Deadline,
	Cancellation,
	Admission,
 Decode,
}

// Unknown is deliberately the zero value: a zero/named legacy aggregate must
// never become evidence that replaying a non-idempotent operation is safe.
HTTP_Write_Effect :: enum {
	Unknown,
	Not_Sent,
	Response_Received,
}

// Classify only facts available from existing typed diagnostics. A received
// response is not proof of business success, transaction commit, or replay safety.
http_error_classify :: proc(error: HTTP_Error, fallback: HTTP_Phase, effect: HTTP_Write_Effect, status: int = 0) -> HTTP_Error {
	result := error
	if result.kind == .None {return result}
	if result.phase == .Unknown {
		result.phase = fallback
		#partial switch result.kind {
		case .Invalid_Config, .Invalid_URL, .Insecure_URL, .Invalid_Method, .Reserved_Header:
			result.phase = .Configuration
		case .Invalid_Header:
			result.phase = .Configuration if fallback == .Configuration else .Protocol
		case .Body_Oversized: result.phase = .Body_Limit
		case .Deadline_Failed: result.phase = .Deadline
		case .Dial_Failed: result.phase = http_network_phase(result.network)
		case .TLS_Failed:
			result.phase = .TLS
			#partial switch result.tls_dial.kind {
			case .Invalid_Config, .Invalid_State: result.phase = .Configuration
			case .TCP_Dial_Failed: result.phase = http_network_phase(result.tls_dial.network)
			}
		case .Invalid_Status, .Conflicting_Framing, .Unsupported_Transfer_Encoding, .Invalid_Content_Length,
       .Invalid_Chunk, .Invalid_Trailer, .Header_Oversized, .Header_Limit, .Too_Many_Informational,
       .Redirect_Limit, .Invalid_Redirect, .Unsafe_Redirect:
			result.phase = .Protocol
		}
	}
	// Record/authentication failures remain TLS failures; transport failures
	// retain the read/write phase until a more specific timeout/cancel is known.
	#partial switch result.tls_io.kind {
	case .Handshake_Failed, .Unexpected_EOF, .Invalid_Record, .Encryption_Failed,
	     .Decryption_Failed, .Unexpected_Content_Type, .Peer_Alert, .Interleaved_Record,
	     .Record_Boundary_Violation, .Invalid_Post_Handshake, .Post_Handshake_Oversized:
		result.phase = .TLS
	}
	// TLS adapters retain their underlying timeout/cancellation diagnostics.
	transport := result.transport
	if result.tls_io.transport.kind != .None {transport = result.tls_io.transport}
	for candidate in ([?]trans.Connection_Error{
		result.tls_dial.handshake.client_hello.transport,
		result.tls_dial.handshake.server_hello.record.transport,
		result.tls_dial.handshake.record.transport,
		result.tls_dial.handshake.transport,
	}) {
		if candidate.kind != .None {transport = candidate}
	}
	if transport.kind == .Timeout {result.phase = .Deadline}
	if transport.kind == .Cancelled {result.phase = .Cancellation}
	if result.tls_dial.handshake.kind == .Deadline_Failed {result.phase = .Deadline}
	result.write_effect = effect
	if result.status == 0 {result.status = status}
	return result
}

http_network_phase :: proc(error: trans.Network_Error) -> HTTP_Phase {
	if error == nil {return .Unknown}
	#partial switch cause in error {
	case trans.Resolve_Error: return .DNS
	case trans.DNS_Error:
		if cause == .Timeout {return .Deadline}
		return .DNS
	case trans.Dial_Error:
		if cause == .Timeout {return .Deadline}
		return .Connect
	case trans.Create_Socket_Error: return .Connect
	case trans.Parse_Endpoint_Error: return .Configuration
	}
	return .Unknown
}
