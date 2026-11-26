package surf

import "core:mem"
import "core:os"
import "core:strings"
import "core:time"
import "shared:async"


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
	scope: async.Budget_Scope = {},
	allocator_scope: async.Budget_Scope = {},
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
		scope != (async.Budget_Scope{}),
	)
	if validation.kind != .None {
		return nil, {error = validation}
	}
	// Borrowed output has no independent destructor: managed mode requires an
	// explicit host promise about the temporary allocator's covered lifetime.
	if scope != (async.Budget_Scope{}) && allocator_scope == (async.Budget_Scope{}) {
		return nil, {error = budget_error(.Invalid_Config)}
	}
	ctx, output, admission := budget_begin(scope, allocator_scope, context.temp_allocator)
	if admission.kind != .None {
		return nil, {error = admission}
	}
	defer budget_cleanup(&ctx)
	scratch, denied := buffered_http_scratch(scope)
	if denied.kind != .None {
		return nil, {error = denied}
	}
	defer async.budget_release(&scratch)
	reply: Buffered_HTTP_Reply
	result = buffered_http_perform(method, url, body, headers, ca_file, timeout_ms, upload_file, upload_size, &reply)
	if !result.transport_ok {
		return
	}
	copied, ae := make([]byte, reply.used, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae)
		return
	}
	copy(copied, reply.data[:reply.used])
	return copied, result
}

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
	scope: async.Budget_Scope = {},
	allocator_scope: async.Budget_Scope = {},
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
		scope != (async.Budget_Scope{}),
	)
	if validation.kind != .None {
		return {}, {error = validation}
	}
	ctx, output, admission := budget_begin(scope, allocator_scope, allocator)
	if admission.kind != .None {
		return {}, {error = admission}
	}
	defer budget_cleanup(&ctx)
	scratch, denied := buffered_http_scratch(scope)
	if denied.kind != .None {
		return {}, {error = denied}
	}
	defer async.budget_release(&scratch)
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
	if !result.transport_ok {
		return
	}
	copied, ae := buffered_http_owned_copy(&reply, result.status, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae)
		return
	}
	response = copied
	budget_response(&ctx, &response)
	return
}

buffered_http_scratch :: proc(scope: async.Budget_Scope) -> (async.Budget_Lease, HTTP_Error) {
	if scope == (async.Budget_Scope{}) {
		return {}, {}
	}
	lease, denied := async.budget_reserve(scope, {bytes = 64 * 1024})
	if denied != .None {
		return {}, budget_error(denied)
	}

	return lease, {}
}
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

buffered_http_owned_copy :: proc(
	reply: ^Buffered_HTTP_Reply,
	status: int,
	allocator: mem.Allocator,
) -> (
	Response,
	mem.Allocator_Error,
) {
	storage, error := make([dynamic]u8, reply.used, reply.used, allocator)
	if error != nil {
		return {}, error
	}
	copy(storage[:], reply.data[:reply.used])
	return {status = status, body = storage[:], body_storage = storage, allocator = allocator}, nil
}

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
	parsed, parse_error := async.http_url_parse(url)
	if parse_error.kind != .None {
		error.kind = parse_error.kind
		return error
	}
	if !allow_http && !parsed.secure {
		error.kind = .Insecure_URL
		return error
	}
	if !async.http_header_name_valid(method) {
		error.kind = .Invalid_Method
		return error
	}
	if timeout_ms <= 0 || timeout_ms > 120000 || upload_size < 0 {
		return error
	}
	if managed && len(headers) > async.HTTP_MAX_HEADERS {
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
			if len(header) > async.HTTP_MAX_HEADER_SIZE - bytes {
				error.kind = .Header_Oversized
				return error
			}

			bytes += len(header)
		}
	}

	return {}
}

// One request through execute. The reply holds at most 64 KiB of body.
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
	refuse :: proc(kind: async.Http_Error_Kind) -> Buffered_HTTP_Result {
		return {error = {kind = kind, phase = .Configuration, write_effect = .Not_Sent}}
	}

	target := url

	// A fragment never goes on the wire.
	if hash := strings.index_byte(target, '#'); hash >= 0 {
		target = target[:hash]
	}

	parsed, parse_error := async.http_url_parse(target)
	if parse_error.kind != .None {
		return refuse(parse_error.kind)
	}

	verb, known := buffered_http_method(method)
	if !known {
		return refuse(.Invalid_Method)
	}

	fields, allocation := make([]async.Http_Header, len(headers), context.temp_allocator)
	if allocation != nil {
		return {error = buffered_http_allocation_error(allocation)}
	}

	count := 0

	for header in headers {
		name, value, suppress, present := buffered_http_header(header)
		if !present || suppress {
			continue
		}

		if !async.http_header_name_valid(name) || !async.http_header_value_valid(value) {
			return refuse(.Invalid_Header)
		}

		fields[count] = {name = name, value = value}
		count += 1
	}

	// Only PUT and POST carry the body, and an upload file replaces it.
	payload := body
	if upload_file != nil || (verb != .PUT && verb != .POST) {
		payload = nil
	}

	timeout := time.Duration(timeout_ms) * time.Millisecond
	config := Config {
		timeout       = timeout,
		setup_timeout = min(timeout, 5 * time.Second),
		allow_http    = !parsed.secure,
		max_body_size = len(reply.data),
	}

	// Keep the pool until this procedure returns.
	pool: ^async.Root_Pool
	defer if pool != nil {
		async.root_pool_destroy(pool)
		free(pool)
	}

	if ca_file != "" {
		allocated, pool_error := new(async.Root_Pool)
		if pool_error != nil {
			return {error = buffered_http_allocation_error(pool_error)}
		}

		pool = allocated

		if async.root_pool_load_file(pool, ca_file) != nil {
			return {error = {kind = .TLS_Failed, phase = .TLS, write_effect = .Not_Sent}}
		}

		config.tls.roots = pool
	}

	request := async.Http_Request {
		method  = verb,
		url     = target,
		headers = fields[:count],
		body    = payload,
	}
	response: Response
	error: HTTP_Error

	if upload_file != nil {
		response, error = execute_upload(request, {stream = os.to_stream(upload_file), content_length = upload_size}, config)
	} else {
		response, error = execute(request, config)
	}
	defer response_destroy(&response)

	if error.kind != .None {
		result.status = error.status
		result.error = error
		return
	}

	copy(reply.data[:], response.body)
	reply.used = len(response.body)

	return {status = response.status, ok = response.status >= 200 && response.status < 300, transport_ok = true}
}


buffered_http_method :: proc(method: string) -> (async.Http_Method, bool) {
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

// curl's header syntax: "Name: value" sends a field, "Name:" suppresses it,
// "Name;" sends it empty, and a line with neither is ignored.
buffered_http_header :: proc(header: string) -> (name, value: string, suppress, present: bool) {
	if colon := strings.index_byte(header, ':'); colon >= 0 {
		value = strings.trim(header[colon + 1:], " \t")
		return header[:colon], value, value == "", true
	}

	semi := strings.index_byte(header, ';')
	if semi < 0 {
		return
	}

	return header[:semi], "", false, true
}
