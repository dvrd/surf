package surf

import http "../http"
import http3 "../http/v3"
import "core:mem"
import "core:io"
import "core:net"
import "core:strings"
import "core:time"

// Fixed discovery table. A full slot replaces the oldest entry.
ALT_SVC_SLOTS :: 4
ALT_SVC_MAX_AGE :: 7 * 24 * 60 * 60

Alt_Svc :: struct {
	used:     bool,
	host:     [256]u8,
	host_len: int,
	port:     int,
	origin_port: int,
	expires:  time.Time,
}

Alt_Svc_Cache :: struct {
	slots: [ALT_SVC_SLOTS]Alt_Svc,
	next:  int,
}

// GET and HEAD are the only methods retried after HTTP/3 fails before a send.
http3_fallback_allowed :: proc(method: http.Method) -> bool {
	return method == .GET || method == .HEAD
}

// Half of the remaining deadline is the HTTP/3 budget. A miss that has not
// transmitted falls back only for GET and HEAD. Early data requires the configured request predicate.
execute_http3 :: proc(
	url: http.URL,
	request: http.Request,
	config: Config,
	total_deadline: time.Time,
	allocator: mem.Allocator,
	upload: ^Upload_Source = nil,
) -> (
	Response,
	HTTP_Error,
) {
	remain := time.diff(time.now(), total_deadline)
	if remain <= 0 {
		return {}, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
	}
	budget := remain / 2
	if budget < 50 * time.Millisecond && remain >= 100 * time.Millisecond {
		budget = 50 * time.Millisecond
	}
	if budget <= 0 do budget = remain
	deadline := time.time_add(time.now(), budget)
	port := http3_dial_port(config.alt_svc, url.host, url.port, time.now())
	endpoint, resolve_error := http3_resolve(url.host, port, deadline, config.resolver)
	if resolve_error.kind != .None {
		return {}, resolve_error
	}
	path := url.target
	if len(path) == 0 do path = "/"
	fields: [http.MAX_HEADERS]http3.Field
	if len(request.headers) > len(fields) {
		return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
	}
	names: [http.MAX_HEADER_SIZE]u8
	names_n := 0
	for header, i in request.headers {
		if len(header.name) > len(names)-names_n {return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}}
		at := names_n
		for character, j in header.name {
			lower := character
			if lower >= 'A' && lower <= 'Z' {lower += 32}
			names[at+j] = u8(lower)
		}
		names_n += len(header.name)
		fields[i] = {name = string(names[at:names_n]), value = header.value}
	}
	wire := http3.Client_Request{
 session_cache=config.tls.session_cache,
 cancel=config._http3_cancel,cancel_data=config._http3_cancel_data,
		qpack = config.http3_qpack,
 ecn=config.http3_ecn,
		client_credentials=config.tls.client_credentials,
		client_credential_lease=config.tls.client_credential_lease,
		method = http.method_text(request.method), target = path, authority = url.authority,
		headers = fields[:len(request.headers)], body = request.body,
		max_response_bytes = config.max_body_size,
	}
 if config.http3_early_data!=nil {policy_request:=request;wire.early_data=config.http3_early_data(&policy_request)}
 trailer_fields:[32]http3.Field
 trailer_names:[4096]u8;trailer_bytes:=0
 if len(request.trailers)>len(trailer_fields) {return {},{kind=.Header_Limit,phase=.Configuration,write_effect=.Not_Sent}}
 for field,i in request.trailers {
  if len(field.name)>len(trailer_names)-trailer_bytes {return {},{kind=.Header_Limit,phase=.Configuration,write_effect=.Not_Sent}}
  start:=trailer_bytes
  for character,j in field.name {lower:=character;if lower>='A'&&lower<='Z' {lower+=32};trailer_names[start+j]=u8(lower)}
  trailer_bytes+=len(field.name);trailer_fields[i]={name=string(trailer_names[start:trailer_bytes]),value=field.value}
 }
 wire.trailers=trailer_fields[:len(request.trailers)]
	source: HTTP3_Upload
	wire_source: http3.Upload_Source
	if upload != nil {
		source.source = upload
		wire_source = {data = &source, read = http3_upload_read, content_length = upload.content_length}
		wire.upload = &wire_source
	}
	result: http3.Client_Result
	if config.http3_pool != nil {
		result = http3.pool_exchange_request(config.http3_pool, endpoint, url.host, wire, config.tls.root_cas, deadline)
	} else {
		result = http3.client_exchange_request(endpoint, url.host, wire, config.tls.root_cas, deadline)
	}
	if result.error != .None {
		error := http3_map_error(result, total_deadline)
		error.source_io = source.error
		return {}, error
	}
	return http3_response(&result, allocator)
}

@(private)
HTTP3_Upload :: struct {source: ^Upload_Source, error: io.Error}

@(private)
http3_upload_read :: proc(data: rawptr, destination: []u8) -> (int, bool) {
	source := cast(^HTTP3_Upload)data
	n, error := io.read(source.source.stream, destination)
	if error != nil && error != io.Error.EOF {
		source.error = error
		return n, false
	}
	if n == 0 {source.error = io.Error.EOF; return 0, false}
	return n, true
}

// Alt-Svc wins only while the lookup is valid. Otherwise the URL port, or 443.
http3_dial_port :: proc(cache: ^Alt_Svc_Cache, host: string, url_port: int, now: time.Time) -> int {
	if port, ok := alt_svc_lookup(cache, host, now, url_port); ok && port > 0 {
		return port
	}
	if url_port > 0 do return url_port
	return 443
}

// An IP literal does not query a resolver. A hostname uses the caller's
// nameservers, or the platform resolver, and must finish inside deadline.
@(private)
http3_resolve :: proc(host: string, port: int, deadline: time.Time, options: net.Resolver_Options) -> (net.Endpoint, HTTP_Error) {
	endpoints, resolve_error := net.resolve_endpoints_until(host, port, deadline, options)
	if resolve_error != nil || endpoints.count == 0 {
		if resolve_error == nil {
			resolve_error = net.Resolve_Error.Unable_To_Resolve
		}
		return {}, http_error_classify({kind = .Dial_Failed, network = resolve_error}, .DNS, .Not_Sent)
	}
	return endpoints.items[0], {}
}

@(private)
http3_map_error :: proc(result: http3.Client_Result, total_deadline: time.Time) -> HTTP_Error {
	effect := HTTP_Write_Effect.Not_Sent
	if result.sent do effect = .Unknown
	if result.error == .Deadline && time.diff(time.now(), total_deadline) <= 0 {
		return {kind = .Deadline_Failed, phase = .Deadline, write_effect = effect}
	}
	if result.error == .Invalid_Request {return {kind = .Invalid_Config, phase = .Configuration, write_effect = effect}}
	if result.error == .Body_Limit {return {kind = .Body_Oversized, phase = .Body_Limit, write_effect = effect}}
	if result.error == .Source {return {kind = .IO_Failed, phase = .Read, write_effect = effect}}
	if result.error == .Cancelled {return {kind = .IO_Failed, phase = .Cancellation, write_effect = effect, transport = {kind = .Cancelled}}}
	if result.error == .Certificate {
		return {kind = .IO_Failed, phase = .TLS, write_effect = effect}
	}
	return {kind = .IO_Failed, phase = .Protocol, write_effect = effect}
}

@(private)
http3_response :: proc(result: ^http3.Client_Result, allocator: mem.Allocator) -> (Response, HTTP_Error) {
	if result == nil {
		return {}, {kind = .IO_Failed, phase = .Protocol, write_effect = .Response_Received}
	}
	response := Response {
		allocator = allocator,
		status = result.status,
	}
	n := result.body_len
	if n < 0 do n = 0
	if n > len(result.body) do n = len(result.body)
	body, alloc_error := make([dynamic]u8, n, allocator)
	if alloc_error != nil {
		return {}, {kind = .Allocation_Failed, allocation = alloc_error, phase = .Configuration, write_effect = .Response_Received}
	}
	if n > 0 do copy(body[:n], result.body[:n])
	response.body_storage = body
	response.body = response.body_storage[:]
	bytes := 0
	for i in 0..<result.header_count {
		field, ok := http3.client_result_header(result, i)
		if !ok {response_destroy(&response); return {}, {kind = .IO_Failed, phase = .Protocol, write_effect = .Response_Received}}
		bytes += len(field.name) + len(field.value)
	}
	storage, storage_error := make([]u8, bytes, allocator)
	if storage_error != nil {response_destroy(&response); return {}, {kind = .Allocation_Failed, allocation = storage_error, phase = .Configuration, write_effect = .Response_Received}}
	response.header_storage = storage
	headers, header_error := make([]http.Header, result.header_count, allocator)
	if header_error != nil {response_destroy(&response); return {}, {kind = .Allocation_Failed, allocation = header_error, phase = .Configuration, write_effect = .Response_Received}}
	response.headers = headers
	at := 0
	for i in 0..<result.header_count {
		field, _ := http3.client_result_header(result, i)
		copied := copy(storage[at:], field.name)
		headers[i].name = string(storage[at:at+copied]); at += copied
		copied = copy(storage[at:], field.value)
		headers[i].value = string(storage[at:at+copied]); at += copied
	}
 if trailer_error:=http3_response_trailers(&response,result,allocator);trailer_error.kind!=.None {response_destroy(&response);return {},trailer_error}
 return response, {}
}

// Stores h3=":port"; ma=seconds only for an authenticated HTTPS origin.
// ma is required. Zero, expired, cleartext, and unauthenticated inputs do not write.
alt_svc_note :: proc(
	cache: ^Alt_Svc_Cache,
	host, value: string,
	authenticated, secure: bool,
	now: time.Time,
	origin_port: int = 443,
) -> bool {
	if cache == nil || !authenticated || !secure || len(host) == 0 || len(host) > 256 {
		return false
	}
	effective_port := origin_port
	if effective_port == 0 {effective_port = 443}
	port, ma, parsed := alt_svc_h3(value)
	if !parsed || ma <= 0 {
		return false
	}
	if ma > ALT_SVC_MAX_AGE do ma = ALT_SVC_MAX_AGE
	index := cache.next % ALT_SVC_SLOTS
	replaced := false
	for i in 0 ..< ALT_SVC_SLOTS {
		if cache.slots[i].used && cache.slots[i].origin_port == effective_port && string(cache.slots[i].host[:cache.slots[i].host_len]) == host {
			index = i
			replaced = true
			break
		}
	}
	slot := &cache.slots[index]
	copy(slot.host[:], host)
	slot.host_len = len(host)
	slot.port = port
	slot.origin_port = effective_port
	slot.expires = time.time_add(now, time.Duration(ma) * time.Second)
	slot.used = true
	if !replaced do cache.next += 1
	return true
}

alt_svc_lookup :: proc(cache: ^Alt_Svc_Cache, host: string, now: time.Time, origin_port: int = 443) -> (port: int, ok: bool) {
	effective_port := origin_port
	if effective_port == 0 {effective_port = 443}
	if cache == nil do return 0, false
	for i in 0 ..< ALT_SVC_SLOTS {
		slot := &cache.slots[i]
		if !slot.used || slot.origin_port != effective_port || string(slot.host[:slot.host_len]) != host do continue
		if time.diff(now, slot.expires) <= 0 {
			slot^ = {}
			return 0, false
		}
		return slot.port, true
	}
	return 0, false
}

@(private)
alt_svc_h3 :: proc(value: string) -> (port, ma: int, ok: bool) {
	at := strings.index(value, "h3=\"")
	if at < 0 do return
	rest := value[at + 4:]
	end := strings.index(rest, "\"")
	if end <= 0 do return
	token := rest[:end]
	if len(token) > 1 && token[0] == ':' {
		token = token[1:]
	}
	if len(token) == 0 do return
	for rune in token {
		if rune < '0' || rune > '9' do return
		port = port * 10 + int(rune - '0')
		if port > 65535 do return 0, 0, false
	}
	if port == 0 do return
	tail := rest[end + 1:]
	loc := strings.index(tail, "ma=")
	if loc < 0 do return
	for rune in tail[loc + 3:] {
		if rune < '0' || rune > '9' do break
		ma = ma * 10 + int(rune - '0')
		if ma > ALT_SVC_MAX_AGE {
			ma = ALT_SVC_MAX_AGE
			break
		}
	}
	ok = ma > 0
	return
}
