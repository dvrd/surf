package surf

import "base:runtime"
import "core:c"
import "core:io"
import "core:os"
import "core:strings"
import "core:sync"
import "core:mem"
import http "../http"
import curl "vendor:curl"

// Streaming file uploads retain the existing curl adapter: unlike execute(),
// it supports PUT/DELETE and fixed-memory file reads. No redirects or proxies.
// Response bytes borrow the caller's temporary allocator, bounded to 64 KiB.
Buffered_HTTP_Result :: struct {
	status: int,
	ok: bool,
	// A complete HTTP response can be non-2xx without a transport failure.
	transport_ok: bool,
	error: HTTP_Error,
}

Buffered_HTTP_Reply :: struct {
	data: [64 * 1024]byte,
	used: int,
	limit_exceeded: bool,
}
buffered_http_ready: sync.Once
buffered_http_initialized: bool
buffered_http_initialize :: proc() {
	if curl.global_init(curl.GLOBAL_DEFAULT) != .E_OK do return
	version := curl.version_info(.FIRST)
	buffered_http_initialized = version != nil && version.features & curl.VERSION_ASYNCHDNS != 0
}
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
	data: []byte,
	result: Buffered_HTTP_Result,
) {
	result.error = {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	parsed, parse_error := http.url_parse(url)
	if parse_error.kind != .None {result.error.kind = parse_error.kind; return}
	if !allow_http && !parsed.secure {result.error.kind = .Insecure_URL; return}
	if !http.header_name_valid(method) {result.error.kind = .Invalid_Method; return}
	if timeout_ms <= 0 || timeout_ms > 120000 || upload_size < 0 {return}
	sync.once_do(&buffered_http_ready, buffered_http_initialize)
	if !buffered_http_initialized do return
	handle := curl.easy_init()
	if handle == nil {result.error.kind = .Allocation_Failed; return}
	list: ^curl.slist
	defer {curl.easy_cleanup(handle); if list != nil do curl.slist_free_all(list)}
	for header in headers {
		if strings.contains_any(header, "\r\n\x00") {result.error.kind = .Invalid_Header; return}
		text, allocation_error := buffered_http_cstring_checked(header)
		if allocation_error != nil {result.error = buffered_http_allocation_error(allocation_error); return}
		next := curl.slist_append(list, text)
		if next == nil {result.error.kind = .Allocation_Failed; return}
		list = next
	}
	if list != nil && !buffered_http_setopt(handle, .HTTPHEADER, list, &result.error) {return}
	if !buffered_http_options(handle, method, url, ca_file, timeout_ms, &result.error) {return}
	if upload_file != nil {
		if !buffered_http_setopt(handle, .UPLOAD, c.long(1), &result.error) ||
		   !buffered_http_setopt(handle, .READFUNCTION, buffered_http_read_file, &result.error) ||
		   !buffered_http_setopt(handle, .READDATA, upload_file, &result.error) ||
		   !buffered_http_setopt(handle, .INFILESIZE_LARGE, c.longlong(upload_size), &result.error) {return}
	} else if method == "PUT" || method == "POST" {
		empty: byte
		pointer := raw_data(body)
		if pointer == nil do pointer = &empty
		if !buffered_http_setopt(handle, .POSTFIELDS, pointer, &result.error) ||
		   !buffered_http_setopt(handle, .POSTFIELDSIZE_LARGE, c.longlong(len(body)), &result.error) {return}
	}
	reply: Buffered_HTTP_Reply
	if !buffered_http_setopt(handle, .WRITEFUNCTION, buffered_http_receive, &result.error) ||
	   !buffered_http_setopt(handle, .WRITEDATA, &reply, &result.error) {
		return
	}
	code := curl.easy_perform(handle)
	status: c.long
	info_code := curl.easy_getinfo(handle, .RESPONSE_CODE, &status)
	if info_code == .E_OK {result.status = int(status)}
	if code != .E_OK {
		request_size: c.long = -1
		if curl.easy_getinfo(handle, .REQUEST_SIZE, &request_size) != .E_OK {request_size = -1}
		result.error = buffered_http_error(code, result.status, reply.limit_exceeded, upload_file != nil, i64(request_size))
		return
	}
	if info_code != .E_OK {
		result.error = {kind = .IO_Failed, phase = .Unknown, provider_code = int(info_code), write_effect = .Unknown}
		return
	}
	copied, allocation_error := make([]byte, reply.used, context.temp_allocator)
	if allocation_error != nil {
		result.error = {kind = .Allocation_Failed, phase = .Read, allocation = allocation_error,
                  status = result.status, write_effect = .Response_Received}
		return
	}
	copy(copied, reply.data[:reply.used])
	result.ok = status >= 200 && status < 300
	result.transport_ok = true
	result.error = {}
	return copied, result
}
// Keep the existing bool helper interface; callers may request typed setup
// diagnostics without losing allocation or provider option failure details.
buffered_http_options :: proc(
	handle: ^curl.CURL, method, url, ca_file: string, timeout_ms: i64,
	error: ^HTTP_Error = nil,
) -> bool {
	for setting in ([]struct {key: curl.option, value: string}{
		{.URL, url}, {.CUSTOMREQUEST, method}, {.PROXY, ""},
	}) {
		text, allocation_error := buffered_http_cstring_checked(setting.value)
		if allocation_error != nil {
			if error != nil {error^ = buffered_http_allocation_error(allocation_error)}
			return false
		}
		if !buffered_http_setopt(handle, setting.key, text, error) {return false}
	}
	if ca_file != "" {
		text, allocation_error := buffered_http_cstring_checked(ca_file)
		if allocation_error != nil {
			if error != nil {error^ = buffered_http_allocation_error(allocation_error)}
			return false
		}
		if !buffered_http_setopt(handle, .CAINFO, text, error) {return false}
	}
	if timeout_ms <= 0 || timeout_ms > 120000 {
		if error != nil {error^ = {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}}
		return false
	}
	for setting in ([]struct {key: curl.option, value: c.long}{
		{.NOSIGNAL, 1}, {.PATH_AS_IS, 1}, {.SSL_VERIFYPEER, 1}, {.SSL_VERIFYHOST, 2},
		{.FOLLOWLOCATION, 0}, {.CONNECTTIMEOUT_MS, c.long(min(timeout_ms, 5000))},
		{.TIMEOUT_MS, c.long(timeout_ms)},
	}) {
		if !buffered_http_setopt(handle, setting.key, setting.value, error) {return false}
	}
	return true
}

@(private)
buffered_http_setopt :: proc(handle: ^curl.CURL, key: curl.option, value: $T, error: ^HTTP_Error) -> bool {
	code := curl.easy_setopt(handle, key, value)
	if code == .E_OK {return true}
	if error != nil {
		error^ = {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent, provider_code = int(code)}
		if code == .E_OUT_OF_MEMORY {error.kind = .Allocation_Failed}
	}
	return false
}

@(private)
buffered_http_allocation_error :: proc(error: mem.Allocator_Error) -> HTTP_Error {
	return {kind = .Allocation_Failed, phase = .Configuration, write_effect = .Not_Sent, allocation = error}
}

@(private)
buffered_http_cstring_checked :: proc(value: string) -> (cstring, mem.Allocator_Error) {
	return strings.clone_to_cstring(value, context.temp_allocator)
}

buffered_http_receive :: proc "c" (
	data: rawptr, size, count: c.size_t, userdata: rawptr,
) -> c.size_t {
	reply := cast(^Buffered_HTTP_Reply)userdata
	if size == 0 do return 0
	if count > c.size_t(len(reply.data) - reply.used) / size {
		reply.limit_exceeded = true
		return 0
	}
	n := int(size * count)
	copy(reply.data[reply.used:], ([^]byte)(data)[:n]); reply.used += n
	return c.size_t(n)
}
buffered_http_cstring :: proc(value: string) -> cstring {
	result, _ := strings.clone_to_cstring(value, context.temp_allocator)
	return result
}

buffered_http_read_file :: proc "c" (
	buffer: [^]byte, size, count: c.size_t, userdata: rawptr,
) -> c.size_t {
	context = runtime.default_context()
	if size == 0 || count == 0 do return 0
	if count > c.size_t(max(int)) / size do return curl.READFUNC_ABORT
	n, error := os.read(cast(^os.File)userdata, buffer[:int(size * count)])
	if error != nil && error != io.Error.EOF do return curl.READFUNC_ABORT
	return c.size_t(n)
}

// RESPONSE_CODE is valid independently of easy_perform's result. libcurl's
// numeric codes identify some phases; timeout does not reveal which phase
// exhausted its budget, so no fabricated DNS/connect/TLS precision is returned.
buffered_http_error :: proc(code: curl.code, status: int, body_limit, file_upload: bool, request_size: i64 = -1) -> HTTP_Error {
	error := HTTP_Error{kind = .IO_Failed, provider_code = int(code), status = status}
	#partial switch code {
	case .E_URL_MALFORMAT, .E_NOT_BUILT_IN, .E_BAD_FUNCTION_ARGUMENT, .E_UNKNOWN_OPTION:
		error.kind, error.phase, error.write_effect = .Invalid_Config, .Configuration, .Not_Sent
	case .E_UNSUPPORTED_PROTOCOL:
		// This also means a received HTTP/0.9-style reply on some providers.
		// With no positive request counter, its phase is genuinely ambiguous.
		error.kind = .Invalid_Status
	case .E_COULDNT_RESOLVE_HOST, .E_COULDNT_RESOLVE_PROXY:
		error.kind, error.phase, error.write_effect = .Dial_Failed, .DNS, .Not_Sent
	case .E_COULDNT_CONNECT:
		error.kind, error.phase, error.write_effect = .Dial_Failed, .Connect, .Not_Sent
	case .E_SSL_CONNECT_ERROR, .E_PEER_FAILED_VERIFICATION, .E_SSL_CERTPROBLEM,
      .E_SSL_CIPHER, .E_SSL_CACERT_BADFILE, .E_SSL_CRL_BADFILE, .E_SSL_ISSUER_ERROR,
      .E_SSL_PINNEDPUBKEYNOTMATCH, .E_SSL_INVALIDCERTSTATUS, .E_SSL_CLIENTCERT:
		error.kind, error.phase, error.write_effect = .TLS_Failed, .TLS, .Not_Sent
	case .E_OPERATION_TIMEDOUT:
		error.kind, error.phase = .Deadline_Failed, .Deadline
	case .E_SEND_ERROR, .E_READ_ERROR, .E_UPLOAD_FAILED, .E_SEND_FAIL_REWIND:
		error.phase = .Write
	case .E_RECV_ERROR, .E_PARTIAL_FILE, .E_GOT_NOTHING, .E_WRITE_ERROR:
		error.phase = .Read
	case .E_WEIRD_SERVER_REPLY, .E_HTTP2, .E_HTTP2_STREAM, .E_HTTP3, .E_BAD_CONTENT_ENCODING:
		error.kind, error.phase = .Invalid_Status, .Protocol
	case .E_OUT_OF_MEMORY:
		error.kind = .Allocation_Failed
	case .E_ABORTED_BY_CALLBACK:
		// The only aborting callback here is a file reader. It does not establish
		// user cancellation; preserve that distinction rather than inventing one.
		if file_upload {error.phase = .Write}
	}
	// libcurl also uses UNSUPPORTED_PROTOCOL for an HTTP/0.9-style reply.
	// A recorded HTTP request distinguishes that response failure from a local
	// unsupported URL scheme. Do not use a zero counter as proof of no effects.
	if code == .E_UNSUPPORTED_PROTOCOL && request_size > 0 {
		error.kind, error.phase, error.write_effect = .Invalid_Status, .Protocol, .Unknown
	}
	if request_size > 0 && error.write_effect == .Not_Sent {error.write_effect = .Unknown}
	if body_limit {error.kind, error.phase = .Body_Oversized, .Body_Limit}
	if status != 0 {error.write_effect = .Response_Received}
	return error
}
