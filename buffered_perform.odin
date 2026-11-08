package surf

import http "../http"
import "core:c"
import "core:os"
import "core:strings"
import "core:sync"
import curl "vendor:curl"

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
	result.error = {
		kind         = .Invalid_Config,
		phase        = .Configuration,
		write_effect = .Not_Sent,
	}
	sync.once_do(&buffered_http_ready, buffered_http_initialize)
	if !buffered_http_initialized do return
	handle := curl.easy_init()
	if handle == nil {
		result.error.kind = .Allocation_Failed; return
	}
	list: ^curl.slist
	defer {curl.easy_cleanup(handle); if list != nil do curl.slist_free_all(list)}
	stored, header_error := buffered_http_headers(handle, headers)
	if header_error.kind != .None {
		result.error = header_error; return
	}
	list = stored
	if !buffered_http_options(handle, method, url, ca_file, timeout_ms, &result.error) do return
	empty: byte
	if !buffered_http_source(
		handle,
		method,
		body,
		upload_file,
		upload_size,
		&empty,
		&result.error,
	) {
		return
	}
	if !buffered_http_setopt(handle, .WRITEFUNCTION, buffered_http_receive, &result.error) ||
	   !buffered_http_setopt(handle, .WRITEDATA, reply, &result.error) {
		return
	}
	code := curl.easy_perform(handle)
	return buffered_http_completed(handle, code, reply, upload_file != nil)
}

@(private)
buffered_http_headers :: proc(handle: ^curl.CURL, headers: []string) -> (^curl.slist, HTTP_Error) {
	list: ^curl.slist
	for header in headers {
		text, ae := buffered_http_cstring_checked(header)
		if ae != nil {
			if list != nil do curl.slist_free_all(list)
			return nil, buffered_http_allocation_error(ae)
		}
		next := curl.slist_append(list, text)
		if next == nil {
			if list != nil do curl.slist_free_all(list)
			return nil, {
				kind = .Allocation_Failed,
				phase = .Configuration,
				write_effect = .Not_Sent,
			}
		}
		list = next
	}
	error: HTTP_Error
	if list != nil && !buffered_http_setopt(handle, .HTTPHEADER, list, &error) {
		curl.slist_free_all(list); return nil, error
	}
	return list, {}
}

@(private)
buffered_http_source :: proc(
	handle: ^curl.CURL,
	method: string,
	body: []byte,
	file: ^os.File,
	size: i64,
	empty: ^byte,
	error: ^HTTP_Error,
) -> bool {
	if file != nil {
		return(
			buffered_http_setopt(handle, .UPLOAD, c.long(1), error) &&
			buffered_http_setopt(handle, .READFUNCTION, buffered_http_read_file, error) &&
			buffered_http_setopt(handle, .READDATA, file, error) &&
			buffered_http_setopt(handle, .INFILESIZE_LARGE, c.longlong(size), error) \
		)
	}
	if method == "PUT" || method == "POST" {
		pointer := raw_data(body)
		if pointer == nil do pointer = empty
		return(
			buffered_http_setopt(handle, .POSTFIELDS, pointer, error) &&
			buffered_http_setopt(handle, .POSTFIELDSIZE_LARGE, c.longlong(len(body)), error) \
		)
	}
	return true
}

@(private)
buffered_http_completed :: proc(
	handle: ^curl.CURL,
	code: curl.code,
	reply: ^Buffered_HTTP_Reply,
	file_upload: bool,
) -> (
	result: Buffered_HTTP_Result,
) {
	status: c.long
	info_code := curl.easy_getinfo(handle, .RESPONSE_CODE, &status)
	if info_code == .E_OK do result.status = int(status)
	if code != .E_OK {
		request_size: c.long = -1
		if curl.easy_getinfo(handle, .REQUEST_SIZE, &request_size) != .E_OK do request_size = -1
		result.error = buffered_http_error(
			code,
			result.status,
			reply.limit_exceeded,
			file_upload,
			i64(request_size),
		)
		return
	}
	if info_code != .E_OK {
		result.error = {
			kind          = .IO_Failed,
			phase         = .Unknown,
			provider_code = int(info_code),
			write_effect  = .Unknown,
		}
		return
	}
	result.ok = status >= 200 && status < 300
	result.transport_ok = true
	return
}
