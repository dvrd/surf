package client

import "base:runtime"
import "core:c"
import "core:io"
import "core:os"
import "core:strings"
import "core:sync"
import curl "vendor:curl"

// Streaming file uploads retain the existing curl adapter: unlike execute(),
// it supports PUT/DELETE and fixed-memory file reads. No redirects or proxies.
// Response bytes borrow the caller's temporary allocator, bounded to 64 KiB.
Buffered_HTTP_Result :: struct {
	status: int,
	ok: bool,
}

Buffered_HTTP_Reply :: struct {
	data: [64 * 1024]byte,
	used: int,
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
	if !allow_http && !strings.has_prefix(url, "https://") do return
	sync.once_do(&buffered_http_ready, buffered_http_initialize)
	if !buffered_http_initialized do return
	handle := curl.easy_init()
	if handle == nil do return
	list: ^curl.slist
	defer {curl.easy_cleanup(handle); if list != nil do curl.slist_free_all(list)}
	for header in headers {
		if strings.contains_any(header, "\r\n\x00") do return
		next := curl.slist_append(list, buffered_http_cstring(header))
		if next == nil do return
		list = next
	}
	if list != nil && curl.easy_setopt(handle, .HTTPHEADER, list) != .E_OK do return
	if !buffered_http_options(handle, method, url, ca_file, timeout_ms) {return}
	if upload_file != nil {
		if curl.easy_setopt(handle, .UPLOAD, c.long(1)) != .E_OK ||
		   curl.easy_setopt(handle, .READFUNCTION, buffered_http_read_file) != .E_OK ||
		   curl.easy_setopt(handle, .READDATA, upload_file) != .E_OK ||
		   curl.easy_setopt(handle, .INFILESIZE_LARGE, c.longlong(upload_size)) != .E_OK {
			return
		}
	} else if method == "PUT" || method == "POST" {
		empty: byte
		pointer := raw_data(body)
		if pointer == nil do pointer = &empty
		if curl.easy_setopt(handle, .POSTFIELDS, pointer) != .E_OK ||
		   curl.easy_setopt(handle, .POSTFIELDSIZE_LARGE, c.longlong(len(body))) != .E_OK {
			return
		}
	}
	reply: Buffered_HTTP_Reply
	if curl.easy_setopt(handle, .WRITEFUNCTION, buffered_http_receive) != .E_OK ||
	   curl.easy_setopt(handle, .WRITEDATA, &reply) != .E_OK {
		return
	}
	if curl.easy_perform(handle) != .E_OK do return
	status: c.long
	if curl.easy_getinfo(handle, .RESPONSE_CODE, &status) != .E_OK do return
	copied := make([]byte, reply.used, context.temp_allocator)
	copy(copied, reply.data[:reply.used])
	return copied, {status = int(status), ok = status >= 200 && status < 300}
}
buffered_http_options :: proc(
	handle: ^curl.CURL, method, url, ca_file: string, timeout_ms: i64,
) -> bool {
	for setting in ([]struct {
			key:   curl.option,
			value: string,
		}{{.URL, url}, {.CUSTOMREQUEST, method}, {.PROXY, ""}}) {
		if curl.easy_setopt(handle, setting.key, buffered_http_cstring(setting.value)) != .E_OK {
			return false
		}
	}
	if ca_file != "" && curl.easy_setopt(handle, .CAINFO, buffered_http_cstring(ca_file)) != .E_OK {
		return false
	}
	if timeout_ms <= 0 || timeout_ms > 120000 {return false}
	timeout := timeout_ms
	for setting in ([]struct {
			key:   curl.option,
			value: c.long,
		} {
			{.NOSIGNAL, 1},
			{.PATH_AS_IS, 1},
			{.SSL_VERIFYPEER, 1},
			{.SSL_VERIFYHOST, 2},
			{.FOLLOWLOCATION, 0},
			{.CONNECTTIMEOUT_MS, c.long(min(timeout, 5000))},
			{.TIMEOUT_MS, c.long(timeout)},
		}) {
		if curl.easy_setopt(handle, setting.key, setting.value) != .E_OK do return false
	}
	return true
}

buffered_http_receive :: proc "c" (
	data: rawptr, size, count: c.size_t, userdata: rawptr,
) -> c.size_t {
	reply := cast(^Buffered_HTTP_Reply)userdata
	if size == 0 || count > c.size_t(len(reply.data) - reply.used) / size do return 0
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
