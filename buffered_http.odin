package surf

import "core:mem"
import "core:os"
import "core:strings"
import resources "core:sync/budget"

// Native TCP/TLS client. No redirects or proxies. The method token is sent
// unchanged on HTTP/1. Response bytes borrow the caller's temporary allocator,
// bounded to 64 KiB. provider_code stays zero.
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
	result = buffered_http_perform(
		method,
		url,
		body,
		headers,
		ca_file,
		timeout_ms,
		upload_file,
		upload_size,
		&reply,
	)
	if !result.transport_ok do return
	copied, ae := make([]byte, reply.used, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae); return
	}
	copy(copied, reply.data[:reply.used])
	return copied, result
}

@(private)
buffered_http_allocation_error :: proc(error: mem.Allocator_Error) -> HTTP_Error {
	return {kind = .Allocation_Failed, phase = .Configuration, write_effect = .Not_Sent, allocation = error}
}

buffered_http_cstring :: proc(value: string) -> cstring {
	result, _ := strings.clone_to_cstring(value, context.temp_allocator)
	return result
}

// Historical libcurl numbers. Native transfers leave provider_code zero; this
// mapping remains for the provider fixture and does not perform a transfer.
buffered_http_error :: proc(code: int, status: int, body_limit, file_upload: bool, request_size: i64 = -1) -> HTTP_Error {
	error := HTTP_Error{kind = .IO_Failed, provider_code = code, status = status}
	switch code {
	case 3, 4, 43, 48: // URL_MALFORMAT, NOT_BUILT_IN, BAD_FUNCTION_ARGUMENT, UNKNOWN_OPTION
		error.kind, error.phase, error.write_effect = .Invalid_Config, .Configuration, .Not_Sent
	case 1: // UNSUPPORTED_PROTOCOL
		error.kind = .Invalid_Status
	case 6, 5: // COULDNT_RESOLVE_HOST, COULDNT_RESOLVE_PROXY
		error.kind, error.phase, error.write_effect = .Dial_Failed, .DNS, .Not_Sent
	case 7: // COULDNT_CONNECT
		error.kind, error.phase, error.write_effect = .Dial_Failed, .Connect, .Not_Sent
	case 35, 60, 58, 59, 77, 82, 83, 90, 91, 98:
		error.kind, error.phase, error.write_effect = .TLS_Failed, .TLS, .Not_Sent
	case 28: // OPERATION_TIMEDOUT
		error.kind, error.phase = .Deadline_Failed, .Deadline
	case 55, 26, 25, 65: // SEND, READ, UPLOAD, SEND_FAIL_REWIND
		error.phase = .Write
	case 56, 18, 52, 23: // RECV, PARTIAL_FILE, GOT_NOTHING, WRITE
		error.phase = .Read
	case 8, 16, 92, 95, 61: // WEIRD_SERVER_REPLY, HTTP2, HTTP2_STREAM, HTTP3, BAD_CONTENT_ENCODING
		error.kind, error.phase = .Invalid_Status, .Protocol
	case 27: // OUT_OF_MEMORY
		error.kind = .Allocation_Failed
	case 42: // ABORTED_BY_CALLBACK
		if file_upload {error.phase = .Write}
	}
	if code == 1 && request_size > 0 {
		error.kind, error.phase, error.write_effect = .Invalid_Status, .Protocol, .Unknown
	}
	if request_size > 0 && error.write_effect == .Not_Sent {error.write_effect = .Unknown}
	if body_limit {error.kind, error.phase = .Body_Oversized, .Body_Limit}
	if status != 0 {error.write_effect = .Response_Received}
	return error
}
