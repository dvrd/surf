package surf

import "core:mem"
import "core:os"
import resources "core:sync/budget"

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
	copied, ae := buffered_http_owned_copy(&reply, result.status, output)
	if ae != nil {
		result = buffered_http_copy_error(result, ae); return
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
buffered_http_copy_error :: proc(
	previous: Buffered_HTTP_Result,
	error: mem.Allocator_Error,
) -> Buffered_HTTP_Result {
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
