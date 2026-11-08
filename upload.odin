package surf

import http "../http"
import http1 "../http/v1"
import "core:io"
import "core:mem"
import resources "core:sync/budget"
import "core:net"
import "core:time"

UPLOAD_BUFFER_SIZE :: 32 * 1024

// Borrows the source at its current position. Exactly content_length bytes are
// consumed: excess bytes stay unread, and no EOF probe, rewind, close or replay
// occurs. Reads must be cooperatively bounded; a transport deadline cannot
// preempt an arbitrary blocking source callback. Files use os.to_stream(file).
Upload_Source :: struct {
	stream: io.Stream,
	content_length: i64,
}

execute_upload :: proc(request: http.Request, source: Upload_Source, config: Config, allocator := context.allocator) -> (Response, HTTP_Error) {
	if config.max_redirects != 0 {
		return {}, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	if error := upload_validate(request, source); error.kind != .None {return {}, error}
	upload := source
	return execute_with_upload(request, config, &upload, allocator)
}

// Uses a caller-owned, already connected transport. Does not close either
// stream. Set transport deadlines before calling; an optional absolute deadline
// is also checked around source reads. It cannot interrupt a source callback.
exchange_upload :: proc(
	stream: net.Connection,
	request: http.Request,
	source: Upload_Source,
	max_body_size: int = 0,
	allocator := context.allocator,
	deadline: time.Time = {},
) -> (
	Response,
	HTTP_Error,
) {
	return exchange_upload_scoped(stream, request, source, max_body_size, allocator, deadline)
}

exchange_upload_scoped :: proc(
	stream: net.Connection,
	request: http.Request,
	source: Upload_Source,
	max_body_size: int = 0,
	allocator := context.allocator,
	deadline: time.Time = {},
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
	response, error := exchange_upload_internal(
		stream,
		request,
		source,
		max_body_size,
		call_allocator,
		deadline,
		&outcome,
	)
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
upload_validate :: proc(request: http.Request, source: Upload_Source) -> HTTP_Error {
	if source.content_length < 0 || (source.content_length > 0 && source.stream.procedure == nil) || len(request.body) != 0 {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	if source.content_length > 0 && !http.request_body_allowed(request.method) {
		return {kind = .Invalid_Method, phase = .Configuration, write_effect = .Not_Sent}
	}
	return {}
}

@(private)
upload_deadline_expired :: proc(deadline: time.Time) -> bool {
	return deadline != time.Time{} && time.diff(time.now(), deadline) <= 0
}

@(private)
exchange_upload_internal :: proc(
	stream: net.Connection, request: http.Request, source: Upload_Source,
	max_body_size: int, allocator: mem.Allocator, deadline: time.Time,
	outcome: ^HTTP_Exchange_Outcome,
) -> (Response, HTTP_Error) {
	if error := upload_validate(request, source); error.kind != .None {return {}, error}
	if !net.connection_valid(stream) || max_body_size < 0 || max_body_size > http.MAX_BODY_SIZE {
		return {}, {kind = .Invalid_Config, phase = .Configuration}
	}
	limit := max_body_size
	if limit == 0 {limit = http.DEFAULT_MAX_BODY_SIZE}
	header: [http.MAX_HEADER_SIZE]u8
	size, validation := http1.request_encode(header[:], request, source.content_length)
	if validation.kind != .None {
		return {}, {kind = validation.kind, phase = .Configuration, allocation = validation.allocation}
	}
	if upload_deadline_expired(deadline) {return {}, {kind = .Deadline_Failed, phase = .Deadline}}
	outcome.write_started = true
	if _, error := net.write_all(stream, header[:size]); error.kind != .None {
		return {}, {kind = .IO_Failed, phase = .Write, transport = error}
	}
	buffer: [UPLOAD_BUFFER_SIZE]u8
	remaining := source.content_length
	for remaining > 0 {
		if upload_deadline_expired(deadline) {return {}, {kind = .Deadline_Failed, phase = .Deadline}}
		wanted := int(min(remaining, i64(len(buffer))))
		count, read_error := source.stream.procedure(source.stream.data, .Read, buffer[:wanted], 0, nil)
		if count < 0 || count > i64(wanted) {
			return {}, {kind = .IO_Failed, phase = .Write, transport = {kind = .Invalid_Count}, source_io = read_error}
		}
		if upload_deadline_expired(deadline) {return {}, {kind = .Deadline_Failed, phase = .Deadline, source_io = read_error}}
		if read_error != .None && read_error != .EOF {
			return {}, {kind = .IO_Failed, phase = .Write, source_io = read_error}
		}
		if count == 0 {
			if read_error == .EOF {return {}, {kind = .Unexpected_EOF, phase = .Write, source_io = .EOF}}
			return {}, {kind = .No_Progress, phase = .Write, source_io = .No_Progress}
		}
		if _, error := net.write_all(stream, buffer[:int(count)]); error.kind != .None {
			return {}, {kind = .IO_Failed, phase = .Write, transport = error}
		}
		remaining -= count
		if read_error == .EOF && remaining > 0 {
			return {}, {kind = .Unexpected_EOF, phase = .Write, source_io = .EOF}
		}
	}
	return exchange_read_response(stream, request, limit, allocator, outcome)
}
