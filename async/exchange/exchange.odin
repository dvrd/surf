package surf_exchange

import surf "../.."
import http "../../../http"
import "core:time"
import h1 "../../../http/v1"
import "core:mem"
import "core:net"
import channel "../stream"
import "core:compress/deflate"
import "core:strings"
import "core:mem/owned"

// Pure bounds/default selection. No allocator, clock, retention, callbacks or
// network calls. On rejection no partially normalized result is returned.
options_normalize :: proc(input: Options) -> (Resolved_Options, surf.HTTP_Error) {
	if input.body_limit < 0 ||
	   input.body_limit > http.MAX_BODY_SIZE ||
	   input.informational_limit < 0 ||
	   input.informational_limit > MAX_INFORMATIONAL_RESPONSES {
		return {}, {kind = .Invalid_Config}
	}

	result := Resolved_Options {
		body_limit          = input.body_limit,
		informational_limit = input.informational_limit,
	}

	if result.body_limit == 0 {
		result.body_limit = http.DEFAULT_MAX_BODY_SIZE
	}

	if result.informational_limit == 0 {
		result.informational_limit = MAX_INFORMATIONAL_RESPONSES
	}

	return result, {}
}

// Structural clock-pair validation only. Negative/nonzero wall times are legal
// absolute times; no source of current time or Runtime epoch is consulted here.
budget_validate :: proc(input: Budget) -> surf.HTTP_Error {
	if input.at < 0 ||
	   (input.at == 0 && input.wall != (time.Time{})) ||
	   (input.at > 0 && input.wall == (time.Time{})) {
		return {kind = .Invalid_Config}
	}

	return {}
}

Exchange_Step :: enum {
	Continue,
	Waiting,
	Barrier,
}
exchange_valid :: proc(x: ^Exchange) -> bool {
	return x != nil && x._self == x
}
exchange_pending_error :: proc() -> surf.HTTP_Error {
	return {kind = .Invalid_Config, transport = {kind = .Operation_Pending}, phase = .Configuration}
}

exchange_init :: proc(x: ^Exchange, options: Options, allocator: mem.Allocator) -> surf.HTTP_Error {
	if x == nil || x._self != nil {
		return {kind = .Invalid_Config}
	}

	normalized, error := options_normalize(options)

	if error.kind != .None {
		return error
	}

	if allocator.procedure == nil {
		return {kind = .Invalid_Config}
	}

	// Query is arbitrary allocator code too: reject reentry until construction
	// commits or rolls back, and require individual frees for every owned grant.
	x^ = {
		_self  = x,
		_busy  = true,
		_phase = .Idle,
	}

	if .Free not_in mem.query_features(allocator) {
		x^ = {}
		return {kind = .Invalid_Config}
	}

	x^ = {
		_self      = x,
		_options   = normalized,
		_allocator = allocator,
		_phase     = .Idle,
	}

	return {}
}

exchange_begin :: proc(
	x: ^Exchange,
	stream: net.Async_Connection,
	request: http.Request,
	budget: Budget,
	notify: Notify,
	encoded_head: []u8 = nil,
) -> surf.HTTP_Error {
	if !exchange_valid(x) {
		return {kind = .Invalid_Config}
	}
	if x._busy || x._phase != .Idle {
		return exchange_pending_error()
	}
	if stream.submit == nil || stream.cancel == nil || notify.wake == nil {
		return {kind = .Invalid_Config}
	}
	if error := budget_validate(budget); error.kind != .None {
		return error
	}
	if len(request.url) < 0 || len(request.url) > 0 && raw_data(request.url) == nil {
		return {kind = .Invalid_URL}
	}
	if len(request.body) < 0 || len(request.body) > 0 && raw_data(request.body) == nil {
		return {kind = .Invalid_Config}
	}
	if len(request.headers) < 0 || len(request.headers) > http.MAX_HEADERS {
		return {kind = .Header_Limit}
	}
	if len(request.headers) > 0 && raw_data(request.headers) == nil {
		return {kind = .Invalid_Header}
	}
	// Descriptor shape must precede alias traversal and the shared encoder.
	for field in request.headers {
		if len(field.name) < 0 ||
		   len(field.value) < 0 ||
		   len(field.name) > 0 && raw_data(field.name) == nil ||
		   len(field.value) > 0 && raw_data(field.value) == nil {
			return {kind = .Invalid_Header}
		}
	}
	if exchange_aliases(x, request) {
		return {kind = .Overlapping_Buffers}
	}
	// All rejection paths preserve the complete Exchange and caller inputs.
	// A caller that already encoded this request (stream_exchange_begin, which
	// needs a different Accept-Encoding and length) passes the head instead.
	header: [HEAD_BUFFER_SIZE]u8
	head := encoded_head
	if head == nil {
		count, error := h1.request_encode_content(header[:], request, .Keep_Alive, .Identity)
		if error.kind != .None {
			return surf.http_protocol_error(error)
		}
		head = header[:count]
	}
	count := len(head)
	options, allocator := x._options, x._allocator
	x^ = {
		_self              = x,
		_options           = options,
		_allocator         = allocator,
		_phase             = .Writing_Head,
		_stream            = stream,
		_budget            = budget,
		_notify            = notify,
		_method            = request.method,
		_request_head_used = count,
		_request_body      = request.body,
	}
	copy(x._request_head[:count], head)
	x._read.owner = x
	x._write.owner = x
	x._read.operation = {
		callback  = exchange_operation_done,
		user_data = &x._read,
	}
	x._write.operation = {
		callback  = exchange_operation_done,
		user_data = &x._write,
	}
	return {}
}

exchange_fail :: proc(x: ^Exchange, error: surf.HTTP_Error) {
	if x._failure.kind == .None {
		x._failure = error
	}

	x._reuse_eligible = false
	x._phase = .Draining
}
exchange_error :: proc(x: ^Exchange) -> surf.HTTP_Error {
	effect: surf.HTTP_Write_Effect = .Unknown

	if x._response.status > 0 {
		effect = .Response_Received
	} else if x._written == 0 && !x._write.accepted {
		effect = .Not_Sent
	}

	return surf.http_error_classify(x._failure, .Read, effect, x._response.status)
}
exchange_check_budget :: proc(x: ^Exchange, now: i64, cancelled: bool) {
	if x._failure.kind != .None {
		return
	}

	if cancelled {
		x._cancelled = true
		exchange_fail(x, {kind = .IO_Failed, transport = {kind = .Cancelled}, phase = .Cancellation})
	} else if x._budget.at != 0 && now >= x._budget.at {
		exchange_fail(x, {kind = .Deadline_Failed, transport = {kind = .Timeout}, phase = .Deadline})
	}
}
exchange_drain :: proc(x: ^Exchange) -> bool {
	if x._write.ready {
		error := exchange_write_result(x)

		if error.kind != .None && x._failure.kind == .None {
			exchange_fail(x, error)
		}
	}

	if x._read.ready {
		x._read.ready = false

		if x._read.result.count < 0 || x._read.result.count > READ_BUFFER_SIZE {
			exchange_fail(x, {kind = .IO_Failed, transport = {kind = .Invalid_Count}, phase = .Read})
		}
	}

	if x._read.accepted && !x._read.cancel_requested {
		x._read.cancel_requested = true
		_ = net.async_cancel(x._stream, &x._read.operation)
	}

	if x._write.accepted && !x._write.cancel_requested {
		x._write.cancel_requested = true
		_ = net.async_cancel(x._stream, &x._write.operation)
	}

	return !x._read.accepted && !x._write.accepted
}

// Fresh now is required on every drive call. A physical allocation/free or HTTP
// end boundary returns Progress before success, so the next call can gate its
// completion using a clock sampled AFTER that synchronous work. Work counts
// finite steps: protocol scans/copies use fixed read/head buffers. Physical
// allocation and body growth/copy are additionally bounded by body_limit (up to
//64MiB), not preempted or represented as per-byte work. No CPU deadline or
// preemption guarantee is made for allocators, owned growth or protocol crypto.
exchange_drive :: proc(x: ^Exchange, now: i64, cancelled: bool, work: int) -> Drive_Result {
	if !exchange_valid(x) || now < 0 || work < 1 || work > MAX_WORK_PER_DRIVE {
		return {status = .Done, error = {kind = .Invalid_Config}}
	}

	if x._busy {
		return {status = .Waiting, error = exchange_pending_error()}
	}

	if x._phase == .Idle {
		return {status = .Done, error = {kind = .Invalid_Config}}
	}

	if x._phase == .Done {
		return {status = .Done, error = x._failure, reuse_eligible = x._reuse_eligible}
	}

	x._busy = true
	used := 0

	for used < work {
		exchange_check_budget(x, now, cancelled)
		used += 1
		step: Exchange_Step

		switch x._phase {
		case .Writing_Head, .Writing_Body:
			step = exchange_write_step(x)
		case .Reading_Head:
			step = exchange_head_step(x)
		case .Copying_Head:
			error := exchange_copy_head(x)

			if error.kind != .None {
				exchange_fail(x, error)
			} else {
				x._body_remaining = x._head.content_length

				if x._head.framing == .Chunked {
					error = surf.http_protocol_error(h1.chunk_decoder_init(&x._chunk, u64(x._options.body_limit)))

					if error.kind != .None {
						exchange_fail(x, error)
					}
				}

				if x._phase != .Draining {
					x._phase = .Reading_Body
				}
			}

			step = .Barrier
		case .Reading_Body:
			step = exchange_body_step(x)
		case .Draining:
			if !exchange_drain(x) {
				step = .Waiting
				break
			}

			// Commit before disposal: arbitrary frees may destroy the public owner.
			error := exchange_error(x)
			x._failure = error
			x._phase = .Done
			x._request_body = nil
			disposal: surf.Response

			if error.kind != .None {
				disposal = x._response
				x._response = {}
			} else {
				x._response.body = x._response.body_storage[:]
			}

			result := Drive_Result {
				status         = .Done,
				work_used      = used,
				error          = error,
				reuse_eligible = x._reuse_eligible,
			}

			x._busy = false
			surf.response_destroy(&disposal)
			return result // Locals only: x may have been physically freed.
		case .Idle, .Done:
			panic("invalid exchange drive transition")
		}

		if step == .Barrier {
			result := Drive_Result {
				status    = .Progress,
				work_used = used,
				error     = exchange_error(x),
			}

			x._busy = false
			return result
		}

		if step == .Waiting {
			result := Drive_Result {
				status    = .Waiting,
				work_used = used,
				error     = exchange_error(x),
			}

			x._busy = false
			return result
		}
	}

	result := Drive_Result {
		status    = .Progress,
		work_used = used,
		error     = exchange_error(x),
	}

	x._busy = false

	return result
}

exchange_quiescent :: proc(x: ^Exchange) -> bool {
	return(
		exchange_valid(x) &&
		!x._busy &&
		(x._phase == .Idle || x._phase == .Done) &&
		!x._read.accepted &&
		!x._write.accepted &&
		!x._read.ready &&
		!x._write.ready \
	)
}
exchange_take :: proc(x: ^Exchange, destination: ^surf.Response) -> surf.HTTP_Error {
	if !exchange_valid(x) || destination == nil {
		return {kind = .Invalid_Config}
	}

	if exchange_overlap(x, size_of(Exchange), destination, size_of(surf.Response)) {
		return {kind = .Overlapping_Buffers}
	}

	if !exchange_quiescent(x) || x._phase != .Done {
		return exchange_pending_error()
	}

	if x._failure.kind != .None {
		return x._failure
	}

	if x._result_taken || !exchange_response_empty(destination) {
		return {kind = .Invalid_Config}
	}

	destination^ = x._response
	x._response = {}
	x._result_taken = true

	return {}
}
exchange_reset :: proc(x: ^Exchange) -> surf.HTTP_Error {
	if !exchange_valid(x) {
		return {kind = .Invalid_Config}
	}

	if !exchange_quiescent(x) {
		return exchange_pending_error()
	}

	if !exchange_response_empty(&x._response) {
		return exchange_pending_error()
	}

	options, allocator := x._options, x._allocator
	x^ = {
		_self      = x,
		_options   = options,
		_allocator = allocator,
		_phase     = .Idle,
	}

	return {}
}
exchange_destroy :: proc(x: ^Exchange) -> surf.HTTP_Error {
	if !exchange_valid(x) {
		return {kind = .Invalid_Config}
	}

	if !exchange_quiescent(x) {
		return exchange_pending_error()
	}

	response := x._response
	x^ = {}
	surf.response_destroy(&response)

	return {} // No owner access after an arbitrary physical free.
}

exchange_grant :: proc(size, alignment: int, allocator: mem.Allocator) -> ([]u8, surf.HTTP_Error) {
	if size < 0 || allocator.procedure == nil {
		return nil, {kind = .Invalid_Config}
	}

	if size == 0 {
		return nil, {}
	}

	grant, cause := allocator.procedure(allocator.data, .Alloc, size, alignment, nil, 0)
	if cause != nil ||
	   len(grant) != size ||
	   raw_data(grant) == nil ||
	   uintptr(raw_data(grant)) % uintptr(alignment) != 0 {
		if raw_data(grant) != nil {
			_, _ = allocator.procedure(allocator.data, .Free, 0, alignment, raw_data(grant), len(grant))
		}
		if cause == nil {
			cause = .Out_Of_Memory
		}
		return nil, {kind = .Allocation_Failed, allocation = cause}
	}

	for &byte in grant {
		byte = 0
	}

	return grant, {}
}
exchange_free :: proc(grant: []u8, alignment: int, allocator: mem.Allocator) {
	if raw_data(grant) != nil {
		_, _ = allocator.procedure(allocator.data, .Free, 0, alignment, raw_data(grant), len(grant))
	}
}
exchange_response_empty :: proc(r: ^surf.Response) -> bool {
	return(
		r != nil &&
		r.status == 0 &&
		raw_data(r.headers) == nil &&
		raw_data(r.header_storage) == nil &&
		raw_data(r.body) == nil &&
		raw_data(r.body_storage) == nil &&
		cap(r.body_storage) == 0 &&
		r.allocator.procedure == nil &&
		r._allocator_scope == {} \
	)
}
exchange_overlap :: proc(a: rawptr, an: int, b: rawptr, bn: int) -> bool {
	if an <= 0 || bn <= 0 {
		return false
	}

	av, bv := uintptr(a), uintptr(b)

	return (av <= bv && bv - av < uintptr(an)) || (bv < av && av - bv < uintptr(bn))
}
exchange_aliases :: proc(x: ^Exchange, request: http.Request) -> bool {
	if exchange_overlap(x, size_of(Exchange), raw_data(request.url), len(request.url)) ||
	   exchange_overlap(x, size_of(Exchange), raw_data(request.body), len(request.body)) {
		return true
	}

	if len(request.headers) > http.MAX_HEADERS {
		return false
	} // Encoder reports the bound before dereference.
	if exchange_overlap(x, size_of(Exchange), raw_data(request.headers), len(request.headers) * size_of(http.Header)) {
		return true
	}

	for field in request.headers {
		if exchange_overlap(x, size_of(Exchange), raw_data(field.name), len(field.name)) ||
		   exchange_overlap(x, size_of(Exchange), raw_data(field.value), len(field.value)) {
			return true
		}
	}

	return false
}

exchange_copy_head :: proc(x: ^Exchange) -> surf.HTTP_Error {
	storage, error := exchange_grant(x._response_head_used, 1, x._allocator)

	if error.kind != .None {
		return error
	}

	x._response.header_storage = storage
	x._response.allocator = x._allocator
	copy(storage, x._response_head[:x._response_head_used])
	head, _, decoded := h1.response_header_decode(storage)

	if decoded.kind != .None {
		return surf.http_protocol_error(decoded)
	}

	descriptors, allocation := exchange_grant(
		head.header_count * size_of(http.Header),
		align_of(http.Header),
		x._allocator,
	)

	if allocation.kind != .None {
		return allocation
	}

	if head.header_count > 0 {
		headers := (cast([^]http.Header)raw_data(descriptors))[:head.header_count]
		copy(headers, head.headers[:head.header_count])
		x._response.headers = headers
	}

	x._response.status = head.status
	x._response.body_storage.allocator = x._allocator

	return {}
}

// Growth publishes the new owner before freeing old storage. _busy excludes
// reentrant public mutation until the caller returns a fresh-clock barrier.
exchange_grow_body :: proc(x: ^Exchange, needed: int) -> (bool, surf.HTTP_Error) {
	body := x._response.body_storage

	if needed <= cap(body) {
		return false, {}
	}

	if needed > x._options.body_limit {
		return false, {kind = .Body_Oversized}
	}

	capacity := min(x._options.body_limit, max(needed, 4096, 2 * cap(body)))
	storage, error := exchange_grant(capacity, 1, x._allocator)

	if error.kind != .None {
		return false, error
	}

	copy(storage, body[:])
	replacement := transmute([dynamic]u8)mem.Raw_Dynamic_Array {
		data = raw_data(storage),
		len = len(body),
		cap = len(storage),
		allocator = x._allocator,
	}

	x._response.body_storage = replacement

	if raw_data(body) != nil {
		exchange_free(raw_data(body)[:cap(body)], 1, body.allocator)
	}

	return true, {}
}
exchange_append_body :: proc(x: ^Exchange, source: []u8) -> (bool, surf.HTTP_Error) {
	length := len(x._response.body_storage)

	if len(source) > x._options.body_limit - length {
		return false, {kind = .Body_Oversized}
	}

	grew, error := exchange_grow_body(x, length + len(source))

	if error.kind != .None || grew {
		return grew, error
	}

	raw := cast(^mem.Raw_Dynamic_Array)&x._response.body_storage
	copy((cast([^]u8)raw.data)[length:length + len(source)], source)
	raw.len += len(source)

	return false, {}
}

// Owner-loop metadata only. Query after an API call returns, never concurrently
// with a drive or from its allocator/provider callbacks. Reading_Head begins
// only after the final accepted request-write callback has been consumed.
// No transport/TLS readiness, peer liveness or closed-quiescence is implied.
// Reentrant/busy and copied/uninitialized owners reject without mutation.
exchange_phase :: proc(x: ^Exchange) -> (Exchange_Phase, bool) {
	if !exchange_valid(x) || x._busy {
		return {}, false
	}

	switch x._phase {
	case .Idle, .Writing_Head, .Writing_Body, .Reading_Head, .Copying_Head, .Reading_Body, .Draining, .Done:
		return x._phase, true
	case:
		return {}, false
	}
}

exchange_fill :: proc(x: ^Exchange) -> Exchange_Step {
	if x._read_at < x._read_used {
		return .Continue
	}

	if x._read.accepted {
		return .Waiting
	}

	if x._read.ready {
		x._read.ready = false
		result := x._read.result

		if result.count < 0 || result.count > len(x._read_buffer) {
			exchange_fail(x, {kind = .IO_Failed, transport = {kind = .Invalid_Count}, phase = .Read})
			return .Continue
		}

		x._read_at = 0
		x._read_used = result.count

		if result.err.kind == .Peer_Closed {
			x._peer_eof = true
		}

		if result.count > 0 {
			return .Continue
		}

		if result.err.kind == .None {
			exchange_fail(x, {kind = .No_Progress, phase = .Read})
			return .Continue
		}
	}

	error := x._read.result.err

	if error.kind != .None {
		if error.kind == .Peer_Closed {
			if x._phase == .Reading_Body && x._head.framing == .EOF {
				x._phase = .Draining
				return .Barrier
			}

			exchange_fail(x, {kind = .Unexpected_EOF, transport = error, phase = .Read})
		} else {
			exchange_fail(x, {kind = .IO_Failed, transport = error, phase = .Read})
		}

		return .Continue
	}

	x._read.result = {}
	x._read.cancel_requested = false
	x._read.accepted = true
	error = net.async_read(x._stream, &x._read.operation, x._read_buffer[:], x._budget.wall)

	if error.kind != .None {
		x._read.accepted = false
		exchange_fail(x, {kind = .IO_Failed, transport = error, phase = .Read})
		return .Continue
	}

	return .Waiting
}
exchange_head_step :: proc(x: ^Exchange) -> Exchange_Step {
	if x._response_head_used == HEAD_BUFFER_SIZE {
		exchange_fail(x, {kind = .Header_Oversized, phase = .Protocol})
		return .Continue
	}

	if x._read_at == x._read_used {
		step := exchange_fill(x)

		if step != .Continue || x._phase == .Draining {
			return step
		}
	}

	for x._read_at < x._read_used {
		if x._response_head_used == len(x._response_head) {
			exchange_fail(x, {kind = .Header_Oversized, phase = .Protocol})
			return .Continue
		}

		x._response_head[x._response_head_used] = x._read_buffer[x._read_at]
		x._response_head_used += 1
		x._read_at += 1
		n := x._response_head_used
		if n < 4 ||
		   x._response_head[n - 4] != 13 ||
		   x._response_head[n - 3] != 10 ||
		   x._response_head[n - 2] != 13 ||
		   x._response_head[n - 1] != 10 {
			continue
		}

		head, _, error := h1.response_header_decode(x._response_head[:n])

		if error.kind != .None {
			exchange_fail(x, surf.http_protocol_error(error))
			return .Continue
		}

		x._response.status = head.status

		if head.status < 200 {
			if head.status == 101 {
				exchange_fail(x, {kind = .Invalid_Status, phase = .Protocol})
				return .Continue
			}

			x._informational += 1

			if x._informational > x._options.informational_limit {
				exchange_fail(x, {kind = .Too_Many_Informational, phase = .Protocol})
				return .Continue
			}

			x._response_head_used = 0
			continue
		}

		h1.response_apply_method(&head, x._method)
		allowed, reuse_error := h1.response_reuse_allowed(&head, http.method_text(x._method))

		if reuse_error.kind != .None {
			exchange_fail(x, surf.http_protocol_error(reuse_error))
			return .Continue
		}

		if head.framing == .Length && head.content_length > u64(x._options.body_limit) {
			exchange_fail(x, {kind = .Body_Oversized, phase = .Body_Limit})
			return .Continue
		}

		x._head = head
		x._reuse_eligible = allowed
		x._phase = .Copying_Head
		return .Continue
	}

	return .Continue
}
exchange_body_finished :: proc(x: ^Exchange) -> Exchange_Step {
	// Surplus belongs to the retiring stream, never to a future request. The
	// completed HTTP response is still valid, but its connection is not reusable.
	if x._read_at != x._read_used || x._peer_eof || x._read.result.err.kind != .None {
		x._reuse_eligible = false
	}

	x._phase = .Draining

	return .Barrier // Fresh caller monotonic sample before publishing success.
}
exchange_body_step :: proc(x: ^Exchange) -> Exchange_Step {
	if x._head.framing == .None || x._head.framing == .Length && x._body_remaining == 0 {
		return exchange_body_finished(x)
	}

	if x._read_at == x._read_used {
		step := exchange_fill(x)

		if step != .Continue || x._phase == .Draining {
			return step
		}
	}

	source := x._read_buffer[x._read_at:x._read_used]

	if x._head.framing == .Chunked {
		body := x._response.body_storage
		storage: []u8

		if cap(body) > 0 {
			storage = raw_data(body)[:cap(body)]
		}

		consumed, written, done, error := h1.chunk_decoder_feed(&x._chunk, source, storage[len(body):])
		raw := cast(^mem.Raw_Dynamic_Array)&x._response.body_storage
		raw.len += written
		x._read_at += consumed

		if error.kind != .None {
			exchange_fail(x, surf.http_protocol_error(error))
			return .Continue
		}

		if done {
			return exchange_body_finished(x)
		}

		if consumed == 0 && written == 0 && len(source) > 0 {
			if len(body) == x._options.body_limit {
				exchange_fail(x, {kind = .Body_Oversized, phase = .Body_Limit})
				return .Continue
			}

			grew, allocation := exchange_grow_body(
				x,
				len(body) + min(READ_BUFFER_SIZE, x._options.body_limit - len(body)),
			)

			if allocation.kind != .None {
				exchange_fail(x, allocation)
				return .Continue
			}

			if grew {
				return .Barrier
			}
		}

		return .Continue
	}

	count := len(source)

	if x._head.framing == .Length {
		count = int(min(u64(count), x._body_remaining))
	}

	grew, error := exchange_append_body(x, source[:count])

	if error.kind != .None {
		exchange_fail(x, error)
		return .Continue
	}

	if grew {
		return .Barrier
	}

	x._read_at += count

	if x._head.framing == .Length {
		x._body_remaining -= u64(count)
	}

	return .Continue
}

stream_exchange_begin :: proc(
	x: ^Stream_Exchange,
	stream: net.Async_Connection,
	request: http.Request,
	budget: Budget,
	notify: Notify,
	cell: ^channel.Channel,
	redirects: bool,
	allocator: mem.Allocator,
) -> surf.HTTP_Error {
	if x == nil || cell == nil {
		return {kind = .Invalid_Config}
	}
	if x.base._self != nil || x.channel != nil {
		return exchange_pending_error()
	}
	options := cell.options
	length := i64(-1)
	if size, upload := options.upload_length.?; upload {
		length = size
	}
	encoding := h1.Request_Accept_Encoding.Identity
	if options.decoding == .Gzip {
		encoding = .Gzip
	}
	head: [HEAD_BUFFER_SIZE]u8
	count, error := h1.request_encode_content(head[:], request, .Keep_Alive, encoding, length)
	if error.kind != .None {
		return surf.http_protocol_error(error)
	}
	x^ = {
		channel   = cell,
		tx        = .Head,
		redirects = redirects,
	}
	if error := exchange_init(&x.base, {body_limit = int(options.max_encoded_bytes)}, allocator); error.kind != .None {
		return error
	}
	if error := exchange_begin(&x.base, stream, request, budget, notify, head[:count]); error.kind != .None {
		return error
	}
	// RX is enabled after the independent TX head finishes.
	x.base._phase = .Reading_Head
	return {}
}

stream_encoding :: proc(x: ^Stream_Exchange) -> surf.HTTP_Error {
	x.decoded = false

	if x.channel.options.decoding == .Identity {
		return {}
	}

	coding := ""
	count := 0

	for field in x.base._response.headers {
		if strings.equal_fold(field.name, "Content-Encoding") {
			coding = strings.trim(field.value, " \t")
			count += 1
		}
	}

	if count == 0 || count == 1 && strings.equal_fold(coding, "identity") {
		return {}
	}

	if count != 1 || !strings.equal_fold(coding, "gzip") {
		return {kind = .Unsupported_Content_Encoding, phase = .Decode}
	}

	if x.base._head.framing == .None {
		return {}
	}

	options := x.channel.options
	error := deflate.inflate_gzip_decoder_init(
		&x.decoder,
		{
			max_encoded_bytes = options.max_encoded_bytes,
			max_decoded_bytes = options.max_decoded_bytes,
			max_header_bytes = 8192,
			max_members = 1,
		},
	)

	if error != .None {
		return {kind = .Content_Decoding_Failed, decoding = error, phase = .Decode}
	}

	x.decoded = true

	return {}
}

stream_copy_head :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	if error := exchange_copy_head(&x.base); error.kind != .None {
		exchange_fail(&x.base, error)
		return .Continue
	}

	x.status = x.base._response.status

	if error := stream_encoding(x); error.kind != .None {
		exchange_fail(&x.base, error)
		return .Continue
	}

	x.private_response =
		x.redirects && (x.status == 301 || x.status == 302 || x.status == 303 || x.status == 307 || x.status == 308)
	x.base._body_remaining = x.base._head.content_length

	if x.base._head.framing == .Chunked {
		error := h1.chunk_decoder_init(&x.base._chunk, x.channel.options.max_encoded_bytes)

		if error.kind != .None {
			exchange_fail(&x.base, surf.http_protocol_error(error))
			return .Continue
		}
	}

	x.base._phase = .Reading_Body
	x.head_pending = true

	if x.tx != .Done && x.tx != .Stopped {
		x.early_response = true
		x.base._reuse_eligible = false
	}

	return .Barrier // Header allocations require a fresh owner clock before publication.
}

stream_exchange_drive :: proc(x: ^Stream_Exchange, now: i64, cancelled: bool, work: int) -> Drive_Result {
	if x == nil || !exchange_valid(&x.base) || work < 1 || work > MAX_WORK_PER_DRIVE || now < 0 {
		return {status = .Done, error = {kind = .Invalid_Config}}
	}

	base := &x.base

	if base._busy {
		return {status = .Waiting, error = exchange_pending_error()}
	}

	if base._phase == .Done {
		return {status = .Done, error = base._failure, reuse_eligible = base._reuse_eligible}
	}

	base._busy = true
	used := 0

	for used < work {
		exchange_check_budget(base, now, cancelled || channel.is_closed(x.channel))

		if base._failure.kind == .None && base._response.status < 200 {
			source := channel.upload_failure(x.channel)

			if source.kind != .None {
				exchange_fail(base, source)
			}
		}

		used += 1

		if base._failure.kind != .None {
			if base._write.ready {
				stream_write_ready(x)
			}

			if !exchange_drain(base) {
				base._busy = false
				return {status = .Waiting, work_used = used, error = exchange_error(base)}
			}

			if x.upload.release != nil || x.upload.allocator.procedure != nil {
				channel.upload_release(x.channel, &x.upload)
				base._busy = false
				return {status = .Progress, work_used = used, error = exchange_error(base)}
			}

			base._failure = exchange_error(base)
			base._phase = .Done
			base._busy = false
			return {status = .Done, work_used = used, error = base._failure}
		}

		tx := stream_write_step(x)

		if tx == .Barrier {
			base._busy = false
			return {status = .Progress, work_used = used}
		}

		if base._failure.kind != .None {
			continue
		}

		rx := Exchange_Step.Waiting

		if x.tx != .Head && !x.rx_done {
			switch base._phase {
			case .Reading_Head:
				rx = exchange_head_step(base)
			case .Copying_Head:
				rx = stream_copy_head(x)
			case .Reading_Body:
				remaining := work - used
				rx = stream_body_step(x, &remaining)
				used = work - remaining
			case .Draining, .Done, .Idle, .Writing_Head, .Writing_Body:
				exchange_fail(base, {kind = .Invalid_Config})
			}
		}

		if rx == .Barrier {
			base._busy = false
			return {status = .Progress, work_used = used}
		}

		if base._failure.kind != .None {
			continue
		}

		if x.rx_done && (x.tx == .Done || x.tx == .Stopped) && !base._read.accepted && !base._write.accepted {
			base._phase = .Done
			base._busy = false
			return {status = .Done, work_used = used, reuse_eligible = base._reuse_eligible}
		}

		if tx == .Waiting && rx == .Waiting {
			base._busy = false
			return {status = .Waiting, work_used = used}
		}
	}

	base._busy = false

	return {status = .Progress, work_used = used}
}

stream_exchange_quiescent :: proc(x: ^Stream_Exchange) -> bool {
	return x != nil && exchange_quiescent(&x.base)
}

stream_exchange_destroy :: proc(x: ^Stream_Exchange) -> surf.HTTP_Error {
	if !stream_exchange_quiescent(x) {
		return exchange_pending_error()
	}

	channel.stop_upload(x.channel)

	return exchange_destroy(&x.base)
}

stream_exchange_take_redirect :: proc(x: ^Stream_Exchange, destination: ^surf.Response) -> bool {
	if !stream_exchange_quiescent(x) ||
	   !x.private_response ||
	   x.base._failure.kind != .None ||
	   !exchange_response_empty(destination) {
		return false
	}

	destination^ = x.base._response
	x.base._response = {}

	return true
}

stream_entity_step :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	if x.encoded_at < x.encoded_used || x.entity_done {
		return .Continue
	}

	base := &x.base
	x.encoded_at = 0
	x.encoded_used = 0

	if base._head.framing == .None || base._head.framing == .Length && base._body_remaining == 0 {
		x.entity_done = true
		return .Continue
	}

	if base._read_at == base._read_used {
		step := exchange_fill(base)

		if base._phase == .Draining && base._failure.kind == .None {
			x.entity_done = true
			base._phase = .Reading_Body
			return .Continue
		}

		if step != .Continue || base._failure.kind != .None {
			return step
		}
	}

	source := base._read_buffer[base._read_at:base._read_used]
	consumed, produced := 0, 0

	if base._head.framing == .Chunked {
		done: bool
		n, written, finished, cause := h1.chunk_decoder_feed(&base._chunk, source, x.encoded[:])
		consumed, produced, done = n, written, finished

		if cause.kind != .None {
			exchange_fail(base, surf.http_protocol_error(cause))
			return .Continue
		}

		x.entity_done = done
	} else {
		count := min(len(source), len(x.encoded))

		if base._head.framing == .Length {
			count = int(min(u64(count), base._body_remaining))
		}

		consumed, produced = count, count
		copy(x.encoded[:], source[:count])

		if base._head.framing == .Length {
			base._body_remaining -= u64(count)
			x.entity_done = base._body_remaining == 0
		}
	}

	base._read_at += consumed

	if u64(produced) > x.channel.options.max_encoded_bytes - x.encoded_total {
		exchange_fail(base, {kind = .Body_Oversized, phase = .Body_Limit})
		return .Continue
	}

	x.encoded_total += u64(produced)
	x.encoded_used = produced

	return .Continue
}

stream_publish_head :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	if !x.head_pending {
		return .Continue
	}

	x.head_pending = false

	if x.private_response {
		return .Continue
	}

	length := i64(-1)

	for field in x.base._response.headers {
		if strings.equal_fold(field.name, "Content-Length") {
			if x.base._head.content_length > u64(max(i64)) {
				exchange_fail(&x.base, {kind = .Invalid_Content_Length, phase = .Protocol})
				return .Continue
			}

			length = i64(x.base._head.content_length)
		}
	}

	encoding := channel.Encoding.Decoded_Gzip if x.decoded else channel.Encoding.Wire

	if !channel.publish_head(x.channel, &x.base._response, length, encoding) {
		exchange_fail(&x.base, {kind = .IO_Failed, transport = {kind = .Cancelled}, phase = .Cancellation})
		return .Continue
	}

	x.base._response.status = x.status

	return .Continue
}

stream_body_step :: proc(x: ^Stream_Exchange, work: ^int) -> Exchange_Step {
	if x.rx_done {
		return .Waiting
	}

	stream_publish_head(x)

	if x.base._failure.kind != .None {
		return .Continue
	}

	// Advance bounded entity metadata/lookahead before demanding payload credit.
	// stream_entity_step stops immediately while any payload remains staged.
	step := stream_entity_step(x)

	if step != .Continue || x.base._failure.kind != .None {
		return step
	}

	source := x.encoded[x.encoded_at:x.encoded_used]

	if len(source) == 0 && !x.entity_done {
		return .Continue
	}

	output: ^channel.Output
	destination: []u8

	if x.private_response {
		destination = x.discard[:]
	} else {
		output, destination = channel.reserve_output(x.channel)
		// With all payload slots held, the decoder may still validate a trailer.
		// A zero-length output advances metadata only and stops at Need_Output.
		if output == nil && !x.decoded && len(source) > 0 {
			return .Waiting
		}
	}

	published := false

	defer if output != nil && !published {
		channel.abandon_output(output)
	}

	produced := 0

	if x.decoded {
		decoded := deflate.inflate_gzip_decoder_step(&x.decoder, source, destination, x.entity_done, max(1, work^))
		work^ = max(0, work^ - decoded.work)

		if decoded.err != .None {
			exchange_fail(&x.base, {kind = .Content_Decoding_Failed, decoding = decoded.err, phase = .Decode})
			return .Continue
		}

		x.encoded_at += decoded.consumed
		produced = decoded.produced

		if decoded.status == .Done {
			x.rx_done = true
		}

		if output == nil && !x.private_response && decoded.status == .Need_Output {
			return .Waiting
		}
	} else {
		produced = min(len(source), len(destination))

		if u64(produced) > x.channel.options.max_decoded_bytes - x.delivered_total {
			exchange_fail(&x.base, {kind = .Body_Oversized, phase = .Body_Limit})
			return .Continue
		}

		copy(destination[:produced], source[:produced])
		x.encoded_at += produced

		if x.entity_done && x.encoded_at == x.encoded_used {
			x.rx_done = true
		}
	}

	x.delivered_total += u64(produced)

	if output != nil && produced > 0 {
		accepted := channel.publish_output(output, produced)
		// Publish consumes the reservation even when concurrent closure rejects it.
		published = true

		if !accepted {
			exchange_fail(&x.base, {kind = .IO_Failed, transport = {kind = .Cancelled}, phase = .Cancellation})
			return .Continue
		}
	}

	if x.rx_done {
		if x.base._read_at != x.base._read_used || x.base._peer_eof || x.base._read.result.err.kind != .None {
			x.base._reuse_eligible = false
		}

		return .Barrier
	}

	return .Continue
}

Stream_TX :: enum {
	Head,
	Body,
	Upload,
	Done,
	Stopped,
}
// Separate TX/RX state preserves the existing buffered Exchange unchanged.
Stream_Exchange :: struct {
	base:                                                        Exchange,
	channel:                                                     ^channel.Channel,
	tx:                                                          Stream_TX,
	decoder:                                                     deflate.Gzip_Decoder,
	upload:                                                      owned.Chunk,
	upload_at, write_requested:                                  int,
	encoded:                                                     [READ_BUFFER_SIZE]u8,
	discard:                                                     [READ_BUFFER_SIZE]u8,
	encoded_at, encoded_used:                                    int,
	encoded_total, delivered_total:                              u64,
	decoded, entity_done, rx_done, early_response, head_pending: bool,
	private_response, redirects, upload_released:                bool,
	status:                                                      int,
}

stream_write_ready :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	base := &x.base
	result := base._write.result
	base._write.ready = false

	if result.count < 0 || result.count > x.write_requested {
		exchange_fail(base, {kind = .IO_Failed, transport = {kind = .Invalid_Count}, phase = .Write})
		return .Continue
	}

	base._written += u64(result.count)

	if x.tx == .Head {
		base._request_head_at += result.count
	} else if x.tx == .Body {
		base._request_body_at += result.count
	} else if x.tx == .Upload {
		x.upload_at += result.count
	}

	if result.err.kind != .None && !(x.early_response && result.err.kind == .Cancelled) {
		exchange_fail(base, {kind = .IO_Failed, transport = result.err, phase = .Write})
		return .Continue
	}

	if result.count == 0 && result.err.kind == .None {
		exchange_fail(base, {kind = .No_Progress, phase = .Write})
		return .Continue
	}

	return .Continue
}

stream_stop_upload :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	base := &x.base

	if !x.upload_released {
		x.upload_released = true
		channel.stop_upload(x.channel)
		return .Barrier // Arbitrary source release callbacks require fresh now.
	}

	if base._write.accepted {
		if !base._write.cancel_requested {
			base._write.cancel_requested = true
			_ = net.async_cancel(base._stream, &base._write.operation)
		}

		return .Waiting
	}

	if x.upload.release != nil || x.upload.allocator.procedure != nil {
		channel.upload_release(x.channel, &x.upload)
		x.upload_at = 0
		return .Barrier
	}

	x.tx = .Stopped

	return .Continue
}

stream_write_step :: proc(x: ^Stream_Exchange) -> Exchange_Step {
	base := &x.base

	if base._write.ready {
		stream_write_ready(x)

		if base._failure.kind != .None {
			return .Continue
		}
	}

	if x.early_response {
		return stream_stop_upload(x)
	}

	if base._write.accepted {
		return .Waiting
	}

	if x.tx == .Head && base._request_head_at == base._request_head_used {
		_, upload := x.channel.options.upload_length.?
		x.tx = .Upload if upload else .Body
	}

	if x.tx == .Body && base._request_body_at == len(base._request_body) {
		x.tx = .Done
		return .Continue
	}

	if x.tx == .Upload && x.upload_at == len(x.upload.data) {
		if x.upload.release != nil || x.upload.allocator.procedure != nil {
			channel.upload_release(x.channel, &x.upload)
			x.upload_at = 0
			return .Barrier
		}

		taken, finished, error := channel.upload_take(x.channel, &x.upload)

		if error.kind != .None {
			exchange_fail(base, error)
			return .Continue
		}

		if !taken {
			if finished {
				x.tx = .Done
				return .Continue
			}

			return .Waiting
		}
	}

	if x.tx == .Done || x.tx == .Stopped {
		return .Waiting
	}

	source: []u8

	switch x.tx {
	case .Head:
		source = base._request_head[base._request_head_at:base._request_head_used]
	case .Body:
		source = base._request_body[base._request_body_at:]
	case .Upload:
		source = x.upload.data[x.upload_at:]
	case .Done, .Stopped:
		return .Waiting
	}

	source = source[:min(len(source), READ_BUFFER_SIZE)]
	x.write_requested = len(source)
	base._write.result = {}
	base._write.cancel_requested = false
	base._write.accepted = true
	error := net.async_write(base._stream, &base._write.operation, source, base._budget.wall)

	if error.kind != .None {
		base._write.accepted = false
		exchange_fail(base, {kind = .IO_Failed, transport = error, phase = .Write})
		return .Continue
	}

	return .Waiting
}

READ_BUFFER_SIZE :: 16 << 10
HEAD_BUFFER_SIZE :: http.MAX_HEADER_SIZE
MAX_WORK_PER_DRIVE :: 4096
// Root Surf accepts seven interim heads before a final eighth head. Its eighth
// interim is Too_Many_Informational; this limit counts interim responses only.
MAX_INFORMATIONAL_RESPONSES :: 7

Options :: struct {
	// Zero selects HTTP's8MiB default; positive values are bounded at64MiB.
	body_limit:          int,
	// Zero selects Root Surf's existing seven-interim bound.
	informational_limit: int,
}
Resolved_Options :: struct {
	body_limit, informational_limit: int,
}

// The owner supplies both clocks from one retained mapping. Zero/zero is
// unlimited; positive at requires a nonzero absolute wall deadline. Pure shape
// validation cannot establish epoch identity, actual expiry or mapping accuracy.
Budget :: struct {
	at:   i64,
	wall: time.Time,
}
// Borrowed until all accepted operations retire and reset/destroy clears it.
// wake may notify/enqueue the owning loop; it is not a completion callback and
// must not free an Exchange with pending operations. Callbacks snapshot Notify
// and perform no Exchange access after invoking it.
Notify :: struct {
	data: rawptr,
	wake: proc(_: rawptr),
}
Drive_Status :: enum {
	Waiting,
	Progress,
	Done,
}
Drive_Result :: struct {
	status:         Drive_Status,
	work_used:      int,
	error:          surf.HTTP_Error,
	// HTTP framing+lookahead only, NEVER proof of idle TLS/socket health.
	reuse_eligible: bool,
}

// Idle means initialized/no exchange. Done means every accepted operation's terminal callback
// arrived; a successful Response may still await take.
Exchange_Phase :: enum {
	Idle,
	Writing_Head,
	Writing_Body,
	Reading_Head,
	Copying_Head,
	Reading_Body,
	Draining,
	Done,
}
Operation_State :: struct {
	operation:                         net.Async_Operation,
	owner:                             ^Exchange,
	// accepted is independent of operation.pending: even a completed provider
	// slot remains borrowed until our callback actually records its result.
	accepted, ready, cancel_requested: bool,
	result:                            net.Async_Result,
}
// One move-forbidden caller-owned exchange on its Async_Connection's owning
// loop. No Runtime/Task/Client/Kernel, scheduler, transport close owner or lock.
// request.body is borrowed from the admitted Request_Owner through the last
// accepted write callback. No caller header/URL arena is retained after begin
// encodes the head. Response allocations retain their own allocator provenance.
Exchange :: struct {
	_self:                                                 ^Exchange,
	_busy:                                                 bool,
	_options:                                              Resolved_Options,
	_allocator:                                            mem.Allocator,
	_phase:                                                Exchange_Phase,
	_stream:                                               net.Async_Connection,
	_budget:                                               Budget,
	_notify:                                               Notify,
	_read, _write:                                         Operation_State,
	_read_buffer:                                          [READ_BUFFER_SIZE]u8,
	_read_at, _read_used:                                  int,
	_request_head:                                         [HEAD_BUFFER_SIZE]u8,
	_request_head_used, _request_head_at:                  int,
	_request_body:                                         []u8,
	_request_body_at:                                      int,
	_method:                                               http.Method,
	_response_head:                                        [HEAD_BUFFER_SIZE]u8,
	_response_head_used:                                   int,
	// All borrowed fields in head refer to _response_head until copied; never
	// overwrite that backing while constructing owned Response header storage.
	_head:                                                 h1.Response_Head,
	_informational:                                        int,
	_chunk:                                                h1.Chunk_Decoder,
	_body_remaining:                                       u64,
	_response:                                             surf.Response,
	_failure:                                              surf.HTTP_Error,
	_written:                                              u64,
	_cancelled, _peer_eof, _reuse_eligible, _result_taken: bool,
}

exchange_operation_done :: proc(op: ^net.Async_Operation) {
	state := cast(^Operation_State)op.user_data
	x := state.owner
	state.result = op.result
	state.accepted = false
	state.ready = true
	notify := x._notify

	if notify.wake != nil {
		notify.wake(notify.data)
	}

	// Notification may reenter its owner; no operation/Exchange access follows.
}
exchange_write_result :: proc(x: ^Exchange) -> surf.HTTP_Error {
	if !x._write.ready {
		return {}
	}

	result := x._write.result
	x._write.ready = false
	head := x._request_head_at < x._request_head_used
	expected :=
		x._request_head_used - x._request_head_at if \
			head else \
			min(READ_BUFFER_SIZE, len(x._request_body) - x._request_body_at)

	if result.count < 0 || result.count > expected {
		return {kind = .IO_Failed, transport = {kind = .Invalid_Count}, phase = .Write}
	}

	x._written += u64(result.count)

	if head {
		x._request_head_at += result.count
	} else {
		x._request_body_at += result.count
	}

	if result.err.kind != .None {
		return {kind = .IO_Failed, transport = result.err, phase = .Write}
	}

	if result.count != expected {
		return {kind = .IO_Failed, transport = {kind = .Invalid_Count}, phase = .Write}
	}

	return {}
}
exchange_write_step :: proc(x: ^Exchange) -> Exchange_Step {
	if x._write.accepted {
		return .Waiting
	}

	if x._write.ready {
		if error := exchange_write_result(x); error.kind != .None {
			exchange_fail(x, error)
			return .Continue
		}
	}

	if x._phase == .Writing_Head && x._request_head_at == x._request_head_used {
		x._phase = .Writing_Body
	}

	if x._phase == .Writing_Body && x._request_body_at == len(x._request_body) {
		x._request_body = nil
		x._phase = .Reading_Head
		return .Continue
	}

	source: []u8

	if x._phase == .Writing_Head {
		source = x._request_head[x._request_head_at:x._request_head_used]
	} else {
		start := x._request_body_at
		source = x._request_body[start:start + min(READ_BUFFER_SIZE, len(x._request_body) - start)]
	}

	x._write.result = {}
	x._write.cancel_requested = false
	x._write.accepted = true
	error := net.async_write(x._stream, &x._write.operation, source, x._budget.wall)

	if error.kind != .None {
		x._write.accepted = false
		exchange_fail(x, {kind = .IO_Failed, transport = error, phase = .Write})
		return .Continue
	}

	return .Waiting
}
