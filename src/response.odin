package surf

import "core:mem"
import "shared:async"

// Copies the head into response, owned by allocator. The body starts empty.
response_head_copy :: proc(
	response: ^Response,
	status: int,
	headers: []async.Http_Header,
	allocator: mem.Allocator,
) -> HTTP_Error {
	storage, fields, error := header_fields_copy(headers, allocator)
	if error != nil {
		return {kind = .Allocation_Failed, allocation = error, phase = .Read}
	}

	response^ = {
		status         = status,
		headers        = fields,
		header_storage = storage,
		allocator      = allocator,
	}
	response.body_storage.allocator = allocator

	return {}
}

response_trailers_copy :: proc(response: ^Response, trailers: []async.Http_Header) -> HTTP_Error {
	if len(trailers) == 0 {
		return {}
	}

	storage, fields, error := header_fields_copy(trailers, response.allocator)
	if error != nil {
		return {kind = .Allocation_Failed, allocation = error, phase = .Read}
	}

	response.trailers, response.trailer_storage = fields, storage

	return {}
}

// A deep copy of source owned by allocator.
response_clone :: proc(source: ^Response, allocator: mem.Allocator) -> (Response, HTTP_Error) {
	result: Response

	if failure := response_head_copy(&result, source.status, headers_async(source.headers), allocator); failure.kind != .None {
		return {}, failure
	}

	if failure := response_trailers_copy(&result, headers_async(source.trailers)); failure.kind != .None {
		response_destroy(&result)
		return {}, failure
	}

	if len(source.body) > 0 {
		if _, error := append(&result.body_storage, ..source.body); error != nil {
			response_destroy(&result)
			return {}, {kind = .Allocation_Failed, allocation = error, phase = .Read, status = source.status}
		}
	}

	result.body = result.body_storage[:]

	return result, {}
}

header_fields_copy :: proc(
	headers: []async.Http_Header,
	allocator: mem.Allocator,
) -> (
	storage: []u8,
	fields: []Header,
	error: mem.Allocator_Error,
) {
	size := 0

	for h in headers {
		size += len(h.name) + len(h.value)
	}

	storage = make([]u8, size, allocator) or_return

	// An allocator may return nothing without an error.
	if len(storage) != size {
		return nil, nil, .Out_Of_Memory
	}

	fields, error = make([]Header, len(headers), allocator)
	if error == nil && len(fields) != len(headers) {
		error = .Out_Of_Memory
	}

	if error != nil {
		delete(storage, allocator)
		return nil, nil, error
	}

	at := 0

	for h, i in headers {
		name := storage[at:][:len(h.name)]
		copy(name, h.name)
		at += len(h.name)
		value := storage[at:][:len(h.value)]
		copy(value, h.value)
		at += len(h.value)
		fields[i] = {name = string(name), value = string(value)}
	}

	return
}
