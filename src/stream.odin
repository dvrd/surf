package surf

import "core:io"
import "core:sync"
import "shared:async"

Content_Decoding :: enum {
	Identity,
	// Advertises gzip and hands out the decoded body.
	Gzip,
}

Stream_Options :: struct {
	// Set: the body is pushed with client_upload_submit, exactly this many
	// bytes, then client_upload_finish.
	upload_length:     Maybe(i64),
	// Body bytes handed out, after decoding. Zero is Config.max_body_size.
	max_decoded_bytes: u64,
	decoding:          Content_Decoding,
}

// The response head. response has no body: it arrives through
// client_stream_next. Destroy with stream_head_destroy.
Stream_Head :: struct {
	response: Response,
}

Stream_Read_Status :: enum {
	Pending,
	Chunk,
	End,
}

Upload_Submit_Status :: enum {
	Accepted,
	// The queue is full: the chunk stays the caller's. Retry after a notify.
	Backpressure,
	Closed,
	Invalid,
}

stream_head_destroy :: proc(head: ^Stream_Head) {
	response_destroy(&head.response)
}

// Submits request and hands its body out in chunks as it arrives. Without
// options.upload_length the request body is request.body.
client_submit_stream :: proc(
	c: ^Client,
	request: async.Http_Request,
	options: Stream_Options = {},
	deadline: async.Deadline = {},
) -> (
	Request_Handle,
	Client_Error,
) {
	submit_options := Submit_Options {
		stream = true,
		limits = options,
	}

	if length, set := options.upload_length.?; set {
		submit_options.upload, submit_options.upload_length = .Queue, length
	}

	return submit(c, request, deadline, submit_options)
}

// Moves the head into destination once it arrived: .Pending before that,
// .Request_Error when the request failed first.
client_stream_take_head :: proc(c: ^Client, handle: Request_Handle, destination: ^Stream_Head) -> Client_Error {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return error
	}
	defer sync.unlock(&s.mu)

	if !slot.stream || destination == nil || slot.head_taken {
		return {kind = .Invalid_State}
	}

	if !slot.head_ready {
		if slot.phase == .Done {
			return {kind = .Request_Error, http = slot.error}
		}
		return {kind = .Pending}
	}

	destination.response = {
		status         = slot.response.status,
		headers        = slot.response.headers,
		header_storage = slot.response.header_storage,
		allocator      = slot.response.allocator,
	}
	slot.response.headers, slot.response.header_storage = nil, nil
	slot.head_taken = true

	return {}
}

// The next body chunk, moved into destination. .End once the body ended;
// .Request_Error when the request failed.
client_stream_next :: proc(
	c: ^Client,
	handle: Request_Handle,
	destination: ^async.Owned_Chunk,
) -> (
	Stream_Read_Status,
	Client_Error,
) {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return .Pending, error
	}

	if !slot.stream || destination == nil {
		sync.unlock(&s.mu)
		return .Pending, {kind = .Invalid_State}
	}

	if len(slot.chunks) > 0 {
		destination^ = slot.chunks[0]
		ordered_remove(&slot.chunks, 0)
		sync.unlock(&s.mu)
		async.signal_wake(s.wake)
		return .Chunk, {}
	}

	defer sync.unlock(&s.mu)

	if slot.phase != .Done {
		return .Pending, {}
	}

	if slot.error.kind != .None {
		return .Pending, {kind = .Request_Error, http = slot.error}
	}

	return .End, {}
}

// Queues one upload chunk; on .Accepted the client owns it.
client_upload_submit :: proc(
	c: ^Client,
	handle: Request_Handle,
	source: ^async.Owned_Chunk,
) -> (
	Upload_Submit_Status,
	Client_Error,
) {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return .Invalid, error
	}

	if slot.upload != .Queue || source == nil || slot.queue_finished {
		sync.unlock(&s.mu)
		return .Invalid, {}
	}

	if slot.phase == .Done {
		sync.unlock(&s.mu)
		return .Closed, {}
	}

	if len(slot.queue) >= s.capacities.upload_chunks {
		sync.unlock(&s.mu)
		return .Backpressure, {}
	}

	if _, e := append(&slot.queue, source^); e != nil {
		sync.unlock(&s.mu)
		return .Invalid, {kind = .Allocation_Failed}
	}

	source^ = {}
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return .Accepted, {}
}

// Ends the upload. A source_error fails the request with it.
client_upload_finish :: proc(c: ^Client, handle: Request_Handle, source_error: io.Error = nil) -> Client_Error {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return error
	}

	if slot.upload != .Queue {
		sync.unlock(&s.mu)
		return {kind = .Invalid_State}
	}

	slot.queue_finished = true
	slot.queue_error = source_error

	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// ---- the task ----

@(private)
stream_head_publish :: proc(s: ^Client_State, slot: ^Slot, head: async.Client_Response) {
	slot.head_ready = true
	slot_signal(s, slot)
}

@(private)
stream_body :: proc(s: ^Client_State, slot: ^Slot) -> bool {
	limit := response_limit(s, slot)

	for len(slot.chunks) < s.capacities.response_chunks {
		n, error := async.client_exchange_read(&slot.x, s.read_buffer[:])

		#partial switch error.kind {
		case .None:
			slot.received += u64(n)
			if slot.received > limit {
				request_fail(s, slot, {kind = .Body_Oversized, phase = .Body_Limit})
				return false
			}

			chunk, copied := async.owned_copy_bounded(s.read_buffer[:n], n, s.response_alloc)
			if copied.kind != .None {
				request_fail(s, slot, {kind = .Allocation_Failed, allocation = copied.allocation, phase = .Read})
				return false
			}

			if _, e := append(&slot.chunks, chunk); e != nil {
				async.owned_destroy(&chunk)
				request_fail(s, slot, {kind = .Allocation_Failed, allocation = e, phase = .Read})
				return false
			}

			slot_signal(s, slot)
		case .Pending:
			return false
		case .Peer_Closed:
			request_complete(s, slot)
			return false
		case:
			request_exchange_fail(s, slot, error)
			return false
		}
	}

	// Paused while the caller drains its chunks; the deadline still holds.
	if async.sleep_until_earlier(s.runtime, slot.deadline).kind == .None {
		request_fail(s, slot, {kind = .Deadline_Failed, phase = .Deadline})
	}

	return false
}
