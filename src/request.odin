package surf

import "core:io"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "shared:async"

@(private)
Slot_Phase :: enum u8 {
	Free,
	// Submitted; the task has not picked it up.
	Pending,
	Active,
	// Completed; the result waits for client_take or client_release.
	Done,
}

@(private)
Request_Step :: enum u8 {
	Start,
	Send,
	Head,
	Body,
}

@(private)
Upload_Kind :: enum u8 {
	None,
	// The copied request.body.
	Body,
	// Read from an Upload_Source on the task (execute only).
	Source,
	// Chunks pushed with client_upload_submit or by client_execute_upload.
	Queue,
}

// One request from submit to release. Slots never move: the exchange inside
// must stay put between its begin and its destroy.
@(private)
Slot :: struct {
	generation:     u64,
	phase:          Slot_Phase,
	step:           Request_Step,
	stage:          Request_Stage,
	stream:         bool,
	// Released while in flight: freed when it completes, never reported.
	released:       bool,
	cancel:         bool,
	// url, header strings and body of the submitted request.
	storage:        []u8,
	method:         async.Http_Method,
	headers:        []async.Http_Header,
	body:           []u8,
	// The current hop's URL: in storage, or owned after a redirect.
	url:            string,
	url_owned:      bool,
	request:        async.Http_Request,
	deadline:       async.Deadline,
	upload:         Upload_Kind,
	upload_length:  i64,
	source:         ^Upload_Source,
	buffer:         []u8,
	buffer_at:      int,
	buffer_used:    int,
	queue:          [dynamic]async.Owned_Chunk,
	queue_finished: bool,
	queue_error:    io.Error,
	chunk:          async.Owned_Chunk,
	chunk_at:       int,
	written:        i64,
	finished:       bool,
	// Posted whenever the slot's caller may proceed: it completed, an upload
	// chunk was taken, or a stream event is ready.
	waiter:         ^sync.Sema,
	x:              async.Client_Exchange,
	x_live:         bool,
	origin:         ^Origin,
	parsed:         async.Http_URL,
	redirects:      int,
	decode:         bit_set[async.Coding],
	last_status:    int,
	// client_take moved the Response out.
	taken:          bool,
	// This hop's response head parsed.
	head_parsed:    bool,
	response:       Response,
	error:          HTTP_Error,
	// Streaming.
	limits:         Stream_Options,
	head_ready:     bool,
	head_taken:     bool,
	chunks:         [dynamic]async.Owned_Chunk,
	received:       u64,
	stream_end:     bool,
}

// Drives one request as far as it can go now.
@(private)
request_step :: proc(s: ^Client_State, slot: ^Slot) -> (yield: bool) {
	if slot.cancel {
		request_fail(s, slot, {kind = .IO_Failed, phase = .Cancellation, transport = net.Connection_Error.Cancelled})
		return false
	}

	for slot.phase == .Active {
		advanced: bool

		switch slot.step {
		case .Start:
			advanced = request_begin(s, slot)
		case .Send:
			advanced = request_send(s, slot)
		case .Head:
			advanced = request_head(s, slot)
		case .Body:
			if slot.stream {
				advanced = stream_body(s, slot)
			} else {
				advanced = request_body(s, slot)
			}
		}

		if !advanced {
			break
		}
	}

	return false
}

@(private)
request_begin :: proc(s: ^Client_State, slot: ^Slot) -> bool {
	u, parse := async.http_url_parse(slot.url)
	if parse.kind != .None {
		request_fail(s, slot, {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent})
		return false
	}

	origin, waiting, error := origin_get(s, u, slot.decode)
	if error.kind != .None {
		request_fail(s, slot, error)
		return false
	}

	if waiting {
		slot.stage = .Queued

		if async.sleep_until_earlier(s.runtime, slot.deadline).kind == .None {
			request_fail(s, slot, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent})
		}

		return false
	}

	slot.request = {
		method  = slot.method,
		url     = slot.url,
		headers = slot.headers,
	}

	length: i64 = -1

	switch slot.upload {
	case .Body:
		length = i64(len(slot.body))
	case .Source, .Queue:
		length = slot.upload_length
	case .None:
		if async.http_request_body_allowed(slot.method) {
			length = 0
		}
	}

	if begun := async.client_exchange_begin(&origin.client, &slot.x, &slot.request, length, slot.deadline);
	   begun.kind != .None {
		request_fail(s, slot, begin_error(begun))
		return false
	}

	slot.x_live, slot.origin, slot.parsed = true, origin, u
	slot.written, slot.finished, slot.head_parsed = 0, false, false
	slot.buffer_at, slot.buffer_used = 0, 0
	slot.stage = .Connecting
	slot.step = .Send
	origin.active += 1

	return true
}

@(private)
request_send :: proc(s: ^Client_State, slot: ^Slot) -> bool {
	total: i64 = 0

	switch slot.upload {
	case .Body:
		total = i64(len(slot.body))
	case .Source, .Queue:
		total = slot.upload_length
	case .None:
	}

	for slot.written < total {
		if stop, advanced := upload_interrupted(s, slot); stop {
			return advanced
		}

		data, ready := upload_data(s, slot, total)
		if slot.phase != .Active {
			return false
		}

		if !ready {
			return false
		}

		n, error := async.client_exchange_write(&slot.x, data)
		if error.kind == .Pending {
			request_stage_update(slot)

			if async.sleep_until_earlier(s.runtime, slot.deadline).kind == .None {
				request_fail(s, slot, {kind = .Deadline_Failed, phase = .Deadline})
			}

			return false
		}

		if error.kind != .None {
			return request_write_failed(s, slot, error)
		}

		upload_advance(slot, n)
		slot.written += i64(n)
		request_stage_update(slot)
	}

	if !slot.finished {
		error := async.client_exchange_finish(&slot.x)
		if error.kind == .Pending {
			request_stage_update(slot)
			return false
		}

		if error.kind != .None {
			return request_write_failed(s, slot, error)
		}

		slot.finished = true
	}

	slot.stage = .Reading
	slot.step = .Head

	return true
}

// The upload stops early when the server already answered (read its response)
// or the producer failed. advanced: go on to the next step now.
@(private)
upload_interrupted :: proc(s: ^Client_State, slot: ^Slot) -> (stop: bool, advanced: bool) {
	if slot.upload == .Queue && slot.queue_finished && slot.queue_error != nil {
		request_fail(s, slot, {kind = .IO_Failed, phase = .Write, source_io = slot.queue_error})
		return true, false
	}

	if _, error := async.client_exchange_head(&slot.x); error.kind == .None {
		slot.stage = .Reading
		slot.step = .Head
		return true, true
	}

	return false, false
}

// The bytes to write next. ready false: wait for the producer.
@(private)
upload_data :: proc(s: ^Client_State, slot: ^Slot, total: i64) -> (data: []u8, ready: bool) {
	switch slot.upload {
	case .Body:
		return slot.body[slot.written:], true
	case .Source:
		if slot.buffer_at < slot.buffer_used {
			return slot.buffer[slot.buffer_at:slot.buffer_used], true
		}

		want := int(min(i64(len(slot.buffer)), total - slot.written))
		n, error := io.read(slot.source.stream, slot.buffer[:want])
		if n > want {
			request_fail(s, slot, {kind = .IO_Failed, phase = .Write, source_io = .Unknown})
			return nil, false
		}

		if n <= 0 {
			if error == nil || error == .EOF {
				error = .Unexpected_EOF
			}
			request_fail(s, slot, {kind = .IO_Failed, phase = .Write, source_io = error})
			return nil, false
		}

		slot.buffer_at, slot.buffer_used = 0, n
		return slot.buffer[:n], true
	case .Queue:
		if slot.chunk_at < len(slot.chunk.data) {
			return slot.chunk.data[slot.chunk_at:], true
		}

		if len(slot.queue) == 0 {
			if slot.queue_finished {
				error := slot.queue_error
				if error == nil {
					error = .Unexpected_EOF
				}
				request_fail(s, slot, {kind = .IO_Failed, phase = .Write, source_io = error})
			} else if async.sleep_until_earlier(s.runtime, slot.deadline).kind == .None {
				request_fail(s, slot, {kind = .Deadline_Failed, phase = .Deadline})
			}
			return nil, false
		}

		async.owned_destroy(&slot.chunk)
		slot.chunk = slot.queue[0]
		ordered_remove(&slot.queue, 0)
		slot.chunk_at = 0

		if slot.written + i64(len(slot.chunk.data)) > total {
			request_fail(s, slot, {kind = .Invalid_Config, phase = .Write})
			return nil, false
		}

		// A queue slot freed up.
		slot_signal(s, slot)
		return slot.chunk.data, true
	case .None:
	}

	return nil, false
}

@(private)
upload_advance :: proc(slot: ^Slot, n: int) {
	#partial switch slot.upload {
	case .Source:
		slot.buffer_at += n
	case .Queue:
		slot.chunk_at += n
	}
}

// An HTTP/1.1 server that answers early stops the upload: read its response.
@(private)
request_write_failed :: proc(s: ^Client_State, slot: ^Slot, error: async.Error) -> bool {
	if error.kind == .Peer_Closed {
		slot.stage = .Reading
		slot.step = .Head
		return true
	}

	request_exchange_fail(s, slot, error)

	return false
}

@(private)
request_stage_update :: proc(slot: ^Slot) {
	if _, bound := async.client_exchange_protocol(&slot.x); bound {
		slot.stage = .Writing
	} else {
		slot.stage = .Connecting
	}
}

@(private)
request_head :: proc(s: ^Client_State, slot: ^Slot) -> bool {
	head, error := async.client_exchange_head(&slot.x)
	if error.kind == .Pending {
		return false
	}

	if error.kind != .None {
		request_exchange_fail(s, slot, error)
		return false
	}

	slot.last_status = head.status
	slot.head_parsed = true

	// Redirect bodies are bounded too.
	if head.content_length > i64(response_limit(s, slot)) {
		request_fail(s, slot, {kind = .Body_Oversized, phase = .Body_Limit})
		return false
	}

	if s.config.alt_svc != nil && slot.parsed.secure {
		if value, found := header_find(head.headers, "Alt-Svc"); found {
			_ = alt_svc_note(s.config.alt_svc, slot.parsed.host, value, true, true, time.now(), slot.parsed.port)
		}
	}

	if status_redirect(head.status) && s.config.max_redirects > 0 {
		next, failure := redirect_next(
			head.status,
			head.headers,
			slot.request,
			slot.parsed,
			s.config,
			slot.redirects,
			s.allocator,
		)
		if failure.kind != .None {
			request_fail(s, slot, http_error_classify(failure, .Protocol, .Response_Received, head.status))
			return false
		}

		request_exchange_end(s, slot)

		if slot.url_owned {
			delete(slot.url, s.allocator)
		}

		slot.url, slot.url_owned = next, true
		slot.redirects += 1
		slot.stage = .Redirecting
		slot.step = .Start

		return true
	}

	if failure := response_head_copy(&slot.response, head.status, head.headers, s.response_alloc);
	   failure.kind != .None {
		request_fail(s, slot, failure)
		return false
	}

	if slot.stream {
		stream_head_publish(s, slot, head)
	}

	slot.step = .Body

	return true
}

@(private)
request_body :: proc(s: ^Client_State, slot: ^Slot) -> bool {
	limit := effective_body_limit(s.config)

	for {
		n, error := async.client_exchange_read(&slot.x, s.read_buffer[:])

		#partial switch error.kind {
		case .None:
			if len(slot.response.body_storage) + n > limit {
				request_fail(s, slot, {kind = .Body_Oversized, phase = .Body_Limit})
				return false
			}

			if _, e := append(&slot.response.body_storage, ..s.read_buffer[:n]); e != nil {
				request_fail(s, slot, {kind = .Allocation_Failed, allocation = e, phase = .Read})
				return false
			}
		case .Pending:
			return false
		case .Peer_Closed:
			if failure := response_trailers_copy(&slot.response, async.client_exchange_trailers(&slot.x));
			   failure.kind != .None {
				request_fail(s, slot, failure)
				return false
			}

			request_complete(s, slot)
			return false
		case:
			request_exchange_fail(s, slot, error)
			return false
		}
	}
}

@(private)
request_complete :: proc(s: ^Client_State, slot: ^Slot) {
	request_exchange_end(s, slot)
	slot.response.body = slot.response.body_storage[:]
	slot.error = {}
	slot.phase = .Done
	slot.stage = .Completed
	request_finish(s, slot)
}

@(private)
request_exchange_fail :: proc(s: ^Client_State, slot: ^Slot, error: async.Error) {
	request_fail(s, slot, exchange_error(s, slot, error))
}

@(private)
request_fail :: proc(s: ^Client_State, slot: ^Slot, error: HTTP_Error) {
	failure := error
	effect := failure.write_effect

	// Response_Received needs a status line that parsed, not merely response
	// bytes.
	if slot.x_live && effect == .Unknown {
		on_wire, _ := async.client_exchange_sent(&slot.x)
		effect = .Not_Sent if !on_wire else (.Response_Received if slot.head_parsed else .Unknown)
	} else if !slot.x_live && effect == .Unknown && slot.last_status == 0 {
		effect = .Not_Sent
	}

	if slot.last_status != 0 && effect == .Not_Sent {
		effect = .Response_Received
	}

	failure = http_error_classify(failure, .Read, effect, slot.last_status)
	request_exchange_end(s, slot)
	response_destroy(&slot.response)
	slot.error = failure
	slot.phase = .Done
	slot.stage = .Completed
	request_finish(s, slot)
}

@(private)
request_finish :: proc(s: ^Client_State, slot: ^Slot) {
	upload_queue_clear(slot)

	if slot.released {
		slot_clear(s, slot)
		return
	}

	index := u32(slot_index(s, slot))
	append(&s.completions, index)
	s.notify_pending = true
	slot_signal(s, slot)
}

@(private)
request_exchange_end :: proc(s: ^Client_State, slot: ^Slot) {
	if !slot.x_live {
		return
	}

	async.client_exchange_destroy(&slot.x)
	slot.x_live = false
	origin := slot.origin
	slot.origin = nil
	origin.active -= 1

	if origin.active == 0 {
		origin.idle_at = async.deadline_after(s.runtime, s.idle_timeout)
	}
}

@(private)
slot_signal :: proc(s: ^Client_State, slot: ^Slot) {
	if slot.waiter != nil {
		sync.sema_post(slot.waiter)
	}

	s.notify_pending = true
}

@(private)
slot_index :: proc(s: ^Client_State, slot: ^Slot) -> int {
	return int((uintptr(slot) - uintptr(raw_data(s.slots))) / size_of(Slot))
}

@(private)
upload_queue_clear :: proc(slot: ^Slot) {
	for &chunk in slot.queue {
		async.owned_destroy(&chunk)
	}
	clear(&slot.queue)
	async.owned_destroy(&slot.chunk)
	slot.chunk_at = 0
}

// Frees everything the slot holds and makes it free.
@(private)
slot_clear :: proc(s: ^Client_State, slot: ^Slot) {
	if slot.x_live {
		request_exchange_end(s, slot)
	}

	upload_queue_clear(slot)
	delete(slot.queue)

	for &chunk in slot.chunks {
		async.owned_destroy(&chunk)
	}
	delete(slot.chunks)

	if slot.url_owned {
		delete(slot.url, s.allocator)
	}

	delete(slot.storage, s.allocator)
	delete(slot.headers, s.allocator)
	delete(slot.buffer, s.allocator)
	response_destroy(&slot.response)
	generation := slot.generation + 1
	slot^ = {}
	slot.generation = generation
}

// Body bytes the caller accepts, after decoding.
@(private)
response_limit :: proc(s: ^Client_State, slot: ^Slot) -> u64 {
	if slot.stream && slot.limits.max_decoded_bytes > 0 {
		return slot.limits.max_decoded_bytes
	}

	return u64(effective_body_limit(s.config))
}

@(private)
status_redirect :: proc(status: int) -> bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}

	return false
}

@(private)
header_find :: proc(headers: []async.Http_Header, name: string) -> (string, bool) {
	for h in headers {
		if strings.equal_fold(h.name, name) {
			return h.value, true
		}
	}

	return "", false
}

// ---- errors ----

@(private)
begin_error :: proc(error: async.Error) -> HTTP_Error {
	#partial switch error.kind {
	case .Invalid_Config:
		return {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent}
	case .Unsupported:
		return {kind = .Insecure_URL, phase = .Configuration, write_effect = .Not_Sent}
	case .Closed, .Cancelled:
		return {kind = .IO_Failed, phase = .Cancellation, transport = net.Connection_Error.Cancelled, write_effect = .Not_Sent}
	case .Allocation_Failed:
		return {kind = .Allocation_Failed, allocation = error.allocation_cause, phase = .Admission, write_effect = .Not_Sent}
	}

	return {kind = .IO_Failed, phase = .Configuration, write_effect = .Not_Sent}
}

// What the exchange's failure means to a caller.
@(private)
exchange_error :: proc(s: ^Client_State, slot: ^Slot, error: async.Error) -> HTTP_Error {
	failure := async.client_exchange_failure(&slot.x)
	_, bound := async.client_exchange_protocol(&slot.x)
	result: HTTP_Error

	http_kind := failure.http.kind
	if http_kind == .None {
		http_kind = failure.h2.http.kind
	}
	if http_kind == .None {
		http_kind = failure.h3.http.kind
	}

	on_wire, _ := async.client_exchange_sent(&slot.x)

	switch {
	case error.kind == .Timeout:
		result = {kind = .Deadline_Failed, phase = .Deadline}
	case error.kind == .Cancelled:
		result = {kind = .IO_Failed, phase = .Cancellation, transport = net.Connection_Error.Cancelled}
	case error.kind == .Allocation_Failed:
		result = {kind = .Allocation_Failed, allocation = error.allocation_cause}
	// Over HTTP/3 the exchange is bound before its dial; nothing was sent.
	case !on_wire && slot.origin != nil && slot.origin.refused:
		result = {kind = .Address_Rejected, phase = .Connect}
	case failure.decode != .None:
		result = {kind = .Content_Decoding_Failed, decoding = failure.decode, phase = .Decode}
	case http_kind != .None && http_kind != .IO_Failed:
		result = {kind = http_kind, allocation = failure.http.allocation}
	case !bound:
		cause := error.network_cause
		if slot.parsed.secure && (failure.tls != nil || dial_tls_failed(cause)) {
			result = {kind = .TLS_Failed, phase = .TLS, network = cause, transport = cause}
		} else {
			result = {kind = .Dial_Failed, network = cause, transport = cause}
			if http_network_phase(cause) == .Unknown {
				result.phase = .Connect
			}
		}
	case:
		result = {kind = .IO_Failed, transport = error.network_cause}
	}

	result.tls_error = failure.tls

	// The server said it never processed the request: nothing was acted on.
	if failure.h2.not_processed || failure.h3.not_processed {
		result.write_effect = .Not_Sent
	}

	return result
}

@(private)
dial_tls_failed :: proc(cause: net.Network_Error) -> bool {
	if connection, ok := cause.(net.Connection_Error); ok {
		return connection == .Protocol_Failed
	}

	return false
}
