package surf

import "base:runtime"
import "core:io"
import "core:mem"
import "core:sync"
import "core:thread"
import "shared:async"

// How a request is submitted, beyond the request itself.
@(private)
Submit_Options :: struct {
	upload:        Upload_Kind,
	upload_length: i64,
	source:        ^Upload_Source,
	stream:        bool,
	limits:        Stream_Options,
	waiter:        ^sync.Sema,
}

// Queues request. It is copied: nothing of it is borrowed after the call. A
// zero deadline is Config.timeout from now; it bounds every redirect hop.
// Poll for the Completion, take the Response, then release the handle.
client_submit :: proc(
	c: ^Client,
	request: async.Http_Request,
	deadline: async.Deadline = {},
) -> (
	Request_Handle,
	Client_Error,
) {
	return submit(c, request, deadline, {})
}

// The next completed request, oldest first.
client_poll :: proc(c: ^Client) -> (Completion, bool) {
	s, error := client_state(c)
	if error.kind != .None {
		return {}, false
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	for len(s.completions) > 0 {
		index := s.completions[0]
		ordered_remove(&s.completions, 0)
		slot := &s.slots[index]

		if slot.phase == .Done {
			return {request = slot_handle(s, slot), error = slot.error}, true
		}
	}

	return {}, false
}

// Moves the completed request's Response into destination. .Request_Error
// carries the request's HTTP_Error. The handle stays valid until release.
client_take :: proc(c: ^Client, handle: Request_Handle, destination: ^Response) -> Client_Error {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return error
	}
	defer sync.unlock(&s.mu)

	if destination == nil || slot.stream {
		return {kind = .Invalid_State}
	}

	if slot.phase != .Done {
		return {kind = .Pending}
	}

	if slot.error.kind != .None {
		return {kind = .Request_Error, http = slot.error}
	}

	if slot.taken {
		return {kind = .Invalid_State}
	}

	destination^ = slot.response
	slot.response = {}
	slot.taken = true

	return {}
}

// Frees the request. One still in flight is cancelled and freed when it ends.
client_release :: proc(c: ^Client, handle: Request_Handle) -> Client_Error {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return error
	}

	wake := false

	if slot.phase == .Done {
		slot_clear(s, slot)
	} else {
		slot.released, slot.cancel, slot.waiter = true, true, nil
		wake = true
	}

	sync.unlock(&s.mu)

	if wake {
		async.signal_wake(s.wake)
	}

	return {}
}

// The request fails with phase .Cancellation unless it already completed.
client_cancel :: proc(c: ^Client, handle: Request_Handle) -> Client_Error {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return error
	}

	if slot.phase != .Done {
		slot.cancel = true
	}

	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

client_request_stage :: proc(c: ^Client, handle: Request_Handle) -> (Request_Stage, Client_Error) {
	s, slot, error := slot_lock(c, handle)
	if error.kind != .None {
		return {}, error
	}
	defer sync.unlock(&s.mu)

	return slot.stage, {}
}

// Sends request and waits for its response on the calling thread. The
// Response is owned by allocator. Config.scope and allocator_scope charge that
// Response; responses taken with client_take are not charged.
client_execute :: proc(
	c: ^Client,
	request: async.Http_Request,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	return client_execute_upload(c, request, nil, allocator)
}

// As client_execute, with a request body read from upload on the calling
// thread, exactly upload.content_length bytes.
client_execute_upload :: proc(
	c: ^Client,
	request: async.Http_Request,
	upload: ^Upload_Source,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	s, state_error := client_state(c)
	if state_error.kind != .None {
		return {}, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	if async.is_current_task(&s.task) {
		return {}, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	wait: sync.Sema
	// client_release clears the slot, and with it this pointer, before wait
	// goes out of scope.
	options := Submit_Options {
		waiter = (^sync.Sema)(rawptr(&wait)),
	}

	if upload != nil {
		if failure := upload_validate(request, upload^); failure.kind != .None {
			return {}, failure
		}
		options.upload, options.upload_length = .Queue, upload.content_length
	}

	handle, submitted := submit(c, request, {}, options)
	if submitted.kind != .None {
		return {}, client_error_http(submitted)
	}

	if upload != nil {
		upload_push_source(c, s, handle, upload, &wait)
	}

	for {
		sync.lock(&s.mu)
		done := s.slots[handle.slot].phase == .Done
		sync.unlock(&s.mu)

		if done {
			break
		}

		sync.sema_wait(&wait)
	}

	response: Response
	taken := client_take(c, handle, &response)
	_ = client_release(c, handle)

	if taken.kind != .None {
		return {}, client_error_http(taken)
	}

	// Config.scope charges the Response the caller keeps, as execute does.
	ctx, call_allocator, admission := budget_begin(s.config.scope, s.config.allocator_scope, allocator)
	if admission.kind != .None {
		admission.status, admission.write_effect = response.status, .Response_Received
		response_destroy(&response)
		return {}, admission
	}
	defer budget_cleanup(&ctx)

	if response.allocator == call_allocator {
		budget_response(&ctx, &response)
		return response, {}
	}

	result, failure := response_clone(&response, call_allocator)
	response_destroy(&response)

	if failure.kind == .None {
		budget_response(&ctx, &result)
	}

	return result, failure
}

// Reads the caller's source on the calling thread and queues it chunk by
// chunk, waiting while the queue is full.
@(private)
upload_push_source :: proc(
	c: ^Client,
	s: ^Client_State,
	handle: Request_Handle,
	upload: ^Upload_Source,
	wait: ^sync.Sema,
) {
	buffer: [UPLOAD_BUFFER_SIZE]u8
	remaining := upload.content_length

	for remaining > 0 {
		want := int(min(i64(len(buffer)), remaining))
		n, read_error := io.read(upload.stream, buffer[:want])

		if n > want {
			_ = client_upload_finish(c, handle, .Unknown)
			return
		}

		if n <= 0 {
			if read_error == nil || read_error == .EOF {
				read_error = .Unexpected_EOF
			}
			_ = client_upload_finish(c, handle, read_error)
			return
		}

		chunk, copied := async.owned_copy_bounded(buffer[:n], n, s.allocator)
		if copied.kind != .None {
			_ = client_upload_finish(c, handle, .Unknown)
			return
		}

		for {
			status, pushed := client_upload_submit(c, handle, &chunk)
			if pushed.kind != .None || status == .Closed || status == .Invalid {
				async.owned_destroy(&chunk)
				return
			}

			if status == .Accepted {
				break
			}

			sync.sema_wait(wait)
		}

		remaining -= i64(n)
	}

	_ = client_upload_finish(c, handle, nil)
}

// One request on a runtime that lives for this call, on the calling thread.
// HTTPS authentication always derives server_name from the URL. Roots borrow
// the caller's Root_Pool. Called from a runtime worker it runs on a helper
// thread instead, since a worker cannot host a second runtime.
execute :: proc(
	request: async.Http_Request,
	config: Config,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	return execute_with_upload(request, config, nil, allocator)
}

// Requires config.max_redirects == 0: a streamed body cannot be sent again.
execute_upload :: proc(
	request: async.Http_Request,
	source: Upload_Source,
	config: Config,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	if config.max_redirects != 0 {
		return {}, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	if error := upload_validate(request, source); error.kind != .None {
		return {}, error
	}

	upload := source

	return execute_with_upload(request, config, &upload, allocator)
}

execute_with_upload :: proc(
	request: async.Http_Request,
	config: Config,
	upload: ^Upload_Source,
	allocator: mem.Allocator,
) -> (
	Response,
	HTTP_Error,
) {
	if validation := config_validate(config); validation.kind != .None {
		return {}, http_error_classify(validation, .Configuration, .Not_Sent)
	}

	ctx, call_allocator, admission := budget_begin(config.scope, config.allocator_scope, allocator)
	if admission.kind != .None {
		return {}, admission
	}
	defer budget_cleanup(&ctx)

	response, error := execute_once(request, config, upload, call_allocator)
	if error.kind != .None {
		if error.phase == .Unknown {
			error = http_error_classify(error, .Configuration, .Not_Sent)
		}
	} else {
		budget_response(&ctx, &response)
	}

	return response, error
}

@(private)
Execute_Job :: struct {
	request:  async.Http_Request,
	config:   Config,
	upload:   ^Upload_Source,
	response: Response,
	error:    HTTP_Error,
}

@(private)
execute_once :: proc(
	request: async.Http_Request,
	config: Config,
	upload: ^Upload_Source,
	allocator: mem.Allocator,
) -> (
	Response,
	HTTP_Error,
) {
	if !async.worker_thread_active() {
		return execute_run(request, config, upload, allocator)
	}

	job := Execute_Job {
		request = request,
		config  = config,
		upload  = upload,
	}
	worker := thread.create_and_start_with_poly_data(&job, proc(job: ^Execute_Job) {
		job.response, job.error = execute_run(job.request, job.config, job.upload, runtime.heap_allocator())
	})

	if worker == nil {
		return {}, {kind = .IO_Failed, phase = .Configuration, write_effect = .Not_Sent}
	}

	thread.join(worker)
	thread.destroy(worker)

	if job.error.kind != .None {
		return {}, job.error
	}

	result, failure := response_clone(&job.response, allocator)
	response_destroy(&job.response)

	return result, failure
}

@(private)
execute_run :: proc(
	request: async.Http_Request,
	config: Config,
	upload: ^Upload_Source,
	allocator: mem.Allocator,
) -> (
	response: Response,
	failure: HTTP_Error,
) {
	r: async.Runtime

	if error := async.init(&r, {workers = 1, task_capacity = 8, io_capacity = 256}); error.kind != .None {
		return {}, {kind = .IO_Failed, phase = .Configuration, write_effect = .Not_Sent}
	}
	defer async.destroy(&r)

	c: Client
	capacities := Capacities {
		requests               = 1,
		origins                = 4,
		connections_per_origin = 1,
		upload_chunks          = 1,
		response_chunks        = 1,
		websockets             = 1,
	}

	if error := client_init(&c, &r, {http = config, capacities = capacities}, runtime.heap_allocator());
	   error.kind != .None {
		return {}, client_error_http(error)
	}

	s := c._state
	s.once = true
	s.response_alloc = allocator
	options: Submit_Options

	if upload != nil {
		options.upload, options.upload_length, options.source = .Source, upload.content_length, upload
	}

	handle, submitted := submit(&c, request, {}, options)
	_ = async.run(&r)

	if submitted.kind != .None {
		failure = client_error_http(submitted)
	} else if taken := client_take(&c, handle, &response); taken.kind != .None {
		failure = client_error_http(taken)
	}

	_ = client_release(&c, handle)
	_ = client_destroy(&c)

	return
}

@(private)
client_error_http :: proc(error: Client_Error) -> HTTP_Error {
	if error.http.kind != .None {
		return error.http
	}

	#partial switch error.kind {
	case .Allocation_Failed:
		return {kind = .Allocation_Failed, phase = .Admission, write_effect = .Not_Sent}
	case .Closed:
		return {kind = .IO_Failed, phase = .Cancellation, write_effect = .Not_Sent}
	case .Capacity:
		return {kind = .IO_Failed, phase = .Admission, write_effect = .Not_Sent}
	}

	return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
}

@(private)
submit :: proc(
	c: ^Client,
	request: async.Http_Request,
	deadline: async.Deadline,
	options: Submit_Options,
) -> (
	Request_Handle,
	Client_Error,
) {
	s, state_error := client_state(c)
	if state_error.kind != .None {
		return {}, state_error
	}

	if failure := request_validate(s.config, request, options); failure.kind != .None {
		return {}, {kind = .Request_Error, http = failure}
	}

	sync.lock(&s.mu)

	if s.closing || s.finished {
		sync.unlock(&s.mu)
		return {}, {kind = .Closed}
	}

	slot: ^Slot

	for &candidate in s.slots {
		if candidate.phase == .Free {
			slot = &candidate
			break
		}
	}

	if slot == nil {
		sync.unlock(&s.mu)
		return {}, {kind = .Capacity}
	}

	if error := slot_fill(s, slot, request, options); error.kind != .None {
		slot_clear(s, slot)
		sync.unlock(&s.mu)
		return {}, error
	}

	slot.deadline = deadline

	if deadline == {} {
		slot.deadline = async.deadline_after(s.runtime, effective_timeout(s.config))
	}

	slot.phase = .Pending
	append(&s.pending, u32(slot_index(s, slot)))
	handle := slot_handle(s, slot)
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return handle, {}
}

// Checks what can be checked before anything is queued.
@(private)
request_validate :: proc(config: Config, request: async.Http_Request, options: Submit_Options) -> HTTP_Error {
	refuse :: proc(kind: async.Http_Error_Kind) -> HTTP_Error {
		return {kind = kind, phase = .Configuration, write_effect = .Not_Sent}
	}

	u, parse := async.http_url_parse(request.url)
	if parse.kind != .None {
		return refuse(.Invalid_URL)
	}

	if !u.secure && (!config.allow_http || config.http3) {
		return refuse(.Insecure_URL)
	}

	for h in request.headers {
		if header_reserved(h.name) {
			return refuse(.Reserved_Header)
		}

		if !async.http_header_name_valid(h.name) || !async.http_header_value_valid(h.value) {
			return refuse(.Invalid_Header)
		}
	}

	if len(request.trailers) > 0 {
		return refuse(.Invalid_Trailer)
	}

	if len(request.body) > 0 && !async.http_request_body_allowed(request.method) {
		return refuse(.Invalid_Method)
	}

	if options.upload == .Source || options.upload == .Queue {
		if len(request.body) > 0 || options.upload_length < 0 || config.max_redirects != 0 {
			return refuse(.Invalid_Config)
		}

		if options.upload_length > 0 && !async.http_request_body_allowed(request.method) {
			return refuse(.Invalid_Method)
		}
	}

	return {}
}

// Copies request into the slot.
@(private)
slot_fill :: proc(s: ^Client_State, slot: ^Slot, request: async.Http_Request, options: Submit_Options) -> Client_Error {
	size := len(request.url) + len(request.body)

	for h in request.headers {
		size += len(h.name) + len(h.value)
	}

	storage, error := make([]u8, size, s.allocator)
	if error != nil {
		return {kind = .Allocation_Failed}
	}
	slot.storage = storage

	at := 0
	copy(storage[at:], request.url)
	slot.url = string(storage[at:][:len(request.url)])
	at += len(request.url)
	copy(storage[at:], request.body)
	slot.body = storage[at:][:len(request.body)]
	at += len(request.body)

	slot.headers, error = make([]async.Http_Header, len(request.headers), s.allocator)
	if error != nil {
		return {kind = .Allocation_Failed}
	}

	for h, i in request.headers {
		name := storage[at:][:len(h.name)]
		copy(name, h.name)
		at += len(h.name)
		value := storage[at:][:len(h.value)]
		copy(value, h.value)
		at += len(h.value)
		slot.headers[i] = {name = string(name), value = string(value)}
	}

	slot.method = request.method
	slot.upload = options.upload
	slot.upload_length = options.upload_length
	slot.source = options.source
	slot.stream = options.stream
	slot.limits = options.limits
	slot.waiter = options.waiter
	slot.step = .Start
	slot.stage = .Queued
	slot.queue.allocator = s.allocator
	slot.chunks.allocator = s.allocator

	if slot.upload == .None && len(request.body) > 0 {
		slot.upload = .Body
	}

	if options.stream && options.limits.decoding == .Gzip {
		slot.decode = {.Gzip}
	}

	if slot.upload == .Source {
		slot.buffer, error = make([]u8, UPLOAD_BUFFER_SIZE, s.allocator)
		if error != nil {
			return {kind = .Allocation_Failed}
		}
	}

	return {}
}

@(private)
slot_handle :: proc(s: ^Client_State, slot: ^Slot) -> Request_Handle {
	return {owner_id = s.id, slot = u32(slot_index(s, slot)), generation = slot.generation}
}

// Locks the client and finds the handle's slot. Unlocked again on error.
@(private)
slot_lock :: proc(c: ^Client, handle: Request_Handle) -> (^Client_State, ^Slot, Client_Error) {
	s, error := client_state(c)
	if error.kind != .None {
		return nil, nil, error
	}

	if handle.owner_id != s.id || int(handle.slot) >= len(s.slots) {
		return nil, nil, {kind = .Invalid_Handle}
	}

	sync.lock(&s.mu)
	slot := &s.slots[handle.slot]

	if slot.generation != handle.generation || slot.phase == .Free || slot.released {
		sync.unlock(&s.mu)
		return nil, nil, {kind = .Invalid_Handle}
	}

	return s, slot, {}
}
