package surf_async

import runtime_async "shared:async"
import surf ".."
import http "shared:http"
import rt "base:runtime"
import "core:mem"
import "core:testing"
import "core:time"

// These fixtures use ONLY public Client/Runtime entrypoints. No model result or
// callback is injected to pretend that a request performed network I/O.
client20_config :: proc() -> Client_Config {
	return {
		http = {allow_http = true, timeout = time.Second},
		capacities = Capacities {
			requests = 2,
			origins = 2,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 2,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}
}
client20_runtime :: proc(r: ^runtime_async.Runtime, allocator: mem.Allocator, tasks: int = 2) {
	assert(
		runtime_async.init(r, {workers = 1, task_capacity = tasks, io_capacity = 1, allocator = allocator}).kind ==
		.None,
	)
}

@(test)
client20_atomic_group_rejection_leaves_no_registered_partial_client :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	r: runtime_async.Runtime
	client20_runtime(&r, allocator, 1)
	c: Client
	failure := client_init(&c, &r, client20_config(), allocator)
	testing.expect(t, failure.kind != .None)
	testing.expect(t, !client_quiescent(&c))
	testing.expect(t, client_destroy(&c).kind != .None)
	// The one available runtime slot must still be wholly usable after rejection.
	sentinel := runtime_async.Task {
		resume = proc(_: rawptr) -> runtime_async.Resume_Result {return .Done},
		on_cancel = proc(_: rawptr) -> runtime_async.Resume_Result {return .Done},
	}

	testing.expect_value(t, runtime_async.register(&r, &sentinel).kind, .None)
	testing.expect_value(t, runtime_async.unregister(&r, &sentinel).kind, .None)
	testing.expect_value(t, runtime_async.destroy(&r).kind, .None)
	testing.expect_value(t, track.current_memory_allocated, 0)
	testing.expect_value(t, len(track.bad_free_array), 0)
	mem.tracking_allocator_destroy(&track)
}

@(test)
client20_prestart_close_keeps_terminal_results_until_release :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	client20_runtime(&r, context.allocator)
	c: Client
	testing.expect_value(t, client_init(&c, &r, client20_config(), context.allocator).kind, .None)
	first, error := client_submit(&c, {method = .GET, url = "http://bank-empty.example/A"})
	testing.expect_value(t, error.kind, .None)
	second, second_error := client_submit(&c, {method = .GET, url = "http://bank-empty.example/B"})
	testing.expect_value(t, second_error.kind, .None)
	testing.expect(t, client_release(&c, first).kind != .None)
	testing.expect_value(t, client_cancel(&c, first).kind, .None)
	testing.expect_value(t, client_close(&c).kind, .None)
	testing.expect_value(t, client_close(&c).kind, .None)
	testing.expect(t, client_quiescent(&c))
	testing.expect(t, client_destroy(&c).kind != .None)
	seen_first, seen_second := false, false
	count := 0

	for {
		completion, available := client_poll(&c)

		if !available {
			break
		}

		count += 1
		testing.expect_value(t, completion.error.transport.kind, .Cancelled)

		if completion.request == first {
			testing.expect(t, !seen_first)
			seen_first = true
		}

		if completion.request == second {
			testing.expect(t, !seen_second)
			seen_second = true
		}

		testing.expect_value(t, client_release(&c, completion.request).kind, .None)
	}

	testing.expect_value(t, count, 2)
	testing.expect(t, seen_first && seen_second)
	testing.expect(t, client_cancel(&c, first).kind != .None)
	testing.expect_value(t, client_destroy(&c).kind, .None)
	testing.expect_value(t, runtime_async.destroy(&r).kind, .None)
}

@(test)
client20_results_survive_runtime_destroy_before_start_and_physical_header_free :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	r := new(runtime_async.Runtime, allocator)
	client20_runtime(r, allocator)
	c: Client
	testing.expect_value(t, client_init(&c, r, client20_config(), allocator).kind, .None)
	handle, error := client_submit(&c, {method = .GET, url = "http://never-queried.example/A"})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, runtime_async.destroy(r).kind, .None)
	free(r, allocator)
	testing.expect(t, client_quiescent(&c))
	stats, valid := client_stats(&c)
	testing.expect(t, valid)
	testing.expect_value(t, stats.tasks, 0)
	completion, available := client_poll(&c)
	testing.expect(t, available && completion.request == handle)
	testing.expect_value(t, completion.error.transport.kind, .Cancelled)
	destination: surf.Response
	testing.expect(t, client_take(&c, handle, &destination).kind != .None)
	testing.expect_value(t, destination.status, 0)
	testing.expect_value(t, client_release(&c, handle).kind, .None)
	testing.expect_value(t, client_destroy(&c).kind, .None)
	testing.expect_value(t, track.current_memory_allocated, 0)
	testing.expect_value(t, len(track.bad_free_array), 0)
	mem.tracking_allocator_destroy(&track)
}

@(test)
client20_rejected_submit_preserves_source_and_foreign_handles_are_rejected :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	client20_runtime(&r, context.allocator, 4)
	a, b: Client
	testing.expect_value(t, client_init(&a, &r, client20_config(), context.allocator).kind, .None)
	testing.expect_value(t, client_init(&b, &r, client20_config(), context.allocator).kind, .None)
	handle, error := client_submit(&a, {method = .GET, url = "http://waiting.example/A"})
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, client_cancel(&b, handle).kind != .None)
	testing.expect(t, client_release(&b, handle).kind != .None)
	destination: surf.Response
	testing.expect(t, client_take(&b, handle, &destination).kind != .None)
	malformed := "broken URL"
	body := [3]u8{'a', 'b', 'c'}
	before := body
	_, failure := client_submit(&a, {method = .POST, url = malformed, body = body[:]})
	testing.expect(t, failure.kind != .None)
	testing.expect_value(t, body, before)
	testing.expect_value(t, client_close(&a).kind, .None)
	testing.expect_value(t, client_close(&b).kind, .None)
	testing.expect_value(t, client_release(&a, handle).kind, .None)
	testing.expect(t, client_release(&a, handle).kind != .None)
	testing.expect_value(t, client_destroy(&a).kind, .None)
	testing.expect_value(t, client_destroy(&b).kind, .None)
	testing.expect_value(t, runtime_async.destroy(&r).kind, .None)
}

@(test)
client20_malformed_descriptors_reject_without_allocation_or_source_mutation :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	r: runtime_async.Runtime
	client20_runtime(&r, allocator)
	c: Client
	testing.expect_value(t, client_init(&c, &r, client20_config(), allocator).kind, .None)
	// Deliberately malformed descriptors model a defensive FFI boundary. Construct
	// their bit patterns without dereferencing the absent/negative source storage.
	positive_string := transmute(string)mem.Raw_String{data = nil, len = 1}
	negative_string := transmute(string)mem.Raw_String{data = nil, len = -1}
	positive_bytes := transmute([]u8)mem.Raw_Slice{data = nil, len = 1}
	negative_bytes := transmute([]u8)mem.Raw_Slice{data = nil, len = -1}
	positive_fields := transmute([]http.Header)mem.Raw_Slice{data = nil, len = 1}
	negative_fields := transmute([]http.Header)mem.Raw_Slice{data = nil, len = -1}
	fields := [4][1]http.Header {
		{{name = positive_string, value = "ok"}},
		{{name = negative_string, value = "ok"}},
		{{name = "X-Test", value = positive_string}},
		{{name = "X-Test", value = negative_string}},
	}

	cases := [10]http.Request {
		{method = .GET, url = positive_string},
		{method = .GET, url = negative_string},
		{method = .POST, url = "http://invalid.example/", body = positive_bytes},
		{method = .POST, url = "http://invalid.example/", body = negative_bytes},
		{method = .GET, url = "http://invalid.example/", headers = positive_fields},
		{method = .GET, url = "http://invalid.example/", headers = negative_fields},
		{method = .GET, url = "http://invalid.example/", headers = fields[0][:]},
		{method = .GET, url = "http://invalid.example/", headers = fields[1][:]},
		{method = .GET, url = "http://invalid.example/", headers = fields[2][:]},
		{method = .GET, url = "http://invalid.example/", headers = fields[3][:]},
	}

	for request in cases {
		before := request
		allocations, bytes := track.total_allocation_count, track.current_memory_allocated
		result, failure := client_submit(&c, request)
		testing.expect_value(t, result, Request_Handle{})
		testing.expect(t, failure.kind != .None)
		testing.expect_value(t, track.total_allocation_count, allocations)
		testing.expect_value(t, track.current_memory_allocated, bytes)
		testing.expect_value(t, raw_data(request.url), raw_data(before.url))
		testing.expect_value(t, len(request.url), len(before.url))
		testing.expect_value(t, raw_data(request.body), raw_data(before.body))
		testing.expect_value(t, len(request.body), len(before.body))
		testing.expect_value(t, raw_data(request.headers), raw_data(before.headers))
		testing.expect_value(t, len(request.headers), len(before.headers))
	}

	testing.expect_value(t, client_close(&c).kind, .None)
	testing.expect_value(t, client_destroy(&c).kind, .None)
	testing.expect_value(t, runtime_async.destroy(&r).kind, .None)
	testing.expect_value(t, track.current_memory_allocated, 0)
	testing.expect_value(t, len(track.bad_free_array), 0)
	mem.tracking_allocator_destroy(&track)
}

Client20_Reentry :: struct {
	backing:                               mem.Allocator,
	runtime:                               ^runtime_async.Runtime,
	client:                                ^Client,
	config:                                Client_Config,
	mode:                                  int,
	entered, final_callback, header_freed: bool,
	inner:                                 Client_Error,
	live:                                  int,
}
client20_reentrant_allocator :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	p := cast(^Client20_Reentry)data
	if !p.entered && ((p.mode == 1 && mode == .Query_Features) || (p.mode == 2 && mode == .Alloc)) {
		p.entered = true
		p.inner = client_init(p.client, p.runtime, p.config, {client20_reentrant_allocator, p})
	}
	if mode == .Free && old_memory != nil {
		assert(p.live > 0)

		if p.mode == 3 && p.live == 1 {
			// This constructor's final backing free must see the already-cleared
			// failed public header; freeing that header here prohibits later outer writes.
			assert(!p.final_callback)
			p.final_callback = true
			assert(client_destroy(p.client).kind == .Invalid_State)
			free(p.client, p.backing)
			p.client = nil
			p.header_freed = true
		}

		p.live -= 1
	}
	grant, error := p.backing.procedure(p.backing.data, mode, size, alignment, old_memory, old_size, location)
	if (mode == .Alloc || mode == .Alloc_Non_Zeroed) && raw_data(grant) != nil {
		p.live += 1
	}
	return grant, error
}

@(test)
client20_constructor_reentry_rejects_and_failed_registration_clears_before_final_free :: proc(t: ^testing.T) {
	for mode in ([3]int{1, 2, 3}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		backing := mem.tracking_allocator(&track)
		r: runtime_async.Runtime
		client20_runtime(&r, backing, 1 if mode == 3 else 4)
		c := new(Client, backing)
		p := Client20_Reentry {
			backing = backing,
			runtime = &r,
			client  = c,
			config  = client20_config(),
			mode    = mode,
		}

		outer := client_init(c, &r, p.config, {client20_reentrant_allocator, &p})

		if mode == 3 {
			testing.expect(t, outer.kind != .None)
			testing.expect(t, p.final_callback && p.header_freed && p.client == nil)
		} else {
			testing.expect_value(t, outer.kind, .None)
			testing.expect(t, p.entered)
			testing.expect_value(t, p.inner.kind, .Invalid_State)
			a, b := runtime_async.Task{}, runtime_async.Task{}
			a.resume = proc(_: rawptr) -> runtime_async.Resume_Result {return .Done}
			a.on_cancel = a.resume
			b.resume = a.resume
			b.on_cancel = b.resume
			testing.expect_value(t, runtime_async.register(&r, &a).kind, .None)
			testing.expect_value(t, runtime_async.register(&r, &b).kind, .None)
			testing.expect_value(t, runtime_async.unregister(&r, &a).kind, .None)
			testing.expect_value(t, runtime_async.unregister(&r, &b).kind, .None)
			testing.expect_value(t, client_close(c).kind, .None)
			testing.expect_value(t, client_destroy(c).kind, .None)
			free(c, backing)
		}

		testing.expect_value(t, p.live, 0)
		testing.expect_value(t, runtime_async.destroy(&r).kind, .None)
		testing.expect_value(t, track.current_memory_allocated, 0)
		testing.expect_value(t, len(track.bad_free_array), 0)
		mem.tracking_allocator_destroy(&track)
	}
}
