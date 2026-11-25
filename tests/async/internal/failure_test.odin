package surf_async

import runtime_async "shared:async"
import rt "base:runtime"
import "core:bytes"
import "core:mem"
import scopes "shared:async/sync/budget"
import "core:testing"
import "core:time"

// These are public Client tests. Constructor malformed-grant coverage remains
// the separately sealed414-cell prerequisite; only new submit boundaries run.
Failure32_Grant :: struct {
	raw, view: []u8,
	alignment: int,
}
Failure32_Allocator :: struct {
	backing:                                          mem.Allocator,
	grants:                                           [64]Failure32_Grant,
	calls, fail_at, mode, live, bad_frees, callbacks: int,
	client:                                           ^Client,
	other:                                            Request_Handle,
	action:                                           int,
	armed:                                            bool,
}
failure32_allocator :: proc(
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
	p := cast(^Failure32_Allocator)data
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.calls += 1

		if p.armed {
			p.armed = false
			p.callbacks += 1
			stats, valid := client_stats(p.client)
			assert(valid && stats.preparing_requests > 0)

			if p.action == 1 {
				assert(client_cancel(p.client, p.other).kind == .None)
			}

			if p.action == 2 {
				closed := client_close(p.client)
				assert(closed.kind == .None || closed.kind == .Pending)
			}

			if p.action == 3 || p.action == 4 {
				time.sleep(50 * time.Millisecond)
			}
		}

		selected := p.mode if p.calls == p.fail_at else 0

		if selected == 1 {
			return nil, .Out_Of_Memory
		}

		if selected == 3 {
			return nil, nil
		}

		actual := size

		if selected == 4 {
			actual = max(0, size - 1)
		}

		if selected == 5 || selected == 6 {
			actual = size + 1
		}

		raw, error := p.backing.procedure(p.backing.data, mode, actual, max(alignment, 16), nil, 0, location)
		assert(error == nil)
		view := raw

		if selected == 6 {
			view = raw[1:]
		}

		for &grant in p.grants {
			if raw_data(grant.raw) == nil {
				grant = {raw, view, max(alignment, 16)}; p.live += len(raw); break
			}
		}

		if selected == 2 {
			return view, .Out_Of_Memory
		}

		return view, nil
	case .Free:
		if old_memory == nil {
			return nil, nil
		}

		for &grant in p.grants {
			if raw_data(grant.view) == old_memory {
				if old_size != 0 && old_size != len(grant.view) {
					p.bad_frees += 1
				}

				old := grant
				grant = {}
				p.live -= len(old.raw)
				return p.backing.procedure(
					p.backing.data,
					.Free,
					0,
					old.alignment,
					raw_data(old.raw),
					len(old.raw),
					location,
				)
			}
		}

		p.bad_frees += 1
		return nil, .Invalid_Pointer
	case .Query_Features:
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		return nil, nil
	case .Free_All, .Resize, .Resize_Non_Zeroed, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, .Mode_Not_Implemented
}
failure32_config :: proc(scope: scopes.Scope = {}) -> Client_Config {
	return {
		http = {allow_http = true, timeout = time.Second, scope = scope},
		capacities = Capacities {
			requests = 3,
			origins = 3,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 2,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}
}
failure32_runtime :: proc(r: ^runtime_async.Runtime, allocator: mem.Allocator) {
	assert(
		runtime_async.init(r, {workers = 1, task_capacity = 2, io_capacity = 1, allocator = allocator}).kind == .None,
	)
}
failure32_close :: proc(c: ^Client) {
	assert(client_close(c).kind == .None)

	for {
		item, available := client_poll(c); if !available {
			break
		}; assert(client_release(c, item.request).kind == .None)
	}

	assert(client_quiescent(c))
	assert(client_destroy(c).kind == .None)
}

@(test)
failure32_public_submit_grants_preserve_full_caller_inputs_and_rollback :: proc(t: ^testing.T) {
	points := 0
	malformed, valid_interior := 0, 0

	for point in 0 ..< 3 {
		for mode in 1 ..< 7 {
			track: mem.Tracking_Allocator
			mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
			backing := mem.tracking_allocator(&track)
			r: runtime_async.Runtime
			failure32_runtime(&r, backing)
			p := Failure32_Allocator {
				backing = backing,
			}

			c: Client
			assert(client_init(&c, &r, failure32_config(), {failure32_allocator, &p}).kind == .None)
			base_calls, base_live := p.calls, p.live

			if point > 0 {
				p.fail_at = base_calls + point; p.mode = mode
			}

			url := "http://127.0.0.1:9/never-connected"
			body: [128]u8
			for &b, index in body {b = u8(index)}
			before := body
			handle, error := client_submit(&c, {method = .POST, url = url, body = body[:]})
			testing.expect(t, bytes.equal(body[:], before[:]))

			if point == 0 {
				testing.expect_value(t, error.kind, .None); points = p.calls - base_calls
			} else if mode == 6 && point == 1 {
				testing.expect_value(t, error.kind, .None)
				valid_interior += 1
			} else {
				testing.expect_value(t, error.kind, .Allocation_Failed)
				testing.expect_value(t, handle, Request_Handle{})
				testing.expect_value(t, p.live, base_live)
				stats, valid := client_stats(&c)
				testing.expect(
					t,
					valid &&
					stats.preparing_requests == 0 &&
					stats.queued_requests == 0 &&
					stats.active_requests == 0 &&
					stats.completed_requests == 0,
				)
				_, available := client_poll(&c)
				testing.expect(t, !available)
				malformed += 1
			}

			failure32_close(&c)
			assert(runtime_async.destroy(&r).kind == .None)
			testing.expect_value(t, p.live, 0)
			testing.expect_value(t, p.bad_frees, 0)
			testing.expect_value(t, track.current_memory_allocated, 0)
			testing.expect_value(t, len(track.bad_free_array), 0)
			mem.tracking_allocator_destroy(&track)
		}
	}

	testing.expect_value(t, points, 2)
	testing.expect_value(t, malformed, 11)
	testing.expect_value(t, valid_interior, 1)
}

@(test)
failure32_closed_scope_rejects_before_new_allocation_and_refunds_lease :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := scopes.create_root({bytes = 32 << 20, streams = 3, jobs = 8}, allocator)
	assert(cause == .None)
	r: runtime_async.Runtime
	failure32_runtime(&r, allocator)
	c: Client
	assert(client_init(&c, &r, failure32_config(scope), allocator).kind == .None)
	assert(scopes.close(scope) == .None)
	before := track.total_allocation_count
	h, error := client_submit(&c, {method = .GET, url = "http://127.0.0.1:9/not-sent"})
	testing.expect_value(t, error.kind, .Budget_Rejected)
	testing.expect_value(t, error.http.budget, .Closed)
	testing.expect_value(t, h, Request_Handle{})
	testing.expect_value(t, track.total_allocation_count, before)
	_, available := client_poll(&c)
	testing.expect(t, !available)
	failure32_close(&c)
	assert(runtime_async.destroy(&r).kind == .None)
	usage, _ := scopes.snapshot(scope)
	testing.expect_value(t, usage.used, scopes.Usage{})
	scopes.release_scope(&scope)
	testing.expect_value(t, track.current_memory_allocated, 0)
	testing.expect_value(t, len(track.bad_free_array), 0)
	mem.tracking_allocator_destroy(&track)
}

@(test)
failure32_allocation_callbacks_use_public_close_stats_cancel_and_fresh_clock :: proc(t: ^testing.T) {
	for action in 0 ..< 5 {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		backing := mem.tracking_allocator(&track)
		r: runtime_async.Runtime
		failure32_runtime(&r, backing)
		p := Failure32_Allocator {
			backing = backing,
		}

		c: Client
		assert(client_init(&c, &r, failure32_config(), {failure32_allocator, &p}).kind == .None)
		first, error := client_submit(&c, {method = .GET, url = "http://bank-empty.example/queued"})
		assert(error.kind == .None)
		p.client = &c
		p.other = first
		p.action = action
		p.armed = true
		deadline := runtime_async.Deadline{}

		if action == 3 || action == 4 {
			deadline = runtime_async.deadline_after(&r, 20 * time.Millisecond)
		}

		if action == 4 {
			p.fail_at = p.calls + 2; p.mode = 1
		}

		second, result := client_submit(
			&c,
			{method = .POST, url = "http://127.0.0.1:9/clone", body = transmute([]u8)string("owned")},
			deadline,
		)
		testing.expect_value(t, p.callbacks, 1)

		if action == 2 {
			testing.expect(t, result.kind != .None); testing.expect_value(t, second, Request_Handle{})
		} else if action == 4 {
			testing.expect_value(t, result.kind, .Allocation_Failed)
			testing.expect_value(t, result.http.kind, .Allocation_Failed)
			testing.expect_value(t, second, Request_Handle{})
		} else if action == 3 {
			testing.expect_value(t, result.kind, .Request_Error)
			testing.expect_value(t, result.http.kind, .Deadline_Failed)
			testing.expect_value(t, second, Request_Handle{})
		} else {
			testing.expect_value(t, result.kind, .None)
		}

		failure32_close(&c)
		assert(runtime_async.destroy(&r).kind == .None)
		testing.expect_value(t, p.live, 0)
		testing.expect_value(t, p.bad_frees, 0)
		testing.expect_value(t, track.current_memory_allocated, 0)
		mem.tracking_allocator_destroy(&track)
	}
}
