package surf_async

import runtime_async "shared:async"
import "core:testing"
import "core:time"
import surf ".."
import "core:mem"
import scopes "shared:async/sync/budget"
import "core:net"
import http "shared:async/http"
import rt "base:runtime"
import "core:bytes"
import "core:fmt"
import charged "shared:async/mem/budget"
import "core:os"
import "core:strings"
import "core:sync"

@(test)
redirect28_public_config_and_prestart_handle_lifecycle :: proc(t: ^testing.T) {
	for redirects in 0 ..= 5 {
		runtime: runtime_async.Runtime
		assert(
			runtime_async.init(&runtime, {workers = 1, task_capacity = 2, io_capacity = 1, allocator = context.allocator}).kind ==
			.None,
		)
		c: Client
		config := Client_Config {
			http = {allow_http = true, max_redirects = redirects, timeout = time.Second},
			capacities = Capacities {
				requests = 1,
				origins = 1,
				connections = 1,
				connections_per_origin = 1,
				waiters_per_origin = 0,
				dns_ids = 0,
				work_per_resume = 1,
			},
		}

		testing.expect_value(t, client_init(&c, &runtime, config, context.allocator).kind, .None)
		handle, error := client_submit(&c, {method = .GET, url = "http://127.0.0.1:1/no-network-before-start"})
		testing.expect_value(t, error.kind, .None)
		testing.expect(t, handle.owner_id != 0 && handle.slot != 0 && handle.generation != 0)
		closed := client_close(&c)
		testing.expect(t, closed.kind == .None || closed.kind == .Pending)
		testing.expect(t, client_quiescent(&c))
		completion, available := client_poll(&c)
		testing.expect(t, available)
		testing.expect_value(t, completion.request, handle)
		testing.expect(t, completion.error.kind != .None)
		testing.expect_value(t, client_release(&c, handle).kind, .None)
		_, again := client_poll(&c)
		testing.expect(t, !again)
		testing.expect_value(t, client_destroy(&c).kind, .None)
		testing.expect_value(t, runtime_async.destroy(&runtime).kind, .None)
	}
}

redirect_ledger_init :: proc(f: ^Pool_Case, connections: int = 1) {
	caps := pool_case_caps()
	caps.connections = connections
	caps.origins = 3
	caps.requests = 4
	pool_case_init(f, caps, 10000, 100000)
}
redirect_ledger_start :: proc(
	f: ^Pool_Case,
	allocator: mem.Allocator = {},
	retiring: bool = true,
) -> (
	Request_Handle,
	Assignment,
) {
	start := pool_case_time(f)
	lease, error := resources_request_lease(&f.resources)
	assert(error.kind == .None)
	preparing, reserved := kernel_reserve(&f.kernel, {epoch = 77, at = 1000}, &lease)
	assert(reserved.kind == .None)
	_, claim := pool_case_claim(f, preparing, "https://old.test/original", start)
	assert(claim.kind == .None)
	selected := allocator
	if selected.procedure == nil {
		selected = f.resources.allocator
	}
	payload := "original-body"
	input, cloned := request_clone(
		{method = .POST, url = "https://old.test/original", body = transmute([]u8)payload},
		selected,
	)
	assert(cloned.kind == .None)
	assert(kernel_commit(&f.kernel, preparing, &input, pool_case_clock(start + 1)).kind == .None)
	assigned := pool_case_dispatch(f, preparing.request, now = start + 2)
	if retiring {
		assert(pool_session_state(&f.kernel, assigned.session, .Retiring, start + 3).kind == .None)
	}
	return preparing.request, assigned
}
redirect_ledger_streams :: proc(f: ^Pool_Case) -> u64 {
	usage, error := scopes.snapshot(f.scope)
	assert(error == .None)

	return usage.used.streams
}
redirect_ledger_dispose_finish :: proc(
	f: ^Pool_Case,
	handle: Request_Handle,
	disposal: ^Request_Disposal,
	now: runtime_async.Deadline,
) -> Completion {
	pool_case_dispose(f, disposal)
	next, done, error := kernel_cleanup_finish(&f.kernel, handle, now)
	assert(error.kind == .None && done)
	pool_case_dispose(f, &next)
	result, available := kernel_poll(&f.kernel)
	assert(available && result.request == handle)
	_, again := kernel_poll(&f.kernel)
	assert(!again)
	assert(kernel_release(&f.kernel, handle).kind == .None)
	return result
}
redirect_ledger_cleanup_active :: proc(f: ^Pool_Case, handle: Request_Handle, session: Cell_Handle) {
	response: surf.Response
	disposal, error := kernel_begin_complete(
		&f.kernel,
		handle,
		&response,
		{kind = .Invalid_Redirect, phase = .Protocol, status = 302, write_effect = .Response_Received},
	)
	assert(error.kind == .None)
	_ = redirect_ledger_dispose_finish(f, handle, &disposal, pool_case_clock(300))
	assert(pool_retire(&f.kernel, session).kind == .None)
}

@(test)
redirect_ledger_two_hops_keep_one_stream_lease_handle_and_cutoff :: proc(t: ^testing.T) {
	f: Pool_Case
	redirect_ledger_init(&f)
	defer pool_case_destroy(&f)
	handle, assignment := redirect_ledger_start(&f)
	original_lease := f.kernel.requests[handle.slot - 1].lease
	original_deadline := f.kernel.requests[handle.slot - 1].deadline

	for hop in 0 ..< 2 {
		before := f.kernel.references
		disposal, error := kernel_redirect_begin(&f.kernel, handle, pool_case_clock(120 + 100 * i64(hop)))
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, disposal.request, handle)
		testing.expect_value(t, disposal.returning_to, .Preparing)
		testing.expect_value(t, disposal.lease, scopes.Lease{})
		testing.expect(t, len(disposal.input.storage) > 0)
		testing.expect_value(t, f.kernel.references, before + 1)
		testing.expect_value(t, f.kernel.counters.active_requests, 0)
		testing.expect_value(t, f.kernel.counters.returning_requests, 1)
		testing.expect_value(t, f.kernel.sessions[assignment.session.slot - 1].request, Request_Handle{})
		testing.expect_value(t, f.kernel.counters.retiring_connections, 1)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].lease, original_lease)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].deadline, original_deadline)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))
		_, available := kernel_poll(&f.kernel)
		testing.expect(t, !available)
		pool_case_dispose(&f, &disposal)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))
		testing.expect_value(t, pool_retire(&f.kernel, assignment.session).kind, .None)
		testing.expect_value(t, f.kernel.counters.origins, 0)
		testing.expect_value(
			t,
			kernel_redirect_ready(&f.kernel, handle, pool_case_clock(130 + 100 * i64(hop))).kind,
			.None,
		)
		testing.expect_value(t, f.kernel.references, before + 1)
		testing.expect_value(t, f.kernel.counters.returning_requests, 0)
		testing.expect_value(t, f.kernel.counters.preparing_requests, 1)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].stage, .Redirecting)
		url := "https://middle.test/target" if hop == 0 else "https://final.test/target"
		accepted := Preparing_Request {
			request = handle,
		} 	// Actual accepted Preparing ticket.
		_, claimed := pool_case_claim(&f, accepted, url, 140 + 100 * i64(hop))
		testing.expect_value(t, claimed.kind, .None)
		input, cloned := request_clone({method = .POST, url = url}, f.resources.allocator)
		assert(cloned.kind == .None)
		testing.expect_value(
			t,
			kernel_commit(&f.kernel, accepted, &input, pool_case_clock(150 + 100 * i64(hop))).kind,
			.None,
		)
		testing.expect_value(t, f.kernel.references, before)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].generation, handle.generation)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].lease, original_lease)
		assignment = pool_case_dispatch(&f, handle, now = 160 + 100 * i64(hop))
		testing.expect_value(
			t,
			pool_session_state(&f.kernel, assignment.session, .Retiring, 170 + 100 * i64(hop)).kind,
			.None,
		)
	}

	redirect_ledger_cleanup_active(&f, handle, assignment.session)
	testing.expect_value(t, redirect_ledger_streams(&f), u64(0))
	testing.expect_value(t, f.kernel.references, 1)
	testing.expect_value(t, kernel_release(&f.kernel, handle).kind, .Invalid_Handle)
}

@(test)
redirect_ledger_begin_rejections_preserve_all_accepted_owners :: proc(t: ^testing.T) {
	for mode in 0 ..< 9 {
		f: Pool_Case
		redirect_ledger_init(&f)
		handle, assignment := redirect_ledger_start(&f, retiring = mode != 8)
		bad := handle
		now := pool_case_clock(120)

		switch mode {
		case 0:
			bad.owner_id += 1
		case 1:
			bad.generation += 1
		case 2:
			bad.slot = u32(len(f.kernel.requests) + 1)
		case 3:
			bad = {}
		case 4:
			now.epoch += 1
		case 5:
			now.at = 1000
		case 6:
			assert(kernel_cancel(&f.kernel, handle).kind == .None)
		case 7:
			assert(kernel_close(&f.kernel).kind == .None)
		case 8:
		}

		before := f.kernel.requests[handle.slot - 1]
		counters := f.kernel.counters
		references := f.kernel.references
		disposal, error := kernel_redirect_begin(&f.kernel, bad, now)
		testing.expect(t, error.kind != .None)
		testing.expect_value(t, disposal.request, Request_Handle{})
		testing.expect_value(t, raw_data(disposal.input.storage), nil)
		after := f.kernel.requests[handle.slot - 1]
		testing.expect_value(t, after.state, before.state)
		testing.expect_value(t, after.stage, before.stage)
		testing.expect_value(t, after.deadline, before.deadline)
		testing.expect_value(t, after.lease, before.lease)
		testing.expect_value(t, raw_data(after.input.storage), raw_data(before.input.storage))
		testing.expect_value(t, string(after.input.request.body), "original-body")
		testing.expect_value(t, after.origin, before.origin)
		testing.expect_value(t, after.session, before.session)
		testing.expect_value(t, f.kernel.counters, counters)
		testing.expect_value(t, f.kernel.references, references)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))

		if mode == 8 {
			assert(pool_session_state(&f.kernel, assignment.session, .Retiring, 130).kind == .None)
		}

		redirect_ledger_cleanup_active(&f, handle, assignment.session)
		pool_case_destroy(&f)
	}
}

@(test)
redirect_ledger_ready_rechecks_fresh_clock_cancel_close_then_fails_once :: proc(t: ^testing.T) {
	for mode in 0 ..< 4 {
		f: Pool_Case
		redirect_ledger_init(&f)
		handle, assignment := redirect_ledger_start(&f)
		disposal, error := kernel_redirect_begin(&f.kernel, handle, pool_case_clock(120))
		assert(error.kind == .None)
		pool_case_dispose(&f, &disposal)
		assert(pool_retire(&f.kernel, assignment.session).kind == .None)
		now := pool_case_clock(140)

		if mode == 0 {
			now.epoch += 1
		}

		if mode == 1 {
			now.at = 1000
		}

		if mode == 2 {
			assert(kernel_cancel(&f.kernel, handle).kind == .None)
		}

		if mode == 3 {
			assert(kernel_close(&f.kernel).kind == .None)
		}

		before_refs := f.kernel.references
		failure := kernel_redirect_ready(&f.kernel, handle, now)
		testing.expect(t, failure.kind != .None)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].state, .Returning)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].returning_to, .Preparing)
		testing.expect_value(t, f.kernel.references, before_refs)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))
		primary := failure.http

		if mode == 3 {
			primary = {
				kind = .IO_Failed,
				transport = net.Connection_Error.Cancelled,
				phase = .Cancellation,
			}
		}

		failed, cause := kernel_redirect_fail(&f.kernel, handle, primary)
		assert(cause.kind == .None)
		testing.expect_value(t, f.kernel.references, before_refs)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))
		result := redirect_ledger_dispose_finish(&f, handle, &failed, now)
		testing.expect_value(t, result.error, primary)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(0))
		testing.expect_value(t, f.kernel.references, 1)
		pool_case_destroy(&f)
	}
}

@(test)
redirect_ledger_accepted_failure_cleans_returning_unclaimed_reserved_waiter_and_idle :: proc(t: ^testing.T) {
	for mode in 0 ..< 5 {
		f: Pool_Case
		redirect_ledger_init(&f, connections = 2 if mode == 4 else 1)
		idle: Assignment

		if mode == 4 {
			warm, _ := pool_case_accept(&f, "https://target.test/")
			idle = pool_case_dispatch(&f, warm)
			pool_case_complete(&f, warm)
			pool_case_idle(&f, idle.session)
		}

		handle, old := redirect_ledger_start(&f)
		original := f.kernel.requests[handle.slot - 1].lease
		begin, error := kernel_redirect_begin(&f.kernel, handle, pool_case_clock(120))
		assert(error.kind == .None)
		pool_case_dispose(&f, &begin)
		assert(pool_retire(&f.kernel, old.session).kind == .None)

		if mode > 0 {
			assert(kernel_redirect_ready(&f.kernel, handle, pool_case_clock(130)).kind == .None)
		}

		claim := Pool_Reservation{}

		if mode >= 2 {
			candidate, prepared := origin_prepare(&f.profile, "https://target.test/", f.resources.allocator)
			assert(prepared.kind == .None)
			claim, error = pool_reserve_policy(&f.kernel, {handle}, &candidate, 140, mode != 3)
			assert(error.kind == .None)
			origin_destroy(&candidate)

			if mode == 3 {
				testing.expect(t, claim.waiting && claim.session.slot == 0)
			}

			if mode == 4 {
				testing.expect_value(t, claim.session, idle.session)
				testing.expect_value(t, f.kernel.sessions[claim.session.slot - 1].reserved_from, .Idle)
			}
		}

		references := f.kernel.references
		primary := surf.HTTP_Error {
			kind         = .Unsafe_Redirect,
			phase        = .Protocol,
			status       = 307,
			write_effect = .Response_Received,
		}

		if mode == 2 {
			primary = {
				kind = .IO_Failed,
				transport = net.TCP_Send_Error.Connection_Closed,
				phase = .Write,
				status = 503,
				write_effect = .Unknown,
			}
		}

		disposal, cause := kernel_redirect_fail(&f.kernel, handle, primary)
		testing.expect_value(t, cause.kind, .None)
		testing.expect_value(t, disposal.lease, original)
		testing.expect_value(t, f.kernel.requests[handle.slot - 1].lease, scopes.Lease{})
		// A retiring target Origin has its OWN detached-disposal Kernel keepalive.
		testing.expect_value(t, f.kernel.references, references + (1 if disposal.origin.origin.slot != 0 else 0))
		testing.expect_value(t, f.kernel.preparing, 0)
		testing.expect_value(t, f.kernel.returning, 1)
		testing.expect_value(t, f.kernel.counters.reserved_connections, 0)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))

		if mode == 4 {
			testing.expect_value(t, f.kernel.sessions[idle.session.slot - 1].state, .Idle)
			testing.expect_value(t, f.kernel.sessions[idle.session.slot - 1].generation, idle.session.generation)
		}

		result := redirect_ledger_dispose_finish(&f, handle, &disposal, pool_case_clock(160))
		testing.expect_value(t, result.error, primary)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(0))
		testing.expect_value(t, f.kernel.references, 1)
		pool_case_destroy(&f)
	}
}

@(test)
redirect_ledger_fail_rejects_original_preparing_and_absent_primary :: proc(t: ^testing.T) {
	f: Pool_Case
	redirect_ledger_init(&f)
	defer pool_case_destroy(&f)
	producer := pool_case_prepare(&f)
	before := f.kernel.requests[producer.request.slot - 1].lease
	_, error := kernel_redirect_fail(&f.kernel, producer.request, {kind = .Invalid_Redirect})
	testing.expect_value(t, error.kind, .Invalid_State)
	testing.expect_value(t, f.kernel.requests[producer.request.slot - 1].lease, before)
	pool_case_rollback(&f, producer) // Only this never-accepted producer may roll back.
	handle, assignment := redirect_ledger_start(&f)
	disposal, cause := kernel_redirect_begin(&f.kernel, handle, pool_case_clock(120))
	assert(cause.kind == .None)
	pool_case_dispose(&f, &disposal)
	assert(pool_retire(&f.kernel, assignment.session).kind == .None)
	references := f.kernel.references
	_, error = kernel_redirect_fail(&f.kernel, handle, {})
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, f.kernel.references, references)
	testing.expect_value(t, f.kernel.requests[handle.slot - 1].returning_to, .Preparing)
	failure, failed := kernel_redirect_fail(&f.kernel, handle, {kind = .Invalid_Redirect})
	assert(failed.kind == .None)
	_ = redirect_ledger_dispose_finish(&f, handle, &failure, pool_case_clock(160))
}

Redirect_Ledger_Callback :: struct {
	backing:       mem.Allocator,
	kernel:        ^Kernel,
	scope:         scopes.Scope,
	handle:        Request_Handle,
	storage:       rawptr,
	armed:         bool,
	calls, action: int,
}
redirect_ledger_allocator :: proc(
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
	p := cast(^Redirect_Ledger_Callback)data
	if mode == .Free && old_memory == p.storage && p.armed {
		p.armed = false
		p.calls += 1
		assert(
			p.kernel.requests[p.handle.slot - 1].state == .Returning &&
			p.kernel.requests[p.handle.slot - 1].stage == .Redirecting,
		)
		assert(kernel_destroy(p.kernel).kind == .Pending) // Would deadlock under Kernel.mu.
		usage, error := scopes.snapshot(p.scope)
		assert(error == .None && usage.used.streams == 1)

		if p.action == 0 {
			assert(kernel_cancel(p.kernel, p.handle).kind == .None)
		} else {
			assert(kernel_close(p.kernel).kind == .None)
		}
	}
	grant, error := p.backing.procedure(p.backing.data, mode, size, alignment, old_memory, old_size, location)
	if mode == .Alloc {
		p.storage = raw_data(grant)
	}
	return grant, error
}

@(test)
redirect_ledger_physical_old_input_free_can_cancel_or_close_outside_mutex :: proc(t: ^testing.T) {
	for action in 0 ..< 2 {
		f: Pool_Case
		redirect_ledger_init(&f)
		p := Redirect_Ledger_Callback {
			backing = f.resources.allocator,
			kernel  = &f.kernel,
			scope   = f.scope,
			action  = action,
		}

		handle, assignment := redirect_ledger_start(&f, {redirect_ledger_allocator, &p})
		p.handle = handle
		p.armed = true
		disposal, error := kernel_redirect_begin(&f.kernel, handle, pool_case_clock(120))
		assert(error.kind == .None)
		pool_case_dispose(&f, &disposal)
		testing.expect_value(t, p.calls, 1)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(1))
		assert(pool_retire(&f.kernel, assignment.session).kind == .None)
		rejected := kernel_redirect_ready(&f.kernel, handle, pool_case_clock(140))
		testing.expect_value(t, rejected.kind, .Request_Error if action == 0 else .Closed)
		primary := surf.HTTP_Error {
			kind = .IO_Failed,
			transport = net.Connection_Error.Cancelled,
			phase = .Cancellation,
		}

		failure, cause := kernel_redirect_fail(&f.kernel, handle, primary)
		assert(cause.kind == .None)
		result := redirect_ledger_dispose_finish(&f, handle, &failure, pool_case_clock(160))
		testing.expect_value(t, result.error, primary)
		testing.expect_value(t, redirect_ledger_streams(&f), u64(0))
		pool_case_destroy(&f)
	}
}

Prepare_Fault :: struct {
	backing:                   mem.Allocator,
	calls, at, mode, returned: int,
	alignments:                [16]int,
	whole, reported:           []u8,
	triggered:                 bool,
	hook:                      proc(_: rawptr),
	user:                      rawptr,
	hook_mode:                 mem.Allocator_Mode,
}
prepare_fault :: proc(
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
	f := cast(^Prepare_Fault)data
	if mode == f.hook_mode && f.hook != nil {
		hook := f.hook
		f.hook = nil
		hook(f.user)
	}
	if mode == .Free && old_memory != nil && old_memory == raw_data(f.reported) {
		assert(old_size == len(f.reported))
		whole := f.whole
		f.whole = nil
		f.reported = nil
		f.returned += 1
		return f.backing.procedure(f.backing.data, .Free, 0, alignment, raw_data(whole), len(whole), location)
	}
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		assert(f.calls < len(f.alignments))
		f.alignments[f.calls] = alignment
		f.calls += 1

		if f.at > 0 && f.calls == f.at {
			f.triggered = true

			if f.mode == 0 {
				return nil, .Out_Of_Memory
			}

			if f.mode == 1 {
				return nil, nil
			}

			requested := size

			if f.mode == 3 {
				requested -= 1
			}

			if f.mode == 4 {
				requested += 1
			}

			if f.mode == 5 {
				requested += alignment
			}

			grant, error := f.backing.procedure(f.backing.data, mode, requested, alignment, nil, 0, location)
			assert(error == nil && raw_data(grant) != nil)
			f.whole, f.reported = grant, grant

			if f.mode == 5 {
				f.reported = grant[1:size + 1]
			}

			return f.reported, .Out_Of_Memory if f.mode == 2 else nil
		}
	}
	return f.backing.procedure(f.backing.data, mode, size, alignment, old_memory, old_size, location)
}
Prepare_Wire :: struct {
	wire: string,
	at:   int,
}
prepare_read :: proc(data: rawptr, dst: []u8) -> (int, net.Network_Error) {
	f := cast(^Prepare_Wire)data

	if f.at == len(f.wire) {
		return 0, net.Connection_Error.Peer_Closed
	}

	n := copy(dst, f.wire[f.at:])
	f.at += n

	return n, nil
}
prepare_write :: proc(_: rawptr, src: []u8) -> (int, net.Network_Error) {
	return len(src), nil
}
prepare_close :: proc(_: rawptr) -> net.Network_Error {
	return nil
}
prepare_response :: proc(
	status: int,
	location: string,
	allocator: mem.Allocator,
	duplicate: bool = false,
) -> surf.Response {
	extra := ""
	if duplicate {
		extra = "Location: /other\r\n"
	}
	wire := fmt.aprintf(
		"HTTP/1.1 %d Redirect\r\nContent-Length: 4\r\nLocation: %s\r\n%sX-Old: yes\r\n\r\nbody",
		status,
		location,
		extra,
		allocator = allocator,
	)
	fixture := Prepare_Wire {
		wire = wire,
	}
	response, error := surf.exchange(
		{data = &fixture, read = prepare_read, write = prepare_write, close = prepare_close},
		{method = .GET, url = "https://example.test/a/b?old=1"},
		8,
		allocator,
	)
	delete(wire, allocator)
	assert(error.kind == .None)
	return response
}
prepare_profile :: proc(p: ^Profile, allocator: mem.Allocator, scope: scopes.Scope = {}, redirects: int = 5) {
	config, error := config_normalize({http = {allow_http = true, scope = scope, max_redirects = redirects}})
	assert(error.kind == .None)
	assert(profile_init(p, config, allocator).kind == .None)
}
prepare_handle :: proc() -> Request_Handle {
	return {owner_id = 71, slot = 1, generation = 3}
}

@(test)
redirect_prepare_literal_methods_origins_and_relative_policy :: proc(t: ^testing.T) {
	profile: Profile
	prepare_profile(&profile, context.allocator)
	defer profile_destroy(&profile)
	vectors := [?]struct {
		method:         http.Method,
		status:         int,
		location, want: string,
		error:          http.Error_Kind,
		headers:        []http.Header,
	} {
		{.GET, 301, "/next", "https://example.test/next", .None, nil},
		{.GET, 302, "../next?x=2", "https://example.test/next?x=2", .None, nil},
		{.GET, 303, "?x=2", "https://example.test/a/b?x=2", .None, nil},
		{.GET, 307, "//EXAMPLE.TEST:443/next", "https://EXAMPLE.TEST:443/next", .None, nil},
		{.GET, 308, "/a/./b/../next", "https://example.test/a/next", .None, nil},
		{.HEAD, 301, "/next", "", .Unsafe_Redirect, nil},
		{.HEAD, 302, "/next", "", .Unsafe_Redirect, nil},
		{.HEAD, 303, "/next", "", .Unsafe_Redirect, nil},
		{.HEAD, 307, "/next", "https://example.test/next", .None, nil},
		{.HEAD, 308, "/next", "https://example.test/next", .None, nil},
		{.POST, 301, "/next", "", .Unsafe_Redirect, nil},
		{.POST, 302, "/next", "", .Unsafe_Redirect, nil},
		{.POST, 303, "/next", "", .Unsafe_Redirect, nil},
		{.POST, 307, "/next", "https://example.test/next", .None, nil},
		{.POST, 308, "/next", "https://example.test/next", .None, nil},
		{
			.GET,
			302,
			"https://other.test/next",
			"https://other.test/next",
			.None,
			{{"Accept", "text/plain"}, {"User-Agent", "owned-test"}},
		},
		{.GET, 302, "https://other.test/next", "", .Unsafe_Redirect, {{"Authorization", "Bearer opaque"}}},
		{.GET, 302, "https://other.test/next", "", .Unsafe_Redirect, {{"Cookie", "opaque=value"}}},
		{.GET, 302, "https://other.test/next", "", .Unsafe_Redirect, {{"X-Private", "opaque"}}},
		{.POST, 307, "https://other.test/next", "", .Unsafe_Redirect, nil},
		{.HEAD, 307, "https://other.test/next", "", .Unsafe_Redirect, nil},
		{.GET, 302, "http://example.test/next", "", .Insecure_URL, nil},
		{.GET, 302, "https://other.test/#fragment", "", .Invalid_Redirect, nil},
		{.GET, 302, "", "", .Invalid_Redirect, nil},
	}

	for sample in vectors {
		response := prepare_response(sample.status, sample.location, context.allocator)
		target: Redirect_Handoff
		body: []u8

		if sample.method == .POST {
			body = []u8{'p', 0, 255}
		}

		current := http.Request {
			method  = sample.method,
			url     = "https://example.test/a/b?old=1",
			headers = sample.headers,
			body    = body,
		}

		error := redirect_prepare(&target, &profile, prepare_handle(), current, &response, 0, 17, context.allocator)
		testing.expect_value(t, error.http.kind, sample.error)
		testing.expect(t, response.status == 0 && response.header_storage == nil && response.body_storage == nil)

		if sample.error == .None {
			testing.expect(t, error.kind == .None && target.phase == .Ready)
			testing.expect_value(t, target.input.request.url, sample.want)
			testing.expect_value(t, target.input.request.method, sample.method)
			testing.expect(t, bytes.equal(target.input.request.body, body))
			testing.expect_value(t, target.next_hop, 1)
			testing.expect_value(t, target.queries_remaining, 17)
			testing.expect_value(t, target.last_status, sample.status)
			testing.expect_value(t, target.request, prepare_handle())
			testing.expect(
				t,
				target.input.allocator.procedure == context.allocator.procedure &&
				target.origin.allocator.procedure == context.allocator.procedure,
			)
		} else {
			testing.expect(
				t,
				target.phase == .Empty &&
				error.kind != .None &&
				error.http.status == sample.status &&
				error.http.write_effect == .Response_Received,
			)
		}

		redirect_handoff_destroy(&target)
	}

	for hops in ([2]int{4, 5}) {
		response := prepare_response(307, "/next", context.allocator)
		target: Redirect_Handoff
		error := redirect_prepare(
			&target,
			&profile,
			prepare_handle(),
			{method = .GET, url = "https://example.test"},
			&response,
			hops,
			0,
			context.allocator,
		)
		testing.expect_value(t, error.http.kind, http.Error_Kind.None if hops == 4 else http.Error_Kind.Redirect_Limit)

		if hops == 4 {
			testing.expect_value(t, target.next_hop, 5)
			testing.expect_value(t, target.queries_remaining, 0)
		}

		redirect_handoff_destroy(&target)
	}

	response := prepare_response(302, "/one", context.allocator, true)
	target: Redirect_Handoff
	error := redirect_prepare(
		&target,
		&profile,
		prepare_handle(),
		{method = .GET, url = "https://example.test"},
		&response,
		0,
		32,
		context.allocator,
	)
	testing.expect_value(t, error.http.kind, .Invalid_Redirect)
	redirect_handoff_destroy(&target)
	fmt.printf("REDIRECT_PREPARE policy_literal_vectors=%d boundary_vectors=3 memory_codec_only=true\n", len(vectors))
}

@(test)
redirect_prepare_all_new_grant_failures_and_valid_byte_interior_grants :: proc(t: ^testing.T) {
	for managed in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		backing := mem.tracking_allocator(&track)
		fault := Prepare_Fault {
			backing = backing,
		}

		allocator := mem.Allocator{prepare_fault, &fault}
		scope: scopes.Scope
		binding: charged.Binding

		if managed {
			owner_scope, error := scopes.create_root({bytes = 16 << 20, streams = 1}, backing)
			assert(error == .None)
			scope = owner_scope
			owner, cause := charged.create(scope, {backing = allocator, metadata_allocator = backing})
			assert(cause.kind == .None)
			binding = owner
			allocator = charged.allocator(binding)
		}

		profile: Profile
		prepare_profile(&profile, backing, scope)
		baseline := track.current_memory_allocated
		response := prepare_response(307, "/a/../next", backing)
		target: Redirect_Handoff
		error := redirect_prepare(
			&target,
			&profile,
			prepare_handle(),
			{method = .POST, url = "https://example.test/a/b", body = []u8{'p', 0, 255}},
			&response,
			0,
			1,
			allocator,
		)
		assert(error.kind == .None)
		points := fault.calls
		alignments := fault.alignments
		assert(points > 0 && points < 16)
		testing.expect(
			t,
			target.input.allocator.procedure == allocator.procedure && target.input.allocator.data == allocator.data,
		)
		testing.expect(
			t,
			target.origin.allocator.procedure == allocator.procedure && target.origin.allocator.data == allocator.data,
		)
		redirect_handoff_destroy(&target)
		assert(track.current_memory_allocated == baseline)
		failed_cells, valid_interiors := 0, 0

		for at in 1 ..= points {
			for mode in 0 ..< 6 {
				fault = {
					backing = backing,
					at      = at,
					mode    = mode,
				}

				response = prepare_response(307, "/a/../next", backing)
				error = redirect_prepare(
					&target,
					&profile,
					prepare_handle(),
					{method = .POST, url = "https://example.test/a/b", body = []u8{'p', 0, 255}},
					&response,
					0,
					1,
					allocator,
				)
				valid := mode == 5 && alignments[at - 1] == 1

				if valid {
					testing.expect(t, error.kind == .None && target.phase == .Ready)
					valid_interiors += 1
				} else {
					testing.expect(
						t,
						error.kind != .None && error.http.kind == .Allocation_Failed && target.phase == .Empty,
					)
					testing.expect(
						t,
						error.http.allocation == .Out_Of_Memory &&
						error.http.status == 307 &&
						error.http.write_effect == .Response_Received,
					)
					failed_cells += 1
				}

				testing.expect(t, fault.triggered && response.status == 0 && response.headers == nil)
				redirect_handoff_destroy(&target)
				testing.expect(t, fault.whole == nil && fault.returned == (0 if mode < 2 else 1))
				testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)

				if managed {
					snapshot, _ := scopes.snapshot(scope)
					testing.expect_value(t, snapshot.used, scopes.Usage{})
				}
			}
		}

		fmt.printf(
			"REDIRECT_PREPARE managed=%v allocation_points=%d malformed_cells=%d valid_align1_interior_cells=%d\n",
			managed,
			points,
			failed_cells,
			valid_interiors,
		)
		profile_destroy(&profile)

		if managed {
			charged.release(&binding)
			scopes.release_scope(&scope)
		}

		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}
}

Prepare_Reentry :: struct {
	target:                                   ^Redirect_Handoff,
	profile:                                  ^Profile,
	outer, inner:                             ^surf.Response,
	allocator:                                mem.Allocator,
	called:                                   int,
	guarded, source_preserved, outer_cleared: bool,
}
prepare_reenter :: proc(data: rawptr) {
	c := cast(^Prepare_Reentry)data
	c.called += 1
	before := c.inner^
	c.outer_cleared = c.outer.status == 0 && c.outer.headers == nil && c.outer.header_storage == nil
	error := redirect_prepare(
		c.target,
		c.profile,
		prepare_handle(),
		{method = .GET, url = "https://example.test/"},
		c.inner,
		0,
		32,
		c.allocator,
	)
	c.source_preserved =
		error.kind == .Invalid_State &&
		c.inner.status == before.status &&
		raw_data(c.inner.headers) == raw_data(before.headers) &&
		raw_data(c.inner.header_storage) == raw_data(before.header_storage) &&
		raw_data(c.inner.body_storage) == raw_data(before.body_storage) &&
		len(c.inner.body_storage) == len(before.body_storage)
	redirect_handoff_destroy(c.target)
	c.guarded = c.target.phase == .Preparing
}
Prepare_Header_Free :: struct {
	target:                   ^Redirect_Handoff,
	backing:                  mem.Allocator,
	cleared, recursive_empty: bool,
	called:                   int,
}
prepare_free_cleared_header :: proc(data: rawptr) {
	c := cast(^Prepare_Header_Free)data
	c.called += 1
	h := c.target
	c.cleared =
		h.phase == .Empty &&
		h.request == (Request_Handle{}) &&
		raw_data(h.input.storage) == nil &&
		raw_data(h.origin.storage) == nil
	redirect_handoff_destroy(h)
	c.recursive_empty = h.phase == .Empty
	c.target = nil
	free(h, c.backing)
}

@(test)
redirect_prepare_guards_constructor_callbacks_and_destroy_clears_heap_header :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	backing := mem.tracking_allocator(&track)
	profile: Profile
	prepare_profile(&profile, backing)
	baseline := track.current_memory_allocated

	for mode in ([3]mem.Allocator_Mode{.Query_Features, .Alloc, .Free}) {
		fault := Prepare_Fault {
			backing = backing,
		}

		allocator := mem.Allocator{prepare_fault, &fault}
		outer := prepare_response(307, "/next", allocator)
		inner := prepare_response(302, "/independent", backing)
		target: Redirect_Handoff
		c := Prepare_Reentry {
			target    = &target,
			profile   = &profile,
			outer     = &outer,
			inner     = &inner,
			allocator = backing,
		}

		fault.calls = 0
		fault.hook = prepare_reenter
		fault.user = &c
		fault.hook_mode = mode
		error := redirect_prepare(
			&target,
			&profile,
			prepare_handle(),
			{method = .GET, url = "https://example.test/"},
			&outer,
			0,
			32,
			allocator,
		)
		testing.expect_value(t, error.kind, .None)
		testing.expect(
			t,
			c.called == 1 && c.guarded && c.source_preserved && c.outer_cleared && target.phase == .Ready,
		)
		redirect_handoff_destroy(&target)
		surf.response_destroy(&inner)
		testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)
	}

	fault := Prepare_Fault {
		backing = backing,
	}

	allocator := mem.Allocator{prepare_fault, &fault}
	h := new(Redirect_Handoff, backing)
	response := prepare_response(307, "/next", backing)
	assert(
		redirect_prepare(h, &profile, prepare_handle(), {method = .GET, url = "https://example.test/"}, &response, 0, 32, allocator).kind ==
		.None,
	)
	c := Prepare_Header_Free {
		target  = h,
		backing = backing,
	}

	fault.hook = prepare_free_cleared_header
	fault.user = &c
	fault.hook_mode = .Free
	redirect_handoff_destroy(h) // The callback physically frees h; no later h access.
	testing.expect(t, c.target == nil && c.called == 1 && c.cleared && c.recursive_empty)
	testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)
	profile_destroy(&profile)
	testing.expect_value(t, track.current_memory_allocated, 0)
	mem.tracking_allocator_destroy(&track)
	fmt.println("REDIRECT_PREPARE constructor_reentry_modes=3 cleared_heap_header_free=true")
}

@(test)
redirect_prepare_rejects_borrowed_response_aliases_before_consumption :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	profile: Profile
	prepare_profile(&profile, allocator)

	for mode in 0 ..< 2 {
		response := prepare_response(307, "/next", allocator)
		before := response
		field := [1]http.Header{{name = "X-Borrow", value = response.headers[0].value}}
		current := http.Request {
			method = .POST,
			url    = "https://example.test/",
		}

		if mode == 0 {
			current.body = response.body
		} else {
			current.headers = field[:]
		}

		target: Redirect_Handoff
		allocations, allocated := track.total_allocation_count, track.current_memory_allocated
		error := redirect_prepare(&target, &profile, prepare_handle(), current, &response, 0, 32, allocator)
		testing.expect_value(t, error.http.kind, .Overlapping_Buffers)
		testing.expect(
			t,
			target.phase == .Empty &&
			response.status == before.status &&
			raw_data(response.headers) == raw_data(before.headers) &&
			raw_data(response.header_storage) == raw_data(before.header_storage) &&
			raw_data(response.body_storage) == raw_data(before.body_storage) &&
			string(response.body) == "body",
		)
		testing.expect(t, track.total_allocation_count == allocations && track.current_memory_allocated == allocated)
		surf.response_destroy(&response)
	}

	profile_destroy(&profile)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.println("REDIRECT_PREPARE borrowed_response_alias_rejections=2 source_preserved=true")
}

@(test)
redirect_prepare_preserves_managed_limit_and_closed_scope_causes :: proc(t: ^testing.T) {
	for closed in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		backing := mem.tracking_allocator(&track)
		scope, cause := scopes.create_root({bytes = 0, streams = 1}, backing)
		assert(cause == .None)
		binding, error := charged.create(scope, {backing = backing, metadata_allocator = backing})
		assert(error.kind == .None)
		allocator := charged.allocator(binding)
		profile: Profile
		prepare_profile(&profile, backing, scope)
		baseline := track.current_memory_allocated
		response := prepare_response(307, "/next", backing)

		if closed {
			assert(scopes.close(scope) == .None)
		}

		target: Redirect_Handoff
		failure := redirect_prepare(
			&target,
			&profile,
			prepare_handle(),
			{method = .GET, url = "https://example.test/"},
			&response,
			0,
			32,
			allocator,
		)
		testing.expect(t, failure.kind == .Budget_Rejected && failure.http.kind == .Allocation_Failed)
		testing.expect_value(t, failure.http.budget, scopes.Error.Closed if closed else scopes.Error.Limit_Exceeded)
		testing.expect(
			t,
			failure.http.status == 307 &&
			failure.http.write_effect == .Response_Received &&
			response.status == 0 &&
			target.phase == .Empty,
		)
		snapshot, snapshot_error := scopes.snapshot(scope)
		testing.expect(t, snapshot_error == .None && snapshot.used == (scopes.Usage{}))
		testing.expect_value(t, track.current_memory_allocated, baseline)
		profile_destroy(&profile)
		charged.release(&binding)
		scopes.release_scope(&scope)
		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}

	fmt.println("REDIRECT_PREPARE typed_managed_budget_causes=2 consumed_once=true")
}

Redirect_Queue_Fixture :: struct {
	runtime: runtime_async.Runtime,
	s:       ^Client_State,
	scope:   scopes.Scope,
}
rq_wait :: proc(_: rawptr) -> runtime_async.Resume_Result {
	return .Waiting
}
rq_cancel :: proc(_: rawptr) -> runtime_async.Resume_Result {
	return .Done
}
rq_coord_done :: proc(data: rawptr) {
	network_task_done((cast(^Coordinator_State)data).owner, 0, false)
}
rq_actor_done :: proc(data: rawptr) {
	a := cast(^Session_Actor)data
	network_task_done(a.owner, int(a.index), false)
}
rq_init :: proc(f: ^Redirect_Queue_Fixture, dns: int = 32, registered: bool = false, scoped: bool = false) {
	if scoped {
		owner, error := scopes.create_root({bytes = 32 << 20, streams = 1}, context.allocator)
		assert(error == .None)
		f.scope = owner
	}

	assert(
		runtime_async.init(&f.runtime, {workers = 1, task_capacity = 2, io_capacity = 2, allocator = context.allocator}).kind ==
		.None,
	)
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}
	config, error := config_normalize(
		{
			http = {allow_http = true, scope = f.scope, resolver = {name_servers = servers[:]}},
			capacities = Capacities {
				requests = 3,
				origins = 3,
				connections = 1,
				connections_per_origin = 1,
				waiters_per_origin = 3,
				dns_ids = dns,
				work_per_resume = 1,
			},
		},
	)
	assert(error.kind == .None)
	f.s, error = network_prepare(&f.runtime, config, context.allocator)
	assert(error.kind == .None)
	f.s.phase = .Published
	// Initial cryptographic preparation is real, but no network query consumes
	// these test draws; later assertions concern counts and move semantics only.
	if registered {
		s := f.s
		s.coordinator.task = {
			resume    = rq_wait,
			on_cancel = rq_cancel,
			on_done   = rq_coord_done,
			data      = &s.coordinator,
		}

		s.actors[0].task = {
			resume    = rq_wait,
			on_cancel = rq_cancel,
			on_done   = rq_actor_done,
			data      = &s.actors[0],
		}

		s.references += 2
		s.registered_tasks = 2
		s.coordinator.registered = true
		s.actors[0].registered = true
		assert(runtime_async.register_group(&f.runtime, s.task_index).kind == .None)
	}
}
rq_now :: proc(f: ^Redirect_Queue_Fixture) -> runtime_async.Deadline {
	return runtime_async.deadline_after(&f.runtime, 0)
}
rq_reserve :: proc(f: ^Redirect_Queue_Fixture) -> Preparing_Request {
	lease, error := resources_request_lease(&f.s.resources)
	assert(error.kind == .None)
	deadline := runtime_async.deadline_after(&f.runtime, 10 * time.Second)
	preparing, cause := kernel_reserve(&f.s.kernel, deadline, &lease)
	assert(cause.kind == .None)

	return preparing
}
rq_dispose :: proc(f: ^Redirect_Queue_Fixture, disposal: Request_Disposal) {
	local := disposal
	origin := local.origin.origin
	request_disposal_destroy(&local)

	if origin.slot != 0 {
		assert(kernel_origin_cleanup_finish(&f.s.kernel, origin).kind == .None)
	}
}
rq_rollback :: proc(f: ^Redirect_Queue_Fixture, p: Preparing_Request) {
	sync.lock(&f.s.mu)
	disposal, error := kernel_rollback(&f.s.kernel, p)
	assert(error.kind == .None)
	network_queue_forget_locked(f.s, p.request)
	sync.unlock(&f.s.mu)
	rq_dispose(f, disposal)
	next, done, cause := kernel_cleanup_finish(&f.s.kernel, p.request, rq_now(f))
	assert(cause.kind == .None && done)
	rq_dispose(f, next)
}
rq_claim :: proc(f: ^Redirect_Queue_Fixture, p: Preparing_Request, url: string, budget: int) -> Client_Error {
	origin, error := origin_prepare(&f.s.profile, url, f.s.resources.allocator)
	assert(error.kind == .None)
	_, cause := network_queue_claim_budget(f.s, p, &origin, rq_now(f).at, budget)
	origin_destroy(&origin)

	return cause
}
rq_commit :: proc(f: ^Redirect_Queue_Fixture, p: Preparing_Request, url: string) {
	input, error := request_clone({method = .GET, url = url}, f.s.resources.allocator)
	assert(error.kind == .None)
	sync.lock(&f.s.mu)
	cause := network_queue_committed_locked(f.s, p, &input, rq_now(f))
	sync.unlock(&f.s.mu)
	assert(cause.kind == .None && input.storage == nil)
}
rq_dispatch :: proc(f: ^Redirect_Queue_Fixture) -> Assignment {
	for _ in 0 ..< 64 {
		assignment, used, error := pool_dispatch(&f.s.kernel, 1, rq_now(f).at)
		assert(used <= 1 && (error.kind == .None || error.kind == .Pending))

		if assignment.request != (Request_Handle{}) {
			return assignment
		}
	}

	panic("bounded queue fixture did not dispatch")
}
rq_take_assignment :: proc(f: ^Redirect_Queue_Fixture, assignment: Assignment) -> Session_Assignment {
	f.s.actors[0].command = {
		assignment = assignment,
		pending    = true,
	}

	snapshot, error := network_assignment_take(&f.s.actors[0])
	assert(error.kind == .None)

	return snapshot
}
rq_complete :: proc(f: ^Redirect_Queue_Fixture, h: Request_Handle) {
	response: surf.Response
	disposal, error := kernel_begin_complete(
		&f.s.kernel,
		h,
		&response,
		{kind = .Dial_Failed, phase = .DNS, write_effect = .Not_Sent},
	)
	assert(error.kind == .None)
	network_queue_forget_locked(f.s, h)
	rq_dispose(f, disposal)

	for {
		next, done, cause := kernel_cleanup_finish(&f.s.kernel, h, rq_now(f))
		assert(cause.kind == .None)
		rq_dispose(f, next)

		if done {
			break
		}
	}

	assert(kernel_release(&f.s.kernel, h).kind == .None)
}
rq_destroy :: proc(f: ^Redirect_Queue_Fixture) {
	for request, index in f.s.kernel.requests {
		h := Request_Handle {
			owner_id   = f.s.kernel.owner_id,
			slot       = u32(index + 1),
			generation = request.generation,
		}

		if request.state == .Preparing {
			rq_rollback(f, {request = h})
		}

		if request.state == .Queued || request.state == .Active {
			rq_complete(f, h)
		}

		if request.state == .Completed {
			assert(kernel_release(&f.s.kernel, h).kind == .None)
		}
	}

	for model, index in f.s.kernel.sessions {
		h := Cell_Handle {
			slot       = u32(index + 1),
			generation = model.generation,
		}

		if model.state == .Idle || model.state == .Connecting || model.state == .Busy {
			assert(pool_session_state(&f.s.kernel, h, .Retiring, rq_now(f).at).kind == .None)
		}

		if model.state == .Idle || model.state == .Connecting || model.state == .Busy || model.state == .Retiring {
			assert(pool_retire(&f.s.kernel, h).kind == .None)
		}
	}

	registered := f.s.registered_tasks > 0

	if registered {
		assert(runtime_async.destroy(&f.runtime).kind == .None)
	}

	f.s.base_owned = false
	network_state_release(f.s)
	f.s = nil

	if !registered {
		assert(runtime_async.destroy(&f.runtime).kind == .None)
	}

	if f.scope != (scopes.Scope{}) {
		snapshot, error := scopes.snapshot(f.scope)
		assert(error == .None && snapshot.used == (scopes.Usage{}))
		scopes.close(f.scope)
		scopes.release_scope(&f.scope)
	}
}

@(test)
redirect_queue_budget_bounds_and_atomic_source_preservation :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f)
	defer rq_destroy(&f)

	for budget in ([4]int{-1, 33, min(int), max(int)}) {
		p := rq_reserve(&f)
		origin, error := origin_prepare(&f.s.profile, "http://bounds.example/A", f.s.resources.allocator)
		assert(error.kind == .None)
		storage := raw_data(origin.storage)
		before := f.s.kernel.counters
		bank := f.s.dns_count
		metadata_before := f.s.requests[int(p.request.slot) - 1]
		_, cause := network_queue_claim_budget(f.s, p, &origin, rq_now(&f).at, budget)
		testing.expect_value(t, cause.kind, .Invalid_Config)
		testing.expect_value(t, raw_data(origin.storage), storage)
		testing.expect_value(t, f.s.dns_count, bank)
		testing.expect_value(t, f.s.kernel.counters, before)
		testing.expect_value(t, f.s.requests[int(p.request.slot) - 1], metadata_before)
		testing.expect(t, f.s.kernel.requests[int(p.request.slot) - 1].origin.slot == 0)
		origin_destroy(&origin)
		rq_rollback(&f, p)
	}
}

@(test)
redirect_queue_explicit_remainders_bound_draws_before_assignment :: proc(t: ^testing.T) {
	for budget in ([6]int{0, 1, 15, 16, 17, 32}) {
		f: Redirect_Queue_Fixture
		rq_init(&f, 32, true)
		p := rq_reserve(&f)
		cause := rq_claim(&f, p, "http://remainder.example/A", budget)

		if budget == 0 {
			testing.expect_value(t, cause.kind, .Request_Error)
			testing.expect_value(t, cause.http.kind, .Dial_Failed)
			testing.expect_value(t, cause.http.phase, .DNS)
			testing.expect_value(t, cause.http.budget, scopes.Error.None)
			testing.expect_value(t, f.s.dns_count, 32)
			testing.expect_value(t, f.s.kernel.counters.reserved_connections, 0)
		} else {
			testing.expect_value(t, cause.kind, .None)
			moved := min(16, budget)
			metadata := f.s.requests[int(p.request.slot) - 1]
			testing.expect_value(t, metadata.ids.count, moved)
			testing.expect_value(t, metadata.query_budget_left, budget)
			testing.expect_value(t, f.s.dns_count, 32 - moved)
			rq_commit(&f, p, "http://remainder.example/A")
			snapshot := rq_take_assignment(&f, rq_dispatch(&f))
			testing.expect_value(t, snapshot.ids.count, moved)
			testing.expect_value(t, f.s.requests[int(p.request.slot) - 1].query_budget_left, budget - moved)
			second, error := network_assignment_take(&f.s.actors[0])
			testing.expect_value(t, error.kind, .Pending)
			testing.expect_value(t, second.ids.count, 0)
			block := snapshot.ids
			network_dns_burn(f.s, &block)
		}

		rq_destroy(&f)
	}
}

@(test)
redirect_queue_empty_bank_parks_but_zero_numeric_and_prepared_hosts_proceed :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f, 0)
	defer rq_destroy(&f)
	p := rq_reserve(&f)
	testing.expect_value(t, rq_claim(&f, p, "http://waiting.example/A", 1).kind, .None)
	testing.expect(t, f.s.requests[int(p.request.slot) - 1].awaiting_ids)
	testing.expect_value(t, f.s.kernel.counters.reserved_connections, 0)
	rq_commit(&f, p, "http://waiting.example/A")
	testing.expect_value(t, f.s.kernel.requests[int(p.request.slot) - 1].stage, .Awaiting_DNS_IDs)
	rq_complete(&f, p.request)

	for url in ([2]string{"http://127.0.0.1/numeric", "http://prepared.example/hosts"}) {
		if url == "http://prepared.example/hosts" {
			resolv, error := os.create_temp_file("/tmp", "surf101-redirect-resolv-*")
			assert(error == nil)
			hosts, host_error := os.create_temp_file("/tmp", "surf101-redirect-hosts-*")
			assert(host_error == nil)
			rp, hp := strings.clone(os.name(resolv)), strings.clone(os.name(hosts))
			os.close(resolv)
			os.close(hosts)
			assert(
				os.write_entire_file(rp, "nameserver 127.0.0.1\n") == nil &&
				os.write_entire_file(hp, "127.0.0.1 prepared.example\n") == nil,
			)
			net.resolver_snapshot_destroy(&f.s.resolver)
			prepared := net.resolver_snapshot_prepare(
				&f.s.resolver,
				{resolv_conf_path = rp, hosts_file_path = hp, limits = net.DEFAULT_RESOLVER_SNAPSHOT_LIMITS},
				f.s.resources.allocator,
			)
			_ = os.remove(rp)
			_ = os.remove(hp)
			delete(rp)
			delete(hp)
			assert(prepared == nil)
		}

		q := rq_reserve(&f)
		testing.expect_value(t, rq_claim(&f, q, url, 0).kind, .None)
		metadata := f.s.requests[int(q.request.slot) - 1]
		testing.expect(t, !metadata.needs_dns && !metadata.awaiting_ids && metadata.prepared_address_count == 1)
		testing.expect_value(t, metadata.ids.count, 0)
		testing.expect_value(t, metadata.query_budget_left, 0)
		rq_rollback(&f, q)
	}
}

@(test)
redirect_queue_idle_zero_budget_reuses_model_without_new_draws :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f, 32, true)
	defer rq_destroy(&f)
	p := rq_reserve(&f)
	assert(rq_claim(&f, p, "http://idle.example/A", 32).kind == .None)
	rq_commit(&f, p, "http://idle.example/A")
	assignment := rq_dispatch(&f)
	snapshot := rq_take_assignment(&f, assignment)
	block := snapshot.ids
	network_dns_burn(f.s, &block)
	assert(pool_session_state(&f.s.kernel, assignment.session, .Busy, rq_now(&f).at).kind == .None)
	rq_complete(&f, p.request)
	assert(pool_session_state(&f.s.kernel, assignment.session, .Idle, rq_now(&f).at).kind == .None)
	before := f.s.dns_draws_reserved
	q := rq_reserve(&f)
	testing.expect_value(t, rq_claim(&f, q, "http://idle.example/B", 0).kind, .None)
	testing.expect_value(t, f.s.dns_draws_reserved, before)
	rq_commit(&f, q, "http://idle.example/B")
	next := rq_dispatch(&f)
	testing.expect_value(t, next.session, assignment.session)
	reused := rq_take_assignment(&f, next)
	testing.expect_value(t, reused.ids.count, 0)
	testing.expect_value(t, f.s.requests[int(q.request.slot) - 1].query_budget_left, 0)
}

@(test)
redirect_queue_legacy_wrapper_exact_type_still_starts_at_32 :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f)
	defer rq_destroy(&f)
	p := rq_reserve(&f)
	origin, error := origin_prepare(&f.s.profile, "http://legacy.example/A", f.s.resources.allocator)
	assert(error.kind == .None)
	legacy: proc(
			s: ^Client_State,
			p: Preparing_Request,
			origin: ^Prepared_Origin,
			now: i64,
		) -> (
			Pool_Reservation,
			Client_Error,
		) =
		network_queue_claim
	_, cause := legacy(f.s, p, &origin, rq_now(&f).at)
	testing.expect_value(t, cause.kind, .None)
	testing.expect_value(t, f.s.requests[int(p.request.slot) - 1].query_budget_left, 32)
	testing.expect_value(t, f.s.requests[int(p.request.slot) - 1].ids.count, 16)
	origin_destroy(&origin)
}

@(test)
redirect_queue_refill_only_unparks_remaining_allowance_and_deducts_once :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f, 17, true)
	defer rq_destroy(&f)

	for f.s.dns_count > 0 {
		block, error := network_dns_reserve(f.s, 16)
		assert(error.kind == .None)
		network_dns_burn(f.s, &block)
	}

	// Admission refills a non-zero bank. Detach that storage so this head is
	// queued awaiting IDs, then restore it for the explicit refill below.
	bank := f.s.dns_ids
	f.s.dns_ids = nil
	p := rq_reserve(&f)
	cause := rq_claim(&f, p, "http://refill.example/A", 1)
	f.s.dns_ids = bank
	assert(cause.kind == .None)
	rq_commit(&f, p, "http://refill.example/A")
	testing.expect(t, f.s.requests[int(p.request.slot) - 1].awaiting_ids)
	draws := [2]u16{0x101, 0x202}
	assert(network_dns_refill(f.s, draws[:]).kind == .None)
	draws[0] = 0 // Refill copied the borrowed source before returning.

	for _ in 0 ..< len(f.s.requests) {
		_ = network_coordinator_dns_step(f.s)
	}

	metadata := f.s.requests[int(p.request.slot) - 1]
	testing.expect(t, !metadata.awaiting_ids)
	testing.expect_value(t, metadata.ids.count, 1)
	testing.expect_value(t, metadata.ids.values[0], u16(0x101))
	testing.expect_value(t, metadata.query_budget_left, 1)
	testing.expect_value(t, f.s.dns_count, 1)
	snapshot := rq_take_assignment(&f, rq_dispatch(&f))
	testing.expect_value(t, snapshot.ids.count, 1)
	testing.expect_value(t, f.s.requests[int(p.request.slot) - 1].query_budget_left, 0)
	block := snapshot.ids
	network_dns_burn(f.s, &block)
	testing.expect_value(t, f.s.dns_draws_reserved, u64(18))
	testing.expect_value(t, f.s.dns_draws_burned, u64(18))
}

@(test)
redirect_queue_same_handle_hops_keep_one_lease_and_total_allowance :: proc(t: ^testing.T) {
	f: Redirect_Queue_Fixture
	rq_init(&f, 32, true, true)
	defer rq_destroy(&f)
	p := rq_reserve(&f)
	original := p.request

	for hop in 0 ..< 2 {
		url := "http://hop-a.example/A"

		if hop == 1 {
			url = "http://hop-b.example/B"
		}

		remaining := 32 - hop * 16
		assert(rq_claim(&f, p, url, remaining).kind == .None)
		rq_commit(&f, p, url)
		assignment := rq_dispatch(&f)
		snapshot := rq_take_assignment(&f, assignment)
		block := snapshot.ids
		network_dns_burn(f.s, &block)
		testing.expect_value(t, f.s.requests[int(original.slot) - 1].query_budget_left, remaining - 16)
		assert(pool_session_state(&f.s.kernel, assignment.session, .Busy, rq_now(&f).at).kind == .None)
		assert(pool_session_state(&f.s.kernel, assignment.session, .Retiring, rq_now(&f).at).kind == .None)
		disposal, error := kernel_redirect_begin(&f.s.kernel, original, rq_now(&f))
		assert(error.kind == .None)
		rq_dispose(&f, disposal)
		assert(pool_retire(&f.s.kernel, assignment.session).kind == .None)
		assert(kernel_redirect_ready(&f.s.kernel, original, rq_now(&f)).kind == .None)
		usage, cause := scopes.snapshot(f.scope)
		assert(cause == .None)
		testing.expect_value(t, usage.used.streams, u64(1))
		_, published := kernel_poll(&f.s.kernel)
		testing.expect(t, !published)
		p = {
			request = original,
		}
	}

	testing.expect_value(t, rq_claim(&f, p, "http://hop-c.example/C", 0).kind, .Request_Error)
	disposal, error := kernel_redirect_fail(
		&f.s.kernel,
		original,
		{kind = .Dial_Failed, phase = .DNS, status = 302, write_effect = .Response_Received},
	)
	assert(error.kind == .None)
	rq_dispose(&f, disposal)
	next, done, finish := kernel_cleanup_finish(&f.s.kernel, original, rq_now(&f))
	assert(finish.kind == .None && done)
	rq_dispose(&f, next)
	completion, published := kernel_poll(&f.s.kernel)
	testing.expect(t, published)
	testing.expect_value(t, completion.request, original)
	testing.expect_value(t, completion.error.status, 302)
	testing.expect_value(t, completion.error.write_effect, .Response_Received)
	_, twice := kernel_poll(&f.s.kernel)
	testing.expect(t, !twice)
	assert(kernel_release(&f.s.kernel, original).kind == .None)
	testing.expect_value(t, f.s.dns_draws_reserved, u64(32))
	testing.expect_value(t, f.s.dns_draws_burned, u64(32))
	usage, cause := scopes.snapshot(f.scope)
	assert(cause == .None)
	testing.expect_value(t, usage.used.streams, u64(0))
}
