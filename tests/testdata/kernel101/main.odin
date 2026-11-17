package main

import kernel "shared:surf/async"
import surf "shared:surf"
import http "shared:http"
import async "shared:async"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import scopes "core:sync/budget"
import "core:strings"
import "core:time"

// A deterministic memory transport exercises the real blocking facade codec.
// It is not a socket, an async actor, TLS, or persistent transport evidence.
Memory_Peer :: struct {
	at, writes: int,
	written:    [2048]u8,
}
read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	peer := cast(^Memory_Peer)data
	wire := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Fixture: owned\r\n\r\nok"

	if peer.at == len(wire) {
		return 0, {kind = .Peer_Closed}
	}

	n := copy(dst[:min(len(dst), 3)], wire[peer.at:])
	peer.at += n

	return n, {}
}
write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	peer := cast(^Memory_Peer)data
	n := min(len(src), 2)
	assert(peer.writes + n <= len(peer.written))
	copy(peer.written[peer.writes:peer.writes + n], src[:n])
	peer.writes += n

	return n, {}
}
close :: proc(_: rawptr) -> net.Connection_Error {
	return {}
}
now :: proc(runtime: ^async.Runtime) -> async.Deadline {
	return async.deadline_after(runtime, 0)
}

finish :: proc(k: ^kernel.Kernel, runtime: ^async.Runtime, disposal: ^kernel.Request_Disposal) {
	for _ in 0 ..< 3 {
		ticket, origin := disposal.request, disposal.origin.origin
		kernel.request_disposal_destroy(disposal)

		if origin.slot != 0 {
			assert(kernel.kernel_origin_cleanup_finish(k, origin).kind == .None)
		}

		next, done, error := kernel.kernel_cleanup_finish(k, ticket, now(runtime))
		assert(error.kind == .None)
		disposal^ = next

		if done {
			return
		}
	}

	panic("physical cleanup did not finish")
}
prepare :: proc(
	k: ^kernel.Kernel,
	p: ^kernel.Profile,
	r: ^kernel.Kernel_Resources,
	runtime: ^async.Runtime,
	deadline: async.Deadline,
) -> (
	kernel.Preparing_Request,
	kernel.Pool_Reservation,
) {
	lease, error := kernel.resources_request_lease(r)
	assert(error.kind == .None)
	preparing, cause := kernel.kernel_reserve(k, deadline, &lease)
	assert(cause.kind == .None && lease == (scopes.Lease{}))
	origin, origin_error := kernel.origin_prepare(p, "https://EXAMPLE.test/", r.allocator)
	assert(origin_error.kind == .None)
	reservation, reserve_error := kernel.pool_reserve(k, preparing, &origin, now(runtime).at)
	kernel.origin_destroy(&origin)
	assert(reserve_error.kind == .None)
	return preparing, reservation
}

main :: proc() {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	runtime: async.Runtime
	assert(
		async.init(&runtime, {workers = 1, task_capacity = 1, io_capacity = 0, allocator = allocator}).kind == .None,
	)
	scope, cause := scopes.create_root({bytes = 8 << 20, streams = 8}, allocator)
	assert(cause == .None)
	config, error := kernel.config_normalize(
		{
			http = {allow_http = true, scope = scope},
			capacities = kernel.Capacities {
				requests = 3,
				origins = 2,
				connections = 1,
				connections_per_origin = 1,
				waiters_per_origin = 3,
				dns_ids = 0,
				work_per_resume = 1,
			},
			idle_timeout = time.Second,
			max_age = 10 * time.Second,
		},
	)
	assert(error.kind == .None)
	profile: kernel.Profile
	resources: kernel.Kernel_Resources
	model, other: kernel.Kernel
	assert(kernel.profile_init(&profile, config, allocator).kind == .None)
	assert(kernel.resources_init(&resources, scope, allocator).kind == .None)
	assert(kernel.kernel_init(&model, &profile, &resources).kind == .None)
	assert(kernel.kernel_init(&other, &profile, &resources).kind == .None)
	assert(model.owner_id != 0 && other.owner_id != 0 && model.owner_id != other.owner_id)
	deadline := async.deadline_after(&runtime, 30 * time.Second)
	a, claim := prepare(&model, &profile, &resources, &runtime, deadline)
	lease, lease_error := kernel.resources_request_lease(&resources)
	assert(lease_error.kind == .None)
	b, b_error := kernel.kernel_reserve(&other, deadline, &lease)
	assert(b_error.kind == .None)
	assert(a.request.slot == b.request.slot && a.request.generation == b.request.generation)
	assert(kernel.kernel_cancel(&model, b.request).kind == .Invalid_Handle)
	assert(kernel.kernel_cancel(&other, a.request).kind == .Invalid_Handle)
	rollback, rollback_error := kernel.kernel_rollback(&other, b)
	assert(rollback_error.kind == .None)
	finish(&other, &runtime, &rollback)
	assert(kernel.kernel_destroy(&other).kind == .None)

	detached: surf.Response
	previous_session: kernel.Cell_Handle
	work1_calls := 0

	for iteration in 0 ..< 2 {
		preparing, reservation := a, claim

		if iteration != 0 {
			preparing, reservation = prepare(&model, &profile, &resources, &runtime, deadline)
		}

		if iteration == 1 {
			assert(reservation.session == previous_session)
		}

		request := http.Request {
			method = .GET,
			url    = "https://example.test/path",
		}

		input, clone_error := kernel.request_clone(request, resources.allocator)
		assert(clone_error.kind == .None)
		assert(kernel.kernel_commit(&model, preparing, &input, now(&runtime)).kind == .None && input.storage == nil)
		_, premature := kernel.kernel_poll(&model)
		assert(!premature)
		session: kernel.Cell_Handle

		for _ in 0 ..< 100 {
			assignment, used, dispatch_error := kernel.pool_dispatch(&model, 1, now(&runtime).at)
			work1_calls += 1
			assert(used <= 1 && (dispatch_error.kind == .None || dispatch_error.kind == .Pending))

			if assignment.request.owner_id != 0 {
				assert(assignment.request == preparing.request)
				session = assignment.session
				break
			}
		}

		assert(session.slot != 0)

		if iteration == 0 {
			assert(kernel.pool_session_state(&model, session, .Busy, now(&runtime).at).kind == .None)
		}

		peer: Memory_Peer
		response, http_error := surf.exchange(
			{data = &peer, read = read, write = write, close = close},
			request,
			8,
			resources.allocator,
		)
		assert(http_error.kind == .None && response.status == 200 && string(response.body) == "ok")
		assert(strings.has_prefix(string(peer.written[:peer.writes]), "GET /path HTTP/1.1\r\n"))
		disposal, complete_error := kernel.kernel_begin_complete(&model, preparing.request, &response, {})
		assert(complete_error.kind == .None && response.body_storage == nil)
		finish(&model, &runtime, &disposal)

		if iteration == 0 {
			completion, ready := kernel.kernel_poll(&model)
			assert(ready && completion.request == preparing.request && completion.error.kind == .None)
			assert(kernel.kernel_take(&model, preparing.request, &detached).kind == .None)
		} else {
			// Direct release must remove the unpolled scalar notification too.
			assert(kernel.kernel_release(&model, preparing.request).kind == .None)
		}

		_, stale := kernel.kernel_poll(&model)
		assert(!stale)
		assert(kernel.kernel_cancel(&model, preparing.request).kind == .Invalid_Handle)
		assert(kernel.pool_session_state(&model, session, .Idle, now(&runtime).at).kind == .None)
		previous_session = session
	}

	assert(work1_calls > 2)
	due: kernel.Cell_Handle

	for _ in 0 ..< 100 {
		candidate, used, idle_error := kernel.pool_idle_candidate(&model, 1, now(&runtime).at + 2 * i64(time.Second))
		assert(used <= 1 && (idle_error.kind == .None || idle_error.kind == .Pending))

		if candidate.slot != 0 {
			due = candidate
			break
		}
	}

	assert(due == previous_session)
	assert(kernel.pool_session_state(&model, due, .Retiring, now(&runtime).at).kind == .None)
	assert(kernel.pool_retire(&model, due).kind == .None)

	pending, _ := prepare(&model, &profile, &resources, &runtime, deadline)
	source, source_error := kernel.request_clone({method = .GET, url = "https://example.test/"}, resources.allocator)
	assert(source_error.kind == .None)
	original := raw_data(source.storage)
	assert(kernel.kernel_close(&model).kind == .None)
	assert(kernel.kernel_commit(&model, pending, &source, now(&runtime)).kind == .Closed)
	assert(raw_data(source.storage) == original)
	kernel.request_owner_destroy(&source)
	disposal, dispose_error := kernel.kernel_rollback(&model, pending)
	assert(dispose_error.kind == .None)
	finish(&model, &runtime, &disposal)
	lease, lease_error = kernel.resources_request_lease(&resources)
	assert(lease_error.kind == .None)
	original_lease := lease
	_, closed_error := kernel.kernel_reserve(&model, deadline, &lease)
	assert(closed_error.kind == .Closed && lease == original_lease)
	scopes.release(&lease)
	assert(kernel.kernel_destroy(&model).kind == .None)
	kernel.profile_destroy(&profile)
	kernel.resources_destroy(&resources)
	assert(string(detached.body) == "ok")
	held, snapshot_error := scopes.snapshot(scope)
	assert(snapshot_error == .None && held.used.bytes > 0 && held.used.streams == 0)
	surf.response_destroy(&detached)
	empty, _ := scopes.snapshot(scope)
	assert(empty.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
	assert(async.destroy(&runtime).kind == .None)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.print(
		"{\"passed\":true,\"scope\":\"kernel-and-memory-codec-only\",\"model_completions\":2,\"memory_exchanges\":2,\"model_idle_reuses\":1,\"work1_calls\":",
	)
	fmt.print(work1_calls)
	fmt.println(",\"foreign_owner_checks\":2,\"close_rejections\":2,\"scope_zero\":true,\"heap_zero\":true}")
}
