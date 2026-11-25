package surf_async

import surf ".."
import "core:mem"
import scopes "shared:async/sync/budget"
import "core:net"
import "core:testing"
import "core:thread"

completion_publish :: proc(p: ^Admission_Probe) -> Request_Handle {
	preparing, _ := adm_prepare(p)
	request := adm_commit(p, preparing)
	response := adm_response(p)
	// Pure kernel result-owner fixture: no HTTP/network execution is represented.
	assert(adm_terminal(p, request, &response) == 1)
	assert(response.body_storage == nil)

	return request
}

@(test)
completion_direct_take_or_release_unlinks_every_notification :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 1, waiters = 1)

	for iteration in 0 ..< 96 {
		request := completion_publish(&p)
		mode := iteration % 4

		if mode >= 2 {
			completion, ok := kernel_poll(&p.kernel)
			testing.expect(t, ok)
			testing.expect_value(t, completion.request, request)
			testing.expect_value(t, completion.error.kind, .None)
		}

		if mode % 2 == 0 {
			result: surf.Response
			assert(kernel_take(&p.kernel, request, &result).kind == .None)
			testing.expect_value(t, string(result.body), "yes")
			surf.response_destroy(&result)
		} else {
			assert(kernel_release(&p.kernel, request).kind == .None)
		}

		_, ok := kernel_poll(&p.kernel)
		testing.expect(t, !ok)
		testing.expect_value(t, kernel_release(&p.kernel, request).kind, .Invalid_Handle)
		testing.expect_value(t, p.kernel.request_free_count, 1)
	}

	adm_destroy(&p)
}

@(test)
completion_two_phase_cleanup_checks_fresh_cutoff_cancel_and_epoch :: proc(t: ^testing.T) {
	for mode in 0 ..< 8 {
		p: Admission_Probe
		adm_init(&p, requests = 1, waiters = 1)
		preparing, _ := adm_prepare(&p)
		request := adm_commit(&p, preparing)
		response: surf.Response
		primary := surf.HTTP_Error{}

		if mode >= 3 {
			primary = {
				kind         = .Invalid_Chunk,
				phase        = .Protocol,
				status       = 502,
				write_effect = .Response_Received,
			}
		} else {
			response = adm_response(&p)
		}

		if mode == 6 {
			primary = {
				kind         = .Deadline_Failed,
				phase        = .Deadline,
				write_effect = .Not_Sent,
			}
		}

		if mode == 7 {
			primary = {
				kind = .IO_Failed,
				phase = .Deadline,
				transport = net.TCP_Recv_Error.Timeout,
				write_effect = .Not_Sent,
			}
		}

		disposal, error := kernel_begin_complete(&p.kernel, request, &response, primary)
		assert(error.kind == .None)
		testing.expect(t, response.body_storage == nil)
		_, ok := kernel_poll(&p.kernel)
		testing.expect(t, !ok)
		testing.expect_value(t, kernel_destroy(&p.kernel).kind, .Pending)
		snapshot, _ := scopes.snapshot(p.scope)
		testing.expect_value(t, snapshot.used.streams, u64(1))
		origin_ticket := disposal.origin.origin
		request_disposal_destroy(&disposal)

		if origin_ticket.slot != 0 {
			assert(kernel_origin_cleanup_finish(&p.kernel, origin_ticket).kind == .None)
		}

		snapshot, _ = scopes.snapshot(p.scope)
		testing.expect_value(t, snapshot.used.streams, u64(0))
		now := adm_now()

		if mode == 0 || mode == 3 {
			now.at = 1000
		}

		if mode == 1 || mode == 4 {
			assert(kernel_cancel(&p.kernel, request).kind == .None)
		}

		if mode == 2 || mode == 5 {
			now.epoch = 8
		}

		testing.expect_value(t, p.kernel.counters.deadline_count, u64(0))
		next, done, finish_error := kernel_cleanup_finish(&p.kernel, request, now)
		assert(finish_error.kind == .None)

		if mode >= 3 {
			testing.expect(t, done)
		} else {
			testing.expect(t, !done && string(next.response.body) == "yes")
			testing.expect_value(t, p.kernel.counters.deadline_count, u64(0))
			_, ok = kernel_poll(&p.kernel)
			testing.expect(t, !ok)
			testing.expect_value(t, kernel_destroy(&p.kernel).kind, .Pending)
			ticket := next.request
			origin := next.origin.origin
			request_disposal_destroy(&next)

			if origin.slot != 0 {
				assert(kernel_origin_cleanup_finish(&p.kernel, origin).kind == .None)
			}

			next, done, finish_error = kernel_cleanup_finish(&p.kernel, ticket, now)
			testing.expect(t, finish_error.kind == .None && done && next.response.body_storage == nil)
		}

		expected_deadlines := u64(0)

		if mode == 0 || mode == 6 || mode == 7 {
			expected_deadlines = 1
		}

		testing.expect_value(t, p.kernel.counters.deadline_count, expected_deadlines)
		completion, found := kernel_poll(&p.kernel)
		testing.expect(t, found)
		testing.expect_value(t, completion.request, request)

		if mode == 0 {
			testing.expect_value(t, completion.error.kind, .Deadline_Failed)
			testing.expect_value(t, completion.error.phase, .Deadline)
		}

		if mode == 1 {
			testing.expect_value(t, completion.error.kind, .IO_Failed)
			testing.expect_value(t, completion.error.transport, net.Connection_Error.Cancelled)
			testing.expect_value(t, completion.error.phase, .Cancellation)
		}

		if mode == 2 {
			testing.expect_value(t, completion.error.kind, .Invalid_Config)
			testing.expect_value(t, completion.error.phase, .Configuration)
		}

		if mode >= 3 {
			testing.expect_value(t, completion.error.kind, primary.kind)
			testing.expect_value(t, completion.error.phase, primary.phase)
			testing.expect_value(t, completion.error.status, primary.status)
			testing.expect_value(t, completion.error.write_effect, primary.write_effect)
		}

		result: surf.Response
		testing.expect_value(t, kernel_take(&p.kernel, request, &result).kind, .Request_Error)
		testing.expect(t, result.body_storage == nil)
		assert(kernel_release(&p.kernel, request).kind == .None)
		adm_destroy(&p)
	}
}

Completion_Reentry :: struct {
	probe:    ^Admission_Probe,
	target:   rawptr,
	request:  Request_Handle,
	disposal: ^Request_Disposal,
	calls:    int,
}
completion_reentry_allocator :: proc(
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
	hook := cast(^Completion_Reentry)data
	if mode == .Free && old_memory == hook.target {
		hook.target = nil
		hook.calls += 1
		assert(hook.disposal.input.storage == nil && hook.disposal.lease == (scopes.Lease{}))
		_, found := kernel_poll(&hook.probe.kernel)
		assert(!found)
		assert(kernel_destroy(&hook.probe.kernel).kind == .Pending)
		// Free callbacks may reenter the kernel. A held Returning slot cannot be
		// recycled, while a concurrent cancellation still prevents late success.
		lease, error := resources_request_lease(&hook.probe.resources)
		assert(error.kind == .None)
		before := lease
		_, error = kernel_reserve(&hook.probe.kernel, adm_deadline(), &lease)
		assert(error.kind == .Capacity && lease == before)
		scopes.release(&lease)
		assert(kernel_cancel(&hook.probe.kernel, hook.request).kind == .None)
	}
	backing := hook.probe.resources.allocator
	return backing.procedure(backing.data, mode, size, alignment, old_memory, old_size, location)
}
@(test)
completion_physical_disposal_reenters_without_lock_or_premature_reuse :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5_000_000_000)
	p: Admission_Probe
	adm_init(&p, requests = 1, waiters = 1)
	preparing, _ := adm_prepare(&p)
	hook := Completion_Reentry {
		probe   = &p,
		request = preparing.request,
	}

	input, error := request_clone(
		{method = .POST, url = "https://example.test/", body = []u8{'x'}},
		{procedure = completion_reentry_allocator, data = &hook},
	); assert(error.kind == .None)
	hook.target = raw_data(input.storage)
	assert(kernel_commit(&p.kernel, preparing, &input, adm_now()).kind == .None)
	response := adm_response(&p)
	disposal, cause := kernel_begin_complete(&p.kernel, preparing.request, &response, {})
	assert(cause.kind == .None)
	hook.disposal = &disposal
	testing.expect_value(t, adm_dispose(&p, &disposal), 2)
	testing.expect_value(t, hook.calls, 1)
	completion, ok := kernel_poll(&p.kernel)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.phase, .Cancellation)
	assert(kernel_release(&p.kernel, preparing.request).kind == .None)
	adm_destroy(&p)
}

@(test)
completion_destination_and_generation_boundaries_are_transactional :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 1, waiters = 1)
	request := completion_publish(&p)
	occupied := adm_response(&p)
	pointer := raw_data(occupied.body)
	testing.expect_value(t, kernel_take(&p.kernel, request, &occupied).kind, .Invalid_State)
	testing.expect_value(t, raw_data(occupied.body), pointer)
	surf.response_destroy(&occupied)
	destination: surf.Response
	bad := request
	bad.owner_id += 1
	testing.expect_value(t, kernel_take(&p.kernel, bad, &destination).kind, .Invalid_Handle)
	testing.expect(t, destination.body_storage == nil)
	assert(kernel_release(&p.kernel, request).kind == .None)
	// Isolated local-generation boundary injection; no process/global owner IDs.
	p.kernel.requests[0].generation = max(u64)
	preparing, _ := adm_prepare(&p)
	testing.expect_value(t, preparing.request.generation, max(u64))
	adm_rollback(&p, preparing)
	testing.expect_value(t, p.kernel.requests[0].state, .Retired)
	testing.expect_value(t, p.kernel.request_free_count, 0)
	lease, error := resources_request_lease(&p.resources)
	assert(error.kind == .None)
	original := lease
	_, error = kernel_reserve(&p.kernel, adm_deadline(), &lease)
	testing.expect_value(t, error.kind, .Capacity)
	testing.expect_value(t, lease, original)
	scopes.release(&lease)
	adm_destroy(&p)
}

Completion_Worker :: struct {
	probe:     ^Admission_Probe,
	completed: int,
}
completion_producer :: proc(worker: ^Completion_Worker) {
	p := worker.probe
	attempts := 0

	for worker.completed < 64 {
		attempts += 1
		assert(attempts < 100000)
		lease, error := resources_request_lease(&p.resources)
		assert(error.kind == .None)
		preparing, admission_error := kernel_reserve(&p.kernel, adm_deadline(), &lease)

		if admission_error.kind == .Capacity {
			scopes.release(&lease)
			thread.yield()
			continue
		}

		assert(admission_error.kind == .None)
		origin, failure := origin_prepare(&p.profile, "https://example.test/", p.resources.allocator)
		assert(failure.kind == .None)
		_, failure = pool_reserve(&p.kernel, preparing, &origin, adm_now().at)
		origin_destroy(&origin)

		if failure.kind == .Capacity {
			adm_rollback(p, preparing)
			thread.yield()
			continue
		}

		assert(failure.kind == .None)
		request := adm_commit(p, preparing)
		response := adm_response(p)
		assert(adm_terminal(p, request, &response) == 1)
		output: surf.Response
		assert(kernel_take(&p.kernel, request, &output).kind == .None)
		assert(string(output.body) == "yes")
		surf.response_destroy(&output)
		worker.completed += 1
	}
}
@(test)
completion_concurrent_producers_take_unpolled_results_without_stale_nodes :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 4, connections = 4, waiters = 4)
	workers: [4]Completion_Worker
	threads: [4]^thread.Thread

	for &worker, index in workers {
		worker.probe = &p
		threads[index] = thread.create_and_start_with_poly_data(&worker, completion_producer)
		assert(threads[index] != nil)
	}

	for worker in threads {
		thread.join(worker)
		thread.destroy(worker)
	}

	for worker in workers {
		testing.expect_value(t, worker.completed, 64)
	}

	_, found := kernel_poll(&p.kernel)
	testing.expect(t, !found)
	testing.expect_value(t, p.kernel.completion_head, u32(0))
	testing.expect_value(t, p.kernel.completion_tail, u32(0))
	testing.expect_value(t, p.kernel.request_free_count, 4)
	adm_destroy(&p)
}

@(test)
completion_fifo_tracks_publication_order_and_rejects_premature_release :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 3, connections = 1, waiters = 3)
	handles: [3]Request_Handle

	for &handle in handles {
		preparing, _ := adm_prepare(&p)
		handle = adm_commit(&p, preparing)
		testing.expect_value(t, kernel_release(&p.kernel, handle).kind, .Pending)
		destination: surf.Response
		testing.expect_value(t, kernel_take(&p.kernel, handle, &destination).kind, .Pending)
	}

	order := [3]int{1, 0, 2}

	for index in order {
		response := adm_response(&p)
		assert(adm_terminal(&p, handles[index], &response) == 1)
	}

	for index in order {
		completion, found := kernel_poll(&p.kernel)
		testing.expect(t, found)
		testing.expect_value(t, completion.request, handles[index])
	}

	_, found := kernel_poll(&p.kernel)
	testing.expect(t, !found)

	for handle in handles {
		assert(kernel_release(&p.kernel, handle).kind == .None)
	}

	adm_destroy(&p)
}

@(test)
completion_taken_response_outlives_kernel_profile_and_resource_owners :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 1, waiters = 1)
	handle := completion_publish(&p)
	output: surf.Response
	assert(kernel_take(&p.kernel, handle, &output).kind == .None)
	testing.expect_value(t, string(output.body), "yes")
	// Taking the result frees its request slot without freeing result backing.
	replacement, _ := adm_prepare(&p)
	adm_rollback(&p, replacement)
	assert(kernel_destroy(&p.kernel).kind == .None)
	profile_destroy(&p.profile)
	resources_destroy(&p.resources)
	before, error := scopes.snapshot(p.scope)
	assert(error == .None)
	testing.expect(t, before.used.bytes > 0 && before.used.streams == 0)
	testing.expect_value(t, string(output.body), "yes")
	surf.response_destroy(&output)
	after, _ := scopes.snapshot(p.scope)
	testing.expect_value(t, after.used, scopes.Usage{})
	scopes.release_scope(&p.scope)
	testing.expect(t, p.track.current_memory_allocated == 0 && len(p.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&p.track)
}
