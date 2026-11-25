package surf_async

import surf ".."
import runtime_async "shared:async"
import rt "base:runtime"
import "core:mem"
import "core:bytes"
import scopes "shared:async/sync/budget"
import "core:net"
import "core:testing"
import "core:thread"
import signal "shared:async/signal"
import "base:intrinsics"
import "core:time"
import "core:fmt"
import "core:sync"
import http "shared:async/http"
import charged "shared:async/mem/budget"

Admission_Probe :: struct {
	track:     mem.Tracking_Allocator,
	allocator: mem.Allocator,
	scope:     scopes.Scope,
	profile:   Profile,
	resources: Kernel_Resources,
	kernel:    Kernel,
}
adm_init :: proc(p: ^Admission_Probe, requests := 3, connections := 1, waiters := 3, managed := true) {
	mem.tracking_allocator_init(&p.track, rt.heap_allocator(), rt.heap_allocator())
	p.allocator = mem.tracking_allocator(&p.track)

	if managed {
		scope, error := scopes.create_root({bytes = 1 << 24, streams = 64, jobs = 64}, p.allocator)
		assert(error == .None)
		p.scope = scope
	}

	config, error := config_normalize(
		{
			http = {allow_http = true, scope = p.scope},
			capacities = Capacities {
				requests = requests,
				origins = requests,
				connections = connections,
				connections_per_origin = connections,
				waiters_per_origin = waiters,
				dns_ids = 0,
				work_per_resume = 8,
			},
		},
	)
	assert(error.kind == .None)
	assert(profile_init(&p.profile, config, p.allocator).kind == .None)
	assert(resources_init(&p.resources, p.scope, p.allocator).kind == .None)
	assert(kernel_init(&p.kernel, &p.profile, &p.resources).kind == .None)
}
adm_destroy :: proc(p: ^Admission_Probe) {
	assert(kernel_destroy(&p.kernel).kind == .None)
	profile_destroy(&p.profile)
	resources_destroy(&p.resources)

	if p.scope != (scopes.Scope{}) {
		snapshot, error := scopes.snapshot(p.scope)
		assert(error == .None && snapshot.used == (scopes.Usage{}))
		scopes.release_scope(&p.scope)
	}

	assert(p.track.current_memory_allocated == 0 && len(p.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&p.track)
}
adm_metadata_snapshot :: proc(k: ^Kernel) -> []u8 {
	header := k^
	header.mu = {}
	header_bytes := (cast(^[size_of(Kernel)]u8)&header)[:]
	total :=
		len(header_bytes) +
		len(mem.slice_to_bytes(k.requests)) +
		len(mem.slice_to_bytes(k.origins)) +
		len(mem.slice_to_bytes(k.sessions)) +
		4 * (len(k.request_free) + len(k.origin_free) + len(k.session_free))
	result := make([]u8, total)
	at := copy(result, header_bytes)

	for part in ([6][]u8 {
			mem.slice_to_bytes(k.requests),
			mem.slice_to_bytes(k.origins),
			mem.slice_to_bytes(k.sessions),
			mem.slice_to_bytes(k.request_free),
			mem.slice_to_bytes(k.origin_free),
			mem.slice_to_bytes(k.session_free),
		}) {at += copy(result[at:], part)}
	assert(at == len(result))

	return result
}
adm_reserve_noalloc :: proc(
	k: ^Kernel,
	deadline: runtime_async.Deadline,
	lease: ^scopes.Lease,
) -> (
	Preparing_Request,
	Client_Error,
) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous
	return kernel_reserve(k, deadline, lease)
}
adm_deadline :: proc() -> runtime_async.Deadline {
	return {epoch = 7, at = 1000}
}
adm_now :: proc() -> runtime_async.Deadline {
	return {epoch = 7, at = 10}
}
adm_clone :: proc(p: ^Admission_Probe) -> Request_Owner {
	owner, error := request_clone(
		{method = .POST, url = "https://example.test/path", body = []u8{'q'}},
		p.resources.allocator,
	)
	assert(error.kind == .None)

	return owner
}
adm_prepare :: proc(p: ^Admission_Probe) -> (Preparing_Request, Pool_Reservation) {
	lease, error := resources_request_lease(&p.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(&p.kernel, adm_deadline(), &lease)
	assert(cause.kind == .None && lease == (scopes.Lease{}))
	origin, failure := origin_prepare(&p.profile, "https://example.test/", p.resources.allocator)
	assert(failure.kind == .None)
	reservation, reserve_error := pool_reserve(&p.kernel, preparing, &origin, adm_now().at)
	origin_destroy(&origin)
	assert(reserve_error.kind == .None)

	return preparing, reservation
}
adm_commit :: proc(p: ^Admission_Probe, preparing: Preparing_Request) -> Request_Handle {
	owner := adm_clone(p)
	assert(kernel_commit(&p.kernel, preparing, &owner, adm_now()).kind == .None)
	assert(owner.storage == nil && owner.request.url == "")

	return preparing.request
}
adm_dispose :: proc(
	p: ^Admission_Probe,
	disposal: ^Request_Disposal,
	now := runtime_async.Deadline{epoch = 7, at = 10},
) -> int {
	for round in 1 ..= 3 {
		request := disposal.request
		origin := disposal.origin.origin
		request_disposal_destroy(disposal)

		if origin.slot != 0 {
			assert(kernel_origin_cleanup_finish(&p.kernel, origin).kind == .None)
		}

		next, done, error := kernel_cleanup_finish(&p.kernel, request, now)
		assert(error.kind == .None)
		disposal^ = next

		if done {
			assert(disposal.input.storage == nil && disposal.response.body_storage == nil)
			return round
		}
	}
	panic("cleanup failed to converge")
}
adm_rollback :: proc(p: ^Admission_Probe, preparing: Preparing_Request) {
	disposal, error := kernel_rollback(&p.kernel, preparing)
	assert(error.kind == .None)
	assert(adm_dispose(p, &disposal) == 1)
}
adm_response :: proc(p: ^Admission_Probe) -> surf.Response {
	body := make([dynamic]u8, 3, 64, p.resources.allocator)
	copy(body[:], []u8{'y', 'e', 's'})

	return {status = 200, allocator = p.resources.allocator, body_storage = body, body = body[:]}
}
adm_terminal :: proc(
	p: ^Admission_Probe,
	request: Request_Handle,
	response: ^surf.Response,
	error := surf.HTTP_Error{},
	now := runtime_async.Deadline{epoch = 7, at = 10},
) -> int {
	disposal, cause := kernel_begin_complete(&p.kernel, request, response, error)
	assert(cause.kind == .None)
	return adm_dispose(p, &disposal, now)
}
adm_activate :: proc(p: ^Admission_Probe, request: Request_Handle) -> Cell_Handle {
	for _ in 0 ..< 1000 {
		assignment, work, error := pool_dispatch(&p.kernel, 1, adm_now().at)
		assert(work <= 1 && (error.kind == .None || error.kind == .Pending))

		if assignment.request.owner_id != 0 {
			assert(assignment.request == request)
			assert(pool_session_state(&p.kernel, assignment.session, .Busy, adm_now().at).kind == .None)
			return assignment.session
		}
	}

	panic("assignment missing")
}
adm_retire :: proc(p: ^Admission_Probe, session: Cell_Handle) {
	assert(pool_session_state(&p.kernel, session, .Retiring, adm_now().at).kind == .None)
	assert(pool_retire(&p.kernel, session).kind == .None)
}

@(test)
admission_preparing_close_and_expiry_preserve_unaccepted_inputs :: proc(t: ^testing.T) {
	for mode in 0 ..< 4 {
		p: Admission_Probe
		adm_init(&p)
		preparing, _ := adm_prepare(&p)
		_, has_completion := kernel_poll(&p.kernel)
		testing.expect(t, !has_completion)
		owner := adm_clone(&p)
		input := raw_data(owner.storage)
		now := runtime_async.Deadline {
			epoch = 7,
			at    = 10,
		}

		want := Client_Error_Kind.Invalid_Config

		if mode == 0 {
			assert(kernel_close(&p.kernel).kind == .None)
			want = .Closed
		}

		if mode == 1 {
			now.at = 1000
			want = .Request_Error
		}

		if mode == 2 {
			now.epoch = 8
		}

		if mode == 3 {
			assert(kernel_cancel(&p.kernel, preparing.request).kind == .None)
			want = .Request_Error
		}

		cause := kernel_commit(&p.kernel, preparing, &owner, now)
		testing.expect_value(t, cause.kind, want)
		testing.expect(t, raw_data(owner.storage) == input && owner.request.url == "https://example.test/path")

		if mode == 1 {
			testing.expect_value(t, cause.http.kind, .Deadline_Failed)
		}

		if mode == 3 {
			testing.expect_value(t, cause.http.transport, net.Connection_Error.Cancelled)
		}

		request_owner_destroy(&owner)
		adm_rollback(&p, preparing)
		_, has_completion = kernel_poll(&p.kernel)
		testing.expect(t, !has_completion)
		testing.expect_value(t, p.kernel.counters.deadline_count, u64(0))
		adm_destroy(&p)
	}
}

@(test)
admission_lease_provenance_rejection_preserves_sources :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p)
	foreign_scope, error := scopes.create_root({streams = 8}, p.allocator)
	assert(error == .None)

	for mode in 0 ..< 4 {
		source := p.scope

		if mode == 0 {
			source = foreign_scope
		}

		cost := scopes.Cost {
			streams = 1,
		}

		if mode == 1 {
			cost.streams = 2
		}

		if mode == 2 {
			cost.bytes = 1
		}

		phase := scopes.Job_Phase.None

		if mode == 3 {
			cost.jobs = 1
			phase = .Held
		}

		lease, cause := scopes.reserve(source, cost, phase)
		assert(cause == .None)
		snapshot := lease
		free_before := p.kernel.request_free_count
		references := p.kernel.references
		metadata := adm_metadata_snapshot(&p.kernel)
		_, failure := adm_reserve_noalloc(&p.kernel, adm_deadline(), &lease)
		after := adm_metadata_snapshot(&p.kernel)
		testing.expect(t, bytes.equal(metadata, after))
		delete(metadata)
		delete(after)
		testing.expect_value(t, failure.kind, .Invalid_Config)

		if mode == 0 {
			testing.expect_value(t, failure.http.budget, .Foreign_Root)
		}

		testing.expect_value(t, lease, snapshot)
		testing.expect_value(t, p.kernel.request_free_count, free_before)
		testing.expect_value(t, p.kernel.references, references)
		scopes.release(&lease)
	}

	scopes.release_scope(&foreign_scope)
	// Empty unmanaged mode may not silently consume a foreign physical lease.
	other: Admission_Probe
	adm_init(&other, managed = false)
	lease, cause := resources_request_lease(&p.resources)
	assert(cause.kind == .None)
	original := lease
	_, cause = kernel_reserve(&other.kernel, adm_deadline(), &lease)
	testing.expect_value(t, cause.kind, .Invalid_Config)
	testing.expect_value(t, lease, original)
	scopes.release(&lease)
	adm_destroy(&other)
	// Local owner-reference overflow boundary; rejection must not wrap or move.
	lease, cause = resources_request_lease(&p.resources)
	assert(cause.kind == .None)
	original = lease
	references := p.kernel.references
	p.kernel.references = max(int)
	_, cause = kernel_reserve(&p.kernel, adm_deadline(), &lease)
	testing.expect(t, cause.kind != .None)
	testing.expect_value(t, p.kernel.references, max(int))
	testing.expect_value(t, lease, original)
	p.kernel.references = references
	scopes.release(&lease)
	adm_destroy(&p)
}

@(test)
admission_capacity_and_stale_tokens_do_not_consume_owners :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 1, waiters = 1)
	preparing, _ := adm_prepare(&p)
	lease, error := resources_request_lease(&p.resources)
	assert(error.kind == .None)
	before := lease
	_, error = kernel_reserve(&p.kernel, adm_deadline(), &lease)
	testing.expect_value(t, error.kind, .Capacity)
	testing.expect_value(t, lease, before)
	scopes.release(&lease)
	bad := preparing
	bad.request.generation += 1
	disposal, rollback_error := kernel_rollback(&p.kernel, bad)
	testing.expect_value(t, rollback_error.kind, .Invalid_Handle)
	testing.expect(t, disposal.input.storage == nil)
	alias := p.kernel
	owner := adm_clone(&p)
	input := raw_data(owner.storage)
	testing.expect_value(t, kernel_commit(&alias, preparing, &owner, adm_now()).kind, .Invalid_State)
	testing.expect_value(t, raw_data(owner.storage), input)
	request_owner_destroy(&owner)
	adm_rollback(&p, preparing)
	testing.expect_value(t, kernel_cancel(&p.kernel, preparing.request).kind, .Invalid_Handle)
	testing.expect_value(t, p.kernel.request_free_count, 1)
	adm_destroy(&p)
}

@(test)
admission_rollback_and_queued_cancel_restore_reserved_provenance :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p, requests = 2, waiters = 2)
	fresh, claim := adm_prepare(&p)
	fresh_generation := claim.session.generation
	adm_rollback(&p, fresh)
	testing.expect_value(t, p.kernel.sessions[int(claim.session.slot) - 1].state, .Free)
	testing.expect(t, p.kernel.sessions[int(claim.session.slot) - 1].generation > fresh_generation)
	initial, _ := adm_prepare(&p)
	handle := adm_commit(&p, initial)
	session := adm_activate(&p, handle)
	response := adm_response(&p)
	assert(adm_terminal(&p, handle, &response) == 1)
	assert(kernel_release(&p.kernel, handle).kind == .None)
	assert(pool_session_state(&p.kernel, session, .Idle, adm_now().at).kind == .None)

	for mode in 0 ..< 2 {
		preparing, reservation := adm_prepare(&p)
		testing.expect_value(t, reservation.session, session)

		if mode == 0 {
			adm_rollback(&p, preparing)
		} else {
			handle = adm_commit(&p, preparing)
			assert(kernel_cancel(&p.kernel, handle).kind == .None)
			empty: surf.Response
			assert(adm_terminal(&p, handle, &empty, {kind = .IO_Failed, transport = net.Connection_Error.Cancelled}) == 1)
			assert(kernel_release(&p.kernel, handle).kind == .None)
		}

		testing.expect_value(t, p.kernel.sessions[int(session.slot) - 1].state, .Idle)
		testing.expect_value(t, p.kernel.sessions[int(session.slot) - 1].generation, session.generation)
	}

	adm_retire(&p, session)
	adm_destroy(&p)
}

@(test)
admission_same_profile_kernels_have_distinct_nonreused_handle_owners :: proc(t: ^testing.T) {
	p: Admission_Probe
	adm_init(&p)
	other: Kernel
	assert(kernel_init(&other, &p.profile, &p.resources).kind == .None)
	testing.expect(t, other.owner_id != 0 && other.owner_id != p.kernel.owner_id)
	lease, error := resources_request_lease(&p.resources)
	assert(error.kind == .None)
	first, first_error := kernel_reserve(&p.kernel, adm_deadline(), &lease)
	assert(first_error.kind == .None)
	lease, error = resources_request_lease(&p.resources)
	assert(error.kind == .None)
	second, second_error := kernel_reserve(&other, adm_deadline(), &lease)
	assert(second_error.kind == .None)
	testing.expect_value(t, first.request.slot, second.request.slot)
	testing.expect_value(t, first.request.generation, second.request.generation)
	testing.expect_value(t, kernel_cancel(&other, first.request).kind, .Invalid_Handle)
	adm_rollback(&p, first)
	disposal, rollback_error := kernel_rollback(&other, second)
	assert(rollback_error.kind == .None)
	ticket := disposal.request
	request_disposal_destroy(&disposal)
	next, done, failure := kernel_cleanup_finish(&other, ticket, adm_now())
	assert(failure.kind == .None && done && next.input.storage == nil)
	previous := other.owner_id
	assert(kernel_destroy(&other).kind == .None)
	assert(kernel_init(&other, &p.profile, &p.resources).kind == .None)
	testing.expect(t, other.owner_id != previous && other.owner_id != p.kernel.owner_id)
	testing.expect_value(t, kernel_cancel(&other, second.request).kind, .Invalid_Handle)
	assert(kernel_destroy(&other).kind == .None)
	adm_destroy(&p)
}

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

@(test)
coordinator_unstarted_close_burns_queued_reserved_dns_metadata :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	config := bootstrap_config({}, 17)
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}
	config.http.resolver.name_servers = servers[:]
	state, error := network_prepare(&runtime, config, allocator)
	assert(error.kind == .None)
	handle := bootstrap_queued(state, &runtime, "http://queued.example/path")
	block, reserved := network_dns_reserve(state, 6)
	assert(reserved.kind == .None && block.count == 6)
	sync.lock(&state.mu)
	state.requests[handle.slot - 1].ids = block
	block = {}
	state.requests[handle.slot - 1].awaiting_ids = true
	state.requests[handle.slot - 1].needs_dns = true
	sync.unlock(&state.mu)
	contexts: [2]Bootstrap_Task_Context

	for task, index in state.task_index {
		contexts[index] = {
			state = state,
			task  = task,
			index = index,
		}

		task^ = {
			resume    = bootstrap_registered_resume,
			on_cancel = bootstrap_registered_cancel,
			on_done   = bootstrap_registered_done,
			data      = &contexts[index],
		}

		assert(network_state_retain(state))
	}

	sync.lock(&state.mu)
	state.registered_tasks = 2
	state.coordinator.registered = true
	state.actors[0].registered = true
	state.phase = .Published
	sync.unlock(&state.mu)
	assert(runtime_async.register_group(&runtime, state.task_index).kind == .None)
	// Real Runtime.destroy invokes on_done synchronously without ever running IO.
	assert(runtime_async.destroy(&runtime).kind == .None)
	testing.expect_value(t, state.requests[handle.slot - 1].ids.count, 0)
	testing.expect_value(t, state.requests[handle.slot - 1].awaiting_ids, false)
	testing.expect_value(t, state.dns_draws_reserved, u64(6))
	testing.expect_value(t, state.dns_draws_burned, u64(6))
	completion, available := kernel_poll(&state.kernel)
	testing.expect(t, available && completion.request == handle && completion.error.transport == net.Connection_Error.Cancelled)
	assert(kernel_release(&state.kernel, handle).kind == .None)
	fmt.printf("COORD17 unstarted_reserved_dns_burn=%d no_protocol_io=true\n", state.dns_draws_burned)
	sync.lock(&state.mu)
	state.base_owned = false
	sync.unlock(&state.mu)
	network_state_release(state)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
}

Coordinator_Test_Actor :: struct {
	actor:                                                                         ^Session_Actor,
	assignment:                                                                    Assignment,
	hold, assigned, completed, done, resumes, observed_cancel, keep_idle, retired: int,
	idle:                                                                          Cell_Handle,
	last_error:                                                                    surf.HTTP_Error,
}
Coordinator_Test_Case :: struct {
	track:     mem.Tracking_Allocator,
	allocator: mem.Allocator,
	scope:     scopes.Scope,
	runtime:   runtime_async.Runtime,
	state:     ^Client_State,
	actors:    [2]Coordinator_Test_Actor,
}
coordinator_test_finish :: proc(c: ^Coordinator_Test_Actor, error: surf.HTTP_Error) {
	s := c.actor.owner
	assignment := c.assignment
	sync.lock(&s.mu)
	keep_idle := error.kind == .None && intrinsics.atomic_load(&c.keep_idle) != 0 && s.phase == .Published

	if !keep_idle {
		assert(
			pool_session_state(&s.kernel, assignment.session, .Retiring, runtime_async.deadline_after(s.runtime, 0).at).kind ==
			.None,
		)
	}

	response: surf.Response
	// Controlled metadata actor only; this status is NOT a received HTTP result.
	if error.kind == .None {
		response.status = 200
	}

	disposal, cause := kernel_begin_complete(&s.kernel, assignment.request, &response, error)
	assert(cause.kind == .None)
	network_queue_forget_locked(s, assignment.request)
	sync.unlock(&s.mu)

	for {
		origin := disposal.origin.origin
		request_disposal_destroy(&disposal)

		if origin.slot != 0 {
			assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
		}

		now, clock := network_clock(s)
		assert(clock.kind == .None)
		next, done, failure := kernel_cleanup_finish(&s.kernel, assignment.request, now)
		assert(failure.kind == .None)
		disposal = next

		if done {
			break
		}
	}

	if keep_idle {
		sync.lock(&s.mu)
		assert(
			pool_session_state(&s.kernel, assignment.session, .Idle, runtime_async.deadline_after(s.runtime, 0).at).kind ==
			.None,
		)
		sync.unlock(&s.mu)
		c.idle = assignment.session
	} else {
		assert(pool_retire(&s.kernel, assignment.session).kind == .None)
	}

	c.last_error = error
	c.assignment = {}
	sync.lock(&s.mu)
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
	_ = signal.wake(s.coordinator.wake)
	intrinsics.atomic_add(&c.completed, 1)
}
coordinator_test_actor_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	c := cast(^Coordinator_Test_Actor)data
	a := c.actor
	s := a.owner
	sync.lock(&s.mu)
	closing := s.phase == .Closing
	cancel := a.command.cancel
	retire := a.command.retire
	pending := a.command.pending
	intrinsics.atomic_add(&c.resumes, 1)
	intrinsics.atomic_store(&c.observed_cancel, 1 if cancel else 0)

	if pending && c.assignment.request.slot == 0 && (closing || cancel) {
		c.assignment = a.command.assignment
		a.command.pending = false
	}

	sync.unlock(&s.mu)

	if pending && c.assignment.request.slot == 0 && !closing && !cancel {
		assigned, error := network_assignment_take(a)
		assert(error.kind == .None)
		c.assignment = assigned.assignment
		network_dns_burn(s, &assigned.ids)
		sync.lock(&s.mu)
		sync.lock(&s.kernel.mu)
		connecting := s.kernel.sessions[c.assignment.session.slot - 1].state == .Connecting
		sync.unlock(&s.kernel.mu)

		if connecting {
			assert(
				pool_session_state(&s.kernel, c.assignment.session, .Busy, runtime_async.deadline_after(s.runtime, 0).at).kind ==
				.None,
			)
		}

		sync.unlock(&s.mu)
		intrinsics.atomic_add(&c.assigned, 1)
	}

	if c.assignment.request.slot != 0 && (closing || cancel || intrinsics.atomic_load(&c.hold) == 0) {
		error: surf.HTTP_Error

		if closing || cancel {
			error = {
				kind = .IO_Failed,
				transport = net.Connection_Error.Cancelled,
				phase = .Cancellation,
				write_effect = .Not_Sent,
			}
		}

		coordinator_test_finish(c, error)
	}

	if (retire || closing) && c.idle.slot != 0 {
		sync.lock(&s.mu)
		sync.lock(&s.kernel.mu)
		state := s.kernel.sessions[c.idle.slot - 1].state
		sync.unlock(&s.kernel.mu)

		if state == .Idle {
			assert(
				pool_session_state(&s.kernel, c.idle, .Retiring, runtime_async.deadline_after(s.runtime, 0).at).kind ==
				.None,
			)
		}

		a.command.retire = false
		sync.unlock(&s.mu)
		assert(pool_retire(&s.kernel, c.idle).kind == .None)
		c.idle = {}
		intrinsics.atomic_add(&c.retired, 1)
		sync.lock(&s.mu)
		network_queue_changed_locked(s)
		sync.unlock(&s.mu)
		_ = signal.wake(s.coordinator.wake)
	}

	if closing {
		a.owner_drained = true
		return .Done
	}

	return .Waiting
}
coordinator_test_actor_cancel :: proc(data: rawptr) -> runtime_async.Resume_Result {
	c := cast(^Coordinator_Test_Actor)data
	sync.lock(&c.actor.owner.mu)
	c.actor.owner.phase = .Closing
	sync.unlock(&c.actor.owner.mu)

	return coordinator_test_actor_resume(data)
}
coordinator_test_actor_done :: proc(data: rawptr) {
	c := cast(^Coordinator_Test_Actor)data
	s, index, drained := c.actor.owner, c.actor.index, c.actor.owner_drained
	network_task_done(s, int(index), drained)
	intrinsics.atomic_store(&c.done, 1)
}
coordinator_test_init :: proc(
	c: ^Coordinator_Test_Case,
	dns: int = 0,
	connections: int = 1,
	idle_timeout: time.Duration = 0,
	requests: int = 4,
	lifetime: time.Duration = 0,
) {
	mem.tracking_allocator_init(&c.track, rt.heap_allocator(), rt.heap_allocator())
	c.allocator = mem.tracking_allocator(&c.track)
	scope, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, c.allocator)
	assert(error == .None)
	c.scope = scope
	bootstrap_runtime(&c.runtime)
	config := bootstrap_config(scope, dns)
	if idle_timeout > 0 {
		config.idle_timeout = idle_timeout
	}
	if lifetime > 0 {
		config.lifetime = runtime_async.deadline_after(&c.runtime, lifetime)
	}
	config.capacities.requests = requests
	config.capacities.origins = 4
	config.capacities.connections = connections
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}
	if dns > 0 {
		config.http.resolver.name_servers = servers[:]
	}
	state, cause := network_prepare(&c.runtime, config, c.allocator)
	assert(cause.kind == .None)
	c.state = state
	state.coordinator.task = {
		data      = &state.coordinator,
		resume    = network_coordinator_resume,
		on_cancel = network_coordinator_cancel,
		on_done   = network_coordinator_done,
	}
	for &actor, index in state.actors {
		actor_context := &c.actors[index]
		actor_context.actor = &actor
		actor.task = {
			data      = actor_context,
			resume    = coordinator_test_actor_resume,
			on_cancel = coordinator_test_actor_cancel,
			on_done   = coordinator_test_actor_done,
		}

		actor.registered = true
		assert(network_state_retain(state))
	}
	assert(network_state_retain(state))
	state.coordinator.registered = true
	state.registered_tasks = len(state.task_index)
	state.phase = .Published
	assert(runtime_async.register_group(&c.runtime, state.task_index).kind == .None)
	assert(runtime_async.start(&c.runtime).kind == .None)
}
coordinator_test_admit :: proc(c: ^Coordinator_Test_Case, url: string, duration: time.Duration) -> Request_Handle {
	s := c.state
	now := runtime_async.deadline_after(&c.runtime, 0)
	lease, error := resources_request_lease(&s.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(&s.kernel, runtime_async.deadline_after(&c.runtime, duration), &lease)
	assert(cause.kind == .None)
	origin, prepared := origin_prepare(&s.profile, url, s.resources.allocator)
	assert(prepared.kind == .None)
	_, claim := network_queue_claim(s, preparing, &origin, now.at)
	origin_destroy(&origin)
	assert(claim.kind == .None)
	input, cloned := request_clone({method = .GET, url = url}, s.resources.allocator)
	assert(cloned.kind == .None)
	sync.lock(&s.mu)
	committed := network_queue_committed_locked(s, preparing, &input, runtime_async.deadline_after(&c.runtime, 0))
	sync.unlock(&s.mu)
	assert(committed.kind == .None && input.storage == nil)
	_ = signal.wake(s.coordinator.wake)

	return preparing.request
}
coordinator_test_wait :: proc(c: ^Coordinator_Test_Case) -> Completion {
	start := time.tick_now()

	for time.tick_since(start) < 3 * time.Second {
		completion, ready := kernel_poll(&c.state.kernel)

		if ready {
			return completion
		}

		time.sleep(time.Millisecond)
	}

	panic("coordinator completion watchdog")
}
coordinator_test_destroy :: proc(c: ^Coordinator_Test_Case) {
	s := c.state
	sync.lock(&s.mu)
	s.phase = .Closing
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
	_ = signal.wake(s.coordinator.wake)

	for actor in s.actors {
		_ = signal.wake(actor.wake)
	}

	start := time.tick_now()

	for {
		sync.lock(&s.mu)
		done := s.registered_tasks == 0 && s.references == 1
		sync.unlock(&s.mu)

		if done {
			break
		}

		assert(time.tick_since(start) < 3 * time.Second, "coordinator shutdown watchdog")
		time.sleep(time.Millisecond)
	}

	assert(runtime_async.wait_idle(&c.runtime).kind == .None)
	assert(runtime_async.destroy(&c.runtime).kind == .None)
	sync.lock(&s.mu)
	s.base_owned = false
	sync.unlock(&s.mu)
	network_state_release(s)
	testing_snapshot, error := scopes.snapshot(c.scope)
	assert(error == .None && testing_snapshot.used == (scopes.Usage{}))
	scopes.release_scope(&c.scope)
	assert(c.track.current_memory_allocated == 0 && len(c.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&c.track)
}

@(test)
coordinator_parked_bankempty_requests_expire_without_connection_claim :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	request := coordinator_test_admit(&c, "http://needs-dns.example/path", 30 * time.Millisecond)
	sync.lock(&c.state.mu)
	sync.lock(&c.state.kernel.mu)
	testing.expect_value(t, c.state.kernel.requests[request.slot - 1].stage, .Awaiting_DNS_IDs)
	testing.expect_value(t, c.state.kernel.counters.reserved_connections, 0)
	testing.expect_value(t, c.state.kernel.counters.connecting_connections, 0)
	sync.unlock(&c.state.kernel.mu)
	sync.unlock(&c.state.mu)
	completed := coordinator_test_wait(&c)
	testing.expect(
		t,
		completed.request == request &&
		completed.error.kind == .Deadline_Failed &&
		completed.error.write_effect == .Not_Sent,
	)
	assert(kernel_release(&c.state.kernel, request).kind == .None)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_empty_bank_rejects_hostname_and_admits_numeric :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c, 1)
	initial, removed := network_dns_reserve(c.state, 1)
	assert(removed.kind == .None)
	network_dns_burn(c.state, &initial)
	s := c.state
	url := "http://refill.example/path"
	now := runtime_async.deadline_after(&c.runtime, 0)
	lease, error := resources_request_lease(&s.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(
		&s.kernel,
		runtime_async.deadline_after(&c.runtime, 30 * time.Second),
		&lease,
	)
	assert(cause.kind == .None)
	origin, prepared := origin_prepare(&s.profile, url, s.resources.allocator)
	assert(prepared.kind == .None)
	started := time.tick_now()
	_, claim := network_queue_claim(s, preparing, &origin, now.at)
	origin_destroy(&origin)
	testing.expect(t, time.tick_since(started) < 2 * time.Second)
	testing.expect_value(t, claim.kind, .Capacity)
	testing.expect_value(t, claim.http.kind, .Dial_Failed)
	testing.expect_value(t, claim.http.phase, .DNS)
	testing.expect_value(t, claim.http.write_effect, .Not_Sent)
	testing.expect_value(
		t,
		claim.http.network,
		net.Network_Error(net.Resolve_Error.Unable_To_Resolve),
	)
	sync.lock(&s.mu)
	disposal, rolled := kernel_rollback(&s.kernel, preparing)
	assert(rolled.kind == .None)
	network_queue_forget_locked(s, preparing.request)
	sync.unlock(&s.mu)
	held := disposal.origin.origin
	request_disposal_destroy(&disposal)

	if held.slot != 0 {
		assert(kernel_origin_cleanup_finish(&s.kernel, held).kind == .None)
	}

	next, done, finish := kernel_cleanup_finish(&s.kernel, preparing.request, now)
	assert(finish.kind == .None && done)
	request_disposal_destroy(&next)
	ready := coordinator_test_admit(&c, "http://127.0.0.1/cheap", time.Second)
	completion := coordinator_test_wait(&c)
	testing.expect(t, completion.request == ready && completion.error.kind == .None)
	assert(kernel_release(&c.state.kernel, ready).kind == .None)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_cancellation_of_parked_waiter_preserves_terminal_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	request := coordinator_test_admit(&c, "http://cancel.example/path", time.Second)
	sync.lock(&c.state.mu)
	assert(kernel_cancel(&c.state.kernel, request).kind == .None)
	network_queue_changed_locked(c.state)
	sync.unlock(&c.state.mu)
	_ = signal.wake(c.state.coordinator.wake)
	completed := coordinator_test_wait(&c)
	testing.expect(
		t,
		completed.request == request &&
		completed.error.transport == net.Connection_Error.Cancelled &&
		completed.error.phase == .Cancellation,
	)
	_, again := kernel_poll(&c.state.kernel)
	testing.expect(t, !again)
	assert(kernel_release(&c.state.kernel, request).kind == .None)
	coordinator_test_destroy(&c)
}

Coordinator_Test_Producer :: struct {
	state:         ^Client_State,
	stop, changes: int,
}
coordinator_test_produce_changes :: proc(p: ^Coordinator_Test_Producer) {
	for intrinsics.atomic_load(&p.stop) == 0 {
		sync.lock(&p.state.mu)
		network_queue_changed_locked(p.state)
		sync.unlock(&p.state.mu)
		_ = signal.wake(p.state.coordinator.wake)
		intrinsics.atomic_add(&p.changes, 1)
		time.sleep(100 * time.Microsecond)
	}
}

@(test)
coordinator_work1_persistent_cursor_expires_behind_continuous_changes :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	sync.lock(&c.state.mu)
	c.state.coordinator.request_cursor = 1
	c.state.coordinator.dns_cursor = 2
	network_queue_changed_locked(c.state)
	testing.expect_value(t, c.state.coordinator.request_cursor, u32(1))
	testing.expect_value(t, c.state.coordinator.dns_cursor, u32(2))
	sync.unlock(&c.state.mu)
	request := coordinator_test_admit(&c, "http://behind-cursor.example/path", 30 * time.Millisecond)
	producer := Coordinator_Test_Producer {
		state = c.state,
	}

	worker := thread.create_and_start_with_poly_data(&producer, coordinator_test_produce_changes)
	assert(worker != nil)
	completion: Completion
	ready := false
	start := time.tick_now()

	for time.tick_since(start) < 500 * time.Millisecond {
		completion, ready = kernel_poll(&c.state.kernel)

		if ready {
			break
		}

		time.sleep(time.Millisecond)
	}

	// The producer was still changing scan state when the terminal was observed.
	changes := intrinsics.atomic_load(&producer.changes)
	intrinsics.atomic_store(&producer.stop, 1)
	thread.join(worker)
	thread.destroy(worker)
	testing.expect(t, ready && changes > 0)

	if !ready {
		completion = coordinator_test_wait(&c)
	}

	testing.expect(t, completion.request == request && completion.error.kind == .Deadline_Failed)
	assert(kernel_release(&c.state.kernel, request).kind == .None)
	fmt.printf("COORD17 persistent_cursor_expired_during_changes=%v producer_changes=%d\n", ready, changes)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_numeric_progress_bypasses_bankempty_named_queue :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	blocked := coordinator_test_admit(&c, "http://bankempty.example/path", time.Second)
	ready := coordinator_test_admit(&c, "http://127.0.0.1/cheap", time.Second)
	completion := coordinator_test_wait(&c)
	testing.expect(t, completion.request == ready && completion.error.kind == .None)
	sync.lock(&c.state.mu)
	sync.lock(&c.state.kernel.mu)
	testing.expect_value(t, c.state.kernel.requests[blocked.slot - 1].state, .Queued)
	testing.expect_value(t, c.state.kernel.requests[blocked.slot - 1].stage, .Awaiting_DNS_IDs)
	testing.expect_value(t, c.state.kernel.requests[blocked.slot - 1].session, Cell_Handle{})
	sync.unlock(&c.state.kernel.mu)
	assert(kernel_cancel(&c.state.kernel, blocked).kind == .None)
	network_queue_changed_locked(c.state)
	sync.unlock(&c.state.mu)
	_ = signal.wake(c.state.coordinator.wake)
	cancelled := coordinator_test_wait(&c)
	testing.expect(t, cancelled.request == blocked && cancelled.error.transport == net.Connection_Error.Cancelled)
	assert(kernel_release(&c.state.kernel, ready).kind == .None)
	assert(kernel_release(&c.state.kernel, blocked).kind == .None)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_active_expiry_wakes_owner_without_forging_explicit_cancel :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	intrinsics.atomic_store(&c.actors[0].hold, 1)
	request := coordinator_test_admit(&c, "http://127.0.0.1/held", 30 * time.Millisecond)
	start := time.tick_now()

	for intrinsics.atomic_load(&c.actors[0].assigned) == 0 {
		assert(time.tick_since(start) < time.Second)
		time.sleep(time.Millisecond)
	}

	time.sleep(40 * time.Millisecond)
	intrinsics.atomic_store(&c.actors[0].observed_cancel, -1)
	sync.lock(&c.state.mu)
	network_queue_changed_locked(c.state)
	sync.unlock(&c.state.mu)
	_ = signal.wake(c.state.coordinator.wake)
	start = time.tick_now()

	for intrinsics.atomic_load(&c.actors[0].observed_cancel) == -1 {
		assert(time.tick_since(start) < time.Second, "expired Active actor was not woken")
		time.sleep(time.Millisecond)
	}

	testing.expect_value(t, intrinsics.atomic_load(&c.actors[0].observed_cancel), 0)
	intrinsics.atomic_store(&c.actors[0].hold, 0)
	_ = signal.wake(c.state.actors[0].wake)
	completed := coordinator_test_wait(&c)
	testing.expect(t, completed.request == request && completed.error.kind == .Deadline_Failed)
	assert(kernel_release(&c.state.kernel, request).kind == .None)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_idle_deadline_retires_metadata_owner_without_new_notification :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c, 0, 1, 20 * time.Millisecond)
	intrinsics.atomic_store(&c.actors[0].keep_idle, 1)
	request := coordinator_test_admit(&c, "http://127.0.0.1/idle", time.Second)
	completed := coordinator_test_wait(&c)
	testing.expect(t, completed.request == request && completed.error.kind == .None)
	assert(kernel_release(&c.state.kernel, request).kind == .None)
	start := time.tick_now()

	for intrinsics.atomic_load(&c.actors[0].retired) == 0 {
		assert(time.tick_since(start) < time.Second, "idle timer lost without external wake")
		time.sleep(time.Millisecond)
	}

	sync.lock(&c.state.mu)
	sync.lock(&c.state.kernel.mu)
	testing.expect_value(t, c.state.kernel.counters.idle_connections, 0)
	testing.expect_value(t, c.state.kernel.counters.retiring_connections, 0)
	testing.expect_value(t, c.state.kernel.session_free_count, 1)
	sync.unlock(&c.state.kernel.mu)
	sync.unlock(&c.state.mu)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_immutable_lifetime_closes_unassigned_task_group_without_external_wake :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c, 0, 2, 0, 3, 100 * time.Millisecond)
	// No request/idle/request timer exists. The Client cap itself must wake the
	// coordinator, and its Closing transition must notify every unassigned owner.
	_ = signal.wake(c.state.coordinator.wake)
	ended := false
	start := time.tick_now()

	for time.tick_since(start) < 500 * time.Millisecond {
		sync.lock(&c.state.mu)
		ended = c.state.registered_tasks == 0 && c.state.references == 1
		sync.unlock(&c.state.mu)

		if ended {
			break
		}

		time.sleep(time.Millisecond)
	}

	testing.expect(t, ended, "immutable Client cap did not wake and retire unassigned actors")
	fmt.printf("COORD17 no_request_lifetime_group_retired=%v\n", ended)
	coordinator_test_destroy(&c)
}

@(test)
coordinator_commit_dns_stage_is_atomic_and_rejection_keeps_input :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	c: Coordinator_Test_Case
	coordinator_test_init(&c)
	s := c.state
	url := "http://atomic-dns.example/path"
	now := runtime_async.deadline_after(&c.runtime, 0)
	lease, error := resources_request_lease(&s.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(&s.kernel, runtime_async.deadline_after(&c.runtime, time.Second), &lease)
	assert(cause.kind == .None)
	origin, ready := origin_prepare(&s.profile, url, s.resources.allocator)
	assert(ready.kind == .None)
	_, claimed := network_queue_claim(s, preparing, &origin, now.at)
	origin_destroy(&origin)
	assert(claimed.kind == .None)
	input, cloned := request_clone({method = .GET, url = url}, s.resources.allocator)
	assert(cloned.kind == .None)
	pointer, length := raw_data(input.storage), len(input.storage)
	sync.lock(&s.mu)
	metadata := &s.requests[preparing.request.slot - 1]
	metadata.generation += 1
	rejected := network_queue_committed_locked(s, preparing, &input, runtime_async.deadline_after(&c.runtime, 0))
	testing.expect_value(t, rejected.kind, .Invalid_State)
	testing.expect_value(t, raw_data(input.storage), pointer)
	testing.expect_value(t, len(input.storage), length)
	sync.lock(&s.kernel.mu)
	testing.expect_value(t, s.kernel.requests[preparing.request.slot - 1].state, .Preparing)
	sync.unlock(&s.kernel.mu)
	metadata.generation = preparing.request.generation
	accepted := network_queue_committed_locked(s, preparing, &input, runtime_async.deadline_after(&c.runtime, 0))
	assert(accepted.kind == .None)
	testing.expect(t, input.storage == nil && metadata.awaiting_ids)
	sync.lock(&s.kernel.mu)
	testing.expect_value(t, s.kernel.requests[preparing.request.slot - 1].state, .Queued)
	testing.expect_value(t, s.kernel.requests[preparing.request.slot - 1].stage, .Awaiting_DNS_IDs)
	sync.unlock(&s.kernel.mu)
	assert(kernel_cancel(&s.kernel, preparing.request).kind == .None)
	network_queue_changed_locked(s)
	sync.unlock(&s.mu)
	_ = signal.wake(s.coordinator.wake)
	completed := coordinator_test_wait(&c)
	testing.expect(t, completed.request == preparing.request && completed.error.transport == net.Connection_Error.Cancelled)
	assert(kernel_release(&s.kernel, preparing.request).kind == .None)
	coordinator_test_destroy(&c)
}

Ownership_Fault :: struct {
	backing:                   mem.Allocator,
	at, calls, mode, returned: int,
	triggered:                 bool,
	whole, reported:           []u8,
	on_free:                   proc(_: rawptr),
	user:                      rawptr,
}
ownership_allocate :: proc(
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
	f := cast(^Ownership_Fault)data
	if mode == .Free && old_memory != nil {
		if callback := f.on_free; callback != nil {
			f.on_free = nil
			callback(f.user)
		}

		if old_memory == raw_data(f.reported) {
			assert(old_size == len(f.reported))
			whole := f.whole
			f.whole = nil
			f.reported = nil
			f.returned += 1
			return f.backing.procedure(f.backing.data, .Free, 0, alignment, raw_data(whole), len(whole), location)
		}
	}
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
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
ownership_usage :: proc(scope: scopes.Scope) -> scopes.Snapshot {
	value, error := scopes.snapshot(scope)
	assert(error == .None)

	return value
}
ownership_config :: proc() -> Normalized_Config {
	caps := Capacities {
		requests               = 2,
		origins                = 2,
		connections            = 2,
		connections_per_origin = 2,
		waiters_per_origin     = 1,
		dns_ids                = 0,
		work_per_resume        = 1,
	}

	config, error := config_normalize({capacities = caps})
	assert(error.kind == .None)

	return config
}
ownership_inside :: proc(storage: []u8, p: rawptr, size: int) -> bool {
	if size == 0 {
		return true
	}

	start, at := uintptr(raw_data(storage)), uintptr(p)

	return at >= start && at - start <= uintptr(len(storage)) && uintptr(size) <= uintptr(len(storage)) - (at - start)
}

@(test)
ownership_request_clone_is_aligned_deep_and_rejection_atomic :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	url: [64]u8
	url_text := "https://example.test/path?q=1"
	copy(url[:], transmute([]u8)url_text)
	name := [4]u8{'X', '-', 'O', 'k'}
	value := [3]u8{'y', 'e', 's'}
	body := [3]u8{'a', 'b', 'c'}
	headers := [1]http.Header{{string(name[:]), string(value[:])}}
	request := http.Request {
		method  = .POST,
		url     = string(url[:len(url_text)]),
		headers = headers[:],
		body    = body[:],
	}

	source_url, source_name, source_value, source_body := url, name, value, body
	owner, error := request_clone(request, allocator)
	assert(error.kind == .None)
	testing.expect(
		t,
		bytes.equal(url[:], source_url[:]) &&
		bytes.equal(name[:], source_name[:]) &&
		bytes.equal(value[:], source_value[:]) &&
		bytes.equal(body[:], source_body[:]),
	)
	testing.expect(t, uintptr(raw_data(owner.request.headers)) % align_of(http.Header) == 0)
	testing.expect(t, ownership_inside(owner.storage, raw_data(owner.request.headers), size_of(http.Header)))
	testing.expect(t, ownership_inside(owner.storage, raw_data(owner.request.url), len(owner.request.url)))
	testing.expect(
		t,
		ownership_inside(owner.storage, raw_data(owner.request.headers[0].name), len(owner.request.headers[0].name)),
	)
	testing.expect(
		t,
		ownership_inside(owner.storage, raw_data(owner.request.headers[0].value), len(owner.request.headers[0].value)),
	)
	testing.expect(t, ownership_inside(owner.storage, raw_data(owner.request.body), len(owner.request.body)))
	url[0] = 'x'
	name[0] = 'z'
	value[0] = 'n'
	body[0] = 'z'
	headers[0] = {"Changed", "changed"}
	testing.expect_value(t, owner.request.url, url_text)
	testing.expect_value(t, owner.request.headers[0], http.Header{"X-Ok", "yes"})
	testing.expect_value(t, string(owner.request.body), "abc")
	request_owner_destroy(&owner)
	request_owner_destroy(&owner)
	testing.expect(
		t,
		owner.storage == nil &&
		owner.request.body == nil &&
		track.current_memory_allocated == 0 &&
		len(track.bad_free_array) == 0,
	)
	// Invalid input is rejected before any allocator call and never retained.
	for invalid in ([]http.Request {
			{method = cast(http.Method)99, url = "https://example.test"},
			{method = .GET, url = "not a URL"},
			{method = .GET, url = "https://example.test", body = []u8{'x'}},
			{method = .GET, url = "https://example.test", headers = {{"X", "bad\r\nvalue"}}},
		}) {
		f := Ownership_Fault {
			backing = allocator,
		}
		a := mem.Allocator{ownership_allocate, &f}
		rejected, cause := request_clone(invalid, a)
		testing.expect(
			t,
			cause.kind != .None && rejected.storage == nil && f.calls == 0 && track.current_memory_allocated == 0,
		)
	}
}

@(test)
ownership_clone_and_kernel_ctor_all_grants_roll_back :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	request := http.Request {
		method  = .POST,
		url     = "https://example.test/path",
		headers = {{"X", "yes"}},
		body    = []u8{'a', 'b', 'c'},
	}

	clone_points := 0
	healthy := Ownership_Fault {
		backing = a,
	}

	owner, error := request_clone(request, {ownership_allocate, &healthy})
	assert(error.kind == .None)
	clone_points = healthy.calls
	assert(clone_points > 0)
	request_owner_destroy(&owner)
	assert(track.current_memory_allocated == 0)

	for at in 1 ..= clone_points {
		for mode in 0 ..< 6 {
			f := Ownership_Fault {
				backing = a,
				at      = at,
				mode    = mode,
			}

			failed, cause := request_clone(request, {ownership_allocate, &f})
			testing.expect(t, cause.kind != .None && failed.storage == nil && f.triggered && f.whole == nil)
			testing.expect_value(t, f.returned, 0 if mode < 2 else 1)
			testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
			testing.expect(
				t,
				request.url == "https://example.test/path" &&
				request.headers[0].value == "yes" &&
				string(request.body) == "abc",
			)
		}
	}

	profile: Profile
	assert(profile_init(&profile, ownership_config(), a).kind == .None)
	baseline := track.current_memory_allocated
	healthy = {
		backing = a,
	}

	resources: Kernel_Resources
	assert(resources_init(&resources, {}, {ownership_allocate, &healthy}).kind == .None)
	kernel: Kernel
	assert(kernel_init(&kernel, &profile, &resources).kind == .None)
	kernel_points := healthy.calls
	assert(kernel_points > 0)
	assert(kernel_destroy(&kernel).kind == .None)
	resources_destroy(&resources)
	assert(track.current_memory_allocated == baseline)

	for at in 1 ..= kernel_points {
		for mode in 0 ..< 6 {
			f := Ownership_Fault {
				backing = a,
				at      = at,
				mode    = mode,
			}

			assert(resources_init(&resources, {}, {ownership_allocate, &f}).kind == .None)
			cause := kernel_init(&kernel, &profile, &resources)
			testing.expect(
				t,
				cause.kind != .None &&
				kernel.self == nil &&
				kernel.requests == nil &&
				kernel.origins == nil &&
				kernel.sessions == nil,
			)
			testing.expect(t, f.triggered && f.whole == nil && f.returned == (0 if mode < 2 else 1))
			// Check before fixture teardown: no destructor can hide an unpublished grant.
			testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)
			resources_destroy(&resources)
		}
	}

	profile_destroy(&profile)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	fmt.printf(
		"OWNERSHIP07 unmanaged clone_points=%d kernel_points=%d fault_cells=%d\n",
		clone_points,
		kernel_points,
		6 * (clone_points + kernel_points),
	)
}

@(test)
ownership_managed_backing_malformed_grants_do_not_retain_charges :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	scope, error := scopes.create_root({bytes = 1 << 20, streams = 2}, a)
	assert(error == .None)
	profile: Profile
	assert(profile_init(&profile, ownership_config(), a).kind == .None)
	baseline := track.current_memory_allocated
	healthy := Ownership_Fault {
		backing = a,
	}

	resources: Kernel_Resources
	assert(resources_init(&resources, scope, {ownership_allocate, &healthy}).kind == .None)
	owner, cause := request_clone({method = .GET, url = "https://example.test"}, resources.allocator)
	assert(cause.kind == .None)
	clone_points := healthy.calls
	request_owner_destroy(&owner)
	kernel: Kernel
	assert(kernel_init(&kernel, &profile, &resources).kind == .None)
	kernel_points := healthy.calls - clone_points
	assert(kernel_destroy(&kernel).kind == .None)
	resources_destroy(&resources)
	assert(track.current_memory_allocated == baseline && ownership_usage(scope).used == (scopes.Usage{}))

	for constructor in 0 ..< 2 {
		points := clone_points if constructor == 0 else kernel_points
		assert(points > 0)

		for at in 1 ..= points {
			for mode in 0 ..< 6 {
				f := Ownership_Fault {
					backing = a,
					at      = at,
					mode    = mode,
				}

				assert(resources_init(&resources, scope, {ownership_allocate, &f}).kind == .None)
				failure: Client_Error

				if constructor == 0 {
					owner, failure = request_clone({method = .GET, url = "https://example.test"}, resources.allocator)
				} else {
					failure = kernel_init(&kernel, &profile, &resources)
				}

				testing.expect(
					t,
					failure.kind == .Allocation_Failed &&
					owner.storage == nil &&
					kernel.self == nil &&
					f.triggered &&
					f.whole == nil,
				)
				testing.expect(
					t,
					f.returned == (0 if mode < 2 else 1) && ownership_usage(scope).used == (scopes.Usage{}),
				)
				testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)
				resources_destroy(&resources)
			}
		}
	}

	profile_destroy(&profile)
	scopes.release_scope(&scope)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	fmt.printf(
		"OWNERSHIP07 managed clone_points=%d kernel_points=%d fault_cells=%d\n",
		clone_points,
		kernel_points,
		6 * (clone_points + kernel_points),
	)
}

@(test)
ownership_resources_scope_and_existing_binding_are_exact :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	root, error := scopes.create_root({bytes = 1 << 20, streams = 1}, a)
	assert(error == .None)
	child, ce := scopes.create_child(root, {bytes = 1 << 19, streams = 1})
	assert(ce == .None)
	sibling, se := scopes.create_child(root, {bytes = 1 << 19, streams = 1})
	assert(se == .None)
	foreign_scope, fe := scopes.create_root({bytes = 1 << 20, streams = 1}, a)
	assert(fe == .None)
	binding, be := charged.create(child, {backing = a, metadata_allocator = a})
	assert(be.kind == .None)
	managed := charged.allocator(binding)
	resources: Kernel_Resources
	assert(resources_init(&resources, root, managed).kind == .None)
	testing.expect(t, resources.allocator.procedure == managed.procedure && resources.allocator.data == managed.data)
	lease, admission := resources_request_lease(&resources)
	assert(admission.kind == .None)
	testing.expect_value(t, ownership_usage(root).used.streams, u64(1))
	_, rejected := resources_request_lease(&resources)
	testing.expect(t, rejected.kind == .Budget_Rejected && rejected.http.budget == .Limit_Exceeded)
	bytes, allocation := mem.alloc_bytes(37, 8, resources.allocator)
	assert(allocation == nil)
	info, known := charged.allocation_info(resources.allocator, raw_data(bytes))
	assert(known)
	testing.expect_value(t, ownership_usage(root).used.bytes, info.backing_bytes)
	testing.expect_value(t, ownership_usage(child).used.bytes, info.backing_bytes)
	testing.expect_value(t, charged.stats(binding).allocations, u64(1))
	scopes.release(&lease)
	resources_destroy(&resources)
	delete(bytes, managed)
	testing.expect_value(t, ownership_usage(root).used, scopes.Usage{})

	for invalid in ([2]scopes.Scope{sibling, foreign_scope}) {
		failure := resources_init(&resources, invalid, managed)
		testing.expect(t, failure.kind == .Invalid_Config && resources.self == nil)
	}

	// A root-bound allocator cannot claim child coverage; the child-bound view can
	// cover an ancestor. These directions are intentionally different.
	ancestor, ae := charged.create(root, {backing = a, metadata_allocator = a})
	assert(ae.kind == .None)
	failure := resources_init(&resources, child, charged.allocator(ancestor))
	testing.expect(t, failure.kind == .Invalid_Config && resources.self == nil)
	charged.release(&ancestor)
	assert(resources_init(&resources, {}, managed).kind == .None)
	charged.release(&binding)
	// Scope0 still retains the existing Binding's allocator view.
	bytes, allocation = mem.alloc_bytes(11, 8, resources.allocator)
	assert(allocation == nil)
	delete(bytes, resources.allocator)
	resources_destroy(&resources)
	binding, be = charged.create(child, {backing = a, metadata_allocator = a})
	assert(be.kind == .None)
	assert(scopes.close(child) == .None)

	for configured in ([3]scopes.Scope{child, root, {}}) {
		failure = resources_init(&resources, configured, charged.allocator(binding))
		testing.expect(t, failure.kind == .Budget_Rejected && failure.http.budget == .Closed && resources.self == nil)
		resources_destroy(&resources)
	}

	charged.release(&binding)
	scopes.release_scope(&child)
	scopes.release_scope(&sibling)
	scopes.release_scope(&foreign_scope)
	scopes.release_scope(&root)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
}

@(test)
ownership_managed_constructor_and_clone_preserve_typed_budget_causes :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	profile: Profile
	assert(profile_init(&profile, ownership_config(), a).kind == .None)

	for closed in ([2]bool{false, true}) {
		limit: u64 = 0

		if closed {
			limit = 1 << 20
		}

		scope, error := scopes.create_root({bytes = limit, streams = 1}, a)
		assert(error == .None)
		resources: Kernel_Resources
		assert(resources_init(&resources, scope, a).kind == .None)
		kernel: Kernel

		if closed {
			assert(kernel_init(&kernel, &profile, &resources).kind == .None)
			assert(kernel_destroy(&kernel).kind == .None)
			assert(scopes.close(scope) == .None)
		}

		baseline := track.current_memory_allocated
		want := scopes.Error.Closed if closed else scopes.Error.Limit_Exceeded
		failure := kernel_init(&kernel, &profile, &resources)
		testing.expect(t, failure.kind == .Budget_Rejected && failure.http.budget == want && kernel.self == nil)
		owner, cause := request_clone({method = .GET, url = "https://example.test"}, resources.allocator)
		testing.expect(t, cause.kind == .Budget_Rejected && cause.http.budget == want && owner.storage == nil)
		snapshot := ownership_usage(scope)
		testing.expect(
			t,
			snapshot.used == (scopes.Usage{}) && snapshot.rejected > 0 && track.current_memory_allocated == baseline,
		)
		resources_destroy(&resources)
		scopes.release_scope(&scope)
	}

	profile_destroy(&profile)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
}

Ownership_Probe :: struct {
	kernel:          ^Kernel,
	request:         ^Request_Owner,
	allocator:       mem.Allocator,
	scope:           scopes.Scope,
	calls:           int,
	physical_header: bool,
}
ownership_free_probe :: proc(data: rawptr) {
	p := cast(^Ownership_Probe)data
	p.calls += 1

	if p.kernel != nil {
		if p.physical_header {
			assert(p.kernel.self == nil)
			assert(kernel_destroy(p.kernel).kind != .None)
			free(p.kernel, p.allocator)
			p.kernel = nil
		} else {
			assert(sync.try_lock(&p.kernel.mu))
			sync.unlock(&p.kernel.mu)
			assert(p.kernel.references > 1 && kernel_destroy(p.kernel).kind != .None)
		}
	}

	if p.request != nil {
		assert(p.request.storage == nil)
		request_owner_destroy(p.request)
		free(p.request, p.allocator)
		p.request = nil
	}

	if p.scope != (scopes.Scope{}) {
		usage := ownership_usage(p.scope)
		assert(usage.used.bytes > 0 && usage.used.streams == 1)
	}
}

@(test)
ownership_kernel_stable_cells_and_origin_physical_retirement :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	profile: Profile
	resources: Kernel_Resources
	kernel: Kernel
	assert(profile_init(&profile, ownership_config(), a).kind == .None)
	assert(resources_init(&resources, {}, a).kind == .None)
	assert(kernel_init(&kernel, &profile, &resources).kind == .None)
	testing.expect(t, kernel.self == &kernel && kernel.owner_id != 0 && kernel.references == 1)
	testing.expect(
		t,
		kernel.request_free_count == 2 && kernel.origin_free_count == 2 && kernel.session_free_count == 2,
	)

	for slot in kernel.requests {
		testing.expect(t, slot.state == .Free && slot.generation == 1)
	}

	for slot in kernel.origins {
		testing.expect(t, slot.state == .Free && slot.generation == 1)
	}

	for slot in kernel.sessions {
		testing.expect(t, slot.state == .Free && slot.generation == 1)
	}

	requests, origins, sessions := raw_data(kernel.requests), raw_data(kernel.origins), raw_data(kernel.sessions)
	testing.expect(
		t,
		kernel_init(&kernel, &profile, &resources).kind != .None &&
		raw_data(kernel.requests) == requests &&
		raw_data(kernel.origins) == origins &&
		raw_data(kernel.sessions) == sessions,
	)
	copied := kernel
	testing.expect(t, kernel_destroy(&copied).kind != .None && kernel.self == &kernel)

	for exhausted in ([2]bool{false, true}) {
		// Seed one legitimate Occupied origin to isolate the shared retain/release
		// module before later admission/pool writers exist. No request is fabricated.
		index := kernel.origin_free[kernel.origin_free_count - 1]
		kernel.origin_free_count -= 1
		kernel.origin_free[kernel.origin_free_count] = 0
		generation := kernel.origins[index - 1].generation

		if exhausted {
			generation = max(u64)
		}

		f := Ownership_Fault {
			backing = a,
		}

		origin, error := origin_prepare(&profile, "https://example.test", {ownership_allocate, &f})
		assert(error.kind == .None)
		kernel.origins[index - 1] = {
			generation = generation,
			state      = .Occupied,
			owner      = origin,
			requests   = 1,
		}

		origin = {}
		kernel.counters.origins += 1
		handle := Cell_Handle{index, generation}
		sync.lock(&kernel.mu)

		for reference in ([3]Origin_Reference{.Session, .Preparing, .Waiter}) {
			assert(kernel_origin_retain_locked(&kernel, handle, reference).kind == .None)
		}

		for reference in ([3]Origin_Reference{.Request, .Session, .Preparing}) {
			disposal, disposal_error := kernel_origin_release_locked(&kernel, handle, reference)
			assert(disposal_error.kind == .None && disposal.owner.storage == nil)
		}

		disposal, release_error := kernel_origin_release_locked(&kernel, handle, .Waiter)
		assert(release_error.kind == .None)
		sync.unlock(&kernel.mu)
		testing.expect(
			t,
			kernel.origins[index - 1].state == .Returning &&
			kernel.origins[index - 1].owner.storage == nil &&
			kernel.references == 2,
		)
		testing.expect(t, kernel_destroy(&kernel).kind != .None)
		probe := Ownership_Probe {
			kernel = &kernel,
		}

		f.on_free = ownership_free_probe
		f.user = &probe
		origin_disposal_destroy(&disposal)
		testing.expect(t, disposal.owner.storage == nil && probe.calls == 1)
		assert(kernel_origin_cleanup_finish(&kernel, handle).kind == .None)
		testing.expect_value(t, kernel.references, 1)

		if exhausted {
			testing.expect_value(t, kernel.origins[index - 1].state, .Retired)
		} else {
			testing.expect(
				t,
				kernel.origins[index - 1].state == .Free && kernel.origins[index - 1].generation == generation + 1,
			)
		}

		testing.expect(t, kernel_origin_cleanup_finish(&kernel, handle).kind != .None)
	}

	assert(kernel_destroy(&kernel).kind == .None)
	profile_destroy(&profile)
	resources_destroy(&resources)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
}

@(test)
ownership_response_disposal_outlives_resources_and_scope :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	root, error := scopes.create_root({bytes = 1 << 20, streams = 1}, a)
	assert(error == .None)
	monitor, me := scopes.retain_scope(root)
	assert(me == .None)
	f := Ownership_Fault {
		backing = a,
	}

	resources: Kernel_Resources
	assert(resources_init(&resources, root, {ownership_allocate, &f}).kind == .None)
	lease, le := resources_request_lease(&resources)
	assert(le.kind == .None)
	body := make([dynamic]u8, 3, 64, resources.allocator)
	copy(body[:], []u8{'o', 'l', 'd'})
	disposal := Request_Disposal {
		response = surf.Response{allocator = resources.allocator, body_storage = body, body = body[:]},
		lease = lease,
	}

	body = nil
	lease = {}
	resources_destroy(&resources)
	scopes.release_scope(&root)
	testing.expect_value(t, string(disposal.response.body), "old")
	testing.expect(t, ownership_usage(monitor).used.bytes > 0 && ownership_usage(monitor).used.streams == 1)
	probe := Ownership_Probe {
		scope = monitor,
	}

	f.on_free = ownership_free_probe
	f.user = &probe
	request_disposal_destroy(&disposal)
	request_disposal_destroy(&disposal)
	testing.expect(t, probe.calls == 1 && disposal.response.body == nil && disposal.lease == (scopes.Lease{}))
	testing.expect_value(t, ownership_usage(monitor).used, scopes.Usage{})
	scopes.release_scope(&monitor)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
}

@(test)
ownership_reentrant_free_can_destroy_physical_owner_headers :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	a := mem.tracking_allocator(&track)
	f := Ownership_Fault {
		backing = a,
	}

	owner, ae := new(Request_Owner, a)
	assert(ae == nil)
	cloned, error := request_clone({method = .GET, url = "https://example.test"}, {ownership_allocate, &f})
	assert(error.kind == .None)
	owner^ = cloned
	cloned = {}
	probe := Ownership_Probe {
		request   = owner,
		allocator = a,
	}

	f.on_free = ownership_free_probe
	f.user = &probe
	request_owner_destroy(owner)
	testing.expect(t, probe.calls == 1 && probe.request == nil && track.current_memory_allocated == 0)
	profile: Profile
	resources: Kernel_Resources
	assert(profile_init(&profile, ownership_config(), a).kind == .None)
	f = {
		backing = a,
	}

	assert(resources_init(&resources, {}, {ownership_allocate, &f}).kind == .None)
	kernel, ke := new(Kernel, a)
	assert(ke == nil)
	assert(kernel_init(kernel, &profile, &resources).kind == .None)
	probe = {
		kernel          = kernel,
		allocator       = a,
		physical_header = true,
	}

	f.on_free = ownership_free_probe
	f.user = &probe
	assert(kernel_destroy(kernel).kind == .None)
	testing.expect(t, probe.calls == 1 && probe.kernel == nil)
	profile_destroy(&profile)
	resources_destroy(&resources)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
}

@(test)
queue_preparing_waiters_are_not_fifo_and_commit_order_is_fifo :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	caps.waiters_per_origin = 3
	f: Pool_Case
	pool_case_init(&f, caps, 1000, 10000)
	defer pool_case_destroy(&f)
	held := pool_case_prepare(&f)
	held_claim, error := pool_case_claim(&f, held, "https://a.test")
	assert(error.kind == .None && !held_claim.waiting)
	first := pool_case_prepare(&f)
	first_claim, cause := pool_case_claim(&f, first, "https://a.test")
	assert(cause.kind == .None && first_claim.waiting)
	second := pool_case_prepare(&f)
	_, cause = pool_case_claim(&f, second, "https://a.test")
	assert(cause.kind == .None)
	origin := &f.kernel.origins[held_claim.origin.slot - 1]
	testing.expect(
		t,
		origin.requests == 3 &&
		origin.preparing == 3 &&
		origin.waiters == 2 &&
		origin.queue_head == 0 &&
		origin.queue_tail == 0,
	)
	testing.expect(
		t,
		f.kernel.requests[first.request.slot - 1].queue_next == 0 &&
		f.kernel.requests[second.request.slot - 1].queue_previous == 0,
	)
	pool_case_commit(&f, second, "https://a.test")
	pool_case_commit(&f, first, "https://a.test")
	testing.expect(
		t,
		origin.queue_head == second.request.slot && origin.queue_tail == first.request.slot && origin.preparing == 1,
	)
	pool_case_commit(&f, held, "https://a.test")
	testing.expect(
		t,
		origin.queue_head == second.request.slot && origin.queue_tail == first.request.slot && origin.preparing == 0,
	)
	// The held earlier resource claim is not a waiter. It can dispatch before the
	// FIFO even though the waiting requests committed first.
	active := pool_case_dispatch(&f, held.request)
	testing.expect_value(t, origin.waiters, 2)
	pool_case_complete(&f, held.request)
	pool_case_idle(&f, active.session)
	active = pool_case_dispatch(&f, second.request, true)
	testing.expect(
		t,
		origin.waiters == 1 && origin.queue_head == first.request.slot && origin.queue_tail == first.request.slot,
	)
	pool_case_complete(&f, second.request)
	pool_case_idle(&f, active.session)
	active = pool_case_dispatch(&f, first.request, true)
	testing.expect(t, origin.waiters == 0 && origin.queue_head == 0 && origin.queue_tail == 0)
	pool_case_complete(&f, first.request)
	pool_case_idle(&f, active.session)
}

@(test)
queue_reserved_idle_commit_or_rollback_preserves_claim_provenance :: proc(t: ^testing.T) {
	for rollback in ([2]bool{false, true}) {
		caps := pool_case_caps()
		caps.connections = 1
		f: Pool_Case
		pool_case_init(&f, caps, 1000, 10000)
		old, _ := pool_case_accept(&f, "https://a.test")
		transport := pool_case_dispatch(&f, old)
		pool_case_complete(&f, old)
		pool_case_idle(&f, transport.session)
		before := f.kernel.sessions[transport.session.slot - 1]
		held := pool_case_prepare(&f)
		claim, error := pool_case_claim(&f, held, "https://a.test")
		assert(error.kind == .None)
		testing.expect(
			t,
			claim.session == transport.session && f.kernel.sessions[claim.session.slot - 1].reserved_from == .Idle,
		)
		waiter, waiting := pool_case_accept(&f, "https://a.test")
		testing.expect(t, waiting.waiting && f.kernel.origins[claim.origin.slot - 1].queue_head == waiter.slot)

		if rollback {
			pool_case_rollback(&f, held)
			restored := f.kernel.sessions[transport.session.slot - 1]
			testing.expect(
				t,
				restored.state == .Idle &&
				restored.generation == before.generation &&
				restored.created_at == before.created_at &&
				restored.idle_since == before.idle_since,
			)
			_, present := kernel_poll(&f.kernel)
			testing.expect(t, !present)
		} else {
			pool_case_commit(&f, held, "https://a.test")
			dispatched := pool_case_dispatch(&f, held.request, true)
			pool_case_complete(&f, held.request)
			pool_case_idle(&f, dispatched.session)
		}

		ready := pool_case_dispatch(&f, waiter, true)
		testing.expect_value(t, ready.session, transport.session)
		pool_case_complete(&f, waiter)
		pool_case_idle(&f, ready.session)
		pool_case_destroy(&f)
	}
}

@(test)
queue_work1_unrelated_origin_progress_and_round_robin_fairness :: proc(t: ^testing.T) {
	f: Pool_Case
	pool_case_init(&f, pool_case_caps(), 1000, 10000)
	defer pool_case_destroy(&f)
	a, _ := pool_case_accept(&f, "https://a.test")
	session_a := pool_case_dispatch(&f, a)
	waiting_a, _ := pool_case_accept(&f, "https://a.test")
	b, _ := pool_case_accept(&f, "https://b.test")
	session_b := pool_case_dispatch(&f, b)
	waiting_b, _ := pool_case_accept(&f, "https://b.test")
	// OriginA's busy session cannot prevent B's queued work progressing.
	pool_case_complete(&f, b)
	pool_case_idle(&f, session_b.session)
	ready_b := pool_case_dispatch(&f, waiting_b, true)
	testing.expect_value(t, f.kernel.requests[a.slot - 1].state, .Active)
	pool_case_complete(&f, waiting_b)
	pool_case_idle(&f, ready_b.session)
	pool_case_complete(&f, a)
	pool_case_idle(&f, session_a.session)
	ready_a := pool_case_dispatch(&f, waiting_a, true)
	pool_case_complete(&f, waiting_a)
	pool_case_idle(&f, ready_a.session)
	// Both origins now have Idle sessions. Keep replenishing the origin most
	// recently served: next-origin RR must still give the other origin a turn.
	qa, _ := pool_case_accept(&f, "https://a.test")
	qb, _ := pool_case_accept(&f, "https://b.test")
	first: Assignment

	for _ in 0 ..< 128 {
		assignment, used, error := pool_dispatch(&f.kernel, 1, pool_case_time(&f))
		assert((error.kind == .None || error.kind == .Pending) && used <= 1 && used >= 0)

		if assignment.request != (Request_Handle{}) {
			first = assignment
			break
		}
	}

	assert(first.request == qa || first.request == qb)
	testing.expect_value(t, f.kernel.sessions[first.session.slot - 1].state, .Busy)
	pool_case_complete(&f, first.request)
	pool_case_idle(&f, first.session)
	first_url := "https://a.test"
	other := qb

	if first.request == qb {
		first_url = "https://b.test"
		other = qa
	}

	replacement, _ := pool_case_accept(&f, first_url)
	second := pool_case_dispatch(&f, other, true)
	pool_case_complete(&f, other)
	pool_case_idle(&f, second.session)
	third := pool_case_dispatch(&f, replacement, true)
	pool_case_complete(&f, replacement)
	pool_case_idle(&f, third.session)
}

@(test)
queue_work_limits_and_idle_cursor_are_independent :: proc(t: ^testing.T) {
	f: Pool_Case
	pool_case_init(&f, pool_case_caps(), 5, 20)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test")
	busy := pool_case_dispatch(&f, request)
	other, _ := pool_case_accept(&f, "https://b.test")
	assignment := pool_case_dispatch(&f, other)
	pool_case_complete(&f, other)
	pool_case_idle(&f, assignment.session)
	testing.expect(t, assignment.session.slot != busy.session.slot)

	for work in ([4]int{-1, 0, 4097, max(int)}) {
		before: [size_of(Kernel)]u8
		copy(before[:], mem.byte_slice(&f.kernel, size_of(Kernel)))
		none, used, error := pool_dispatch(&f.kernel, work, f.now)
		testing.expect(t, error.kind == .Invalid_Config && used == 0 && none == (Assignment{}))
		testing.expect(t, bytes.equal(before[:], mem.byte_slice(&f.kernel, size_of(Kernel))))
	}

	// Interleave a completely quiescent dispatch scan with idle expiry scans.
	// Shared/reset cursors would make work1 starve the late allocated session.
	now := pool_case_time(&f, 1000)
	found := Cell_Handle{}

	for _ in 0 ..< 128 {
		none, used, error := pool_dispatch(&f.kernel, 1, now)
		assert((error.kind == .None || error.kind == .Pending) && none == (Assignment{}) && used <= 1)
		candidate, idle_used, idle_error := pool_idle_candidate(&f.kernel, 1, now)
		assert((idle_error.kind == .None || idle_error.kind == .Pending) && idle_used <= 1)

		if candidate != (Cell_Handle{}) {
			found = candidate
			break
		}
	}

	testing.expect_value(t, found, assignment.session)
	testing.expect_value(t, f.kernel.sessions[found.slot - 1].state, .Idle)
	pool_case_complete(&f, request)
	pool_case_idle(&f, busy.session)
}

@(test)
queue_idle_and_max_age_boundaries_do_not_overflow :: proc(t: ^testing.T) {
	for maximum in ([2]bool{false, true}) {
		caps := pool_case_caps()
		caps.connections = 1
		caps.waiters_per_origin = 0
		idle, max_age := time.Duration(5), time.Duration(20)

		if maximum {
			idle = max(time.Duration)
			max_age = max(time.Duration)
		}

		f: Pool_Case
		pool_case_init(&f, caps, idle, max_age)
		start: i64 = 100

		if maximum {
			start = max(i64) - 10
		}

		request, _ := pool_case_accept(&f, "https://a.test", start)
		assignment := pool_case_dispatch(&f, request, false, start + 1)
		pool_case_complete(&f, request, start + 2)
		pool_case_idle(&f, assignment.session, start + 3)
		before := f.kernel.sessions[assignment.session.slot - 1]
		check_at := pool_case_time(&f, start + 7)

		for _ in 0 ..< 32 {
			candidate, used, error := pool_idle_candidate(&f.kernel, 1, check_at)
			assert((error.kind == .None || error.kind == .Pending) && used <= 1)
			testing.expect_value(t, candidate, Cell_Handle{})

			if error.kind == .None {
				break
			}
		}

		if maximum {
			high := pool_case_time(&f, max(i64))

			for _ in 0 ..< 32 {
				candidate, used, error := pool_idle_candidate(&f.kernel, 1, high)
				assert((error.kind == .None || error.kind == .Pending) && used <= 1)
				testing.expect_value(t, candidate, Cell_Handle{})

				if error.kind == .None {
					break
				}
			}
		} else {
			found := Cell_Handle{}
			expiry := pool_case_time(&f, start + 8)

			for _ in 0 ..< 32 {
				candidate, used, error := pool_idle_candidate(&f.kernel, 1, expiry)
				assert((error.kind == .None || error.kind == .Pending) && used <= 1)

				if candidate != (Cell_Handle{}) {
					found = candidate
					break
				}
			}

			testing.expect_value(t, found, assignment.session)
		}

		testing.expect(
			t,
			f.kernel.sessions[assignment.session.slot - 1].state == .Idle &&
			f.kernel.sessions[assignment.session.slot - 1].generation == before.generation,
		)
		pool_case_destroy(&f)
	}
}

@(test)
queue_quiescent_scan_wakes_on_admission_and_close_makes_idle_due :: proc(t: ^testing.T) {
	f: Pool_Case
	pool_case_init(&f, pool_case_caps(), 1000, 10000)
	defer pool_case_destroy(&f)
	quiet := false

	for _ in 0 ..< 64 {
		assignment, used, error := pool_dispatch(&f.kernel, 1, pool_case_time(&f))
		assert((error.kind == .None || error.kind == .Pending) && assignment == (Assignment{}) && used <= 1)

		if error.kind == .None {
			quiet = true
			break
		}
	}

	testing.expect(t, quiet)
	none, used, error := pool_dispatch(&f.kernel, 1, pool_case_time(&f))
	testing.expect(t, error.kind == .None && none == (Assignment{}) && used == 0)
	request, _ := pool_case_accept(&f, "https://a.test")
	assignment := pool_case_dispatch(&f, request)
	pool_case_complete(&f, request)
	pool_case_idle(&f, assignment.session)
	// A fresh future idle deadline must not delay explicit Client/kernel close.
	for _ in 0 ..< 64 {
		candidate, _, cause := pool_idle_candidate(&f.kernel, 1, pool_case_time(&f))
		testing.expect_value(t, candidate, Cell_Handle{})
		assert(cause.kind == .None || cause.kind == .Pending)

		if cause.kind == .None {
			break
		}
	}

	preparing := pool_case_prepare(&f)
	assert(kernel_close(&f.kernel).kind == .None)
	_, cause := pool_case_claim(&f, preparing, "https://b.test")
	testing.expect_value(t, cause.kind, .Closed)
	pool_case_rollback(&f, preparing)
	none, used, error = pool_dispatch(&f.kernel, 1, pool_case_time(&f))
	testing.expect(t, error.kind == .Closed && used == 0 && none == (Assignment{}))
	due := Cell_Handle{}

	for _ in 0 ..< 64 {
		candidate, _, pending := pool_idle_candidate(&f.kernel, 1, pool_case_time(&f))
		assert(pending.kind == .None || pending.kind == .Pending)

		if candidate != (Cell_Handle{}) {
			due = candidate
			break
		}
	}

	testing.expect_value(t, due, assignment.session)
}

@(test)
queue_max_age_can_expire_a_recently_idle_session :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	f: Pool_Case
	pool_case_init(&f, caps, 1000, 20)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test", 100)
	assignment := pool_case_dispatch(&f, request, false, 101)
	created := f.kernel.sessions[assignment.session.slot - 1].created_at
	pool_case_complete(&f, request, 102)
	pool_case_idle(&f, assignment.session, created + 19)

	for _ in 0 ..< 32 {
		candidate, used, error := pool_idle_candidate(&f.kernel, 1, created + 19)
		assert((error.kind == .None || error.kind == .Pending) && used <= 1)
		testing.expect_value(t, candidate, Cell_Handle{})

		if error.kind == .None {
			break
		}
	}

	f.now = created + 20
	found := Cell_Handle{}

	for _ in 0 ..< 32 {
		candidate, used, error := pool_idle_candidate(&f.kernel, 1, f.now)
		assert((error.kind == .None || error.kind == .Pending) && used <= 1)

		if candidate != (Cell_Handle{}) {
			found = candidate
			break
		}
	}

	testing.expect_value(t, found, assignment.session)
}

@(test)
queue_idle_scan_restarts_after_behind_cursor_idle_transition :: proc(t: ^testing.T) {
	f: Pool_Case
	pool_case_init(&f, pool_case_caps(), 5, 10000)
	defer pool_case_destroy(&f)
	a, _ := pool_case_accept(&f, "https://a.test")
	sa := pool_case_dispatch(&f, a)
	b, _ := pool_case_accept(&f, "https://b.test")
	sb := pool_case_dispatch(&f, b)
	candidate, used, error := pool_idle_candidate(&f.kernel, 1, pool_case_time(&f))
	assert(candidate == (Cell_Handle{}) && used == 1 && error.kind == .Pending)
	visited := u32((int(f.kernel.idle_cursor) + len(f.kernel.sessions) - 1) % len(f.kernel.sessions) + 1)
	completed, session, other, other_session := a, sa.session, b, sb.session

	if sb.session.slot == visited {
		completed, session, other, other_session = b, sb.session, a, sa.session
	}

	assert(session.slot == visited)
	pool_case_complete(&f, completed)
	pool_case_idle(&f, session)
	idle_since := f.kernel.sessions[session.slot - 1].idle_since
	now := pool_case_time(&f)
	candidate, used, error = pool_idle_candidate(&f.kernel, 1, now)
	testing.expect(t, candidate == (Cell_Handle{}) && used == 1 && error.kind == .Pending)
	quiet := false

	for _ in 0 ..< 32 {
		candidate, used, error = pool_idle_candidate(&f.kernel, 1, now)
		assert(used <= 1 && (error.kind == .None || error.kind == .Pending))
		testing.expect_value(t, candidate, Cell_Handle{})

		if error.kind == .None {
			quiet = true
			break
		}
	}

	testing.expect(t, quiet && f.kernel.idle_deadline == idle_since + 5)
	// No new state notification occurs between clean sweep and actual expiry.
	cutoff := pool_case_time(&f, idle_since + 5)
	found := Cell_Handle{}

	for _ in 0 ..< 32 {
		next, spent, pending := pool_idle_candidate(&f.kernel, 1, cutoff)
		assert(spent <= 1 && (pending.kind == .None || pending.kind == .Pending))

		if next != (Cell_Handle{}) {
			found = next
			break
		}
	}

	testing.expect_value(t, found, session)
	pool_case_complete(&f, other)
	pool_case_idle(&f, other_session)
}
