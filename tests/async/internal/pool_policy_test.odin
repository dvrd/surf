package surf_async

import "core:mem"
import "core:sync"
import "core:testing"
import "core:fmt"

policy_case_init :: proc(
	f: ^Pool_Case,
	caps: Capacities = {
		requests = 8,
		origins = 3,
		connections = 2,
		connections_per_origin = 1,
		waiters_per_origin = 2,
		dns_ids = 0,
		work_per_resume = 1,
	},
) {pool_case_init(f, caps, 100000, 200000)}
policy_origin :: proc(f: ^Pool_Case, url: string) -> Prepared_Origin {
	origin, error := origin_prepare(&f.profile, url, f.resources.allocator)
	assert(error.kind == .None)

	return origin
}
// Snapshot all Kernel bytes/arrays and owned origin/key/profile backing while
// the mutex is held. The selector has no ownership or mutation entitlement.
policy_select :: proc(
	t: ^testing.T,
	f: ^Pool_Case,
	key: Origin_Key,
	now: i64,
	allow_new: bool,
) -> (
	Pool_Selection,
	Client_Error,
) {
	k := &f.kernel
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	regions: [16][]u8
	regions[0] = mem.byte_slice(k, size_of(Kernel))
	regions[1] = mem.slice_to_bytes(k.requests)
	regions[2] = mem.slice_to_bytes(k.origins)
	regions[3] = mem.slice_to_bytes(k.sessions)
	regions[4] = mem.slice_to_bytes(k.request_free)
	regions[5] = mem.slice_to_bytes(k.origin_free)
	regions[6] = mem.slice_to_bytes(k.session_free)
	count := 7
	for origin in k.origins {
		regions[count] = origin.owner.storage
		count += 1
	}
	regions[count] = k.profile.storage
	count += 1
	regions[count] = transmute([]u8)key.host
	count += 1
	before: [16][16384]u8
	for region, i in regions[:count] {
		assert(len(region) <= len(before[i]))
		copy(before[i][:], region)
	}
	allocations, frees := f.track.total_allocation_count, f.track.total_free_count
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	selected, error := pool_select_locked(k, key, now, allow_new)
	context = previous
	for region, i in regions[:count] {
		testing.expect_value(t, mem.compare(before[i][:len(region)], region), 0)
	}
	testing.expect_value(t, f.track.total_allocation_count, allocations)
	testing.expect_value(t, f.track.total_free_count, frees)
	return selected, error
}
policy_claim :: proc(
	f: ^Pool_Case,
	p: Preparing_Request,
	url: string,
	allow_new: bool,
) -> (
	Pool_Reservation,
	Client_Error,
) {
	origin := policy_origin(f, url)
	defer origin_destroy(&origin)
	return pool_reserve_policy(&f.kernel, p, &origin, pool_case_time(f), allow_new)
}
policy_accept :: proc(f: ^Pool_Case, url: string, allow_new: bool) -> (Request_Handle, Pool_Reservation) {
	p := pool_case_prepare(f)
	claim, error := policy_claim(f, p, url, allow_new)
	assert(error.kind == .None)
	pool_case_commit(f, p, url)

	return p.request, claim
}
policy_await :: proc(f: ^Pool_Case, h: Request_Handle, awaiting: bool) {
	sync.lock(&f.kernel.mu)
	f.kernel.requests[h.slot - 1].stage = .Awaiting_DNS_IDs if awaiting else .Queued
	f.kernel.dispatch_dirty = true
	sync.unlock(&f.kernel.mu)
}
policy_no_dispatch :: proc(t: ^testing.T, f: ^Pool_Case) {
	for _ in 0 ..< 4 * (len(f.kernel.origins) + len(f.kernel.sessions) + 1) {
		assignment, used, error := pool_dispatch(&f.kernel, 1, pool_case_time(f))
		testing.expect_value(t, assignment, Assignment{})
		testing.expect(t, error.kind == .None || error.kind == .Pending)
		testing.expect(t, used >= 0 && used <= 1)

		if error.kind == .None && used == 0 {
			break
		}
	}
}

@(test)
policy_selector_is_pure_and_preserves_exact_old_callable :: proc(t: ^testing.T) {
	old: proc(_: ^Kernel, _: Preparing_Request, _: ^Prepared_Origin, _: i64) -> (Pool_Reservation, Client_Error) =
		pool_reserve
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	free_origin := f.kernel.origin_free[f.kernel.origin_free_count - 1]
	free_session := f.kernel.session_free[f.kernel.session_free_count - 1]
	selected, error := policy_select(t, &f, origin.key, 100, true)
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, selected.new_origin && selected.new_session && !selected.waiting)
	testing.expect_value(t, selected.origin.slot, free_origin)
	testing.expect_value(t, selected.session.slot, free_session)
	waiting, error2 := policy_select(t, &f, origin.key, 100, false)
	testing.expect_value(t, error2.kind, .None)
	testing.expect(t, waiting.new_origin && !waiting.new_session && waiting.waiting)
	testing.expect_value(t, waiting.session, Cell_Handle{})
	p := pool_case_prepare(&f)
	claim, cause := old(&f.kernel, p, &origin, pool_case_time(&f))
	testing.expect_value(t, cause.kind, .None)
	testing.expect_value(t, claim.session.slot, free_session)
	testing.expect_value(t, claim.waiting, false)
	pool_case_rollback(&f, p)
	fmt.println("POOL_POLICY pure_selection_and_old_callable=1")
}

@(test)
policy_wait_only_never_claims_free_and_rejection_preserves_origin :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.waiters_per_origin = 0
	f: Pool_Case
	policy_case_init(&f, caps)
	defer pool_case_destroy(&f)
	p := pool_case_prepare(&f)
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	pointer, size := raw_data(origin.storage), len(origin.storage)
	free_origins, free_sessions := f.kernel.origin_free_count, f.kernel.session_free_count
	result, cause := pool_reserve_policy(&f.kernel, p, &origin, pool_case_time(&f), false)
	testing.expect_value(t, cause.kind, .Capacity)
	testing.expect_value(t, result, Pool_Reservation{})
	testing.expect_value(t, raw_data(origin.storage), pointer)
	testing.expect_value(t, len(origin.storage), size)
	testing.expect_value(t, f.kernel.origin_free_count, free_origins)
	testing.expect_value(t, f.kernel.session_free_count, free_sessions)
	testing.expect_value(t, f.kernel.requests[p.request.slot - 1].origin, Cell_Handle{})
	pool_case_rollback(&f, p)
}

@(test)
policy_awaiting_dns_head_blocks_free_sessions_and_later_waiters :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	free := f.kernel.session_free_count
	head, head_claim := policy_accept(&f, "https://a.test", false)
	tail, tail_claim := policy_accept(&f, "https://a.test", false)
	testing.expect(t, head_claim.waiting && tail_claim.waiting)
	testing.expect_value(t, f.kernel.session_free_count, free)
	policy_await(&f, head, true)
	policy_no_dispatch(t, &f)
	testing.expect_value(t, f.kernel.requests[tail.slot - 1].state, .Queued)
	testing.expect_value(t, f.kernel.session_free_count, free)
	policy_await(&f, head, false)
	first := pool_case_dispatch(&f, head)
	pool_case_complete(&f, head)
	pool_case_idle(&f, first.session)
	second := pool_case_dispatch(&f, tail, true)
	pool_case_complete(&f, tail)
	pool_case_idle(&f, second.session)
}

@(test)
policy_idle_unparks_same_awaiting_head_in_fifo_order :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	f: Pool_Case
	policy_case_init(&f, caps)
	defer pool_case_destroy(&f)
	active, _ := pool_case_accept(&f, "https://a.test")
	assigned := pool_case_dispatch(&f, active)
	head, _ := policy_accept(&f, "https://a.test", false)
	tail, _ := policy_accept(&f, "https://a.test", false)
	policy_await(&f, head, true)
	pool_case_complete(&f, active)
	pool_case_idle(&f, assigned.session)
	first := pool_case_dispatch(&f, head, true)
	testing.expect_value(t, first.session, assigned.session)
	testing.expect_value(t, f.kernel.requests[head.slot - 1].stage, .Writing)
	testing.expect_value(t, f.kernel.requests[tail.slot - 1].state, .Queued)
	pool_case_complete(&f, head)
	pool_case_idle(&f, first.session)
	second := pool_case_dispatch(&f, tail, true)
	pool_case_complete(&f, tail)
	pool_case_idle(&f, second.session)
}

@(test)
policy_reserved_idle_can_bypass_ids_but_reserved_free_cannot :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test")
	policy_await(&f, request, true)
	policy_no_dispatch(t, &f)
	testing.expect_value(t, f.kernel.counters.reserved_connections, 1)
	policy_await(&f, request, false)
	first := pool_case_dispatch(&f, request)
	pool_case_complete(&f, request)
	pool_case_idle(&f, first.session)
	second, claim := policy_accept(&f, "https://a.test", false)
	testing.expect(t, !claim.waiting && claim.session == first.session)
	policy_await(&f, second, true)
	reused := pool_case_dispatch(&f, second, true)
	pool_case_complete(&f, second)
	pool_case_idle(&f, reused.session)
}

@(test)
policy_blocked_origin_does_not_stop_other_origin_work1 :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	blocked, blocked_claim := policy_accept(&f, "https://a.test", false)
	policy_await(&f, blocked, true)
	ready, _ := pool_case_accept(&f, "https://b.test")
	sync.lock(&f.kernel.mu)
	f.kernel.dispatch_cursor = blocked_claim.origin.slot - 1
	f.kernel.dispatch_origin = {}
	f.kernel.dispatch_remaining = 0
	f.kernel.dispatch_dirty = true
	sync.unlock(&f.kernel.mu)
	assigned := pool_case_dispatch(&f, ready)
	testing.expect_value(t, f.kernel.requests[blocked.slot - 1].state, .Queued)
	testing.expect_value(t, f.kernel.requests[blocked.slot - 1].session, Cell_Handle{})
	pool_case_complete(&f, ready)
	pool_case_idle(&f, assigned.session)
	pool_case_complete(&f, blocked)
}

@(test)
policy_selector_isolates_full_origin_and_zeroes_rejected_witness :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	request, claim := pool_case_accept(&f, "https://a.test")
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	selected, error := policy_select(t, &f, origin.key, pool_case_time(&f), false)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, selected.origin, claim.origin)
	testing.expect(t, !selected.new_origin && selected.waiting)

	for field in 0 ..< 3 {
		key := origin.key

		switch field {
		case 0:
			key.secure = false; case 1:
			key.port = 8443; case 2:
			key.host = "b.test"
		}

		other, cause := policy_select(t, &f, key, pool_case_time(&f), false)
		testing.expect_value(t, cause.kind, .None)
		testing.expect(t, other.new_origin && other.origin != claim.origin)
	}

	wrong := origin.key
	wrong.profile_id += 1
	invalid, cause := policy_select(t, &f, wrong, pool_case_time(&f), true)
	testing.expect_value(t, cause.kind, .Invalid_Config)
	testing.expect_value(t, invalid, Pool_Selection{})
	pool_case_complete(&f, request)
}
