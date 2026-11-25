package surf_async

import surf ".."
import runtime_async "shared:async"
import scopes "shared:async/sync/budget"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

// These are real prepared-State/Kernel ledger fixtures, not public Client or
// received-wire evidence. No test callback performs DNS, TCP or TLS IO.
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

	p := rq_reserve(&f)
	assert(rq_claim(&f, p, "http://refill.example/A", 1).kind == .None)
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
