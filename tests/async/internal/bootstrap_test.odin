package surf_async

import surf ".."
import runtime_async "shared:async"
import signal "shared:async/signal"
import rt "base:runtime"
import "base:intrinsics"
import "core:fmt"
import "core:mem"
import charged "shared:async/mem/budget"
import "core:net"
import scopes "shared:async/sync/budget"
import "core:sync"
import "core:testing"
import "core:time"

bootstrap_config :: proc(scope: scopes.Scope = {}, dns := 0) -> Normalized_Config {
	config, error := config_normalize(
		{
			http = {scope = scope, allow_http = true},
			capacities = Capacities {
				requests = 2,
				origins = 2,
				connections = 1,
				connections_per_origin = 1,
				waiters_per_origin = 2,
				dns_ids = dns,
				work_per_resume = 1,
			},
		},
	)
	assert(error.kind == .None)

	return config
}
bootstrap_runtime :: proc(r: ^runtime_async.Runtime) {
	assert(runtime_async.init(r, {workers = 1, task_capacity = 4, io_capacity = 4}).kind == .None)
}
bootstrap_usage :: proc(scope: scopes.Scope) -> scopes.Snapshot {
	snapshot, error := scopes.snapshot(scope)
	assert(error == .None)

	return snapshot
}

@(test)
bootstrap_prepares_stable_owners_and_signals_without_task_publication :: proc(t: ^testing.T) {
	for running in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		allocator := mem.tracking_allocator(&track)
		runtime: runtime_async.Runtime
		bootstrap_runtime(&runtime)

		if running {
			assert(runtime_async.start(&runtime).kind == .None)
		}

		config := bootstrap_config()
		state, error := network_prepare(&runtime, config, allocator)
		assert(error.kind == .None && state != nil)
		testing.expect(
			t,
			state.self == state &&
			state.resources.self == &state.resources &&
			state.profile.self == &state.profile &&
			state.kernel.self == &state.kernel,
		)
		testing.expect(t, state.kernel.profile == &state.profile && state.kernel.resources == &state.resources)
		testing.expect_value(t, state.references, u64(1))
		testing.expect(t, state.base_owned && state.phase == .Constructing && state.registered_tasks == 0)
		testing.expect_value(t, len(state.actors), 1)
		testing.expect_value(t, len(state.requests), 2)
		testing.expect_value(t, len(state.task_index), 2)
		testing.expect_value(t, state.signal_cells, 2)
		testing.expect_value(t, state.dns_count, 0)
		testing.expect_value(t, len(state.dns_ids), 0)
		testing.expect(
			t,
			state.task_index[0] == &state.coordinator.task && state.task_index[1] == &state.actors[0].task,
		)
		testing.expect(
			t,
			state.coordinator.owner == state && state.actors[0].owner == state && state.actors[0].index == 1,
		)
		testing.expect(t, !signal.wake(state.coordinator.wake) && !signal.wake(state.actors[0].wake))
		servers, prepared := net.resolver_snapshot_name_servers(&state.resolver)
		testing.expect(t, !prepared && len(servers) == 0)
		_, clock_error := network_clock(state)
		testing.expect_value(t, clock_error.kind, .Closed)
		retained, ok := signal.retain(state.actors[0].wake)
		assert(ok)
		testing.expect(t, network_state_retain(state))
		testing.expect_value(t, network_dispose_prepared(state).kind, .Pending)
		network_state_release(state)
		assert(network_dispose_prepared(state).kind == .None)
		assert(runtime_async.destroy(&runtime).kind == .None)
		testing.expect(t, !signal.wake(retained))
		signal.release(&retained)
		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}

	fmt.println("BOOTSTRAP16 prepared_running_profiles=2 task_registration=0 resolver_preparation=0")
}

@(test)
bootstrap_every_reported_caller_grant_failure_unwinds_before_return :: proc(t: ^testing.T) {
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	defer assert(runtime_async.destroy(&runtime).kind == .None)

	for managed in ([2]bool{false, true}) {
		for dns in ([2]int{0, 17}) {
			track: mem.Tracking_Allocator
			mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
			allocator := mem.tracking_allocator(&track)
			scope: scopes.Scope

			if managed {
				owner, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
				assert(error == .None)
				scope = owner
			}

			config := bootstrap_config(scope, dns)
			servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}

			if dns > 0 {
				config.http.resolver.name_servers = servers[:]
			}

			baseline := track.current_memory_allocated
			healthy := Ownership_Fault {
				backing = allocator,
			}

			state, error := network_prepare(&runtime, config, {ownership_allocate, &healthy})
			assert(error.kind == .None)
			points := healthy.calls
			assert(points > 0)
			assert(network_dispose_prepared(state).kind == .None)
			assert(track.current_memory_allocated == baseline)

			for at in 1 ..= points {
				for mode in 0 ..< 6 {
					fault := Ownership_Fault {
						backing = allocator,
						at      = at,
						mode    = mode,
					}

					failed, cause := network_prepare(&runtime, config, {ownership_allocate, &fault})
					testing.expect(t, cause.kind != .None && failed == nil && fault.triggered)
					testing.expect(t, fault.whole == nil && fault.returned == (0 if mode < 2 else 1))
					// Assert before fixture cleanup; no compensating destructor can hide leaks.
					testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)

					if managed {
						testing.expect_value(t, bootstrap_usage(scope).used, scopes.Usage{})
					}
				}
			}

			fmt.printf(
				"BOOTSTRAP16 managed=%v dns_ids=%d constructor_points=%d actual_fault_cells=%d\n",
				managed,
				dns,
				points,
				points * 6,
			)

			if managed {
				scopes.release_scope(&scope)
			}

			testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
			mem.tracking_allocator_destroy(&track)
		}
	}
}

@(test)
bootstrap_scope_coverage_charges_and_closed_source_rejections_are_exact :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	root, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
	assert(error == .None)
	child, ce := scopes.create_child(root, {bytes = 32 << 20, streams = 8, jobs = 8})
	assert(ce == .None)
	sibling, se := scopes.create_child(root, {bytes = 32 << 20, streams = 8, jobs = 8})
	assert(se == .None)
	other, oe := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
	assert(oe == .None)
	binding, be := charged.create(child, {backing = allocator, metadata_allocator = allocator})
	assert(be.kind == .None)
	managed := charged.allocator(binding)
	baseline := track.current_memory_allocated

	for configured in ([2]scopes.Scope{root, {}}) {
		state, cause := network_prepare(&runtime, bootstrap_config(configured), managed)
		assert(cause.kind == .None)
		info, known := charged.allocation_info(managed, raw_data(state.backing.storage))
		assert(known)
		testing.expect_value(t, state.backing.lease, scopes.Lease{})
		// Every managed backing is counted once, including allocator metadata.
		testing.expect_value(t, bootstrap_usage(child).used.bytes, charged.stats(binding).backing_bytes)
		testing.expect(t, info.backing_bytes >= u64(size_of(Client_State)))
		assert(network_dispose_prepared(state).kind == .None)
		testing.expect_value(t, bootstrap_usage(root).used, scopes.Usage{})
		testing.expect_value(t, track.current_memory_allocated, baseline)
	}

	for invalid in ([2]scopes.Scope{sibling, other}) {
		state, cause := network_prepare(&runtime, bootstrap_config(invalid), managed)
		testing.expect(t, state == nil && cause.kind == .Invalid_Config)
		testing.expect_value(
			t,
			cause.http.budget,
			scopes.Error.Foreign_Root if invalid == other else scopes.Error.Invalid_Config,
		)
		testing.expect_value(t, track.current_memory_allocated, baseline)
	}

	ancestor, ae := charged.create(root, {backing = allocator, metadata_allocator = allocator})
	assert(ae.kind == .None)
	state, cause := network_prepare(&runtime, bootstrap_config(child), charged.allocator(ancestor))
	testing.expect(t, state == nil && cause.kind == .Invalid_Config)
	charged.release(&ancestor)
	assert(scopes.close(child) == .None)

	for configured in ([3]scopes.Scope{child, root, {}}) {
		state, cause = network_prepare(&runtime, bootstrap_config(configured), managed)
		testing.expect(t, state == nil && cause.kind == .Budget_Rejected && cause.http.budget == .Closed)
		testing.expect_value(t, track.current_memory_allocated, baseline)
	}

	charged.release(&binding)
	scopes.release_scope(&child)
	scopes.release_scope(&sibling)
	scopes.release_scope(&other)
	scopes.release_scope(&root)
	assert(runtime_async.destroy(&runtime).kind == .None)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
}

@(test)
bootstrap_covered_managed_state_grants_fail_without_double_charging :: proc(t: ^testing.T) {
	for dns in ([2]int{0, 17}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		allocator := mem.tracking_allocator(&track)
		runtime: runtime_async.Runtime
		bootstrap_runtime(&runtime)
		scope, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
		assert(error == .None)
		fault := Ownership_Fault {
			backing = allocator,
		}

		binding, be := charged.create(scope, {backing = {ownership_allocate, &fault}, metadata_allocator = allocator})
		assert(be.kind == .None)
		managed := charged.allocator(binding)
		config := bootstrap_config(scope, dns)
		servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}

		if dns > 0 {
			config.http.resolver.name_servers = servers[:]
		}

		baseline := track.current_memory_allocated
		state, cause := network_prepare(&runtime, config, managed)
		assert(cause.kind == .None)
		points := fault.calls
		assert(points > 0)
		testing.expect_value(t, state.backing.lease, scopes.Lease{})
		testing.expect_value(t, bootstrap_usage(scope).used.bytes, charged.stats(binding).backing_bytes)
		assert(network_dispose_prepared(state).kind == .None)
		assert(track.current_memory_allocated == baseline && bootstrap_usage(scope).used == (scopes.Usage{}))

		for at in 1 ..= points {
			for mode in 0 ..< 6 {
				fault = {
					backing = allocator,
					at      = at,
					mode    = mode,
				}

				failed, failure := network_prepare(&runtime, config, managed)
				testing.expect(t, failed == nil && failure.kind != .None && fault.triggered)
				testing.expect(t, fault.whole == nil && fault.returned == (0 if mode < 2 else 1))
				testing.expect(t, track.current_memory_allocated == baseline && len(track.bad_free_array) == 0)
				testing.expect_value(t, bootstrap_usage(scope).used, scopes.Usage{})
			}
		}

		fmt.printf(
			"BOOTSTRAP16 covered_managed=true dns_ids=%d constructor_points=%d actual_fault_cells=%d\n",
			dns,
			points,
			points * 6,
		)
		charged.release(&binding)
		scopes.release_scope(&scope)
		assert(runtime_async.destroy(&runtime).kind == .None)
		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}
}

Bootstrap_Free_Reentry :: struct {
	state:     ^Client_State,
	header:    ^Client,
	allocator: mem.Allocator,
	calls:     int,
}
bootstrap_free_reentry :: proc(data: rawptr) {
	p := cast(^Bootstrap_Free_Reentry)data
	assert(p.state.phase == .Disposing && !network_state_retain(p.state))
	assert(network_dispose_prepared(p.state).kind == .Pending)
	assert(network_dns_refill(p.state, nil).kind == .Closed)
	_, error := network_clock(p.state)
	assert(error.kind == .Closed)

	if p.header != nil {
		header := p.header
		p.header = nil
		free(header, p.allocator)
	}

	p.calls += 1
}
@(test)
bootstrap_disposal_commits_before_reentrant_physical_free :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	fault := Ownership_Fault {
		backing = allocator,
	}

	state, error := network_prepare(&runtime, bootstrap_config(), {ownership_allocate, &fault})
	assert(error.kind == .None)
	header := new(Client, allocator)
	header^ = {
		_self  = header,
		_state = state,
	}

	// Fixture controller clears its header before State disposal. Arbitrary first
	// child free physically frees that header; no public Client API is claimed.
	header^ = {}
	callback := Bootstrap_Free_Reentry {
		state     = state,
		header    = header,
		allocator = allocator,
	}

	fault.on_free = bootstrap_free_reentry
	fault.user = &callback
	assert(network_dispose_prepared(state).kind == .None)
	testing.expect(t, callback.calls == 1 && callback.header == nil)
	assert(runtime_async.destroy(&runtime).kind == .None)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
}

Bootstrap_Perturb :: struct {
	backing:     mem.Allocator,
	at, calls:   int,
	close_scope: scopes.Scope,
	delay:       time.Duration,
}
bootstrap_perturb :: proc(
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
	p := cast(^Bootstrap_Perturb)data
	storage, error := p.backing.procedure(p.backing.data, mode, size, alignment, old_memory, old_size, location)
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		p.calls += 1

		if p.calls == p.at {
			if p.close_scope != (scopes.Scope{}) {
				assert(scopes.close(p.close_scope) == .None)
			}

			if p.delay > 0 {
				time.sleep(p.delay)
			}
		}
	}
	return storage, error
}
@(test)
bootstrap_rechecks_lifetime_and_scope_after_physical_preparation :: proc(t: ^testing.T) {
	for expire in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		allocator := mem.tracking_allocator(&track)
		runtime: runtime_async.Runtime
		bootstrap_runtime(&runtime)
		scope, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
		assert(error == .None)
		baseline := track.current_memory_allocated
		healthy := Bootstrap_Perturb {
			backing = allocator,
		}

		state, cause := network_prepare(&runtime, bootstrap_config(scope), {bootstrap_perturb, &healthy})
		assert(cause.kind == .None)
		points := healthy.calls
		assert(points > 0)
		assert(network_dispose_prepared(state).kind == .None)
		perturb := Bootstrap_Perturb {
			backing = allocator,
			at      = points,
		}

		config := bootstrap_config(scope)

		if expire {
			config.lifetime = runtime_async.deadline_after(&runtime, 10 * time.Millisecond)
			perturb.delay = 30 * time.Millisecond
		} else {
			perturb.close_scope = scope
		}

		failed, failure := network_prepare(&runtime, config, {bootstrap_perturb, &perturb})
		testing.expect_value(t, failed, nil)

		if expire {
			testing.expect(t, failure.kind == .Error && failure.runtime.kind == .Timeout)
		} else {
			testing.expect(t, failure.kind == .Budget_Rejected && failure.http.budget == .Closed)
		}

		testing.expect_value(t, perturb.calls, points)
		testing.expect_value(t, track.current_memory_allocated, baseline)
		testing.expect_value(t, bootstrap_usage(scope).used, scopes.Usage{})
		scopes.release_scope(&scope)
		assert(runtime_async.destroy(&runtime).kind == .None)
		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}

	fmt.println("BOOTSTRAP16 post_physical_checks=scope_closed,lifetime_expired")
}

Bootstrap_Task_Context :: struct {
	state:                         ^Client_State,
	task:                          ^runtime_async.Task,
	index, resumes, cancels, done: int,
}
bootstrap_registered_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	p := cast(^Bootstrap_Task_Context)data
	p.resumes += 1
	now, error := network_clock(p.state)
	assert(error.kind == .None && now.epoch == p.state.epoch)

	if p.index == 0 {
		sync.lock(&p.state.mu)
		p.state.coordinator.done = true
		sync.unlock(&p.state.mu)
	} else {
		p.state.actors[p.index - 1].owner_drained = true
	}

	return .Done
}
bootstrap_registered_cancel :: proc(data: rawptr) -> runtime_async.Resume_Result {
	p := cast(^Bootstrap_Task_Context)data
	p.cancels += 1

	return bootstrap_registered_resume(data)
}
bootstrap_registered_done :: proc(data: rawptr) {
	p := cast(^Bootstrap_Task_Context)data
	assert(!runtime_async.is_current_task(p.task))
	network_task_done(p.state, p.index, p.resumes > 0)
	// External test callback owner remains alive; no State access after helper.
	intrinsics.atomic_add(&p.done, 1)
}
bootstrap_queued :: proc(
	s: ^Client_State,
	r: ^runtime_async.Runtime,
	url: string = "http://127.0.0.1/path",
) -> Request_Handle {
	now := runtime_async.deadline_after(r, 0)
	lease, error := resources_request_lease(&s.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(&s.kernel, runtime_async.deadline_after(r, time.Second), &lease)
	assert(cause.kind == .None)
	origin, oe := origin_prepare(&s.profile, url, s.resources.allocator)
	assert(oe.kind == .None)
	_, claim := pool_reserve(&s.kernel, preparing, &origin, now.at)
	origin_destroy(&origin)
	assert(claim.kind == .None)
	input, ie := request_clone({method = .GET, url = url}, s.resources.allocator)
	assert(ie.kind == .None)
	assert(kernel_commit(&s.kernel, preparing, &input, now).kind == .None)
	return preparing.request
}
@(test)
bootstrap_real_taskgroup_done_witness_and_unstarted_cleanup_preserve_base :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)

	for started in ([2]bool{false, true}) {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
		allocator := mem.tracking_allocator(&track)
		runtime := new(runtime_async.Runtime, allocator)
		bootstrap_runtime(runtime)
		state, error := network_prepare(runtime, bootstrap_config(), allocator)
		assert(error.kind == .None)
		handles: [2]Request_Handle

		if !started {
			for &handle in handles {
				handle = bootstrap_queued(state, runtime)
			}
		}

		retained: [2]signal.Signal
		retained[0], _ = signal.retain(state.coordinator.wake)
		retained[1], _ = signal.retain(state.actors[0].wake)
		contexts: [2]Bootstrap_Task_Context
		// Fixture-only publication of REAL Runtime tasks, not public Client.init.
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
		assert(runtime_async.register_group(runtime, state.task_index).kind == .None)
		now, clock := network_clock(state)
		assert(clock.kind == .None && now.epoch == state.epoch)

		if started {
			for task in state.task_index {
				assert(runtime_async.wake(runtime, task))
			}

			assert(runtime_async.start(runtime).kind == .None)

			for intrinsics.atomic_load(&contexts[0].done) + intrinsics.atomic_load(&contexts[1].done) < 2 {
				time.sleep(time.Millisecond)
			}
		}

		assert(runtime_async.destroy(runtime).kind == .None)
		free(runtime, allocator)
		testing.expect_value(t, state.references, u64(1))
		testing.expect(t, state.base_owned && state.runtime == nil && state.registered_tasks == 0)
		testing.expect(t, state.coordinator.detached && state.actors[0].detached)
		_, closed := network_clock(state)
		testing.expect_value(t, closed.kind, .Closed)
		testing.expect_value(t, bank_refill(state, nil).kind, .Closed)
		closed_block, closed_bank := bank_reserve(state, 1)
		testing.expect(t, closed_bank.kind == .Closed && closed_block == (DNS_ID_Block{}))

		for callback in contexts {
			testing.expect_value(t, callback.done, 1)
			testing.expect_value(t, callback.cancels, 0)
			testing.expect_value(t, callback.resumes, 1 if started else 0)
		}

		if !started {
			testing.expect(t, state.unstarted_cleanup_started && state.unstarted_cleanup_done)

			for handle in handles {
				completion, valid := kernel_poll(&state.kernel)
				testing.expect(t, valid && completion.error.transport == net.Connection_Error.Cancelled)
				testing.expect_value(t, kernel_release(&state.kernel, handle).kind, .None)
			}
		}

		network_task_done(state, 0, false)
		network_task_done(state, 1, false)
		testing.expect_value(t, state.references, u64(1))
		sync.lock(&state.mu)
		state.base_owned = false
		sync.unlock(&state.mu)
		network_state_release(state)

		for &notification in retained {
			testing.expect(t, !signal.wake(notification))
			signal.release(&notification)
		}

		testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
		mem.tracking_allocator_destroy(&track)
	}

	fmt.println(
		"BOOTSTRAP16 actual_taskgroup_profiles=2 unstarted_no_resume=true runtime_physically_freed_before_clock=true public_client_init=0",
	)
}

Bootstrap_Worker :: struct {
	runtime: ^runtime_async.Runtime,
	fault:   ^Ownership_Fault,
	done:    int,
}
bootstrap_worker_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	p := cast(^Bootstrap_Worker)data
	allocator := mem.Allocator{ownership_allocate, p.fault}
	state, error := network_prepare(p.runtime, bootstrap_config(), allocator)
	assert(error.kind == .None)
	assert(network_dispose_prepared(state).kind == .None)
	calls := p.fault.calls
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}

	for explicit in ([2]bool{false, true}) {
		config := bootstrap_config({}, 1)

		if explicit {
			config.http.resolver.name_servers = servers[:]
		}

		failed, cause := network_prepare(p.runtime, config, allocator)
		assert(failed == nil && cause.kind == .Error && cause.runtime.kind == .Current_Worker_Active)
		assert(p.fault.calls == calls)
	}

	return .Done
}
@(test)
bootstrap_worker_numeric_only_and_preparation_rejections_are_real :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	fault := Ownership_Fault {
		backing = allocator,
	}

	node := Bootstrap_Worker {
		runtime = &runtime,
		fault   = &fault,
	}

	task := runtime_async.Task {
		resume = bootstrap_worker_resume,
		data = &node,
		on_done = proc(data: rawptr) {intrinsics.atomic_add(&(cast(^Bootstrap_Worker)data).done, 1)},
	}

	assert(
		runtime_async.register(&runtime, &task).kind == .None &&
		runtime_async.wake(&runtime, &task) &&
		runtime_async.start(&runtime).kind == .None,
	)

	for intrinsics.atomic_load(&node.done) == 0 {
		time.sleep(time.Millisecond)
	}

	assert(runtime_async.wait_idle(&runtime).kind == .None && runtime_async.destroy(&runtime).kind == .None)
	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.println("BOOTSTRAP16 actual_worker_numeric_prepare=1 worker_dns_rejections_before_alloc=2")
}

bootstrap_dispatch :: proc(s: ^Client_State, r: ^runtime_async.Runtime) -> Assignment {
	for _ in 0 ..< 1000 {
		assignment, used, error := pool_dispatch(&s.kernel, 1, runtime_async.deadline_after(r, 0).at)
		assert(used <= 1 && (error.kind == .None || error.kind == .Pending))

		if assignment.request != (Request_Handle{}) {
			return assignment
		}
	}

	panic("no bounded assignment")
}
bootstrap_complete_model :: proc(s: ^Client_State, r: ^runtime_async.Runtime, request: Request_Handle) {
	response := surf.Response {
		status = 200,
	} 	// Pure model fixture, no received HTTP claim.
	disposal, error := kernel_begin_complete(&s.kernel, request, &response, {})
	assert(error.kind == .None)

	for {
		origin := disposal.origin.origin
		request_disposal_destroy(&disposal)

		if origin.slot != 0 {
			assert(kernel_origin_cleanup_finish(&s.kernel, origin).kind == .None)
		}

		next, done, cause := kernel_cleanup_finish(&s.kernel, request, runtime_async.deadline_after(r, 0))
		assert(cause.kind == .None)
		disposal = next

		if done {
			break
		}
	}

	assert(kernel_release(&s.kernel, request).kind == .None)
}
@(test)
bootstrap_assignment_handoff_moves_ids_once_and_accepts_real_idle_reuse :: proc(t: ^testing.T) {
	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)
	config := bootstrap_config({}, 1)
	config.http.setup_timeout = 5 * time.Millisecond
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}
	config.http.resolver.name_servers = servers[:]
	state, error := network_prepare(&runtime, config, context.allocator)
	assert(error.kind == .None)
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
	request := bootstrap_queued(state, &runtime, "http://mailbox.example/path")
	assignment := bootstrap_dispatch(state, &runtime)
	actor := &state.actors[0]
	actor.command = {
		assignment = assignment,
		pending    = true,
	}

	metadata := &state.requests[int(request.slot) - 1]
	_, missing := network_assignment_take(actor)
	testing.expect_value(t, missing.kind, .Pending)
	block, draw := bank_reserve(state, 1)
	assert(draw.kind == .None && block.count == 1)
	metadata.ids = block
	block = {}
	expected := metadata.ids

	for mode in 0 ..< 4 {
		original := actor.command.assignment
		generation := metadata.generation

		switch mode {
		case 0:
			actor.command.assignment.request.owner_id += 1
		case 1:
			actor.command.assignment.session.generation += 1
		case 2:
			metadata.generation += 1
		case 3:
			metadata.ids.count = 17
		}

		_, rejected := network_assignment_take(actor)
		testing.expect(t, rejected.kind == .Invalid_Handle || rejected.kind == .Invalid_State)
		testing.expect(t, actor.command.pending)
		actor.command.assignment = original
		metadata.generation = generation
		metadata.ids = expected
	}

	source_url := raw_data(state.kernel.requests[int(request.slot) - 1].input.request.url)
	taken, take_error := network_assignment_take(actor)
	assert(take_error.kind == .None)
	testing.expect(t, taken.ids == expected && metadata.ids == (DNS_ID_Block{}) && !actor.command.pending)
	testing.expect_value(t, metadata.query_budget_left, 31)
	testing.expect_value(t, raw_data(taken.request.url), source_url)
	testing.expect_value(t, taken.host, "mailbox.example")
	testing.expect_value(t, taken.port, u16(80))
	testing.expect_value(t, taken.cutoff, state.kernel.requests[int(request.slot) - 1].deadline)
	testing.expect(t, taken.setup_cutoff.at <= taken.cutoff.at && taken.setup_cutoff.epoch == taken.cutoff.epoch)
	_, duplicate := network_assignment_take(actor)
	testing.expect_value(t, duplicate.kind, .Pending)
	bank_burn(state, &taken.ids)
	assert(
		pool_session_state(&state.kernel, assignment.session, .Busy, runtime_async.deadline_after(&runtime, 0).at).kind ==
		.None,
	)
	bootstrap_complete_model(state, &runtime, request)
	assert(
		pool_session_state(&state.kernel, assignment.session, .Idle, runtime_async.deadline_after(&runtime, 0).at).kind ==
		.None,
	)
	reused_request := bootstrap_queued(state, &runtime, "http://mailbox.example/path")
	reused := bootstrap_dispatch(state, &runtime)
	testing.expect_value(t, reused.session, assignment.session)
	testing.expect_value(t, state.kernel.sessions[int(reused.session.slot) - 1].state, .Busy)
	next := &state.requests[int(reused_request.slot) - 1]
	next^ = {
		generation        = reused_request.generation,
		query_budget_left = 32,
	}

	actor.command = {
		assignment = reused,
		pending    = true,
	}

	idle, take_idle := network_assignment_take(actor)
	assert(take_idle.kind == .None)
	testing.expect(t, idle.ids.count == 0 && idle.address_count == 0 && idle.assignment.request == reused_request)
	bootstrap_complete_model(state, &runtime, reused_request)
	assert(
		pool_session_state(&state.kernel, reused.session, .Retiring, runtime_async.deadline_after(&runtime, 0).at).kind ==
		.None,
	)
	assert(pool_retire(&state.kernel, reused.session).kind == .None)
	assert(runtime_async.destroy(&runtime).kind == .None)
	sync.lock(&state.mu)
	state.base_owned = false
	sync.unlock(&state.mu)
	network_state_release(state)
	fmt.println(
		"BOOTSTRAP16 actual_mailbox_handoffs=2 atomic_handoff_rejections=4 connecting_real_id_move=true reused_busy_ids0=true protocol_io=0",
	)
}
