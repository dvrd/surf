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
import http "shared:async/http"
import "core:thread"
import "core:bytes"
import "core:crypto/x509"
import "core:os"
import "core:sys/posix"

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
		testing.expect_value(t, completion.error.transport, net.Connection_Error.Cancelled)

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
	testing.expect_value(t, completion.error.transport, net.Connection_Error.Cancelled)
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

Conc_Gate :: struct {
	backing:                  mem.Allocator,
	armed, entered, released: int,
}
conc_allocate :: proc(
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
	g := cast(^Conc_Gate)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		_, won := intrinsics.atomic_compare_exchange_strong(&g.armed, 1, 0)

		if won {
			intrinsics.atomic_store(&g.entered, 1)
			started := time.tick_now()

			for intrinsics.atomic_load(&g.released) == 0 {
				assert(time.tick_since(started) < 5 * time.Second)
				thread.yield()
			}
		}
	}
	return g.backing.procedure(g.backing.data, mode, size, alignment, old_memory, old_size, location)
}
Conc_Fixture :: struct {
	track:   mem.Tracking_Allocator,
	scope:   scopes.Scope,
	runtime: runtime_async.Runtime,
	client:  Client,
	gate:    Conc_Gate,
}
conc_init :: proc(f: ^Conc_Fixture) {
	mem.tracking_allocator_init(&f.track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&f.track)
	scope, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
	assert(error == .None)
	f.scope = scope
	f.gate.backing = allocator
	assert(
		runtime_async.init(&f.runtime, {workers = 1, task_capacity = 3, io_capacity = 1, allocator = allocator}).kind ==
		.None,
	)
	config := Client_Config {
		http = {allow_http = true, timeout = 30 * time.Second, scope = scope},
		capacities = Capacities {
			requests = 8,
			origins = 1,
			connections = 2,
			connections_per_origin = 1,
			waiters_per_origin = 8,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}

	assert(client_init(&f.client, &f.runtime, config, {conc_allocate, &f.gate}).kind == .None)
}
Conc_Producer :: struct {
	client:                          ^Client,
	handles:                         [64]Request_Handle,
	accepted, rejected, closed, bad: int,
}
conc_produce :: proc(p: ^Conc_Producer) {
	for i in 0 ..< len(p.handles) {
		body := [3]u8{'a', u8(i), 'z'}
		fields := [1]http.Header{{name = "X-Producer", value = "original"}}
		request := http.Request {
			method  = .POST,
			url     = "http://bank-empty.invalid/owned",
			headers = fields[:],
			body    = body[:],
		}

		h, error := client_submit(p.client, request)

		if error.kind == .None {
			p.handles[p.accepted] = h
			p.accepted += 1
		} else {
			p.rejected += 1

			if error.kind == .Closed {
				p.closed += 1
			} else if error.kind != .Capacity && error.kind != .Budget_Rejected {
				p.bad += 1
			}

			if h != (Request_Handle{}) {
				p.bad += 1
			}
		}

		if body[0] != 'a' || body[1] != u8(i) || body[2] != 'z' || fields[0].value != "original" {
			p.bad += 1
		}
	}
}
Conc_Consumer :: struct {
	client:     ^Client,
	handles:    [8]Request_Handle,
	count, bad: int,
}
conc_consume :: proc(c: ^Conc_Consumer) {
	for {
		completion, available := client_poll(c.client)

		if !available {
			break
		}

		assert(c.count < len(c.handles))
		c.handles[c.count] = completion.request
		c.count += 1

		if completion.error.transport != net.Connection_Error.Cancelled {
			c.bad += 1
		}

		response: surf.Response

		if client_take(c.client, completion.request, &response).kind != .Request_Error {
			c.bad += 1
		}

		if response.status != 0 || response.body != nil {
			c.bad += 1
		}

		if client_release(c.client, completion.request).kind != .None {
			c.bad += 1
		}
	}
}
conc_collect :: proc(f: ^Conc_Fixture, producers: []Conc_Producer, expected: int, t: ^testing.T) {
	consumers: [4]Conc_Consumer
	workers: [4]^thread.Thread

	for &consumer, i in consumers {
		consumer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&consumer, conc_consume)
		assert(workers[i] != nil)
	}

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	total := 0

	for consumer in consumers {
		total += consumer.count
		testing.expect_value(t, consumer.bad, 0)
	}

	testing.expect_value(t, total, expected)

	for &producer in producers {
		for h in producer.handles[:producer.accepted] {
			seen := 0

			for &consumer in consumers {
				for actual in consumer.handles[:consumer.count] {
					if actual == h {
						seen += 1
					}
				}
			}

			testing.expect_value(t, seen, 1)
			testing.expect(
				t,
				client_cancel(&f.client, h).kind == .Invalid_Handle &&
				client_release(&f.client, h).kind == .Invalid_Handle,
			)
		}
	}

	_, again := client_poll(&f.client)
	testing.expect(t, !again)
}
conc_destroy :: proc(f: ^Conc_Fixture, t: ^testing.T, runtime_destroyed: bool = false) {
	testing.expect(t, client_quiescent(&f.client))
	testing.expect_value(t, client_destroy(&f.client).kind, .None)

	if !runtime_destroyed {
		testing.expect_value(t, runtime_async.destroy(&f.runtime).kind, .None)
	}

	snapshot, error := scopes.snapshot(f.scope)
	testing.expect(t, error == .None && snapshot.used == (scopes.Usage{}))
	scopes.release_scope(&f.scope)
	testing.expect(t, f.track.current_memory_allocated == 0 && len(f.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&f.track)
}

@(test)
public_concurrency_prestart_bounded_producers_and_parallel_terminal_consumers :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	f: Conc_Fixture
	conc_init(&f)
	producers: [4]Conc_Producer
	workers: [4]^thread.Thread

	for &producer, i in producers {
		producer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&producer, conc_produce)
		assert(workers[i] != nil)
	}

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	accepted, rejected := 0, 0

	for producer in producers {
		accepted += producer.accepted
		rejected += producer.rejected
		testing.expect_value(t, producer.bad, 0)
	}

	testing.expect(t, accepted == 8 && rejected == 248)
	stats, valid := client_stats(&f.client)
	testing.expect(
		t,
		valid &&
		stats.queued_requests == 8 &&
		stats.dns_waiters == 8 &&
		stats.reserved_connections == 0 &&
		stats.tasks == 3,
	)
	testing.expect_value(t, client_close(&f.client).kind, .None)
	testing.expect(t, client_quiescent(&f.client) && client_destroy(&f.client).kind == .Pending)
	conc_collect(&f, producers[:], accepted, t)
	conc_destroy(&f, t)
	fmt.println(
		"PUBLIC_CONCURRENCY producer_threads=4 attempts=256 accepted=8 consumer_threads=4 terminal_once=true protocol_io=0",
	)
}

@(test)
public_concurrency_shutdown_while_producer_is_in_real_allocation_callback :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	f: Conc_Fixture
	conc_init(&f)
	seed, error := client_submit(&f.client, {method = .GET, url = "http://bank-empty.invalid/seed"})
	assert(error.kind == .None)
	assert(runtime_async.start(&f.runtime).kind == .None)
	intrinsics.atomic_store(&f.gate.armed, 1)
	producers: [4]Conc_Producer
	workers: [4]^thread.Thread

	for &producer, i in producers {
		producer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&producer, conc_produce)
		assert(workers[i] != nil)
	}

	started := time.tick_now()

	for intrinsics.atomic_load(&f.gate.entered) == 0 {
		assert(time.tick_since(started) < 5 * time.Second)
		thread.yield()
	}

	// This is an actual out-of-lock producer callback, not a guessed timing race.
	runtime_async.shutdown(&f.runtime)
	closing := client_close(&f.client)
	testing.expect_value(t, closing.kind, .Pending)
	intrinsics.atomic_store(&f.gate.released, 1)

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	accepted, rejected, closed := 1, 0, 0

	for producer in producers {
		accepted += producer.accepted
		rejected += producer.rejected
		closed += producer.closed
		testing.expect_value(t, producer.bad, 0)
	}

	testing.expect(t, accepted <= 8 && accepted + rejected == 257 && closed > 0)
	assert(runtime_async.join(&f.runtime).kind == .None)
	assert(runtime_async.destroy(&f.runtime).kind == .None)
	records: [5]Conc_Producer

	for producer, i in producers {
		records[i] = producer
	}

	records[4].handles[0] = seed
	records[4].accepted = 1
	conc_collect(&f, records[:], accepted, t)
	conc_destroy(&f, t, true)
	fmt.printf(
		"PUBLIC_CONCURRENCY shutdown_during_clone_callback=true producers=4 seeded=1 accepted=%d rejected=%d closed=%d runtime_gone_before_results=true protocol_io=0\n",
		accepted,
		rejected,
		closed,
	)
}

schema_caps :: proc() -> Capacities {
	return {
		requests = 32,
		origins = 16,
		connections = 8,
		connections_per_origin = 2,
		waiters_per_origin = 32,
		dns_ids = 256,
		work_per_resume = 128,
	}
}

schema_normalize :: proc(input: Client_Config) -> (Normalized_Config, Client_Error) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous

	return config_normalize(input)
}

@(test)
schema_defaults_and_explicit_zero_are_distinct :: proc(t: ^testing.T) {
	normalized, error := schema_normalize({})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.capacities, schema_caps())
	testing.expect_value(t, normalized.request_timeout, 30 * time.Second)
	testing.expect_value(t, normalized.response_body_limit, 8 << 20)
	testing.expect_value(t, normalized.idle_timeout, 30 * time.Second)
	testing.expect_value(t, normalized.max_age, 5 * time.Minute)
	testing.expect_value(t, normalized.lifetime, runtime_async.Deadline{})
	caps := schema_caps()
	caps.dns_ids = 0
	caps.waiters_per_origin = 0
	normalized, error = schema_normalize(
		{
			capacities = caps,
			idle_timeout = time.Nanosecond,
			max_age = time.Nanosecond,
			http = {timeout = 7 * time.Second, max_body_size = 17, setup_timeout = 2 * time.Second},
		},
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.capacities, caps)
	testing.expect_value(t, normalized.idle_timeout, time.Nanosecond)
	testing.expect_value(t, normalized.max_age, time.Nanosecond)
	testing.expect_value(t, normalized.request_timeout, 7 * time.Second)
	testing.expect_value(t, normalized.response_body_limit, 17)
	testing.expect_value(t, normalized.http.setup_timeout, 2 * time.Second)
	_, error = schema_normalize({capacities = Capacities{}})
	testing.expect_value(t, error.kind, .Invalid_Config)
}

@(test)
schema_capacity_hard_bounds_and_coupling :: proc(t: ^testing.T) {
	// Independent published limits. Start at the complete maximum so each isolated
	// field boundary is not accidentally rejected by another field's dependency.
	maximum := Capacities {
		requests               = 4096,
		origins                = 1024,
		connections            = 256,
		connections_per_origin = 256,
		waiters_per_origin     = 4096,
		dns_ids                = 65536,
		work_per_resume        = 4096,
	}

	normalized, error := schema_normalize({capacities = maximum})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.capacities, maximum)
	lowers := [7]int{1, 1, 1, 1, 0, 0, 1}
	uppers := [7]int{4096, 1024, 256, 256, 4096, 65536, 4096}

	for field in 0 ..< 7 {
		lower := lowers[field]
		upper := uppers[field]

		for value in ([6]int{lower, upper, lower - 1, upper + 1, min(int), max(int)}) {
			caps := maximum
			fields :=
				([7]^int {
						&caps.requests,
						&caps.origins,
						&caps.connections,
						&caps.connections_per_origin,
						&caps.waiters_per_origin,
						&caps.dns_ids,
						&caps.work_per_resume,
					})
			fields[field]^ = value
			// Keep dependent fields legal when reducing their parent's capacity.
			if field == 0 {
				caps.waiters_per_origin = 0
			}

			if field == 2 {
				caps.connections_per_origin = 1
			}

			_, cause := schema_normalize({capacities = caps})
			want := Client_Error_Kind.None

			if value < lower || value > upper {
				want = .Invalid_Config
			}

			testing.expect_value(t, cause.kind, want)
		}
	}

	caps := schema_caps()
	caps.connections_per_origin = caps.connections + 1
	_, error = schema_normalize({capacities = caps})
	testing.expect_value(t, error.kind, .Invalid_Config)
	caps = schema_caps()
	caps.waiters_per_origin = caps.requests + 1
	_, error = schema_normalize({capacities = caps})
	testing.expect_value(t, error.kind, .Invalid_Config)
	caps = {
		requests               = 1,
		origins                = 1,
		connections            = 1,
		connections_per_origin = 1,
		waiters_per_origin     = 0,
		dns_ids                = 0,
		work_per_resume        = 1,
	}

	normalized, error = schema_normalize({capacities = caps})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.capacities, caps)
}

@(test)
schema_duration_and_lifetime_shape_without_runtime_claim :: proc(t: ^testing.T) {
	for duration in ([3]time.Duration{-1, min(time.Duration), -time.Second}) {
		_, error := schema_normalize({idle_timeout = duration})
		testing.expect_value(t, error.kind, .Invalid_Config)
		_, error = schema_normalize({max_age = duration})
		testing.expect_value(t, error.kind, .Invalid_Config)
	}

	for deadline in ([4]runtime_async.Deadline {
			{},
			{epoch = 1, at = 1},
			{epoch = max(u64), at = max(i64)},
			{epoch = 1, at = max(i64)},
		}) {
		normalized, error := schema_normalize(
			{lifetime = deadline, idle_timeout = max(time.Duration), max_age = max(time.Duration)},
		)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, normalized.lifetime, deadline)
		testing.expect_value(t, normalized.idle_timeout, max(time.Duration))
	}

	for deadline in ([5]runtime_async.Deadline {
			{at = 1},
			{at = -1},
			{epoch = 1},
			{epoch = 1, at = -1},
			{epoch = max(u64), at = min(i64)},
		}) {
		_, error := schema_normalize({lifetime = deadline})
		testing.expect_value(t, error.kind, .Invalid_Config)
	}

	// Numeric epoch/time values above are intentionally not compared with a clock:
	// runtime identity and actual expiry admission belong to the network phase.
}

@(test)
schema_root_http_and_alpn_policy_preserved :: proc(t: ^testing.T) {
	invalid := [?]surf.Config {
		{max_body_size = -1},
		{max_body_size = http.MAX_BODY_SIZE + 1},
		{max_redirects = -1},
		{max_redirects = http.MAX_REDIRECTS + 1},
		{timeout = -1},
		{setup_timeout = -1},
	}

	for config in invalid {
		_, error := schema_normalize({http = config})
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, error.http.kind, surf.config_validate(config).kind)
	}

	normalized, error := schema_normalize(
		{
			http = {
				max_body_size = http.MAX_BODY_SIZE,
				max_redirects = http.MAX_REDIRECTS,
				timeout = max(time.Duration),
				setup_timeout = max(time.Duration),
				allow_http = true,
			},
		},
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.response_body_limit, http.MAX_BODY_SIZE)
	testing.expect_value(t, normalized.request_timeout, max(time.Duration))
	testing.expect_value(t, normalized.http.allow_http, true)

	for offers in ([5][]string{{"h3"}, {"h2", "h3"}, {"http/1.1", "h3"}, {""}, {"http/2"}}) {
		_, error = schema_normalize({http = {tls = {alpn_protocols = offers}}})
		testing.expect_value(t, error.kind, .Invalid_Config)
	}

	for offers in ([3][]string{{"http/1.1"}, {"h2"}, {"http/1.1", "h2"}}) {
		accepted, accepted_error := schema_normalize({http = {tls = {alpn_protocols = offers}}})
		testing.expect_value(t, accepted_error.kind, .None)
		testing.expect_value(t, raw_data(accepted.http.tls.alpn_protocols), raw_data(offers))
	}

	normalized, error = schema_normalize({})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, len(normalized.http.tls.alpn_protocols), 0)
	_, error = schema_normalize({http = {tls = {handshake_timeout = -1}}})
	testing.expect_value(t, error.kind, .Invalid_Config)
}

@(test)
schema_dns_snapshot_bounds_and_scalar_handles :: proc(t: ^testing.T) {
	servers: [9]net.Endpoint

	for &server in servers {
		server = {
			address = net.IP4_Address{127, 0, 0, 1},
			port    = 53,
		}
	}

	for count in ([3]int{0, 1, 8}) {
		normalized, error := schema_normalize({http = {resolver = {name_servers = servers[:count]}}})
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, len(normalized.http.resolver.name_servers), count)
		if count > 0 {
			testing.expect_value(t, raw_data(normalized.http.resolver.name_servers), raw_data(servers[:count]))
		}
	}

	_, error := schema_normalize({http = {resolver = {name_servers = servers[:]}}})
	testing.expect_value(t, error.kind, .Invalid_Config)

	for port in ([5]int{0, -1, 65536, min(int), max(int)}) {
		servers[0].port = port
		_, error = schema_normalize({http = {resolver = {name_servers = servers[:1]}}})
		testing.expect_value(t, error.kind, .Invalid_Config)
	}

	servers[0].port = 65535
	_, error = schema_normalize({http = {resolver = {name_servers = servers[:1]}}})
	testing.expect_value(t, error.kind, .None)
	handle := Request_Handle{}
	testing.expect_value(t, handle.owner_id, u64(0))
	testing.expect_value(t, handle.slot, u32(0))
	testing.expect_value(t, handle.generation, u64(0))
	handle = {
		owner_id   = max(u64),
		slot       = max(u32),
		generation = max(u64),
	}

	alias := handle
	testing.expect_value(t, alias, handle)
	// Scalar construction proves no validity/admission or lifetime behavior.
	completion := Completion {
		request = handle,
	}

	testing.expect_value(t, completion.request, handle)
}

@(test)
schema_scope_is_borrowed_without_admission :: proc(t: ^testing.T) {
	owner, cause := scopes.create_root({bytes = 0, streams = 0, jobs = 0}, context.allocator)
	testing.expect_value(t, cause, .None)
	defer scopes.release_scope(&owner)
	before, _ := scopes.snapshot(owner)
	normalized, error := schema_normalize({http = {scope = owner}})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.http.scope, owner)
	after, _ := scopes.snapshot(owner)
	testing.expect_value(t, after, before)
	testing.expect_value(t, scopes.close(owner), .None)
	closed_before, _ := scopes.snapshot(owner)
	normalized, error = schema_normalize({http = {scope = owner}})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, normalized.http.scope, owner)
	closed_after, _ := scopes.snapshot(owner)
	testing.expect_value(t, closed_after, closed_before)
	// Normalization borrows metadata only. No positive/closed resource admission
	// is inferred; the later resource constructor enforces that contract.
	_, error = schema_normalize({http = {allocator_scope = owner}})
	testing.expect_value(t, error.kind, .Invalid_Config)
}

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

network_schema_normalize :: proc(input: Normalized_Config) -> (Network_Config, Client_Error) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous

	return network_config_normalize(input)
}
network_schema_base :: proc() -> Normalized_Config {
	result, error := config_normalize({})
	assert(error.kind == .None)

	return result
}
network_schema_reject :: proc(t: ^testing.T, input: Normalized_Config) {
	result, error := network_schema_normalize(input)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, result.task_count, 0)
	testing.expect_value(t, result.state_bytes, 0)
	testing.expect_value(t, result.actor_storage_bytes, 0)
	testing.expect_value(t, result.request_storage_bytes, 0)
	testing.expect_value(t, result.task_index_bytes, 0)
	testing.expect_value(t, result.dns_storage_bytes, 0)
	testing.expect_value(t, result.config.request_timeout, time.Duration(0))
	testing.expect_value(t, raw_data(result.config.http.resolver.name_servers), nil)
}

@(test)
network_schema_dns_intent_is_original_borrowed_policy :: proc(t: ^testing.T) {
	input := network_schema_base()
	result, error := network_schema_normalize(input)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result.dns_preparation, .System)
	testing.expect_value(t, result.task_count, 9)
	testing.expect_value(
		t,
		result.resolver_limits,
		net.Resolver_Snapshot_Limits{256 << 10, 4 << 10, 1024, 64 << 10, 8},
	)
	servers: [9]net.Endpoint

	for &server in servers {
		server = {net.IP4_Loopback, 53}
	}

	servers[7] = {net.IP6_Loopback, 65535}

	for count in ([2]int{1, 8}) {
		input.http.resolver.name_servers = servers[:count]
		result, error = network_schema_normalize(input)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, result.dns_preparation, .Explicit)
		testing.expect_value(t, raw_data(result.config.http.resolver.name_servers), raw_data(servers[:count]))
		testing.expect_value(t, len(result.config.http.resolver.name_servers), count)
		testing.expect_value(t, servers[0].port, 53)
		testing.expect_value(t, servers[7].port, 65535)
		input.capacities.dns_ids = 0
		result, error = network_schema_normalize(input)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, result.dns_preparation, .Numeric_Only)
		testing.expect_value(t, result.dns_storage_bytes, 0)
		testing.expect_value(t, raw_data(result.config.http.resolver.name_servers), raw_data(servers[:count]))
		input.capacities.dns_ids = 256
	}

	input.http.resolver.name_servers = servers[:0]
	// Explicit-empty must reject BEFORE profile_init collapses empty views to nil.
	testing.expect(t, raw_data(input.http.resolver.name_servers) != nil)
	network_schema_reject(t, input)
	input.capacities.dns_ids = 0
	network_schema_reject(t, input)
	input.http.resolver.name_servers = nil
	result, error = network_schema_normalize(input)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result.dns_preparation, .Numeric_Only)
	input.capacities.dns_ids = 256
	input.http.resolver.name_servers = servers[:]
	network_schema_reject(t, input)
	input.http.resolver.name_servers = servers[:1]

	for port in ([5]int{0, -1, 65536, min(int), max(int)}) {
		servers[0].port = port
		network_schema_reject(t, input)
	}

	servers[0].port = 53
	servers[0].address = nil
	network_schema_reject(t, input)
	fmt.println("NETWORK_SCHEMA dns_intent_original=true explicit_empty_rejected_before_profile=true")
}

@(test)
network_schema_rejects_forged_normalization_and_invalid_redirect_policy :: proc(t: ^testing.T) {
	for field in 0 ..< 4 {
		for value in ([4]i64{0, -1, min(i64), max(i64)}) {
			input := network_schema_base()

			switch field {
			case 0:
				input.request_timeout = time.Duration(value)
			case 1:
				input.response_body_limit = int(value)
			case 2:
				input.idle_timeout = time.Duration(value)
			case 3:
				input.max_age = time.Duration(value)
			}

			// Positive idle/age values are already valid normalization, even at max.
			if field >= 2 && value == max(i64) {
				_, error := network_schema_normalize(input)
				testing.expect_value(t, error.kind, .None)
			} else {
				network_schema_reject(t, input)
			}
		}
	}

	input := network_schema_base()
	input.request_timeout += 1
	network_schema_reject(t, input)
	input = network_schema_base()
	input.response_body_limit += 1
	network_schema_reject(t, input)

	for redirects in 0 ..= 5 {
		input = network_schema_base()
		input.http.max_redirects = redirects
		result, error := network_schema_normalize(input)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, result.config.http.max_redirects, redirects)
	}

	for redirects in ([3]int{-1, 6, max(int)}) {
		input = network_schema_base()
		input.http.max_redirects = redirects
		network_schema_reject(t, input)
	}

	input = network_schema_base()
	input.http.tls.alpn_protocols = []string{"h3"}
	network_schema_reject(t, input)
	input = network_schema_base()
	input.http.timeout = -1
	network_schema_reject(t, input)
	input = network_schema_base()
	input.lifetime = {
		at = 1,
	}

	network_schema_reject(t, input)
}

@(test)
network_schema_descriptor_shapes_reject_before_borrowed_traversal :: proc(t: ^testing.T) {
	cases := 0

	for length in ([3]int{-1, 1, max(int)}) {
		for field in 0 ..< 5 {
			input := network_schema_base()

			switch field {
			case 0:
				(cast(^mem.Raw_Slice)&input.http.resolver.name_servers)^ = {
					data = nil,
					len  = length,
				}
			case 1:
				(cast(^mem.Raw_Slice)&input.http.tls.alpn_protocols)^ = {
					data = nil,
					len  = length,
				}
			case 2:
				(cast(^mem.Raw_Slice)&input.http.tls.root_cas)^ = {
					data = nil,
					len  = length,
				}
			case 3:
				(cast(^mem.Raw_String)&input.http.tls.server_name)^ = {
					data = nil,
					len  = length,
				}
			case 4:
				offer: string
				(cast(^mem.Raw_String)&offer)^ = {
					data = nil,
					len  = length,
				}

				offers := [1]string{offer}
				input.http.tls.alpn_protocols = offers[:]
				network_schema_reject(t, input)
				cases += 1
				continue
			}

			network_schema_reject(t, input)
			cases += 1
		}
	}

	testing.expect_value(t, cases, 15)
	fmt.println("NETWORK_SCHEMA malformed_descriptor_cells=15 noalloc=true")
}

@(test)
network_schema_actual_owner_sizing_and_finite_dns_workspace_bounds :: proc(t: ^testing.T) {
	for caps in ([3]Capacities {
			{1, 1, 1, 1, 0, 0, 1},
			{32, 16, 8, 2, 32, 256, 128},
			{4096, 1024, 256, 256, 4096, 65536, 4096},
		}) {
		input := network_schema_base()
		input.capacities = caps
		result, error := network_schema_normalize(input)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, result.task_count, caps.connections + 1)
		testing.expect_value(t, result.state_bytes, size_of(Client_State))
		testing.expect_value(t, result.actor_storage_bytes, caps.connections * size_of(Session_Actor))
		testing.expect_value(t, result.request_storage_bytes, caps.requests * size_of(Request_Network))
		testing.expect_value(t, result.task_index_bytes, (caps.connections + 1) * size_of(^runtime_async.Task))
		testing.expect_value(t, result.dns_storage_bytes, caps.dns_ids * 2)
	}

	for field in 0 ..< 7 {
		for extreme in ([2]int{min(int), max(int)}) {
			input := network_schema_base()
			fields := [7]^int {
				&input.capacities.requests,
				&input.capacities.origins,
				&input.capacities.connections,
				&input.capacities.connections_per_origin,
				&input.capacities.waiters_per_origin,
				&input.capacities.dns_ids,
				&input.capacities.work_per_resume,
			}

			fields[field]^ = extreme
			network_schema_reject(t, input)
		}
	}

	testing.expect_value(t, DNS_IDS_PER_QUERY, 16)
	testing.expect_value(t, DNS_TOTAL_QUERY_LIMIT, 32)
	testing.expect_value(t, DNS_MESSAGE_LIMIT, 64)
	testing.expect_value(t, DNS_ROUNDS, 2)
	testing.expect_value(t, DNS_ATTEMPT_TIMEOUT, time.Second)
	actor := new(Session_Actor)
	defer free(actor)
	request: Request_Network
	state: Client_State
	testing.expect_value(t, len(actor.dns_tx), 4096)
	testing.expect_value(t, len(actor.dns_rx), 4096)
	testing.expect_value(t, len(actor.dns_aliases), 9)
	testing.expect_value(t, len(actor.dns_results), 64)
	testing.expect_value(t, len(actor.dns_servers), 8)
	testing.expect_value(t, len(actor.prepared_addresses), 64)
	testing.expect_value(t, len(request.prepared_addresses), 64)
	testing.expect_value(t, len(request.ids.values), 16)
	testing.expect_value(t, state.references, u64(0))
	testing.expect_value(t, state.base_owned, false)
	testing.expect_value(t, state.registered_tasks, 0)
	testing.expect_value(t, state.runtime, nil)
	testing.expect_value(t, state.coordinator.owner, nil)
	testing.expect_value(t, actor.owner, nil)
	testing.expect_value(t, actor.owner_drained, false)
	// Layout/defaults certify no construction, registration, DNS or lifecycle work.
	fmt.println("NETWORK_SCHEMA bounded_sizing_profiles=3 workspace_only=true native_execution=0")
}

@(test)
network_schema_borrows_policy_and_scope_without_retaining_or_admitting :: proc(t: ^testing.T) {
	scope, cause := scopes.create_root({bytes = 0, streams = 0, jobs = 0}, context.allocator)
	assert(cause == .None)
	defer scopes.release_scope(&scope)
	input := network_schema_base()
	input.http.scope = scope
	roots := [1]^x509.Certificate{nil}
	offers := [1]string{"http/1.1"}
	input.http.tls.root_cas = roots[:]
	input.http.tls.alpn_protocols = offers[:]
	input.http.tls.server_name = "borrowed.example"

	for closed in 0 ..< 2 {
		if closed == 1 {
			assert(scopes.close(scope) == .None)
		}

		before, _ := scopes.snapshot(scope)
		result, error := network_schema_normalize(input)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, result.config.http.scope, scope)
		testing.expect_value(t, raw_data(result.config.http.tls.root_cas), raw_data(roots[:]))
		testing.expect_value(t, raw_data(result.config.http.tls.alpn_protocols), raw_data(offers[:]))
		testing.expect_value(t, raw_data(result.config.http.tls.server_name), raw_data(input.http.tls.server_name))
		after, _ := scopes.snapshot(scope)
		testing.expect_value(t, after, before)
	}

	input.http.allocator_scope = scope
	network_schema_reject(t, input)
}

@(test)
network_snapshot_error_keeps_each_dns_code :: proc(t: ^testing.T) {
	hostname := network_snapshot_error(net.Resolver_Snapshot_General_Error.Invalid_Hostname)
	testing.expect_value(t, hostname.kind, .Invalid_Config)
	testing.expect_value(t, hostname.http.kind, .Dial_Failed)
	host_code, host_ok := hostname.http.network.(net.DNS_Error)
	testing.expect(t, host_ok && host_code == .Invalid_Hostname_Error)

	servers := network_snapshot_error(net.Resolver_Snapshot_General_Error.No_Servers)
	testing.expect_value(t, servers.kind, .Invalid_Config)
	server_code, server_ok := servers.http.network.(net.DNS_Error)
	testing.expect(t, server_ok && server_code == .Invalid_Resolv_Config_Error)

	parsed := network_snapshot_error(net.Resolver_Snapshot_General_Error.Parse_Failed)
	testing.expect_value(t, parsed.http.kind, .Dial_Failed)
	parsed_code, parsed_ok := parsed.http.network.(net.DNS_Error)
	testing.expect(t, parsed_ok && parsed_code == .Invalid_Hosts_Config_Error)

	undersized := network_snapshot_error(net.Resolver_Snapshot_General_Error.Destination_Undersized)
	testing.expect_value(t, undersized.kind, .Capacity)
	testing.expect_value(t, undersized.http.kind, .Dial_Failed)
	testing.expect(t, undersized.http.network == nil)

	platform := network_snapshot_error(os.Error(os.Platform_Error(posix.Errno.EIO)))
	testing.expect_value(t, platform.kind, .Error)
	testing.expect_value(t, platform.runtime.kind, .System_Error)
	testing.expect_value(t, platform.runtime.system_code, i32(posix.Errno.EIO))
	platform_code, platform_ok := platform.http.network.(net.DNS_Error)
	testing.expect(t, platform_ok && platform_code == .System_Error)
}
