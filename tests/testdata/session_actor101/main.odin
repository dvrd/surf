package main

import sa "shared:surf/async"
import surf "shared:surf"
import http "shared:http"
import async "shared:async"
import signal "shared:async/signal"
import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import scopes "core:sync/budget"
import "core:strconv"
import "core:sync"
import "core:sys/posix"
import "core:time"

Record :: struct {
	label:                    string,
	handle:                   sa.Request_Handle,
	session:                  sa.Cell_Handle,
	deadline:                 async.Deadline,
	done:                     bool,
	error:                    surf.HTTP_Error,
	status, body, connection: int,
	completed_at:             i64,
	requested_cutoff:         i64,
}
Fixture :: struct {
	runtime:                             async.Runtime,
	state:                               ^sa.Client_State,
	roots:                               tls.Root_Pool,
	allocator:                           mem.Allocator,
	scope:                               scopes.Scope,
	endpoint, dns:                       net.Endpoint,
	mode, dir:                           string,
	encrypted:                           bool,
	lifetime:                            async.Deadline,
	records:                             [4]Record,
	count:                               int,
	held:                                surf.Response,
	task_addresses:                      [2]^async.Task,
	signals:                             [2]signal.Signal,
	pins:                                [2]int,
	resumes:                             [2]u64,
	done:                                [2]int,
	coordinator_done:                    int,
	helper:                              async.Task,
	helper_started, helper_release:      sync.Sema,
	helper_thread, helper_done, workers: int,
}
fixture: ^Fixture
fd_count :: proc() -> int {
	count := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			count += 1
		}
	}

	return count
}
// Fixture controller owns Runtime until final destroy, independently of State's
// registered witness. Completion timestamps remain safe after automatic task
// retirement; this is not a public Client clock implementation.
now :: proc(f: ^Fixture) -> async.Deadline {
	return async.deadline_after(&f.runtime, 0)
}
path :: proc(f: ^Fixture, name: string) -> string {
	return fmt.tprintf("%s/%s", f.dir, name)
}
mark :: proc(f: ^Fixture, name: string) {
	assert(os.write_entire_file(path(f, name), name) == nil)
}
wait_file :: proc(f: ^Fixture, name: string) {
	start := time.tick_now()

	for !os.exists(path(f, name)) {
		assert(time.tick_since(start) < 8 * time.Second)
		time.sleep(time.Millisecond)
	}
}
coordinator_wait :: proc(_: rawptr) -> async.Resume_Result {
	return .Waiting
}
coordinator_cancel :: proc(data: rawptr) -> async.Resume_Result {
	coordinator := cast(^sa.Coordinator_State)data
	s := coordinator.owner
	sync.lock(&s.mu)
	s.coordinator.done = true
	sync.unlock(&s.mu)

	return .Done
}
coordinator_done :: proc(data: rawptr) {
	coordinator := cast(^sa.Coordinator_State)data
	assert(!async.is_current_task(&coordinator.task))
	sa.network_task_done(coordinator.owner, 0, true)
	intrinsics.atomic_add(&fixture.coordinator_done, 1)
}
actor_observe :: proc(actor: ^sa.Session_Actor, entry_thread: int) {
	index := int(actor.index) - 1
	id := sync.current_thread_id()
	assert(id == entry_thread)

	if fixture.pins[index] == 0 {
		fixture.pins[index] = id
	} else {
		assert(fixture.pins[index] == id)
	}

	fixture.resumes[index] += 1
	assert(&actor.task == fixture.task_addresses[index] && actor.wake == fixture.signals[index])
}
actor_resume :: proc(data: rawptr) -> async.Resume_Result {
	id := sync.current_thread_id()
	result := sa.network_session_resume(data)
	actor_observe(cast(^sa.Session_Actor)data, id)

	return result
}
actor_cancel :: proc(data: rawptr) -> async.Resume_Result {
	id := sync.current_thread_id()
	result := sa.network_session_cancel(data)
	actor_observe(cast(^sa.Session_Actor)data, id)

	return result
}
helper_resume :: proc(data: rawptr) -> async.Resume_Result {
	f := cast(^Fixture)data
	f.helper_thread = sync.current_thread_id()
	sync.post(&f.helper_started)
	// Labeled external fixture Task occupies one worker until A completes. It
	// proves a second real worker, not a production blocking/offload mechanism.
	sync.wait(&f.helper_release)

	return .Done
}
actor_done :: proc(data: rawptr) {
	actor := cast(^sa.Session_Actor)data
	index := int(actor.index) - 1
	assert(!async.is_current_task(&actor.task))
	sa.network_session_done(data)
	intrinsics.atomic_add(&fixture.done[index], 1) // External fixture only, no actor access.
}
start :: proc(f: ^Fixture) {
	capacities := sa.Capacities {
		requests               = 4,
		origins                = 4,
		connections            = 1,
		connections_per_origin = 1,
		waiters_per_origin     = 4,
		dns_ids                = 64,
		work_per_resume        = 1,
	}

	if f.mode == "one-worker" {
		capacities.connections = 2
	}

	servers := [1]net.Endpoint{f.dns}
	offers := [1]string{"http/1.1"}
	config, error := sa.config_normalize(
		{
			http = {
				scope = f.scope,
				allow_http = true,
				resolver = {name_servers = servers[:]},
				tls = {
					server_name = "must-not-leak.invalid",
					alpn_protocols = offers[:],
					root_cas = f.roots.roots[:f.roots.count],
				},
			},
			capacities = capacities,
		},
	)
	assert(error.kind == .None)
	f.workers = 1
	extra := 0

	if f.mode == "stale" {
		f.workers = 2
		extra = 1
	}

	assert(
		async.init(&f.runtime, {workers = f.workers, task_capacity = capacities.connections + 1 + extra, io_capacity = 8, allocator = f.allocator}).kind ==
		.None,
	)

	if f.mode == "lifetime" {
		config.lifetime = async.deadline_after(&f.runtime, 250 * time.Millisecond)
		f.lifetime = config.lifetime
	}

	f.state, error = sa.network_prepare(&f.runtime, config, f.allocator)
	assert(error.kind == .None)
	s := f.state
	s.coordinator.task = {
		resume    = coordinator_wait,
		on_cancel = coordinator_cancel,
		on_done   = coordinator_done,
		data      = &s.coordinator,
	}

	for &actor, index in s.actors {
		f.task_addresses[index] = &actor.task
		f.signals[index] = actor.wake
		actor.task = {
			resume    = actor_resume,
			on_cancel = actor_cancel,
			on_done   = actor_done,
			data      = &actor,
		}
	}

	for task in s.task_index {
		assert(sa.network_state_retain(s))
		_ = task
	}

	sync.lock(&s.mu)
	s.coordinator.registered = true

	for &actor in s.actors {
		actor.registered = true
	}

	s.registered_tasks = len(s.task_index)
	s.phase = .Published
	sync.unlock(&s.mu)

	if extra == 1 {
		f.helper = {
			resume = helper_resume,
			data = f,
			on_done = proc(data: rawptr) {intrinsics.atomic_add(&(cast(^Fixture)data).helper_done, 1)},
		}

		tasks := [3]^async.Task{s.task_index[0], s.task_index[1], &f.helper}
		assert(
			async.register_group(&f.runtime, tasks[:]).kind == .None &&
			async.wake(&f.runtime, &f.helper) &&
			async.start(&f.runtime).kind == .None,
		)
		sync.wait(&f.helper_started)
	} else {
		assert(async.register_group(&f.runtime, s.task_index).kind == .None && async.start(&f.runtime).kind == .None)
	}
}
submit :: proc(
	f: ^Fixture,
	label: string,
	duration: time.Duration,
	wake: bool = true,
	queue_only: bool = false,
) -> int {
	index := f.count
	assert(index < len(f.records))
	f.count += 1
	clock := now(f)
	cutoff := async.Deadline {
		epoch = clock.epoch,
		at    = clock.at + i64(duration),
	}
	host := "actor.test"
	if f.mode == "one-worker" && label == "B" {
		host = "cheap.actor.test"
	}
	scheme := "https" if f.encrypted else "http"
	url := fmt.tprintf("%s://%s:%d/%s", scheme, host, f.endpoint.port, label)
	lease, le := sa.resources_request_lease(&f.state.resources)
	assert(le.kind == .None)
	preparing, error := sa.kernel_reserve(&f.state.kernel, cutoff, &lease)
	assert(error.kind == .None)
	origin, oe := sa.origin_prepare(&f.state.profile, url, f.state.resources.allocator)
	assert(oe.kind == .None)
	reservation, claim := sa.network_queue_claim(f.state, preparing, &origin, clock.at)
	sa.origin_destroy(&origin)
	assert(claim.kind == .None)
	_ = reservation
	body: []u8
	method := http.Method.GET
	if f.mode == "uncertain" {
		method = .POST
		body = make([]u8, 1 << 20, f.allocator)

		for &byte in body {
			byte = 'p'
		}
	}
	input, ie := sa.request_clone({method = method, url = url, body = body}, f.state.resources.allocator)
	assert(ie.kind == .None)
	if body != nil {
		for &byte in body {byte = 'x'}; delete(body, f.allocator)
	}
	sync.lock(&f.state.mu)
	committed := sa.network_queue_committed_locked(f.state, preparing, &input, clock)
	sync.unlock(&f.state.mu)
	assert(committed.kind == .None)
	sync.lock(&f.state.kernel.mu)
	selected_cutoff := f.state.kernel.requests[int(preparing.request.slot) - 1].deadline
	sync.unlock(&f.state.kernel.mu)
	f.records[index] = {
		label            = label,
		handle           = preparing.request,
		deadline         = selected_cutoff,
		requested_cutoff = cutoff.at,
	}
	if queue_only {
		assert(reservation.waiting)
	} else {
		activate(f, index, wake)
	}
	return index
}
activate :: proc(f: ^Fixture, index: int, wake: bool = true) {
	assignment: sa.Assignment

	for _ in 0 ..< 1000 {
		sync.lock(&f.state.mu)
		selected, used, cause := sa.pool_dispatch(&f.state.kernel, 1, now_unlocked(f).at)
		sync.unlock(&f.state.mu)
		assert(used <= 1 && (cause.kind == .None || cause.kind == .Pending))

		if selected.request != (sa.Request_Handle{}) {
			assignment = selected
			break
		}
	}

	assert(assignment.request == f.records[index].handle)
	f.records[index].session = assignment.session
	sync.lock(&f.state.mu)
	actor := &f.state.actors[int(assignment.session.slot) - 1]
	assert(!actor.command.pending)
	actor.command = {
		assignment = assignment,
		pending    = true,
	}

	notification := actor.wake
	sync.unlock(&f.state.mu)

	if wake {
		assert(signal.wake(notification))
	}
}
// Only called while State.mu is held and real registered witness is owned.
now_unlocked :: proc(f: ^Fixture) -> async.Deadline {
	return async.deadline_after(&f.runtime, 0)
}
collect :: proc(f: ^Fixture) {
	for {
		completion, valid := sa.kernel_poll(&f.state.kernel)

		if !valid {
			return
		}

		index := -1

		for record, i in f.records[:f.count] {
			if record.handle == completion.request {
				index = i
				break
			}
		}

		assert(index >= 0 && !f.records[index].done)
		record := &f.records[index]
		response: surf.Response
		result := sa.kernel_take(&f.state.kernel, record.handle, &response)

		if result.kind == .None {
			assert(response.status == 200 && len(response.body) == 1)
			record.status = response.status
			record.body = int(response.body[0])
			connection, found := surf.response_header(&response, "X-Connection")
			assert(found)
			parsed, ok := strconv.parse_int(connection)
			assert(ok)
			record.connection = parsed
			// One actual native Response survives full State/Runtime destruction.
			if f.mode == "healthy" && record.label == "B" {
				f.held = response
				response = {}
			}

			surf.response_destroy(&response)
		} else {
			assert(result.kind == .Request_Error)
			record.error = result.http
			record.status = result.http.status
			assert(sa.kernel_release(&f.state.kernel, record.handle).kind == .None)
		}

		record.completed_at = now(f).at
		record.done = true
		fmt.print("{")
		fmt.printf(
			"\"event\":\"completion\",\"label\":\"%s\",\"kind\":\"%v\",\"phase\":\"%v\",\"effect\":\"%v\",\"status\":%d,\"body\":%d,\"connection\":%d,\"cutoff\":%d,\"completed_at\":%d,\"requested_cutoff\":%d,\"generation\":%d}\n",
			record.label,
			record.error.kind,
			record.error.phase,
			record.error.write_effect,
			record.status,
			record.body,
			record.connection,
			record.deadline.at,
			record.completed_at,
			record.requested_cutoff,
			record.handle.generation,
		)
	}
}
await :: proc(f: ^Fixture, index: int) {
	start := time.tick_now()

	for !f.records[index].done {
		collect(f)
		assert(time.tick_since(start) < 8 * time.Second)
		time.sleep(time.Millisecond)
	}
}
wait_model :: proc(f: ^Fixture, handle: sa.Cell_Handle, idle: bool) {
	start := time.tick_now()

	for {
		sync.lock(&f.state.kernel.mu)
		model := f.state.kernel.sessions[int(handle.slot) - 1]
		ready := model.state == .Idle if idle else model.state == .Free || model.state == .Retired
		sync.unlock(&f.state.kernel.mu)

		if ready {
			return
		}

		collect(f)
		assert(time.tick_since(start) < 8 * time.Second)
		time.sleep(time.Millisecond)
	}
}
cancel_request :: proc(f: ^Fixture, index: int) {
	record := f.records[index]
	assert(sa.kernel_cancel(&f.state.kernel, record.handle).kind == .None)
	sync.lock(&f.state.mu)
	actor := &f.state.actors[int(record.session.slot) - 1]
	actor.command.cancel = true
	notification := actor.wake
	sync.unlock(&f.state.mu)
	assert(signal.wake(notification))
}
require_success :: proc(f: ^Fixture, index: int, label: u8) {
	record := f.records[index]
	assert(record.done && record.error.kind == .None && record.body == int(label))
}
main :: proc() {
	assert(len(os.args) == 6)
	endpoint, ep := net.parse_endpoint(os.args[1])
	assert(ep)
	dns, dp := net.parse_endpoint(os.args[2])
	assert(dp)
	descriptors := fd_count()
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	f := new(Fixture, allocator)
	fixture = f
	f.allocator = allocator
	f.endpoint = endpoint
	f.dns = dns
	f.mode = os.args[3]
	f.encrypted = os.args[4] == "tls"
	f.dir = os.args[5]
	scope, se := scopes.create_root({bytes = 128 << 20, streams = 16, jobs = 64}, allocator)
	assert(se == .None)
	f.scope = scope

	if f.encrypted {
		data, error := os.read_entire_file(path(f, "root.pem"), allocator)
		assert(error == nil)
		assert(tls.root_pool_parse(&f.roots, data, allocator).kind == .None)
		delete(data, allocator)
	}

	start(f)
	duration := 250 * time.Millisecond

	if f.mode == "body-deadline" {
		duration = 350 * time.Millisecond
	}

	if f.mode == "cancel-read" ||
	   f.mode == "cancel-mailbox" ||
	   f.mode == "uncertain" ||
	   f.mode == "one-worker" ||
	   f.mode == "lifetime" {
		duration = 2 * time.Second
	}

	if f.mode == "reuse-waiter" {
		duration = 3 * time.Second
	}

	a := submit(f, "A", duration, f.mode != "cancel-mailbox")

	if f.mode == "cancel-mailbox" {
		cancel_request(f, a)
	}

	if f.mode == "reuse-waiter" {
		wait_file(f, "A.stalled")
		b := submit(f, "B", 3 * time.Second, true, true)
		mark(f, "releaseA")
		await(f, a)
		require_success(f, a, 'A')
		wait_model(f, f.records[a].session, true)
		activate(f, b)
		await(f, b)
		require_success(f, b, 'B')
		wait_model(f, f.records[b].session, true)
		assert(f.records[a].connection == f.records[b].connection)
		sync.lock(&f.state.mu)
		reserved, burned := f.state.dns_draws_reserved, f.state.dns_draws_burned
		sync.unlock(&f.state.mu)
		fmt.print("{")
		fmt.printf("\"event\":\"dns_balanced\",\"reserved\":%d,\"burned\":%d}\n", reserved, burned)
		assert(reserved == 32 && burned == reserved)
	}

	if f.mode == "cancel-read" || f.mode == "one-worker" {
		wait_file(f, "A.stalled")

		if f.mode == "cancel-read" {
			cancel_request(f, a)
		} else {
			b := submit(f, "B", 2 * time.Second)
			await(f, b)
			require_success(f, b, 'B')
			assert(!f.records[a].done)
		}
	}

	await(f, a)

	if f.mode == "stale" {
		sync.post(&f.helper_release)
	}

	old_expired := false

	if f.mode == "healthy" || f.mode == "stale" || f.mode == "partial" || f.mode == "close" {
		require_success(f, a, 'A')
		mark(f, "A.done")

		if f.mode != "healthy" {
			wait_file(f, "staged")
		}

		wait_model(f, f.records[a].session, true)

		for now(f).at <= f.records[a].deadline.at + 20 * i64(time.Millisecond) {
			time.sleep(time.Millisecond)
		}

		old_expired = true
		b := submit(f, "B", 2 * time.Second)
		await(f, b)

		if f.mode == "healthy" {
			require_success(f, b, 'B')
			assert(f.records[a].connection == f.records[b].connection)
			wait_model(f, f.records[b].session, true)
			sync.lock(&f.state.mu)
			reserved, burned := f.state.dns_draws_reserved, f.state.dns_draws_burned
			sync.unlock(&f.state.mu)
			assert(burned == reserved)
		} else {
			assert(f.records[b].error.kind != .None && f.records[b].error.write_effect == .Not_Sent)
			wait_model(f, f.records[b].session, false)
			c := submit(f, "C", 2 * time.Second)
			await(f, c)
			require_success(f, c, 'C')
			assert(f.records[c].connection != f.records[a].connection)
		}
	} else if f.mode == "cancel-read" {
		assert(f.records[a].error.phase == .Cancellation)
		wait_model(f, f.records[a].session, false)
		b := submit(f, "B", 2 * time.Second)
		await(f, b)
		require_success(f, b, 'B')
	} else if f.mode == "cancel-mailbox" {
		assert(f.records[a].error.phase == .Cancellation && f.records[a].error.write_effect == .Not_Sent)
		sync.lock(&f.state.mu)
		remaining := f.state.requests[int(f.records[a].handle.slot) - 1].ids.count
		burned := f.state.dns_draws_burned
		sync.unlock(&f.state.mu)
		fmt.print("{")
		fmt.printf("\"event\":\"mailbox_draws\",\"remaining\":%d,\"burned\":%d}\n", remaining, burned)
		assert(remaining == 0 && burned >= 16)
	} else if f.mode == "setup-deadline" || f.mode == "body-deadline" || f.mode == "lifetime" {
		assert(f.records[a].error.phase == .Deadline && f.records[a].error.kind != .None)

		if f.mode == "lifetime" {
			assert(f.records[a].status == 200 && f.records[a].error.write_effect == .Response_Received)
		}
	} else if f.mode == "uncertain" {
		assert(f.records[a].error.kind != .None && f.records[a].error.write_effect == .Unknown)
	} else if f.mode == "one-worker" {
		require_success(f, a, 'A')
	}

	sync.lock(&f.state.mu)
	f.state.phase = .Closing
	sync.unlock(&f.state.mu)
	assert(sa.kernel_close(&f.state.kernel).kind == .None)
	async.shutdown(&f.runtime)
	assert(async.join(&f.runtime).kind == .None && async.destroy(&f.runtime).kind == .None)

	for index in 0 ..< len(f.state.actors) {
		assert(f.done[index] == 1 && f.pins[index] != 0)
	}

	assert(f.coordinator_done == 1 && f.state.registered_tasks == 0 && f.state.runtime == nil)

	if f.mode == "stale" {
		assert(f.helper_done == 1 && f.helper_thread != 0 && f.helper_thread != f.pins[0])
	}

	sync.lock(&f.state.mu)
	f.state.base_owned = false
	sync.unlock(&f.state.mu)
	sa.network_state_release(f.state)
	f.state = nil
	late := f.held.status != 0

	if late {
		assert(string(f.held.body) == "B")
		snapshot, _ := scopes.snapshot(scope)
		assert(snapshot.used.bytes > 0)
		surf.response_destroy(&f.held)
	}

	tls.root_pool_destroy(&f.roots)
	snapshot, snapshot_error := scopes.snapshot(scope)
	assert(snapshot_error == .None && snapshot.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
	fmt.print("{")
	fmt.printf(
		"\"event\":\"summary\",\"mode\":\"%s\",\"tls\":%v,\"completed\":%d,\"old_cutoff_expired\":%v,\"pin0\":%d,\"pin1\":%d,\"resumes0\":%d,\"resumes1\":%d,\"late_response_survived_state_free\":%v,\"lifetime_cutoff\":%d,\"workers\":%d,\"fixture_prepin\":false,\"fixture_helper_thread\":%d,\"fixture_helper_done\":%d,\"scope_zero\":true,\"fixture_controller\":true,\"public_client_init\":false}\n",
		f.mode,
		f.encrypted,
		f.count,
		old_expired,
		f.pins[0],
		f.pins[1],
		f.resumes[0],
		f.resumes[1],
		late,
		f.lifetime.at,
		f.workers,
		f.helper_thread,
		f.helper_done,
	)
	mark(f, "finish")
	free(f, allocator)
	fixture = nil
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(fd_count() == descriptors)
	fmt.println("{\"event\":\"cleanup\",\"heap_zero\":true,\"fd_delta\":0}")
}
