package surf_async

import surf ".."
import runtime_async "shared:async"
import signal "shared:async/signal"
import rt "base:runtime"
import "core:bytes"
import "core:fmt"
import "core:mem"
import scopes "shared:async/sync/budget"
import "core:sync"
import "core:testing"
import "core:time"

@(test)
session_invalid_actor_guards_preserve_response_ownership :: proc(t: ^testing.T) {
	response := surf.Response{status = 203}
	before := response

	testing.expect_value(t, network_assignment_finish(nil, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, response.status, before.status)
	testing.expect_value(t, network_session_resume(nil), .Done)
	testing.expect_value(t, network_session_cancel(nil), .Done)
	network_session_done(nil)

	actor := new(Session_Actor)
	defer free(actor)

	testing.expect_value(t, network_assignment_finish(actor, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, response.status, before.status)
	testing.expect_value(t, network_session_resume(actor), .Done)
	testing.expect_value(t, network_session_cancel(actor), .Done)
	network_session_done(actor)

	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)

	state, error := network_prepare(&runtime, bootstrap_config(), context.allocator)
	assert(error.kind == .None)

	actor^ = state.actors[0] // A copied actor cannot acquire original-address ownership.

	snapshot := make([]u8, size_of(Session_Actor))
	defer delete(snapshot)
	copy(snapshot, (cast([^]u8)&state.actors[0])[:size_of(Session_Actor)])

	testing.expect_value(t, network_assignment_finish(actor, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, network_session_resume(actor), .Done)
	network_session_done(actor)
	testing.expect(t, bytes.equal(snapshot, (cast([^]u8)&state.actors[0])[:size_of(Session_Actor)]))

	assert(network_dispose_prepared(state).kind == .None && runtime_async.destroy(&runtime).kind == .None)
}

@(test)
session_real_registered_cold_mailbox_cancel_has_no_io_and_drains_owners :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)

	scope, se := scopes.create_root({bytes = 16 << 20, streams = 8, jobs = 8}, allocator)
	assert(se == .None)

	runtime: runtime_async.Runtime
	assert(runtime_async.init(&runtime, {workers = 1, task_capacity = 2, io_capacity = 0, allocator = allocator}).kind == .None)

	state, error := network_prepare(&runtime, bootstrap_config(scope), allocator)
	assert(error.kind == .None)

	state.coordinator.task = {
		data = &state.coordinator,
		resume = proc(_: rawptr) -> runtime_async.Resume_Result {
			return .Waiting
		},
		on_cancel = proc(data: rawptr) -> runtime_async.Resume_Result {
			c := cast(^Coordinator_State)data
			sync.lock(&c.owner.mu)
			c.done = true
			sync.unlock(&c.owner.mu)
			return .Done
		},
		on_done = proc(data: rawptr) {
			c := cast(^Coordinator_State)data
			network_task_done(c.owner, 0, true)
		},
	}

	actor := &state.actors[0]
	actor.task = {data = actor, resume = network_session_resume, on_cancel = network_session_cancel, on_done = network_session_done}

	for task in state.task_index {
		assert(network_state_retain(state))
		_ = task
	}

	sync.lock(&state.mu)
	state.registered_tasks = 2
	state.coordinator.registered = true
	actor.registered = true
	state.phase = .Published
	sync.unlock(&state.mu)

	assert(runtime_async.register_group(&runtime, state.task_index).kind == .None)

	request := bootstrap_queued(state, &runtime)
	assignment := bootstrap_dispatch(state, &runtime)

	sync.lock(&state.mu)
	actor.command = {assignment = assignment, pending = true, cancel = true}
	sync.unlock(&state.mu)

	assert(kernel_cancel(&state.kernel, request).kind == .None)
	assert(runtime_async.start(&runtime).kind == .None && signal.wake(actor.wake))

	completion: Completion
	for {
		found, valid := kernel_poll(&state.kernel)
		if valid {
			completion = found
			break
		}

		time.sleep(time.Millisecond)
	}

	testing.expect(t, completion.request == request && completion.error.phase == .Cancellation && completion.error.write_effect == .Not_Sent)
	assert(kernel_release(&state.kernel, request).kind == .None)

	for {
		sync.lock(&state.kernel.mu)
		free := state.kernel.sessions[0].state == .Free
		sync.unlock(&state.kernel.mu)

		if free {
			break
		}

		time.sleep(time.Millisecond)
	}

	testing.expect_value(t, bootstrap_usage(scope).used.streams, u64(0))

	sync.lock(&state.mu)
	state.phase = .Closing
	sync.unlock(&state.mu)

	assert(kernel_close(&state.kernel).kind == .None)

	runtime_async.shutdown(&runtime)
	assert(runtime_async.join(&runtime).kind == .None && runtime_async.destroy(&runtime).kind == .None)

	testing.expect(t, state.registered_tasks == 0 && state.runtime == nil && state.references == 1)

	sync.lock(&state.mu)
	state.base_owned = false
	sync.unlock(&state.mu)
	network_state_release(state)

	testing.expect_value(t, bootstrap_usage(scope).used, scopes.Usage{})
	scopes.release_scope(&scope)

	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)

	fmt.println("SESSION_ACTOR unit_cold_cancel=1 actual_runtime_group=true io_capacity=0 owners_drained=true public_client_init=0")
}
