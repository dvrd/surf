package surf_async

import stream_api "stream"
import runtime_async "../../async"
import "core:mem"
import "core:testing"
import "core:time"

Stream_Start_Allocator :: struct {
	backing: mem.Allocator,
	armed:   bool,
	delays:  int,
}

stream_start_allocator :: proc(
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
	state := cast(^Stream_Start_Allocator)data
	if state.armed && (mode == .Alloc || mode == .Alloc_Non_Zeroed) && size == size_of(stream_api.Channel) {
		state.armed = false
		state.delays += 1
		time.sleep(40 * time.Millisecond)
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
stream_submission_timeout_includes_channel_allocation :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	assert(runtime_async.init(&r, {workers = 1, task_capacity = 2, io_capacity = 1}).kind == .None)
	defer runtime_async.destroy(&r)
	state := Stream_Start_Allocator {
		backing = context.allocator,
	}

	c: Client
	config := Client_Config {
		http = {allow_http = true, timeout = 10 * time.Millisecond},
		capacities = Capacities {
			requests = 1,
			origins = 1,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 1,
			dns_ids = 0,
			work_per_resume = 1,
		},
		streaming = Stream_Client_Limits{},
	}

	assert(client_init(&c, &r, config, {stream_start_allocator, &state}).kind == .None)
	defer failure32_close(&c)
	state.armed = true
	handle, error := client_submit_stream(&c, {url = "http://127.0.0.1:9/not-sent"}, {})
	testing.expect_value(t, state.delays, 1)
	testing.expect_value(t, error.kind, .Request_Error)
	testing.expect_value(t, error.http.kind, .Deadline_Failed)
	testing.expect_value(t, error.http.write_effect, .Not_Sent)
	testing.expect_value(t, handle, Request_Handle{})
}
