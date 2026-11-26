package main

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "shared:async"
import "shared:surf"

fd_count :: proc() -> int {
	n := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			n += 1
		}
	}

	return n
}

Grant :: struct {
	raw, view: []u8,
	alignment: int,
}
Backing :: struct {
	mu:                                                     sync.Mutex,
	allocator:                                              mem.Allocator,
	grants:                                                 [128]Grant,
	live, calls, armed_calls, point, mode, bad_frees, hits: int,
	sizes, alignments:                                      [64]int,
	armed, destroying, header_freed:                        bool,
	first:                                                  rawptr,
	c:                                                      ^surf.Client,
	handle:                                                 surf.Request_Handle,
	// Set by an allocation in modes 8 to 10; the helper thread then acts.
	act:                                                    sync.Sema,
}
allocate :: proc(
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
	p := cast(^Backing)data
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		sync.lock(&p.mu)
		p.calls += 1
		selected := 0

		if p.armed {
			p.armed_calls += 1
			assert(p.armed_calls <= len(p.sizes))
			p.sizes[p.armed_calls - 1] = size
			p.alignments[p.armed_calls - 1] = alignment

			if p.armed_calls == p.point {
				selected = p.mode
				p.hits += 1
			}
		}

		if selected == 1 {
			sync.unlock(&p.mu)
			return nil, .Out_Of_Memory
		}

		if selected == 3 {
			sync.unlock(&p.mu)
			return nil, nil
		}

		sync.unlock(&p.mu)

		// The client's task holds the client lock while it allocates, so the
		// cancel or close comes from another thread while this call is in flight.
		if selected >= 8 {
			sync.sema_post(&p.act)
		}

		sync.lock(&p.mu)
		actual := size

		if selected == 4 {
			actual = max(0, size - 1)
		}

		if selected == 5 || selected == 6 {
			actual = size + 1
		}

		raw, error := p.allocator.procedure(p.allocator.data, mode, actual, max(16, alignment), nil, 0, location)
		assert(error == nil)
		view := raw

		if selected == 6 {
			view = raw[1:]
		}

		stored := false

		for &grant in p.grants {
			if raw_data(grant.raw) == nil {
				grant = {raw, view, max(16, alignment)}
				stored = true
				break
			}
		}

		assert(stored)
		p.live += len(raw)

		if p.first == nil {
			p.first = raw_data(view)
		}

		sync.unlock(&p.mu)

		if selected == 2 {
			return view, .Out_Of_Memory
		}

		return view, nil
	case .Free:
		if old_memory == nil {
			return nil, nil
		}

		sync.lock(&p.mu)
		old := Grant{}

		for &grant in p.grants {
			if raw_data(grant.view) == old_memory {
				old = grant
				grant = {}
				break
			}
		}

		if raw_data(old.raw) == nil {
			p.bad_frees += 1
			sync.unlock(&p.mu)
			return nil, .Invalid_Pointer
		}

		if old_size != 0 && old_size != len(old.view) {
			p.bad_frees += 1
		}

		free_header := p.destroying && old_memory == p.first && !p.header_freed

		if free_header {
			p.header_freed = true
		}

		sync.unlock(&p.mu)
		// The whole State backing's physical Free happens after the public header
		// was cleared. Reentry and physical header disposal must not invalidate the
		// outer client_destroy's detached locals.
		if free_header {
			assert(surf.client_destroy(p.c).kind == .Invalid_State)
			free(p.c, p.allocator)
			p.c = nil
		}

		result, error := p.allocator.procedure(
			p.allocator.data,
			.Free,
			0,
			old.alignment,
			raw_data(old.raw),
			len(old.raw),
			location,
		)
		sync.lock(&p.mu)
		p.live -= len(old.raw)
		sync.unlock(&p.mu)
		return result, error
	case .Query_Features:
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		return nil, nil
	case .Free_All, .Resize, .Resize_Non_Zeroed, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, .Mode_Not_Implemented
}
// Cancels or closes the client when an armed allocation asks for it.
actor :: proc(p: ^Backing) {
	sync.sema_wait(&p.act)

	switch p.mode {
	case 8:
		assert(surf.client_cancel(p.c, p.handle).kind == .None)
	case 9:
		assert(surf.client_close(p.c).kind == .None)
	case 10:
		assert(surf.client_release(p.c, p.handle).kind == .None)
	}
}

main :: proc() {
	assert(len(os.args) == 5)
	endpoint, ok := net.parse_endpoint(os.args[1])
	assert(ok)
	dir := os.args[2]
	point, valid := strconv.parse_int(os.args[3])
	assert(valid)
	mode, valid2 := strconv.parse_int(os.args[4])
	assert(valid2)
	before_fd := fd_count()
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	r: async.Runtime
	assert(async.init(&r, {workers = 1, task_capacity = 2, io_capacity = 8, allocator = allocator}).kind == .None)
	p := Backing {
		allocator = allocator,
		point     = point,
		mode      = mode,
	}

	c := new(surf.Client, allocator)
	p.c = c
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 3 * time.Second, max_redirects = 1},
		capacities = surf.Capacities {
			requests = 1,
			origins = 1,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	assert(surf.client_init(c, &r, config, {allocate, &p}).kind == .None)
	assert(async.start(&r).kind == .None)
	body := "fixed-owned-payload"
	url := fmt.tprintf("http://127.0.0.1:%d/A", endpoint.port)
	handle, error := surf.client_submit(c, {method = .POST, url = url, body = transmute([]u8)body})
	assert(error.kind == .None)
	start := time.tick_now()

	for !os.exists(fmt.tprintf("%s/A.received", dir)) {
		assert(time.tick_since(start) < 5 * time.Second)
		time.sleep(time.Millisecond)
	}

	helper: ^thread.Thread

	if mode >= 8 {
		helper = thread.create_and_start_with_poly_data(&p, actor)
		assert(helper != nil)
	}

	sync.lock(&p.mu)
	p.handle = handle
	p.armed = true
	sync.unlock(&p.mu)
	assert(os.write_entire_file(fmt.tprintf("%s/release", dir), "go") == nil)
	completion: surf.Completion
	response: surf.Response

	if mode == 10 {
		thread.join(helper)
		thread.destroy(helper)
		assert(surf.client_take(c, handle, &response).kind == .Invalid_Handle)
	} else {
		for {
			item, available := surf.client_poll(c)

			if available {
				completion = item
				break
			}

			assert(time.tick_since(start) < 8 * time.Second)
			thread.yield()
		}

		assert(completion.request == handle)

		if helper != nil {
			thread.join(helper)
			thread.destroy(helper)
		}

		if mode == 9 {
			_, refused := surf.client_submit(c, {method = .GET, url = url})
			assert(refused.kind == .Closed)
		}

		if completion.error.kind == .None {
			assert(surf.client_take(c, handle, &response).kind == .None)
			assert(response.status == 200 && string(response.body) == "response")
		} else if mode == 1 {
			assert(completion.error.kind == .Allocation_Failed)
		}

		assert(surf.client_release(c, handle).kind == .None)
	}

	sync.lock(&p.mu)
	p.armed = false
	count, hits := p.armed_calls, p.hits
	sizes, alignments := p.sizes, p.alignments
	sync.unlock(&p.mu)

	if point > 0 {
		assert(hits == 1)
	}

	closed := surf.client_close(c)
	assert(closed.kind == .None)

	for !surf.client_quiescent(c) {
		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}

	_, late := surf.client_poll(c)
	assert(!late)
	sync.lock(&p.mu)
	p.destroying = true
	sync.unlock(&p.mu)
	assert(surf.client_destroy(c).kind == .None)
	assert(p.header_freed && p.c == nil)
	assert(async.wait_idle(&r).kind == .None)
	assert(async.destroy(&r).kind == .None)

	// The taken response keeps its allocations after the client is gone.
	if mode != 10 && completion.error.kind == .None {
		assert(p.live > 0 && string(response.body) == "response")
	}

	surf.response_destroy(&response)
	assert(fd_count() == before_fd)
	assert(p.live == 0 && p.bad_frees == 0)
	assert(track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"point\":%d,\"mode\":%d,\"calls\":%d,\"hits\":%d,\"error\":\"%v\",\"transport\":\"%v\",\"phase\":\"%v\",\"fd_zero\":true,\"header_freed\":true,\"heap_zero\":true,\"sizes\":[",
		point,
		mode,
		count,
		hits,
		completion.error.kind,
		completion.error.transport,
		completion.error.phase,
	)

	for n in 0 ..< count {
		if n > 0 {
			fmt.print(",")
		}

		fmt.printf("%d", sizes[n])
	}

	fmt.print("],\"alignments\":[")

	for n in 0 ..< count {
		if n > 0 {
			fmt.print(",")
		}

		fmt.printf("%d", alignments[n])
	}

	fmt.println("]}")
}
