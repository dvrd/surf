package main

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "shared:async"
import "shared:async/budget"
import "shared:async/tls"
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

Completions :: struct {
	items: [4]surf.Completion,
	count: int,
}

collect :: proc(c: ^surf.Client, pending: ^Completions, want: surf.Request_Handle) -> surf.Completion {
	start := time.tick_now()

	for {
		for item, i in pending.items[:pending.count] {
			if item.request == want {
				result := item

				for j in i ..< pending.count - 1 {
					pending.items[j] = pending.items[j + 1]
				}

				pending.count -= 1
				return result
			}
		}

		result, available := surf.client_poll(c)

		if available {
			assert(pending.count < len(pending.items))
			pending.items[pending.count] = result
			pending.count += 1
			continue
		}

		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}
}

read_endpoint :: proc(dir, name: string, allocator: mem.Allocator) -> net.Endpoint {
	bytes, e := os.read_entire_file(fmt.tprintf("%s/%s.endpoint", dir, name), allocator)
	assert(e == nil)
	defer delete(bytes, allocator)
	endpoint, ok := net.parse_endpoint(string(bytes))
	assert(ok)

	return endpoint
}

run_client :: proc() {
	assert(len(os.args) == 6)
	endpoint, ok := net.parse_endpoint(os.args[1])
	assert(ok)
	phase, encrypted, action, dir := os.args[2], os.args[3] == "tls", os.args[4], os.args[5]
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 96 << 20, streams = 3, jobs = 16}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		root, e := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(e == nil)
		assert(tls.root_pool_parse(&roots, root, allocator) == nil)
		delete(root, allocator)
	}

	cheap := read_endpoint(dir, "cheap", allocator)
	servers := [1]net.Endpoint{read_endpoint(dir, "dns", allocator)}
	before := fd_count()
	r: async.Runtime
	assert(async.init(&r, {workers = 1, task_capacity = 4, io_capacity = 16, allocator = allocator}).kind == .None)
	c: surf.Client
	config := surf.Client_Config {
		http = {
			allow_http = true,
			timeout = 5 * time.Second,
			max_redirects = 5,
			scope = scope,
			resolver = {name_servers = servers[:]},
		},
		capacities = surf.Capacities {
			requests = 3,
			origins = 3,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	if action == "setup" {
		config.http.setup_timeout = 700 * time.Millisecond
	}

	if action == "total" {
		config.http.setup_timeout = 5 * time.Second
	}

	assert(surf.client_init(&c, &r, config, allocator).kind == .None)
	scheme := "https" if encrypted else "http"
	host := "held.cancel.test" if phase == "dns" else "127.0.0.1"
	url := fmt.tprintf("%s://%s:%d/held", scheme, host, endpoint.port)
	payload: []u8

	if phase == "write" {
		payload = make([]u8, 18 << 20, allocator)

		for &b in payload {
			b = 'w'
		}
	}

	timed := action == "total" || action == "close"
	deadline: async.Deadline

	if timed && phase != "queued" {
		deadline = async.deadline_after(&r, 700 * time.Millisecond)
	}

	// A queued request must still be waiting for the connection when its own
	// cutoff passes, so the blocker outlives it.
	if action == "close" && phase == "queued" {
		deadline = async.deadline_after(&r, 1500 * time.Millisecond)
	}

	blocker, error := surf.client_submit(
		&c,
		{method = .POST if phase == "write" else .GET, url = url, body = payload},
		deadline,
	)
	assert(error.kind == .None)
	delete(payload, allocator)
	start := time.tick_now()
	assert(async.start(&r).kind == .None)

	for !os.exists(fmt.tprintf("%s/held", dir)) {
		assert(time.tick_since(start) < 5 * time.Second)
		thread.yield()
	}

	target := blocker

	if phase == "queued" {
		queued_deadline: async.Deadline

		if timed {
			queued_deadline = async.deadline_after(&r, 700 * time.Millisecond)
		}

		target, error = surf.client_submit(&c, {method = .GET, url = url}, queued_deadline)
		assert(error.kind == .None && target != blocker)
	}

	expected: surf.Request_Stage = .Connecting

	switch phase {
	case "write":
		expected = .Writing
	case "header", "body", "redirect":
		expected = .Reading
	}

	observed: surf.Request_Stage

	for _ in 0 ..< 8 {
		time.sleep(5 * time.Millisecond)
		observed, error = surf.client_request_stage(&c, target)
		assert(error.kind == .None)
	}

	cheap_handle, cheap_error := surf.client_submit(
		&c,
		{method = .GET, url = fmt.tprintf("http://127.0.0.1:%d/cheap", cheap.port)},
	)
	assert(cheap_error.kind == .None)
	pending: Completions
	cheap_result := collect(&c, &pending, cheap_handle)
	assert(cheap_result.error.kind == .None)
	response: surf.Response
	assert(surf.client_take(&c, cheap_handle, &response).kind == .None)
	assert(response.status == 200 && string(response.body) == "ok")
	surf.response_destroy(&response)
	assert(surf.client_release(&c, cheap_handle).kind == .None)
	assert(!os.exists(fmt.tprintf("%s/release", dir)))

	switch action {
	case "cancel":
		assert(surf.client_cancel(&c, target).kind == .None)
	case "close":
		assert(surf.client_close(&c).kind == .None)
		_, refused := surf.client_submit(&c, {method = .GET, url = url})
		assert(refused.kind == .Closed)
	case "shutdown":
		async.shutdown(&r)
	}

	terminal := collect(&c, &pending, target)

	if action == "total" || action == "setup" || action == "close" {
		assert(terminal.error.kind == .Deadline_Failed && terminal.error.phase == .Deadline)
	} else {
		assert(terminal.error.kind == .IO_Failed && terminal.error.phase == .Cancellation)
	}

	assert(surf.client_release(&c, target).kind == .None)

	if phase == "queued" {
		if action != "close" && action != "shutdown" {
			assert(surf.client_cancel(&c, blocker).kind == .None)
		}

		other := collect(&c, &pending, blocker)
		assert(other.error.kind != .None)
		assert(surf.client_release(&c, blocker).kind == .None)
	}

	assert(pending.count == 0)
	_, extra := surf.client_poll(&c)
	assert(!extra)
	elapsed := time.tick_since(start)
	assert(surf.client_close(&c).kind == .None)

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(start) < 9 * time.Second)
		thread.yield()
	}

	_, late := surf.client_poll(&c)
	assert(!late)
	assert(surf.client_destroy(&c).kind == .None)
	assert(async.wait_idle(&r).kind == .None)
	assert(async.destroy(&r).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == before)
	state, e := budget.snapshot(scope)
	assert(e == .None && state.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"layer\":\"public_client\",\"workers\":1,\"completed\":%d,\"expected_stage\":\"%v\",\"observed_stage\":\"%v\",\"cheap_before_release\":true,\"terminal_once\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true,\"error\":\"%v\",\"phase\":\"%v\",\"write_effect\":\"%v\",\"status\":%d,\"elapsed_ms\":%d}\n",
		3 if phase == "queued" else 2,
		expected,
		observed,
		terminal.error.kind,
		terminal.error.phase,
		terminal.error.write_effect,
		terminal.error.status,
		i64(elapsed / time.Millisecond),
	)
	assert(observed == expected)
}

Boundary :: struct {
	mu:                  sync.Mutex,
	r:                   ^async.Runtime,
	task:                ^async.Task,
	connecting:          async.Connecting_Socket,
	release:             bool,
	resumes, done_calls: int,
	result:              async.Error,
	supplied:            async.Deadline,
}
boundary_resume :: proc(data: rawptr) -> async.Resume_Result {
	b := cast(^Boundary)data
	sync.lock(&b.mu)
	b.resumes += 1
	release := b.release
	supplied := b.supplied
	sync.unlock(&b.mu)

	if !release && !async.cancelled(b.task) {
		return .Waiting
	}

	socket, error := async.finish_connect(b.connecting, supplied)

	if error.kind == .None {
		assert(async.close_connect(b.connecting).kind == .Invalid_Socket)
		assert(async.close(socket).kind == .None)
	}

	assert(async.close_connect(b.connecting).kind == .Closed)
	sync.lock(&b.mu)
	b.result = error
	sync.unlock(&b.mu)

	return .Done
}
boundary_done :: proc(data: rawptr) {
	b := cast(^Boundary)data
	sync.lock(&b.mu)
	b.done_calls += 1
	sync.unlock(&b.mu)
}
run_raw :: proc(endpoint: net.Endpoint, dir, mode: string, encrypted: bool) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 32 << 20, streams = 1, jobs = 8}, allocator)
	assert(cause == .None)
	bytes, e := os.read_entire_file(fmt.tprintf("%s/cheap.endpoint", dir), allocator)
	assert(e == nil)
	cheap, valid := net.parse_endpoint(string(bytes))
	assert(valid)
	delete(bytes, allocator)
	roots: tls.Root_Pool

	if encrypted {
		root, re := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(re == nil)
		assert(tls.root_pool_parse(&roots, root, allocator) == nil)
		delete(root, allocator)
	}

	before := fd_count()
	r: async.Runtime
	assert(
		async.init(&r, {workers = 1, task_capacity = 3, io_capacity = 8, allocator = allocator}).kind == .None,
	)
	boundary := Boundary {
		r = &r,
	}

	task := async.Task {
		data      = &boundary,
		resume    = boundary_resume,
		on_cancel = boundary_resume,
		on_done   = boundary_done,
	}

	boundary.task = &task
	assert(async.register(&r, &task).kind == .None)
	original := async.deadline_after(
		&r,
		700 * time.Millisecond if mode == "deadline" || mode == "later_finish" else 5 * time.Second,
	)
	connecting, error := async.begin_connect(&r, &task, endpoint, original)
	assert(error.kind == .None)
	boundary.connecting = connecting
	bound, bind_error := async.connect_bound_endpoint(connecting)
	assert(bind_error.kind == .None && bound.port > 0)
	c: surf.Client
	config := surf.Client_Config {
		http = {allow_http = true, scope = scope, timeout = 2 * time.Second},
		capacities = surf.Capacities {
			requests = 1,
			origins = 1,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	assert(surf.client_init(&c, &r, config, allocator).kind == .None)
	scheme := "https" if encrypted else "http"
	handle, submit_error := surf.client_submit(
		&c,
		{method = .GET, url = fmt.tprintf("%s://127.0.0.1:%d/cheap", scheme, cheap.port)},
	)
	assert(submit_error.kind == .None)
	assert(async.wake(&r, &task))
	assert(async.start(&r).kind == .None)
	start := time.tick_now()

	for !os.exists(fmt.tprintf("%s/held", dir)) {
		assert(time.tick_since(start) < time.Second)
		thread.yield()
	}

	for {
		completion, available := surf.client_poll(&c)

		if available {
			assert(completion.request == handle && completion.error.kind == .None)
			break
		}


		assert(time.tick_since(start) < time.Second)
		thread.yield()
	}

	response: surf.Response
	assert(surf.client_take(&c, handle, &response).kind == .None && string(response.body) == "ok")
	surf.response_destroy(&response)
	_, extra := surf.client_poll(&c)
	assert(!extra)
	sync.lock(&boundary.mu)
	assert(boundary.resumes >= 1 && boundary.done_calls == 0)
	sync.unlock(&boundary.mu)
	_, still_connecting := async.connect_bound_endpoint(connecting)
	assert(still_connecting.kind == .None)
	assert(!os.exists(fmt.tprintf("%s/release", dir)))

	if mode == "deadline" || mode == "later_finish" {
		for async.deadline_after(&r, 0).at < original.at + 10 * i64(time.Millisecond) {
			time.sleep(time.Millisecond)
		}
	}

	supplied: async.Deadline

	if mode == "later_finish" {
		supplied = async.deadline_after(&r, 5 * time.Second)
	}

	if mode == "earlier_finish" {
		supplied = async.deadline_after(&r, 0)
		assert(supplied.at < original.at)
	}

	sync.lock(&boundary.mu)
	boundary.supplied = supplied
	boundary.release = true
	sync.unlock(&boundary.mu)

	switch mode {
	case "owner_cancel":
		assert(async.cancel(&r, &task).kind == .None)
	case "close_connect":
		assert(async.close_connect(connecting).kind == .None)
		_ = async.wake(&r, &task)
	case "runtime_shutdown":
		async.shutdown(&r)
	case "release_success", "deadline", "later_finish", "earlier_finish":
		_ = async.wake(&r, &task)
	case:
		panic("unknown mode")
	}

	expected: async.Error_Kind = .Timeout

	if mode == "release_success" {
		expected = .None
	}

	if mode == "owner_cancel" || mode == "runtime_shutdown" {
		expected = .Cancelled
	}

	if mode == "close_connect" {
		expected = .Closed
	}

	result: async.Error

	for {
		sync.lock(&boundary.mu)
		done := boundary.done_calls
		result = boundary.result
		sync.unlock(&boundary.mu)

		if done > 0 {
			assert(done == 1 && result.kind == expected)
			break
		}

		assert(time.tick_since(start) < 3 * time.Second)
		thread.yield()
	}

	closed := surf.client_close(&c)
	assert(closed.kind == .None || closed.kind == .Pending)

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(start) < 3 * time.Second)
		thread.yield()
	}

	_, late := surf.client_poll(&c)
	assert(!late)
	assert(surf.client_destroy(&c).kind == .None)
	assert(async.wait_idle(&r).kind == .None)
	assert(async.destroy(&r).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == before)
	state, se := budget.snapshot(scope)
	assert(se == .None && state.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.bad_free_array) == 0 && len(track.allocation_map) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"layer\":\"runtime_connect_slot\",\"client_completions\":1,\"connecting_slot_held\":true,\"external_socket_outside_client_cap\":true,\"scope\":\"public Runtime Connecting-slot boundary; not public Client SYN stall\",\"mode\":\"%s\",\"workers\":1,\"cheap_tls\":%v,\"cheap_before_release\":true,\"peer_accepted\":true,\"original_cutoff_retained\":%v,\"later_budget_rejected\":%v,\"earlier_budget_selected\":%v,\"owner_done_calls\":1,\"error\":\"%v\",\"scope_zero\":true,\"heap_zero\":true,\"fd_zero\":true}\n",
		mode,
		encrypted,
		mode == "deadline" || mode == "later_finish",
		mode == "later_finish",
		mode == "earlier_finish",
		result.kind,
	)
}

main :: proc() {
	assert(len(os.args) == 6)

	if os.args[2] == "rawconnect" {
		endpoint, ok := net.parse_endpoint(os.args[1])
		assert(ok)
		run_raw(endpoint, os.args[5], os.args[4], os.args[3] == "tls")
		return
	}

	run_client()
}
