package main

import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
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
wait_completion :: proc(c: ^surf.Client, want: surf.Request_Handle) -> surf.Completion {
	started := time.tick_now()

	for {
		result, available := surf.client_poll(c)

		if available {
			assert(result.request == want)
			return result
		}

		assert(time.tick_since(started) < 8 * time.Second)
		thread.yield()
	}
}
header :: proc(response: ^surf.Response, name: string) -> string {
	for field in response.headers {
		if field.name == name {
			return field.value
		}
	}

	return ""
}
main :: proc() {
	assert(len(os.args) == 5)
	endpoint, ok := net.parse_endpoint(os.args[1])
	assert(ok)
	mode, encrypted, dir := os.args[2], os.args[3] == "tls", os.args[4]

	if mode == "progress" {
		run_progress(endpoint, encrypted, dir)
		return
	}

	assert(mode == "healthy" || mode == "fragmented")
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 32 << 20, streams = 2, jobs = 8}, allocator)
	assert(cause == .None)
	roots: surf.Trust_Roots

	if encrypted {
		path := fmt.tprintf("%s/root.pem", dir)
		root, error := os.read_entire_file(path, allocator)
		assert(error == nil)
		assert(surf.trust_roots_parse(&roots, root, allocator) == .None)
		delete(root, allocator)
	}

	fd_before := fd_count()
	runtime: async.Runtime
	assert(async.init(&runtime, {workers = 1, task_capacity = 8, io_capacity = 16, allocator = allocator}).kind == .None)
	c: surf.Client
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 2 * time.Second, scope = scope},
		capacities = surf.Capacities {
			requests = 2,
			origins = 1,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	assert(surf.client_init(&c, &runtime, config, allocator).kind == .None)
	url_storage: [256]u8
	scheme := "https" if encrypted else "http"
	url := fmt.bprintf(url_storage[:], "%s://127.0.0.1:%d/A", scheme, endpoint.port)
	body := [11]u8{'c', 'o', 'p', 'i', 'e', 'd', '-', 'b', 'o', 'd', 'y'}
	value := [8]u8{'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'}
	fields := [1]surf.Header{{name = "X-Copy", value = string(value[:])}}
	cutoff := time.tick_add(time.tick_now(), 600 * time.Millisecond)
	handle, error := surf.client_submit(&c, {method = .POST, url = url, headers = fields[:], body = body[:]}, cutoff)
	assert(error.kind == .None)
	// No runtime worker can have written the source before this overwrite. The
	// peer must receive the accepted clone after Runtime.start below.
	for &b in url_storage {
		b = '!'
	}

	for &b in body {
		b = 'x'
	}

	for &b in value {
		b = 'x'
	}

	fields[0] = {}
	assert(os.write_entire_file(fmt.tprintf("%s/input-mutated", dir), "done") == nil)
	assert(async.start(&runtime).kind == .None)
	first := wait_completion(&c, handle)
	assert(first.error.kind == .None)
	response_a: surf.Response
	assert(surf.client_take(&c, handle, &response_a).kind == .None)
	assert(
		string(response_a.body) == "A" &&
		header(&response_a, "X-Sequence") == "A" &&
		header(&response_a, "X-Connection") == "1",
	)
	// The completion was already polled; taking does not queue another one.
	_, available := surf.client_poll(&c)
	assert(!available)
	assert(surf.client_release(&c, handle).kind == .None)
	assert(surf.client_release(&c, handle).kind == .Invalid_Handle)
	assert(os.write_entire_file(fmt.tprintf("%s/A.done", dir), "done") == nil)

	for time.tick_diff(cutoff, time.tick_now()) <= 20 * time.Millisecond {
		time.sleep(time.Millisecond)
	}

	url_b := fmt.bprintf(url_storage[:], "%s://127.0.0.1:%d/B", scheme, endpoint.port)
	second, accepted := surf.client_submit(&c, {method = .GET, url = url_b})
	assert(accepted.kind == .None && second != handle)

	for &b in url_storage {
		b = '?'
	}

	final := wait_completion(&c, second)
	assert(final.error.kind == .None)
	response_b: surf.Response
	assert(surf.client_take(&c, second, &response_b).kind == .None)
	assert(
		string(response_b.body) == "B" &&
		header(&response_b, "X-Sequence") == "B" &&
		header(&response_b, "X-Connection") == "1",
	)
	assert(surf.client_close(&c).kind == .None)
	started := time.tick_now()

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(started) < 8 * time.Second)
		thread.yield()
	}

	assert(surf.client_destroy(&c).kind == .None)
	async.shutdown(&runtime)
	assert(async.join(&runtime).kind == .None)
	assert(async.destroy(&runtime).kind == .None)
	surf.trust_roots_destroy(&roots)
	assert(fd_count() == fd_before)
	retained, error_scope := budget.snapshot(scope)
	assert(error_scope == .None && retained.used.streams == 0)
	assert(string(response_a.body) == "A" && string(response_b.body) == "B")
	surf.response_destroy(&response_a)
	surf.response_destroy(&response_b)
	freed, _ := budget.snapshot(scope)
	assert(freed.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.print("{")
	fmt.printf(
		"\"completed\":2,\"tls\":%v,\"old_cutoff_expired\":true,\"copied_input\":true,\"late_response\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true}\n",
		encrypted,
	)
}

Public_Completions :: struct {
	items: [8]surf.Completion,
	count: int,
}
collect :: proc(c: ^surf.Client, pending: ^Public_Completions, want: surf.Request_Handle) -> surf.Completion {
	started := time.tick_now()

	for {
		for item, index in pending.items[:pending.count] {
			if item.request == want {
				result := item

				for i in index ..< pending.count - 1 {
					pending.items[i] = pending.items[i + 1]
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

		assert(time.tick_since(started) < 8 * time.Second)
		thread.yield()
	}
}
run_progress :: proc(endpoint: net.Endpoint, encrypted: bool, dir: string) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 32 << 20, streams = 4, jobs = 16}, allocator)
	assert(cause == .None)
	roots: surf.Trust_Roots

	if encrypted {
		root, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(error == nil)
		assert(surf.trust_roots_parse(&roots, root, allocator) == .None)
		delete(root, allocator)
	}

	cheap_bytes, cheap_error := os.read_entire_file(fmt.tprintf("%s/cheap.endpoint", dir), allocator)
	assert(cheap_error == nil)
	cheap, valid_endpoint := net.parse_endpoint(string(cheap_bytes))
	assert(valid_endpoint)
	delete(cheap_bytes, allocator)
	fd_before := fd_count()
	runtime: async.Runtime
	assert(async.init(&runtime, {workers = 1, task_capacity = 8, io_capacity = 16, allocator = allocator}).kind == .None)
	c: surf.Client
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 3 * time.Second, scope = scope},
		capacities = surf.Capacities {
			requests = 4,
			origins = 2,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	assert(surf.client_init(&c, &runtime, config, allocator).kind == .None)
	scheme := "https" if encrypted else "http"
	held_url := fmt.tprintf("%s://127.0.0.1:%d/hold", scheme, endpoint.port)
	held, error := surf.client_submit(&c, {method = .GET, url = held_url})
	assert(error.kind == .None)
	assert(async.start(&runtime).kind == .None)
	start := time.tick_now()

	for !os.exists(fmt.tprintf("%s/held", dir)) {
		assert(time.tick_since(start) < 5 * time.Second)
		time.sleep(time.Millisecond)
	}

	// The held exchange owns the origin's one connection: these two wait for it.
	expiry := time.tick_add(time.tick_now(), 300 * time.Millisecond)
	expired_url := fmt.tprintf("%s://127.0.0.1:%d/expired", scheme, endpoint.port)
	expired, error_expired := surf.client_submit(&c, {method = .GET, url = expired_url}, expiry)
	assert(error_expired.kind == .None)
	cancelled_url := fmt.tprintf("%s://127.0.0.1:%d/cancelled", scheme, endpoint.port)
	cancelled, error_cancelled := surf.client_submit(&c, {method = .GET, url = cancelled_url})
	assert(error_cancelled.kind == .None)
	start = time.tick_now()

	for {
		stage, stage_error := surf.client_request_stage(&c, cancelled)
		assert(stage_error.kind == .None && (stage == .Queued || stage == .Connecting))
		if stage == .Connecting {
			break
		}

		assert(time.tick_since(start) < 200 * time.Millisecond)
		thread.yield()
	}

	cheap_url := fmt.tprintf("http://127.0.0.1:%d/cheap", cheap.port)
	cheap_handle, error_cheap := surf.client_submit(&c, {method = .GET, url = cheap_url})
	assert(error_cheap.kind == .None)
	assert(surf.client_cancel(&c, cancelled).kind == .None)
	pending: Public_Completions
	cheap_result := collect(&c, &pending, cheap_handle)
	assert(cheap_result.error.kind == .None)
	response: surf.Response
	assert(surf.client_take(&c, cheap_handle, &response).kind == .None)
	assert(string(response.body) == "ok")
	surf.response_destroy(&response)
	assert(!os.exists(fmt.tprintf("%s/release", dir)))
	expired_result := collect(&c, &pending, expired)
	assert(expired_result.error.kind == .Deadline_Failed && expired_result.error.phase == .Deadline)
	assert(surf.client_release(&c, expired).kind == .None)
	cancelled_result := collect(&c, &pending, cancelled)
	assert(cancelled_result.error.phase == .Cancellation && cancelled_result.error.write_effect == .Not_Sent)
	assert(surf.client_release(&c, cancelled).kind == .None)
	assert(surf.client_cancel(&c, held).kind == .None)
	held_result := collect(&c, &pending, held)
	assert(held_result.error.phase == .Cancellation)
	assert(surf.client_release(&c, held).kind == .None)
	assert(os.write_entire_file(fmt.tprintf("%s/release", dir), "done") == nil)
	_, extra := surf.client_poll(&c)
	assert(!extra && pending.count == 0)
	assert(surf.client_close(&c).kind == .None)
	start = time.tick_now()

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}

	assert(surf.client_destroy(&c).kind == .None)
	async.shutdown(&runtime)
	assert(async.join(&runtime).kind == .None)
	assert(async.destroy(&runtime).kind == .None)
	surf.trust_roots_destroy(&roots)
	assert(fd_count() == fd_before)
	state, _ := budget.snapshot(scope)
	assert(state.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.print("{")
	fmt.printf(
		"\"completed\":4,\"tls\":%v,\"workers\":1,\"held_body\":true,\"cheap_before_release\":true,\"waiting_expired\":true,\"waiting_cancelled\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true}\n",
		encrypted,
	)
}
