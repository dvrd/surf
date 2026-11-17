package main

import client "shared:surf/async"
import runtime_async "shared:async"
import surf "shared:surf"
import http "shared:http"
import rt "base:runtime"
import "core:crypto/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import scopes "core:sync/budget"
import "core:sys/posix"
import "core:thread"
import "core:time"

fd_count :: proc() -> int {
	n := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			n += 1
		}
	}

	return n
}
wait_completion :: proc(c: ^client.Client, want: client.Request_Handle) -> client.Completion {
	started := time.tick_now()

	for {
		result, available := client.client_poll(c)

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
	scope, cause := scopes.create_root({bytes = 32 << 20, streams = 2, jobs = 8}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		path := fmt.tprintf("%s/root.pem", dir)
		root, error := os.read_entire_file(path, allocator)
		assert(error == nil)
		assert(tls.root_pool_parse(&roots, root, allocator).kind == .None)
		delete(root, allocator)
	}

	fd_before := fd_count()
	runtime: runtime_async.Runtime
	assert(
		runtime_async.init(&runtime, {workers = 1, task_capacity = 3, io_capacity = 1, allocator = allocator}).kind ==
		.None,
	)
	c: client.Client
	config := client.Client_Config {
		http = {allow_http = true, timeout = 2 * time.Second, scope = scope},
		capacities = client.Capacities {
			requests = 2,
			origins = 1,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 1,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}

	protocols := [1]string{"http/1.1"}

	if encrypted {
		config.http.tls.root_cas = roots.roots[:roots.count]
		config.http.tls.alpn_protocols = protocols[:]
	}

	assert(client.client_init(&c, &runtime, config, allocator).kind == .None)
	url_storage: [256]u8
	scheme := "https" if encrypted else "http"
	url := fmt.bprintf(url_storage[:], "%s://127.0.0.1:%d/A", scheme, endpoint.port)
	body := [11]u8{'c', 'o', 'p', 'i', 'e', 'd', '-', 'b', 'o', 'd', 'y'}
	value := [8]u8{'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'}
	fields := [1]http.Header{{name = "X-Copy", value = string(value[:])}}
	cutoff := runtime_async.deadline_after(&runtime, 600 * time.Millisecond)
	handle, error := client.client_submit(&c, {method = .POST, url = url, headers = fields[:], body = body[:]}, cutoff)
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
	assert(runtime_async.start(&runtime).kind == .None)
	first := wait_completion(&c, handle)
	assert(first.error.kind == .None)
	response_a: surf.Response
	assert(client.client_take(&c, handle, &response_a).kind == .None)
	assert(
		string(response_a.body) == "A" &&
		header(&response_a, "X-Sequence") == "A" &&
		header(&response_a, "X-Connection") == "1",
	)
	// Taking directly retires the handle; poll cannot produce a phantom node.
	_, available := client.client_poll(&c)
	assert(!available)
	assert(client.client_release(&c, handle).kind != .None)
	assert(os.write_entire_file(fmt.tprintf("%s/A.done", dir), "done") == nil)

	for runtime_async.deadline_after(&runtime, 0).at <= cutoff.at + 20 * i64(time.Millisecond) {
		time.sleep(time.Millisecond)
	}

	url_b := fmt.bprintf(url_storage[:], "%s://127.0.0.1:%d/B", scheme, endpoint.port)
	second, accepted := client.client_submit(&c, {method = .GET, url = url_b})
	assert(accepted.kind == .None && second != handle)

	for &b in url_storage {
		b = '?'
	}

	final := wait_completion(&c, second)
	assert(final.error.kind == .None)
	response_b: surf.Response
	assert(client.client_take(&c, second, &response_b).kind == .None)
	assert(
		string(response_b.body) == "B" &&
		header(&response_b, "X-Sequence") == "B" &&
		header(&response_b, "X-Connection") == "1",
	)
	stats, valid := client.client_stats(&c)
	assert(valid && stats.reuse_count >= 1)
	close_error := client.client_close(&c)
	assert(close_error.kind == .None || close_error.kind == .Pending)
	started := time.tick_now()

	for !client.client_quiescent(&c) {
		assert(time.tick_since(started) < 8 * time.Second)
		thread.yield()
	}

	stats, valid = client.client_stats(&c)
	assert(valid && stats.tasks == 0)
	assert(client.client_destroy(&c).kind == .None)
	assert(runtime_async.wait_idle(&runtime).kind == .None)
	assert(runtime_async.destroy(&runtime).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == fd_before)
	retained, error_scope := scopes.snapshot(scope)
	assert(error_scope == .None && retained.used.bytes > 0 && retained.used.streams == 0)
	assert(string(response_a.body) == "A" && string(response_b.body) == "B")
	surf.response_destroy(&response_a)
	surf.response_destroy(&response_b)
	freed, _ := scopes.snapshot(scope)
	assert(freed.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.print("{")
	fmt.printf(
		"\"completed\":2,\"tls\":%v,\"old_cutoff_expired\":true,\"copied_input\":true,\"late_response\":true,\"reuse_count\":%d,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true}\n",
		encrypted,
		stats.reuse_count,
	)
}

Public_Completions :: struct {
	items: [8]client.Completion,
	count: int,
}
collect :: proc(c: ^client.Client, pending: ^Public_Completions, want: client.Request_Handle) -> client.Completion {
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

		result, available := client.client_poll(c)

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
	scope, cause := scopes.create_root({bytes = 32 << 20, streams = 4, jobs = 16}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		root, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(error == nil)
		assert(tls.root_pool_parse(&roots, root, allocator).kind == .None)
		delete(root, allocator)
	}

	cheap_bytes, cheap_error := os.read_entire_file(fmt.tprintf("%s/cheap.endpoint", dir), allocator)
	assert(cheap_error == nil)
	cheap, valid_endpoint := net.parse_endpoint(string(cheap_bytes))
	assert(valid_endpoint)
	delete(cheap_bytes, allocator)
	fd_before := fd_count()
	runtime: runtime_async.Runtime
	assert(
		runtime_async.init(&runtime, {workers = 1, task_capacity = 4, io_capacity = 2, allocator = allocator}).kind ==
		.None,
	)
	c: client.Client
	config := client.Client_Config {
		http = {allow_http = true, timeout = 3 * time.Second, scope = scope},
		capacities = client.Capacities {
			requests = 4,
			origins = 4,
			connections = 2,
			connections_per_origin = 1,
			waiters_per_origin = 2,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}

	protocols := [1]string{"http/1.1"}

	if encrypted {
		config.http.tls.root_cas = roots.roots[:roots.count]
		config.http.tls.alpn_protocols = protocols[:]
	}

	assert(client.client_init(&c, &runtime, config, allocator).kind == .None)
	scheme := "https" if encrypted else "http"
	held_url := fmt.tprintf("%s://127.0.0.1:%d/hold", scheme, endpoint.port)
	held, error := client.client_submit(&c, {method = .GET, url = held_url})
	assert(error.kind == .None)
	assert(runtime_async.start(&runtime).kind == .None)
	start := time.tick_now()

	for !os.exists(fmt.tprintf("%s/held", dir)) {
		assert(time.tick_since(start) < 5 * time.Second)
		time.sleep(time.Millisecond)
	}

	expiry := runtime_async.deadline_after(&runtime, 100 * time.Millisecond)
	expired, error_expired := client.client_submit(
		&c,
		{method = .GET, url = "http://bank-empty.example/expired"},
		expiry,
	)
	assert(error_expired.kind == .None)
	cancelled, error_cancelled := client.client_submit(
		&c,
		{method = .GET, url = "http://bank-empty.example/cancelled"},
	)
	assert(error_cancelled.kind == .None)
	stage, stage_error := client.client_request_stage(&c, expired)
	assert(stage_error.kind == .None && stage == .Awaiting_DNS_IDs)
	cheap_url := fmt.tprintf("http://127.0.0.1:%d/cheap", cheap.port)
	cheap_handle, error_cheap := client.client_submit(&c, {method = .GET, url = cheap_url})
	assert(error_cheap.kind == .None)
	assert(client.client_cancel(&c, cancelled).kind == .None)
	pending: Public_Completions
	cheap_result := collect(&c, &pending, cheap_handle)
	assert(cheap_result.error.kind == .None)
	response: surf.Response
	assert(client.client_take(&c, cheap_handle, &response).kind == .None)
	assert(string(response.body) == "ok")
	surf.response_destroy(&response)
	assert(!os.exists(fmt.tprintf("%s/release", dir)))
	expired_result := collect(&c, &pending, expired)
	assert(expired_result.error.kind == .Deadline_Failed && expired_result.error.phase == .Deadline)
	assert(client.client_release(&c, expired).kind == .None)
	cancelled_result := collect(&c, &pending, cancelled)
	assert(cancelled_result.error.transport.kind == .Cancelled && cancelled_result.error.phase == .Cancellation)
	assert(client.client_release(&c, cancelled).kind == .None)
	assert(client.client_cancel(&c, held).kind == .None)
	held_result := collect(&c, &pending, held)
	assert(held_result.error.transport.kind == .Cancelled && held_result.error.phase == .Cancellation)
	assert(client.client_release(&c, held).kind == .None)
	assert(os.write_entire_file(fmt.tprintf("%s/release", dir), "done") == nil)
	_, extra := client.client_poll(&c)
	assert(!extra && pending.count == 0)
	stats, valid := client.client_stats(&c)
	assert(valid && stats.dns_ids == 0 && stats.dns_waiters == 0)
	closed := client.client_close(&c)
	assert(closed.kind == .None || closed.kind == .Pending)
	start = time.tick_now()

	for !client.client_quiescent(&c) {
		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}

	assert(client.client_destroy(&c).kind == .None)
	assert(runtime_async.wait_idle(&runtime).kind == .None)
	assert(runtime_async.destroy(&runtime).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == fd_before)
	state, _ := scopes.snapshot(scope)
	assert(state.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	fmt.print("{")
	fmt.printf(
		"\"completed\":4,\"tls\":%v,\"workers\":1,\"held_body\":true,\"cheap_before_release\":true,\"bank_empty_expired\":true,\"bank_empty_cancelled\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true}\n",
		encrypted,
	)
}
