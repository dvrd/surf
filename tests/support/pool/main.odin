package main
import runtime_async "shared:async"
import "shared:surf"
import http "shared:async/http"
import rt "base:runtime"
import "shared:async/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "shared:async/budget"
import "core:strconv"
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
field :: proc(r: ^surf.Response, name: string) -> string {
	for h in r.headers {
		if h.name == name {
			return h.value
		}
	}; return ""
}
wait :: proc(c: ^surf.Client, h: surf.Request_Handle) -> surf.Completion {
	start := time.tick_now()

	for {
		result, available := surf.client_poll(c)

		if available {
			assert(result.request == h); return result
		}

		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}
}
submit :: proc(c: ^surf.Client, r: ^runtime_async.Runtime, request: http.Request) -> surf.Request_Handle {
	h, error := surf.client_submit(c, request, runtime_async.deadline_after(r, 3 * time.Second))
	assert(error.kind == .None)

	return h
}
main :: proc() {
	assert(len(os.args) == 5)
	endpoint, valid := net.parse_endpoint(os.args[1])
	assert(valid)
	mode, encrypted, dir := os.args[2], os.args[3] == "tls", os.args[4]
	framing := mode == "framing" || mode == "framing-fragmented"
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 32 << 20, streams = 2, jobs = 8}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		raw, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator); assert(error == nil)
		assert(tls.root_pool_parse(&roots, raw, allocator) == nil); delete(raw, allocator)
	}

	before := fd_count()
	r: runtime_async.Runtime
	assert(
		runtime_async.init(&r, {workers = 1, task_capacity = 8, io_capacity = 16, allocator = allocator}).kind == .None,
	)
	c: surf.Client
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 3 * time.Second, scope = scope},
		capacities = surf.Capacities {
			requests = 4,
			origins = 4,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if framing {
		config.capacities = surf.Capacities {
			requests               = 2,
			origins                = 1,
			connections_per_origin = 1,
			upload_chunks          = 1,
			response_chunks        = 1,
		}
	}

	if mode == "idle" {
		config.idle_timeout = 50 * time.Millisecond
	}

	dns_servers: [1]net.Endpoint

	if mode == "host-alias" || mode == "wrong-host" {
		bytes, error := os.read_entire_file(fmt.tprintf("%s/dns.endpoint", dir), allocator)
		assert(error == nil)
		dns_servers[0], valid = net.parse_endpoint(string(bytes))
		assert(valid)
		delete(bytes, allocator)
		config.http.resolver.name_servers = dns_servers[:]
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	assert(surf.client_init(&c, &r, config, allocator).kind == .None)
	assert(runtime_async.start(&r).kind == .None)
	result := Mode_Result{}

	if framing {
		Case :: struct {
			path:           string,
			method:         http.Method,
			body:           string,
			status:         int,
			failure:        http.Error_Kind,
			new_connection: bool,
		}

		cases := [19]Case {
			{"/fixed", .GET, "ok", 200, .None, false},
			{"/zero", .GET, "", 200, .None, false},
			{"/head", .HEAD, "", 200, .None, false},
			{"/204", .GET, "", 204, .None, false},
			{"/304", .GET, "", 304, .None, false},
			{"/chunked", .GET, "abc", 200, .None, false},
			{"/interim", .GET, "ok", 200, .None, false},
			{"/http10", .GET, "ok", 200, .None, false},
			{"/post", .POST, "ok", 200, .None, false},
			{"/close", .GET, "ok", 200, .None, false},
			{"/http10-close", .GET, "ok", 200, .None, true},
			{"/connection-close", .GET, "ok", 200, .None, true},
			{"/eof", .GET, "ok", 200, .None, true},
			{"/truncated", .GET, "", 0, .Unexpected_EOF, true},
			{"/malformed", .GET, "", 0, .Conflicting_Framing, true},
			{"/badchunk", .GET, "", 0, .Invalid_Chunk, true},
			{"/101", .GET, "", 0, .Invalid_Status, true},
			{"/surplus", .GET, "ok", 200, .None, true},
			{"/last", .GET, "ok", 200, .None, true},
		}

		previous, first_connection := 0, 0
		scheme := "https" if encrypted else "http"

		for item, index in cases {
			url := fmt.tprintf("%s://127.0.0.1:%d%s", scheme, endpoint.port, item.path)
			payload := "payload"
			body: []u8

			if item.method == .POST {
				body = transmute([]u8)payload
			}

			h := submit(&c, &r, {method = item.method, url = url, body = body})
			result := wait(&c, h)

			if result.error.kind != item.failure {
				fmt.eprintf("pool case %s got %v expected %v\n", item.path, result.error.kind, item.failure)
			}

			assert(result.error.kind == item.failure)

			if item.failure == .None {
				response: surf.Response
				assert(surf.client_take(&c, h, &response).kind == .None)
				assert(response.status == item.status && string(response.body) == item.body)
				connection, ok := strconv.parse_int(field(&response, "X-Connection"))
				assert(ok && connection > 0)

				if index == 0 {
					first_connection = connection
				}

				if index < 10 {
					assert(connection == first_connection)
				}

				if item.new_connection && previous != 0 {
					assert(connection != previous)
				}

				previous = connection
				surf.response_destroy(&response)
			}

			assert(surf.client_release(&c, h).kind == .None)
		}

		result = {
			completed = 19,
			failures  = 4,
			first     = first_connection,
		}
	} else {
		result = run_mode(&c, &r, config, endpoint, encrypted, mode, dir, allocator)
	}

	close := surf.client_close(&c)
	assert(close.kind == .None || close.kind == .Pending)
	start := time.tick_now()

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}

	assert(surf.client_destroy(&c).kind == .None)
	assert(runtime_async.wait_idle(&r).kind == .None)
	assert(runtime_async.destroy(&r).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == before)
	usage, _ := budget.snapshot(scope)
	assert(usage.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"completed\":%d,\"tls\":%v,\"failures\":%d,\"rejected\":%d,\"framing_cases\":%d,\"first\":%d,\"second\":%d,\"third\":%d,\"timer_ns\":%d,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true}\n",
		result.completed,
		encrypted,
		result.failures,
		result.rejected,
		19 if framing else 0,
		result.first,
		result.second,
		result.third,
		result.timer_ns,
	)
}

Mode_Result :: struct {
	completed, failures, rejected, first, second, third: int,
	timer_ns:                                            i64,
}
fetch :: proc(c: ^surf.Client, r: ^runtime_async.Runtime, url: string) -> (int, surf.HTTP_Error) {
	h := submit(c, r, {method = .GET, url = url})
	completion := wait(c, h)

	if completion.error.kind != .None {
		assert(surf.client_release(c, h).kind == .None)
		return 0, completion.error
	}

	response: surf.Response
	assert(surf.client_take(c, h, &response).kind == .None)
	assert(surf.client_release(c, h).kind == .None)
	assert(response.status == 200 && string(response.body) == "ok")
	id, ok := strconv.parse_int(field(&response, "X-Connection"))
	assert(ok && id > 0)
	surf.response_destroy(&response)

	return id, {}
}
run_mode :: proc(
	c: ^surf.Client,
	r: ^runtime_async.Runtime,
	config: surf.Client_Config,
	endpoint: net.Endpoint,
	encrypted: bool,
	mode, dir: string,
	allocator: mem.Allocator,
) -> Mode_Result {
	result := Mode_Result{}
	scheme := "https" if encrypted else "http"
	host := "A.POOL.TEST" if mode == "host-alias" || mode == "wrong-host" else "127.0.0.1"
	url_a := fmt.tprintf("%s://%s:%d/A", scheme, host, endpoint.port)
	first, error := fetch(c, r, url_a)
	assert(error.kind == .None)
	result.first = first
	result.completed = 1
	if mode == "idle" {
		start := time.tick_now()

		for !os.exists(fmt.tprintf("%s/closed-%d", dir, first)) {
			assert(time.tick_since(start) < time.Second)
			time.sleep(time.Millisecond)
		}

		result.timer_ns = i64(time.tick_since(start))
		second, cause := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))
		assert(cause.kind == .None && second != first)
		result.second = second
		result.completed = 2
		return result
	}
	if mode == "stale" || mode == "peer-close" || mode == "partial" || mode == "separate" || mode == "keyupdate" {
		assert(os.write_entire_file(fmt.tprintf("%s/A.done", dir), "done") == nil)
		start := time.tick_now()

		for !os.exists(fmt.tprintf("%s/staged", dir)) {
			assert(time.tick_since(start) < 3 * time.Second)
			time.sleep(time.Millisecond)
		}

		second, cause := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))
		assert(cause.kind == .None && second != first)
		third, success := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third == second)
		result.completed = 3
		result.second = second
		result.third = third
		return result
	}
	if mode == "keyupdate-inline" {
		second, cause := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))
		assert(cause.kind == .None && second == first)
		result.completed = 2
		result.second = second
		return result
	}
	if mode == "host-alias" || mode == "wrong-host" {
		next := "b.pool.test" if mode == "host-alias" else "wrong.pool.test"
		second, cause := fetch(c, r, fmt.tprintf("%s://%s:%d/B", scheme, next, endpoint.port))

		if mode == "host-alias" {
			assert(cause.kind == .None && second != first)
		} else {
			assert(cause.kind == .TLS_Failed); result.failures = 1
		}

		third, success := fetch(c, r, fmt.tprintf("%s://a.pool.test:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third == first)
		result.completed = 3
		result.second = second
		result.third = third
		return result
	}
	if mode == "ports" || mode == "scheme" {
		second_port := endpoint.port
		second_scheme := scheme

		if mode == "ports" {
			raw, cause := os.read_entire_file(fmt.tprintf("%s/second.endpoint", dir), allocator); assert(cause == nil)
			other, valid := net.parse_endpoint(string(raw)); assert(valid); second_port = other.port
			delete(raw, allocator)
		} else {
			assert(encrypted); second_scheme = "http"
		}

		second, cause := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/B", second_scheme, second_port))
		assert(cause.kind == .None && second != first)
		third, success := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third == first)
		result.completed = 3
		result.second = second
		result.third = third
		return result
	}
	if mode == "clients" || mode == "trust" {
		b: surf.Client
		other := config
		wrong: tls.Root_Pool

		if mode == "trust" {
			raw, cause := os.read_entire_file(fmt.tprintf("%s/wrong.pem", dir), allocator); assert(cause == nil)
			assert(tls.root_pool_parse(&wrong, raw, allocator) == nil); delete(raw, allocator)
			other.http.tls.roots = &wrong
		}

		assert(surf.client_init(&b, r, other, allocator).kind == .None)
		second, cause := fetch(&b, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))

		if mode == "trust" {
			assert(cause.kind == .TLS_Failed); result.failures = 1
		} else {
			assert(cause.kind == .None && second != first)
		}

		result.second = second
		result.completed += 1
		closed := surf.client_close(&b)
		assert(closed.kind == .None || closed.kind == .Pending)
		start := time.tick_now()

		for !surf.client_quiescent(&b) {
			assert(time.tick_since(start) < 5 * time.Second)
			thread.yield()
		}

		assert(surf.client_destroy(&b).kind == .None)

		tls.root_pool_destroy(&wrong)
		third, success := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third == first)
		result.completed += 1
		result.third = third
		return result
	}
	panic("unimplemented pool fixture mode")
}
