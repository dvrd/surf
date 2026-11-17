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
wait :: proc(c: ^client.Client, h: client.Request_Handle) -> client.Completion {
	start := time.tick_now()

	for {
		result, available := client.client_poll(c)

		if available {
			assert(result.request == h); return result
		}

		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}
}
// Rejected Capacity owns no handle or wire attempt. Wait for the previous
// physical Origin/Session retirement, retaining one caller cutoff for admission.
submit :: proc(c: ^client.Client, r: ^runtime_async.Runtime, request: http.Request) -> client.Request_Handle {
	deadline := runtime_async.deadline_after(r, 3 * time.Second)

	for {
		h, error := client.client_submit(c, request, deadline)

		if error.kind == .None {
			return h
		}

		if error.kind != .Capacity {
			fmt.eprintf("submit failed %v\n", error)
		}

		assert(error.kind == .Capacity && h == (client.Request_Handle{}))
		assert(runtime_async.deadline_after(r, 0).at < deadline.at)
		time.sleep(time.Millisecond)
	}
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
	scope, cause := scopes.create_root({bytes = 32 << 20, streams = 2, jobs = 8}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		raw, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator); assert(error == nil)
		assert(tls.root_pool_parse(&roots, raw, allocator).kind == .None); delete(raw, allocator)
	}

	before := fd_count()
	r: runtime_async.Runtime
	assert(
		runtime_async.init(&r, {workers = 1, task_capacity = 6, io_capacity = 4, allocator = allocator}).kind == .None,
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

	if framing {
		config.capacities = client.Capacities {
			requests               = 2,
			origins                = 1,
			connections            = 1,
			connections_per_origin = 1,
			waiters_per_origin     = 1,
			dns_ids                = 0,
			work_per_resume        = 1,
		}
	}

	if mode == "idle" {
		config.idle_timeout = 50 * time.Millisecond; config.max_age = 10 * time.Second
	}

	if mode == "maxage" {
		config.idle_timeout = 10 * time.Second; config.max_age = 100 * time.Millisecond
	}

	dns_servers: [1]net.Endpoint

	if mode == "host-alias" || mode == "wrong-host" {
		bytes, error := os.read_entire_file(fmt.tprintf("%s/dns.endpoint", dir), allocator)
		assert(error == nil)
		dns_servers[0], valid = net.parse_endpoint(string(bytes))
		assert(valid)
		delete(bytes, allocator)
		config.http.resolver.name_servers = dns_servers[:]
		caps, ok := config.capacities.?
		assert(ok)
		caps.dns_ids = 64
		config.capacities = caps
	}

	if encrypted {
		config.http.tls.root_cas = roots.roots[:roots.count]; config.http.tls.alpn_protocols = protocols[:]
	}

	assert(client.client_init(&c, &r, config, allocator).kind == .None)
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
				assert(client.client_take(&c, h, &response).kind == .None)
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
			} else {
				assert(client.client_release(&c, h).kind == .None)
			}
		}

		result = {
			completed = 19,
			failures  = 4,
			first     = first_connection,
		}
	} else {
		result = run_mode(&c, &r, config, endpoint, encrypted, mode, dir, allocator)
	}

	close := client.client_close(&c)
	assert(close.kind == .None || close.kind == .Pending)
	start := time.tick_now()

	for !client.client_quiescent(&c) {
		assert(time.tick_since(start) < 8 * time.Second)
		thread.yield()
	}

	assert(client.client_destroy(&c).kind == .None)
	assert(runtime_async.wait_idle(&r).kind == .None)
	assert(runtime_async.destroy(&r).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == before)
	usage, _ := scopes.snapshot(scope)
	assert(usage.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
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
fetch :: proc(c: ^client.Client, r: ^runtime_async.Runtime, url: string) -> (int, surf.HTTP_Error) {
	h := submit(c, r, {method = .GET, url = url})
	completion := wait(c, h)

	if completion.error.kind != .None {
		assert(client.client_release(c, h).kind == .None)
		return 0, completion.error
	}

	response: surf.Response
	assert(client.client_take(c, h, &response).kind == .None)
	assert(response.status == 200 && string(response.body) == "ok")
	id, ok := strconv.parse_int(field(&response, "X-Connection"))
	assert(ok && id > 0)
	surf.response_destroy(&response)

	return id, {}
}
run_mode :: proc(
	c: ^client.Client,
	r: ^runtime_async.Runtime,
	config: client.Client_Config,
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
	if mode == "idle" || mode == "maxage" {
		start := time.tick_now()

		for {
			stats, valid := client.client_stats(c)
			assert(valid)

			if stats.close_count > 0 {
				break
			}

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

		_, cause := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))
		assert(cause.kind != .None && cause.write_effect == .Not_Sent)
		third, success := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third != first)
		result.completed = 3
		result.failures = 1
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
	if mode == "clients" || mode == "trust" || mode == "alpn" {
		b: client.Client
		other := config
		wrong: tls.Root_Pool
		offers := [1]string{"h3"}

		if mode == "trust" {
			raw, cause := os.read_entire_file(fmt.tprintf("%s/wrong.pem", dir), allocator); assert(cause == nil)
			assert(tls.root_pool_parse(&wrong, raw, allocator).kind == .None); delete(raw, allocator)
			other.http.tls.root_cas = wrong.roots[:wrong.count]
		}

		if mode == "alpn" {
			other.http.tls.alpn_protocols = offers[:]
		}

		init := client.client_init(&b, r, other, allocator)

		if mode == "alpn" {
			assert(init.kind == .Invalid_Config); result.rejected = 1
		} else {
			assert(init.kind == .None)
			second, cause := fetch(&b, r, fmt.tprintf("%s://127.0.0.1:%d/B", scheme, endpoint.port))

			if mode == "trust" {
				assert(cause.kind == .TLS_Failed); result.failures = 1
			} else {
				assert(cause.kind == .None && second != first)
			}

			result.second = second
			result.completed += 1
			closed := client.client_close(&b)
			assert(closed.kind == .None || closed.kind == .Pending)
			start := time.tick_now()

			for !client.client_quiescent(&b) {
				assert(time.tick_since(start) < 5 * time.Second)
				thread.yield()
			}

			assert(client.client_destroy(&b).kind == .None)
		}

		tls.root_pool_destroy(&wrong)
		third, success := fetch(c, r, fmt.tprintf("%s://127.0.0.1:%d/C", scheme, endpoint.port))
		assert(success.kind == .None && third == first)
		result.completed += 1
		result.third = third
		return result
	}
	panic("unimplemented pool fixture mode")
}
