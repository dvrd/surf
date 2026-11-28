package main

import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "shared:async"
import "shared:async/budget"
import "shared:async/tls"
import "shared:surf"

// The peer holds each cutoff hop for 300 ms: the first hop has 500 ms to
// arrive, and the third cannot finish before the cutoff.
CUTOFF :: 800 * time.Millisecond
CUTOFF_SLACK :: 400 * time.Millisecond

fd_count :: proc() -> int {
	n := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			n += 1
		}
	}

	return n
}

// The cross-policy cell refuses the port of the peer's second listener.
refused_port: int

refuse_other :: proc(_: string, addresses: []net.Endpoint, _: rawptr) -> bool {
	for endpoint in addresses {
		if endpoint.port == refused_port {
			return false
		}
	}

	return true
}

wait_completion :: proc(
	c: ^surf.Client,
	want: surf.Request_Handle,
	started: time.Tick,
) -> surf.Completion {
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

main :: proc() {
	assert(len(os.args) == 5)
	endpoint, ok := net.parse_endpoint(os.args[1])
	assert(ok)
	mode, encrypted, dir := os.args[2], os.args[3] == "tls", os.args[4]
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, cause := budget.create_root({bytes = 32 << 20, streams = 1, jobs = 8}, allocator)
	assert(cause == .None)
	roots: surf.Trust_Roots

	if encrypted {
		root, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(error == nil)
		assert(surf.trust_roots_parse(&roots, root, allocator) == .None)
		delete(root, allocator)
	}

	fd_before := fd_count()
	r: async.Runtime
	assert(
		async.init(&r, {workers = 1, task_capacity = 4, io_capacity = 64, allocator = allocator}).kind ==
		.None,
	)
	c: surf.Client
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 2 * time.Second, max_redirects = 5, scope = scope},
		capacities = surf.Capacities {
			requests = 1,
			origins = 1,
			connections_per_origin = 1,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if mode == "disabled" {
		config.http.max_redirects = 0
	}

	if mode == "bodycap" {
		config.http.max_body_size = 64
	}

	if mode == "cutoff" && !encrypted {
		config.http.timeout = CUTOFF
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	if mode == "cross-policy" {
		bytes, e := os.read_entire_file(fmt.tprintf("%s/other.endpoint", dir), allocator)
		assert(e == nil)
		other, parsed := net.parse_endpoint(string(bytes))
		assert(parsed)
		delete(bytes, allocator)
		refused_port = other.port
		config.http.address_policy = refuse_other
	}

	dns_servers: [1]net.Endpoint

	if mode == "dns32" {
		bytes, e := os.read_entire_file(fmt.tprintf("%s/dns.endpoint", dir), allocator)
		assert(e == nil)
		dns_servers[0], ok = net.parse_endpoint(string(bytes))
		assert(ok)
		delete(bytes, allocator)
		config.http.resolver.name_servers = dns_servers[:]
	}

	assert(surf.client_init(&c, &r, config, allocator).kind == .None)
	warmup_case := encrypted && mode == "cutoff"

	if warmup_case {
		// Only the first origin is set up before the timed request's cutoff is
		// chosen; every later hop's TLS setup spends the cutoff.
		assert(async.start(&r).kind == .None)
		warmup_url := fmt.tprintf("https://127.0.0.1:%d/warmup", endpoint.port)
		warmup_handle, warmup_error := surf.client_submit(&c, {url = warmup_url})
		assert(warmup_error.kind == .None)
		warmup := wait_completion(&c, warmup_handle, time.tick_now())
		assert(warmup.error.kind == .None)
		warmup_response: surf.Response
		assert(surf.client_take(&c, warmup_handle, &warmup_response).kind == .None)
		assert(warmup_response.status == 200 && len(warmup_response.body) == 0)
		surf.response_destroy(&warmup_response)
		assert(surf.client_release(&c, warmup_handle).kind == .None)
	}

	scheme := "https" if encrypted else "http"
	host := "one.redirect.test" if mode == "dns32" else "127.0.0.1"
	path := "/dir/start" if mode == "relative" else "/start"
	url := fmt.tprintf("%s://%s:%d%s", scheme, host, endpoint.port, path)
	method := surf.Method.GET

	if strings.has_prefix(mode, "head") {
		method = .HEAD
	}

	if strings.has_prefix(mode, "post") {
		method = .POST
	}

	fields := [1]surf.Header{{name = "Accept", value = "text/plain"}}

	if mode == "cross-auth" {
		fields[0] = {
			name  = "Authorization",
			value = "Bearer private",
		}
	}

	if mode == "cross-cookie" {
		fields[0] = {
			name  = "Cookie",
			value = "secret=value",
		}
	}

	if mode == "cross-custom" {
		fields[0] = {
			name  = "X-Private",
			value = "secret",
		}
	}

	payload := [10]u8{'p', 'r', 'o', 'o', 'f', '-', 'b', 'o', 'd', 'y'}
	body: []u8

	if method == .POST {
		body = payload[:]
	}

	cutoff: time.Tick

	if warmup_case {
		cutoff = time.tick_add(time.tick_now(), CUTOFF)
	}

	handle, error := surf.client_submit(
		&c,
		{method = method, url = url, headers = fields[:], body = body},
		cutoff,
	)
	assert(error.kind == .None)
	started := time.tick_now()

	if !warmup_case {
		assert(async.start(&r).kind == .None)
	}

	held_stage := surf.Request_Stage.Queued

	if mode == "cancel" || mode == "close" {
		for !os.exists(fmt.tprintf("%s/target-held", dir)) {
			assert(time.tick_since(started) < 5 * time.Second)
			thread.yield()
		}

		// The second hop's request is on the wire: the stage reaches Reading.
		for {
			stage, stage_error := surf.client_request_stage(&c, handle)
			assert(stage_error.kind == .None)
			held_stage = stage

			if stage == .Reading {
				break
			}

			assert(time.tick_since(started) < 5 * time.Second)
			thread.yield()
		}

		if mode == "cancel" {
			assert(surf.client_cancel(&c, handle).kind == .None)
		} else {
			assert(surf.client_close(&c).kind == .None)
			_, refused := surf.client_submit(&c, {url = url})
			assert(refused.kind == .Closed)
		}
	}

	completion := wait_completion(&c, handle, started)
	elapsed := time.tick_since(started)
	success :=
		strings.has_prefix(mode, "get") ||
		mode == "relative" ||
		mode == "cross-public" ||
		mode == "head307" ||
		mode == "head308" ||
		mode == "post307" ||
		mode == "post308" ||
		mode == "disabled"
	response: surf.Response
	taken := surf.client_take(&c, handle, &response)

	if success {
		if completion.error.kind != .None {
			fmt.eprintf("%s: %v\n", mode, completion.error)
		}
		assert(completion.error.kind == .None)
		assert(taken.kind == .None)

		if mode == "disabled" {
			assert(response.status == 302 && string(response.body) == "intermediate")
		} else {
			assert(response.status == 200)

			if method == .HEAD {
				assert(len(response.body) == 0)
			} else {
				assert(string(response.body) == "final")
			}
		}
	} else {
		assert(taken.kind == .Request_Error && taken.http == completion.error)
		e := completion.error
		fmt.eprintf("%s: %v\n", mode, e)

		switch mode {
		case "loop", "hopcap", "dns32":
			assert(e.kind == .Redirect_Limit && e.phase == .Protocol && e.status == 302)
		case "bodycap":
			assert(e.kind == .Body_Oversized && e.status == 302)
		case "downgrade":
			assert(e.kind == .Insecure_URL && e.status == 302)
		case "cross-policy":
			assert(e.kind == .Address_Rejected && e.phase == .Connect && e.status == 302)
		case "cutoff":
			valid_cutoff :=
				e.kind == .Deadline_Failed &&
				e.phase == .Deadline &&
				e.status == 302 &&
				(e.write_effect == .Unknown || e.write_effect == .Response_Received) &&
				elapsed < CUTOFF + CUTOFF_SLACK

			if !valid_cutoff {
				fmt.eprintf("cutoff %v elapsed_ms=%d\n", e, i64(elapsed / time.Millisecond))
			}

			assert(valid_cutoff)
		case "cancel":
			assert(e.kind == .IO_Failed && e.phase == .Cancellation && e.status == 302)
		case "close":
			// A close lets the request in flight run to its deadline.
			assert(e.kind == .Deadline_Failed && e.phase == .Deadline && e.status == 302)
		case:
			assert(e.kind == .Unsafe_Redirect && e.phase == .Protocol && e.status != 0)
		}

		if mode != "cancel" && mode != "close" && mode != "cutoff" {
			if e.write_effect != .Response_Received {
				fmt.eprintf("%s: %v\n", mode, e)
			}
			assert(e.write_effect == .Response_Received)
		}
	}

	assert(surf.client_release(&c, handle).kind == .None)
	_, extra := surf.client_poll(&c)
	assert(!extra)
	assert(surf.client_release(&c, handle).kind == .Invalid_Handle)

	if mode != "close" {
		assert(surf.client_close(&c).kind == .None)
	}

	wait_started := time.tick_now()

	for !surf.client_quiescent(&c) {
		assert(time.tick_since(wait_started) < 8 * time.Second)
		thread.yield()
	}

	_, late := surf.client_poll(&c)
	assert(!late)
	assert(surf.client_destroy(&c).kind == .None)
	async.shutdown(&r)
	assert(async.join(&r).kind == .None)
	assert(async.destroy(&r).kind == .None)
	surf.trust_roots_destroy(&roots)
	assert(fd_count() == fd_before)
	response_status := response.status
	surf.response_destroy(&response)
	state, e := budget.snapshot(scope)
	assert(e == .None && state.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(
		track.current_memory_allocated == 0 &&
		len(track.allocation_map) == 0 &&
		len(track.bad_free_array) == 0,
	)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"completed\":1,\"same_handle\":true,\"terminal_once\":true,\"workers\":1,\"cap_one\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true,\"held_stage\":\"%v\",\"status\":%d,\"response_status\":%d,\"error\":\"%v\",\"phase\":\"%v\",\"write_effect\":\"%v\",\"warmup\":%v,\"elapsed_ms\":%d}\n",
		held_stage,
		completion.error.status,
		response_status,
		completion.error.kind,
		completion.error.phase,
		completion.error.write_effect,
		warmup_case,
		i64(elapsed / time.Millisecond),
	)
}
