package main
import client "shared:surf/async"
import runtime_async "shared:async"
import surf "shared:surf"
import http "shared:async/http"
import rt "base:runtime"
import "shared:async/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import scopes "shared:async/sync/budget"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "core:strings"
fd_count :: proc() -> int {
	n := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			n += 1
		}
	}

	return n
}
Handoff_Probe :: struct {
	backing:                  mem.Allocator,
	c:                        ^client.Client,
	handle:                   client.Request_Handle,
	close:                    bool,
	armed, fired, reentering: bool,
}
handoff_allocator :: proc(
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
	probe := cast(^Handoff_Probe)data
	if mode == .Free && probe.armed && !probe.fired && !probe.reentering {
		probe.reentering = true
		stage, error := client.client_request_stage(probe.c, probe.handle)

		if error.kind == .None && stage == .Redirecting {
			probe.fired = true
			_, valid := client.client_stats(probe.c)
			assert(valid)

			if probe.close {
				error = client.client_close(probe.c)
				assert(error.kind == .None || error.kind == .Pending)
			} else {
				assert(client.client_cancel(probe.c, probe.handle).kind == .None)
			}
		}

		probe.reentering = false
	}
	return probe.backing.procedure(probe.backing.data, mode, size, alignment, old_memory, old_size, location)
}
main :: proc() {
	assert(len(os.args) == 5)
	endpoint, ok := net.parse_endpoint(os.args[1])
	assert(ok)
	mode, encrypted, dir := os.args[2], os.args[3] == "tls", os.args[4]
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	probe := Handoff_Probe {
		backing = mem.tracking_allocator(&track),
		close   = mode == "handoff-close",
	}

	allocator := mem.Allocator{handoff_allocator, &probe}
	scope, cause := scopes.create_root({bytes = 32 << 20, streams = 1, jobs = 8}, allocator)
	assert(cause == .None)
	roots: tls.Root_Pool

	if encrypted {
		root, error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(error == nil)
		assert(tls.root_pool_parse(&roots, root, allocator).kind == .None)
		delete(root, allocator)
	}

	fd_before := fd_count()
	runtime: runtime_async.Runtime
	assert(
		runtime_async.init(&runtime, {workers = 1, task_capacity = 2, io_capacity = 1, allocator = allocator}).kind ==
		.None,
	)
	c: client.Client
	probe.c = &c
	config := client.Client_Config {
		http = {allow_http = true, timeout = 2 * time.Second, max_redirects = 5, scope = scope},
		capacities = client.Capacities {
			requests = 1,
			origins = 1,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 0,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}

	if mode == "disabled" {
		config.http.max_redirects = 0
	}

	if mode == "bodycap" {
		config.http.max_body_size = 64
	}

	if mode == "cutoff" && !encrypted {
		config.http.timeout = 200 * time.Millisecond
	}

	protocols := [1]string{"http/1.1"}

	if encrypted {
		config.http.tls.root_cas = roots.roots[:roots.count]
		config.http.tls.alpn_protocols = protocols[:]
	}

	dns_servers: [1]net.Endpoint

	if mode == "dns32" {
		bytes, e := os.read_entire_file(fmt.tprintf("%s/dns.endpoint", dir), allocator)
		assert(e == nil)
		dns_servers[0], ok = net.parse_endpoint(string(bytes))
		assert(ok)
		delete(bytes, allocator)
		config.http.resolver.name_servers = dns_servers[:]
		caps := config.capacities.(client.Capacities)
		caps.dns_ids = 64
		config.capacities = caps
	}

	assert(client.client_init(&c, &runtime, config, allocator).kind == .None)
	warmup_case := encrypted && mode == "cutoff"
	warmup_done := false

	if warmup_case {
		// Establish only the first origin before selecting the timed request's
		// immutable caller cutoff. All later-hop TLS setup still consumes200ms.
		assert(runtime_async.start(&runtime).kind == .None)
		warmup_url := fmt.tprintf("https://127.0.0.1:%d/warmup", endpoint.port)
		warmup_handle, warmup_error := client.client_submit(&c, {url = warmup_url})
		assert(warmup_error.kind == .None)
		warmup_started := time.tick_now()

		for {
			result, available := client.client_poll(&c)

			if available {
				assert(result.request == warmup_handle && result.error.kind == .None)
				warmup_response: surf.Response
				assert(client.client_take(&c, warmup_handle, &warmup_response).kind == .None)
				assert(warmup_response.status == 200 && len(warmup_response.body) == 0)
				surf.response_destroy(&warmup_response)
				break
			}

			assert(time.tick_since(warmup_started) < 8 * time.Second)
			thread.yield()
		}

		for {
			stats, valid := client.client_stats(&c)
			assert(valid)

			if stats.idle_connections == 1 {
				break
			}

			assert(time.tick_since(warmup_started) < 8 * time.Second)
			thread.yield()
		}

		warmup_done = true
	}

	scheme := "https" if encrypted else "http"
	host := "one.redirect.test" if mode == "dns32" else "127.0.0.1"
	path := "/dir/start" if mode == "relative" else "/start"
	url := fmt.tprintf("%s://%s:%d%s", scheme, host, endpoint.port, path)
	method := http.Method.GET

	if strings.has_prefix(mode, "head") {
		method = .HEAD
	}

	if strings.has_prefix(mode, "post") {
		method = .POST
	}

	fields := [1]http.Header{{name = "Accept", value = "text/plain"}}

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

	cutoff: runtime_async.Deadline

	if warmup_case {
		cutoff = runtime_async.deadline_after(&runtime, 200 * time.Millisecond)
	}

	handle, error := client.client_submit(&c, {method = method, url = url, headers = fields[:], body = body}, cutoff)
	assert(error.kind == .None)
	probe.handle = handle
	probe.armed = mode == "handoff-cancel" || mode == "handoff-close"
	started := time.tick_now()

	if !warmup_case {
		assert(runtime_async.start(&runtime).kind == .None)
	}

	if mode == "cancel" || mode == "close" {
		for !os.exists(fmt.tprintf("%s/target-held", dir)) {
			assert(time.tick_since(started) < 5 * time.Second)
			thread.yield()
		}

		if mode == "cancel" {
			assert(client.client_cancel(&c, handle).kind == .None)
		} else {
			closed := client.client_close(&c); assert(closed.kind == .None || closed.kind == .Pending)
		}
	}

	completion: client.Completion

	for {
		result, available := client.client_poll(&c)

		if available {
			assert(result.request == handle)
			completion = result
			break
		}

		assert(time.tick_since(started) < 8 * time.Second)
		thread.yield()
	}

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

	if success {
		assert(completion.error.kind == .None)
		assert(client.client_take(&c, handle, &response).kind == .None)

		if mode == "disabled" {
			assert(response.status == 302 && string(response.body) == "intermediate")
		} else {
			assert(response.status == 200); if method == .HEAD {
				assert(len(response.body) == 0)
			} else {
				assert(string(response.body) == "final")
			}
		}
	} else {
		switch mode {
		case "loop", "hopcap":
			assert(completion.error.kind == .Redirect_Limit && completion.error.status == 302)
		case "bodycap":
			assert(completion.error.kind == .Body_Oversized && completion.error.status == 302)
		case "downgrade":
			assert(completion.error.kind == .Insecure_URL && completion.error.status == 302)
		case "cutoff":
			valid_cutoff :=
				completion.error.kind == .Deadline_Failed &&
				completion.error.phase == .Deadline &&
				completion.error.status == 302 &&
				(completion.error.write_effect == .Unknown || completion.error.write_effect == .Response_Received) &&
				elapsed < 350 * time.Millisecond

			if !valid_cutoff {
				fmt.eprintf(
					"Cutoff context kind=%v phase=%v status=%d effect=%v elapsed_ms=%d transport=%v\n",
					completion.error.kind,
					completion.error.phase,
					completion.error.status,
					completion.error.write_effect,
					i64(elapsed / time.Millisecond),
					completion.error.transport.kind,
				)
			}

			assert(valid_cutoff)
		case "dns32":
			assert(
				completion.error.kind == .Dial_Failed &&
				completion.error.phase == .DNS &&
				completion.error.status == 302,
			)
		case "handoff-cancel", "cancel":
			assert(completion.error.transport.kind == .Cancelled && completion.error.phase == .Cancellation)
		case "handoff-close", "close":
			assert(completion.error.kind != .None)
		case:
			assert(completion.error.kind == .Unsafe_Redirect && completion.error.status != 0)
		}

		if mode != "cancel" &&
		   mode != "close" &&
		   mode != "handoff-cancel" &&
		   mode != "handoff-close" &&
		   mode != "cutoff" {
			assert(completion.error.write_effect == .Response_Received)
		}

		assert(client.client_release(&c, handle).kind == .None)
	}

	if mode == "handoff-cancel" || mode == "handoff-close" {
		assert(probe.fired)
	}

	_, extra := client.client_poll(&c)
	assert(!extra)
	assert(client.client_release(&c, handle).kind == .Invalid_Handle)
	stats, valid := client.client_stats(&c)
	assert(valid)

	if mode == "dns32" {
		assert(stats.dns_ids == 32 && stats.dns_waiters == 0)
	}

	closed := client.client_close(&c)
	assert(closed.kind == .None || closed.kind == .Pending)
	wait_started := time.tick_now()

	for !client.client_quiescent(&c) {
		assert(time.tick_since(wait_started) < 8 * time.Second)
		thread.yield()
	}

	_, late := client.client_poll(&c)
	assert(!late)
	assert(client.client_destroy(&c).kind == .None)
	assert(runtime_async.wait_idle(&runtime).kind == .None)
	assert(runtime_async.destroy(&runtime).kind == .None)
	tls.root_pool_destroy(&roots)
	assert(fd_count() == fd_before)
	response_status := response.status
	surf.response_destroy(&response)
	state, e := scopes.snapshot(scope)
	assert(e == .None && state.used == (scopes.Usage{}))
	scopes.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"completed\":1,\"same_handle\":true,\"terminal_once\":true,\"workers\":1,\"cap_one\":true,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true,\"dns_ids_remaining\":%d,\"status\":%d,\"response_status\":%d,\"error\":\"%v\",\"phase\":\"%v\",\"write_effect\":\"%v\",\"handoff_callback\":%v,\"warmup\":%v,\"elapsed_ms\":%d}\n",
		stats.dns_ids,
		completion.error.status,
		response_status,
		completion.error.kind,
		completion.error.phase,
		completion.error.write_effect,
		probe.fired,
		warmup_done,
		i64(elapsed / time.Millisecond),
	)
}
