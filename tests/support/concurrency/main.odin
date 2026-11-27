package main
import "shared:async"
import "shared:surf"
import rt "base:runtime"
import "base:intrinsics"
import "shared:async/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:sync"
import "shared:async/budget"
import "core:sys/posix"
import "core:thread"
import "core:time"

Record :: struct {
	handle:                  surf.Request_Handle,
	accepted, claimed, done: bool,
	connection:     int,
	error:          surf.HTTP_Error,
}
State :: struct {
	client:                                  surf.Client,
	runtime:                                 async.Runtime,
	mu:                                      sync.Mutex,
	records:                                 [64]Record,
	retained:                                surf.Response,
	endpoint:                                net.Endpoint,
	encrypted, shutdown:                     bool,
	producers, accepted, finished, rejected: int,
}
Producer :: struct {
	state: ^State,
	index: int,
}
Consumer :: struct {
	state: ^State,
	poll:  bool,
}
fd_count :: proc() -> int {
	n := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			n += 1
		}
	}

	return n
}
produce :: proc(p: ^Producer) {
	s := p.state

	for step in 0 ..< 16 {
		id := p.index * 16 + step
		url_storage: [256]u8
		body_storage: [32]u8
		body := fmt.bprintf(body_storage[:], "%d", id)
		url := fmt.bprintf(
			url_storage[:],
			"%s://127.0.0.1:%d/work/%d",
			"https" if s.encrypted else "http",
			s.endpoint.port,
			id,
		)
		cutoff := time.tick_add(time.tick_now(), 10 * time.Second)
		started := time.tick_now()

		for {
			h, error := surf.client_submit(
				&s.client,
				{method = .POST, url = url, headers = {{name = "X-Id", value = body}}, body = transmute([]u8)body},
				cutoff,
			)

			if error.kind == .None {
				sync.lock(&s.mu)
				s.records[id].handle = h
				s.records[id].accepted = true
				sync.unlock(&s.mu)
				intrinsics.atomic_add(&s.accepted, 1)
				for &b in url_storage {b = '!'}; for &b in body_storage {b = '?'}
				break
			}

			original, unchanged := strconv.parse_int(body)
			assert(unchanged && original == id && h == (surf.Request_Handle{}))

			if error.kind == .Closed && s.shutdown {
				intrinsics.atomic_add(&s.rejected, 1)
				intrinsics.atomic_add(&s.producers, 1)
				return
			}

			assert(error.kind == .Capacity)
			intrinsics.atomic_add(&s.rejected, 1)
			assert(time.tick_since(started) < 8 * time.Second)
			time.sleep(100 * time.Microsecond)
		}
	}

	intrinsics.atomic_add(&s.producers, 1)
}
find :: proc(s: ^State, h: surf.Request_Handle) -> int {
	started := time.tick_now()

	for {
		sync.lock(&s.mu)

		for item, id in s.records {
			if item.accepted && item.handle == h {
				sync.unlock(&s.mu)
				return id
			}
		}

		sync.unlock(&s.mu)
		assert(time.tick_since(started) < 5 * time.Second)
		thread.yield()
	}
}
finish :: proc(s: ^State, id: int, response: ^surf.Response, error: surf.HTTP_Error) {
	connection := 0

	if error.kind == .None {
		assert(response.status == 200 && string(response.body) == fmt.tprintf("%d", id))

		for field in response.headers {
			if field.name == "X-Connection" {
				n, ok := strconv.parse_int(field.value)
				assert(ok)
				connection = int(n)
			}
		}

		assert(connection > 0)
	} else {
		assert(s.shutdown && error.kind == .IO_Failed && error.phase == .Cancellation)
	}

	sync.lock(&s.mu)
	assert(!s.records[id].done)
	s.records[id].done = true
	s.records[id].connection = connection
	s.records[id].error = error

	if !s.shutdown && id == 63 {
		s.retained = response^
		response^ = {}
	}

	sync.unlock(&s.mu)
	surf.response_destroy(response)
	intrinsics.atomic_add(&s.finished, 1)
}
// client_take on a handle already taken hands out an empty Response, so the
// two consumers claim a record before either takes it.
take :: proc(s: ^State, h: surf.Request_Handle, id: int) {
	sync.lock(&s.mu)

	if s.records[id].claimed {
		sync.unlock(&s.mu)
		return
	}

	s.records[id].claimed = true
	sync.unlock(&s.mu)
	response: surf.Response
	error := surf.client_take(&s.client, h, &response)

	if error.kind == .Pending {
		sync.lock(&s.mu)
		s.records[id].claimed = false
		sync.unlock(&s.mu)
		return
	}

	assert(error.kind == .None || error.kind == .Request_Error && s.shutdown)
	assert(surf.client_release(&s.client, h).kind == .None)
	finish(s, id, &response, error.http)
}
consume :: proc(c: ^Consumer) {
	s := c.state
	started := time.tick_now()
	for intrinsics.atomic_load(&s.producers) < 4 ||
	    intrinsics.atomic_load(&s.finished) < intrinsics.atomic_load(&s.accepted) {
		assert(time.tick_since(started) < 15 * time.Second)
		if c.poll {
			completion, ready := surf.client_poll(&s.client)

			if ready {
				take(s, completion.request, find(s, completion.request))
			}
		} else {
			for id in 0 ..< len(s.records) {
				sync.lock(&s.mu)
				item := s.records[id]
				sync.unlock(&s.mu)

				if item.accepted && !item.done {
					take(s, item.handle, id)
				}
			}
		}
		time.sleep(100 * time.Microsecond)
	}
}
main :: proc() {
	assert(len(os.args) == 5)
	endpoint, valid := net.parse_endpoint(os.args[1])
	assert(valid)
	mode, encrypted, dir := os.args[2], os.args[3] == "tls", os.args[4]
	assert(mode == "success" || mode == "shutdown")
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	scope, error := budget.create_root({bytes = 64 << 20, streams = 8, jobs = 8}, allocator)
	assert(error == .None)
	roots: surf.Trust_Roots

	if encrypted {
		pem, read_error := os.read_entire_file(fmt.tprintf("%s/root.pem", dir), allocator)
		assert(read_error == nil)
		assert(surf.trust_roots_parse(&roots, pem, allocator) == .None)
		delete(pem, allocator)
	}

	before := fd_count()
	s := State {
		endpoint  = endpoint,
		encrypted = encrypted,
		shutdown  = mode == "shutdown",
	}

	assert(
		async.init(&s.runtime, {workers = 1, task_capacity = 8, io_capacity = 16, allocator = allocator}).kind == .None,
	)
	config := surf.Client_Config {
		http = {allow_http = true, timeout = 10 * time.Second, scope = scope},
		capacities = surf.Capacities {
			requests = 8,
			origins = 1,
			connections_per_origin = 2,
			upload_chunks = 1,
			response_chunks = 1,
		},
	}

	if encrypted {
		config.http.tls.roots = &roots
	}

	assert(
		surf.client_init(&s.client, &s.runtime, config, allocator).kind == .None &&
		async.start(&s.runtime).kind == .None,
	)
	producers: [4]Producer
	producer_threads: [4]^thread.Thread

	for &p, i in producers {
		p = {
			state = &s,
			index = i,
		}

		producer_threads[i] = thread.create_and_start_with_poly_data(&p, produce)
		assert(producer_threads[i] != nil)
	}

	consumers := [2]Consumer{{state = &s, poll = true}, {state = &s, poll = false}}
	consumer_threads: [2]^thread.Thread

	if s.shutdown {
		started := time.tick_now()

		for {
			if os.exists(fmt.tprintf("%s/held", dir)) {
				break
			}; assert(time.tick_since(started) < 10 * time.Second); time.sleep(time.Millisecond)
		}

		async.shutdown(&s.runtime)
		closed := surf.client_close(&s.client)
		assert(closed.kind == .None || closed.kind == .Pending)

		for worker in producer_threads {
			thread.join(worker)
			thread.destroy(worker)
		}

		assert(async.join(&s.runtime).kind == .None && async.destroy(&s.runtime).kind == .None)
		assert(os.write_entire_file(fmt.tprintf("%s/release", dir), "release") == nil)
	}

	for &c, i in consumers {
		consumer_threads[i] = thread.create_and_start_with_poly_data(&c, consume)
		assert(consumer_threads[i] != nil)
	}

	if !s.shutdown {
		for worker in producer_threads {
			thread.join(worker)
			thread.destroy(worker)
		}
	}

	for worker in consumer_threads {
		thread.join(worker)
		thread.destroy(worker)
	}

	// Every losing race must resolve to exactly one completed, retired owner.
	for item in s.records {
		if !item.accepted {
			continue
		}

		assert(item.done)
		assert(surf.client_release(&s.client, item.handle).kind == .Invalid_Handle)
	}

	accepted := intrinsics.atomic_load(&s.accepted)
	finished := intrinsics.atomic_load(&s.finished)
	assert(accepted == finished && (s.shutdown && accepted > 0 && accepted <= 8 || !s.shutdown && accepted == 64))
	_, phantom := surf.client_poll(&s.client)
	assert(!phantom)

	if !s.shutdown {
		closed := surf.client_close(&s.client)
		assert(closed.kind == .None || closed.kind == .Pending)
		started := time.tick_now()

		for !surf.client_quiescent(&s.client) {
			assert(time.tick_since(started) < 10 * time.Second)
			thread.yield()
		}

		assert(async.wait_idle(&s.runtime).kind == .None && async.destroy(&s.runtime).kind == .None)
	}

	assert(surf.client_quiescent(&s.client) && surf.client_destroy(&s.client).kind == .None)
	surf.trust_roots_destroy(&roots)
	assert(fd_count() == before)

	if !s.shutdown {
		assert(string(s.retained.body) == "63")
		surf.response_destroy(&s.retained)
	}

	snapshot, cause := budget.snapshot(scope)
	assert(cause == .None && snapshot.used == (budget.Usage{}))
	budget.release_scope(&scope)
	assert(track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	assert(os.write_entire_file(fmt.tprintf("%s/done", dir), "done") == nil)
	fmt.print("{")
	fmt.printf(
		"\"mode\":\"%s\",\"tls\":%v,\"workers\":1,\"producer_threads\":4,\"consumer_threads\":2,\"accepted\":%d,\"completed\":%d,\"admission_rejections\":%d,\"runtime_gone_before_results\":%v,\"late_response\":%v,\"heap_zero\":true,\"scope_zero\":true,\"fd_zero\":true,\"records\":[",
		mode,
		encrypted,
		accepted,
		finished,
		intrinsics.atomic_load(&s.rejected),
		s.shutdown,
		!s.shutdown,
	)
	first := true

	for item, id in s.records {
		if !item.accepted {
			continue
		}; if !first {
			fmt.print(",")
		}; first = false; fmt.print("{")
		fmt.printf(
			"\"id\":%d,\"connection\":%d,\"kind\":\"%v\",\"phase\":\"%v\",\"effect\":\"%v\",\"status\":%d,\"transport\":\"%v\"}",
			id,
			item.connection,
			item.error.kind,
			item.error.phase,
			item.error.write_effect,
			item.error.status,
			item.error.transport,
		)
	}

	fmt.println("]}")
}
