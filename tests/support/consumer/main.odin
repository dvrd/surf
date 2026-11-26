package main

// A program that uses only surf's public API: execute, a Client on its own
// runtime, and a Client on a runtime the program owns. The server is a plain
// HTTP/1.1 loopback thread.

import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "shared:async"
import "shared:surf"

Server :: struct {
	listener:    net.TCP_Socket,
	port:        int,
	stop:        bool,
	connections: int,
	requests:    int,
	workers:     [dynamic]^thread.Thread,
}

serve :: proc(server: ^Server) {
	for {
		socket, _, accepted := net.accept_tcp(server.listener)
		if sync.atomic_load(&server.stop) {
			if accepted == nil {
				net.close(socket)
			}

			return
		}

		if accepted != nil {
			continue
		}

		sync.atomic_add(&server.connections, 1)
		worker := thread.create_and_start_with_poly_data2(server, socket, serve_connection)
		append(&server.workers, worker)
	}
}

serve_connection :: proc(server: ^Server, socket: net.TCP_Socket) {
	defer net.close(socket)
	pending: [4096]u8
	have := 0

	for {
		n, error := net.recv_tcp(socket, pending[have:])
		if error != nil || n == 0 {
			return
		}

		have += n
		for {
			end := strings.index(string(pending[:have]), "\r\n\r\n")
			if end < 0 {
				break
			}

			line := string(pending[:end])
			if eol := strings.index(line, "\r\n"); eol >= 0 {
				line = line[:eol]
			}

			parts := strings.fields(line, context.temp_allocator)
			target := parts[1] if len(parts) > 1 else "/"
			sync.atomic_add(&server.requests, 1)
			reply := fmt.tprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(target), target)
			if _, sent := net.send_tcp(socket, transmute([]u8)reply); sent != nil {
				return
			}

			copy(pending[:], pending[end + 4:have])
			have -= end + 4
		}

		if have == len(pending) {
			return
		}
	}
}

server_stop :: proc(server: ^Server) {
	sync.atomic_store(&server.stop, true)
	wake, error := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = server.port})
	if error == nil {
		net.close(wake)
	}
}

url :: proc(server: ^Server, path: string) -> string {
	return fmt.tprintf("http://127.0.0.1:%d%s", server.port, path)
}

main :: proc() {
	listener, listened := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	assert(listened == nil)
	bound, _ := net.bound_endpoint(listener)
	server := Server {
		listener = listener,
		port     = bound.port,
	}
	acceptor := thread.create_and_start_with_poly_data(&server, serve)

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)
	config := surf.Config {
		allow_http = true,
		timeout    = 5 * time.Second,
	}

	response, error := surf.execute({method = .GET, url = url(&server, "/execute")}, config, allocator)
	assert(error.kind == .None && response.status == 200 && string(response.body) == "/execute")
	surf.response_destroy(&response)

	started: surf.Client
	assert(surf.client_start(&started, {http = config}, allocator).kind == .None)

	for path in ([?]string{"/started/1", "/started/2"}) {
		response, error = surf.client_execute(&started, {method = .GET, url = url(&server, path)}, allocator)
		assert(error.kind == .None && response.status == 200 && string(response.body) == path)
		surf.response_destroy(&response)
	}

	assert(surf.client_destroy(&started).kind == .None)

	runtime: async.Runtime
	assert(async.init(&runtime, {workers = 1, task_capacity = 8, io_capacity = 64, allocator = allocator}).kind == .None)
	assert(async.start(&runtime).kind == .None)
	owned: surf.Client
	assert(surf.client_init(&owned, &runtime, {http = config}, allocator).kind == .None)
	handle, submitted := surf.client_submit(&owned, {method = .GET, url = url(&server, "/owned")})
	assert(submitted.kind == .None)
	begin := time.tick_now()
	completion: surf.Completion
	found := false

	for !found {
		assert(time.tick_since(begin) < 5 * time.Second)
		completion, found = surf.client_poll(&owned)
		if !found {
			thread.yield()
		}
	}

	assert(completion.request == handle && completion.error.kind == .None)
	assert(surf.client_take(&owned, handle, &response).kind == .None)
	assert(response.status == 200 && string(response.body) == "/owned")
	surf.response_destroy(&response)
	assert(surf.client_release(&owned, handle).kind == .None)
	assert(surf.client_close(&owned).kind == .None)
	_, refused := surf.client_submit(&owned, {method = .GET, url = url(&server, "/late")})
	assert(refused.kind == .Closed)
	begin = time.tick_now()

	for !surf.client_quiescent(&owned) {
		assert(time.tick_since(begin) < 5 * time.Second)
		thread.yield()
	}

	assert(surf.client_destroy(&owned).kind == .None)
	async.shutdown(&runtime)
	assert(async.join(&runtime).kind == .None)
	assert(async.destroy(&runtime).kind == .None)
	assert(track.current_memory_allocated == 0 && len(track.allocation_map) == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)

	server_stop(&server)
	thread.join(acceptor)
	thread.destroy(acceptor)

	for worker in server.workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	delete(server.workers)
	net.close(listener)
	assert(sync.atomic_load(&server.requests) == 4)
	fmt.printf("CONSUMER execute=true client_start=true client_init=true requests=%d heap_zero=true\n", server.requests)
}
