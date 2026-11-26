package site

// An in-process HTTPS server on shared:async's Server: HTTP/1.1, HTTP/2 and
// HTTP/3 on one port of 127.0.0.1, with the localhost certificate at
// ../http3. Every request is answered 200; /protocol answers with the protocol
// that carried it, /echo with the request body, anything else with its path.

import "base:intrinsics"
import "base:runtime"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:time"
import "shared:async"

CERT :: #load("../http3/localhost.pem")
KEY :: #load("../http3/rsa2048.pem")

Site :: struct {
	r:           async.Runtime,
	task:        async.Task,
	server:      async.Server,
	config:      async.Server_Config,
	store:       ^async.Credential_Store,
	port:        int,
	begun:       bool,
	begin_error: async.Error,
	ready:       sync.Sema,
	done:        sync.Sema,
	// Requests that arrived, per protocol.
	requests:    [async.Protocol]int,
}

Answer :: struct {
	x:        async.Exchange_Body,
	body:     [dynamic]u8,
	answered: bool,
}

protocol_name :: proc(p: async.Protocol) -> string {
	switch p {
	case .HTTP1:
		return "HTTP/1.1"
	case .H2:
		return "HTTP/2"
	case .H3:
		return "HTTP/3"
	}

	return "?"
}

// A port free for TCP and UDP at once, so HTTP/3 listens at the URL's port.
shared_port :: proc() -> int {
	for _ in 0 ..< 32 {
		listener, listen_error := net.listen_tcp({net.IP4_Loopback, 0})
		if listen_error != nil {
			continue
		}

		endpoint, _ := net.bound_endpoint(listener)
		udp, error := net.make_bound_udp_socket(net.IP4_Loopback, endpoint.port)
		net.close(listener)

		if error == nil {
			net.close(udp)
			return endpoint.port
		}
	}

	return 0
}

// Starts serving protocols (.H3 needs the TCP side too, at the same port).
start :: proc(s: ^Site, protocols: bit_set[async.Protocol]) -> bool {
	allocator := runtime.heap_allocator()

	if async.init(&s.r, {workers = 2, task_capacity = 64, io_capacity = 256}).kind != .None {
		return false
	}

	if async.start(&s.r).kind != .None {
		async.destroy(&s.r)
		return false
	}

	store, store_error := async.credential_store_from_pem(CERT, KEY, allocator)
	if store_error.kind != .None {
		stop_runtime(s)
		return false
	}

	s.store = store

	s.port = shared_port()
	s.config = {
		endpoint  = {net.IP4_Loopback, s.port},
		tls       = async.Accept_TLS_Config{store = store},
		protocols = protocols,
		quic_port = s.port,
	}
	s.task = {
		data = s,
		resume = site_resume,
		on_cancel = proc(data: rawptr) -> async.Resume_Result {
			return async.server_cancel(&(cast(^Site)data).server)
		},
		on_done = proc(data: rawptr) {
			s := cast(^Site)data
			async.server_destroy(&s.server)
			sync.post(&s.done)
		},
	}

	if async.spawn(&s.r, &s.task).kind != .None {
		_ = async.credential_store_destroy(s.store)
		stop_runtime(s)
		return false
	}

	if !sync.sema_wait_with_timeout(&s.ready, 5 * time.Second) || s.begin_error.kind != .None {
		stop(s)
		return false
	}

	return true
}

stop :: proc(s: ^Site) {
	async.server_shutdown(&s.server, async.deadline_after(&s.r, time.Second))
	_ = sync.sema_wait_with_timeout(&s.done, 5 * time.Second)
	stop_runtime(s)
	_ = async.credential_store_destroy(s.store)
}

stop_runtime :: proc(s: ^Site) {
	async.shutdown(&s.r)
	_ = async.join(&s.r)
	_ = async.destroy(&s.r)
}

requests :: proc(s: ^Site, protocol: async.Protocol) -> int {
	return intrinsics.atomic_load(&s.requests[protocol])
}

url :: proc(s: ^Site, path: string, allocator := context.temp_allocator) -> string {
	return fmt.aprintf("https://localhost:%d%s", s.port, path, allocator = allocator)
}

site_resume :: proc(data: rawptr) -> async.Resume_Result {
	s := cast(^Site)data

	if !s.begun {
		s.begun = true
		s.begin_error = async.server_begin(&s.server, &s.task, s.config, handler, s)
		sync.post(&s.ready)

		if s.begin_error.kind != .None {
			return .Done
		}
	}

	return async.server_resume(&s.server)
}

handler :: proc(r: ^async.Server_Request, w: ^async.Server_Response, user: rawptr) -> async.Resume_Result {
	s := cast(^Site)user
	a := cast(^Answer)r.user

	if async.request_closed(r) {
		if a != nil {
			async.exchange_destroy(&a.x)
			delete(a.body)
			free(a, runtime.heap_allocator())
			r.user = nil
		}

		return .Done
	}

	if a == nil {
		a = new(Answer, runtime.heap_allocator())
		a.body = make([dynamic]u8, runtime.heap_allocator())
		r.user = a
		intrinsics.atomic_add(&s.requests[async.request_protocol(r)], 1)
	}

	if a.answered {
		return .Waiting
	}

	buffer: [4096]u8

	for {
		n, error := async.request_body_read(r, buffer[:])

		#partial switch error.kind {
		case .None:
			append(&a.body, ..buffer[:n])
			continue
		case .Pending:
			return .Waiting
		case .Peer_Closed:
		case:
			return .Done
		}

		break
	}

	path := async.request_path(r)
	body: []u8

	switch path {
	case "/protocol":
		body = transmute([]u8)protocol_name(async.request_protocol(r))
	case "/echo":
		body = a.body[:]
	case:
		body = transmute([]u8)path
	}

	if async.response_exchange_init(w, &a.x).kind != .None {
		return .Done
	}

	if async.exchange_respond(&a.x, {status = 200, content_length = i64(len(body))}).kind != .None {
		return .Done
	}

	chunk, copied := async.owned_copy_bounded(body, len(body))
	if copied.kind != .None {
		return .Done
	}

	if async.exchange_submit(&a.x, &chunk) != .Accepted {
		async.owned_destroy(&chunk)
		return .Done
	}

	if async.exchange_finish(&a.x).kind != .None || async.response_send(w, &a.x).kind != .None {
		return .Done
	}

	a.answered = true

	return .Waiting
}
