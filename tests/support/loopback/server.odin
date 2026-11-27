package loopback

import "core:net"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

SERVER_REQUEST_BYTES :: 1 << 20

Action :: enum {
	Reply,
	// Close without answering.
	Close,
	// Abort the connection with a reset instead of a FIN.
	Reset,
	// Never answer; keep the connection open until the client closes it.
	Silent,
}

Answer :: struct {
	action: Action,
	wire:   string,
	// Close after the reply instead of reading the next request.
	close:  bool,
}

// What the peer received for one request: the head, and the body unless the
// server answers early. Valid only during the call.
Received :: struct {
	method: string,
	target: string,
	head:   string,
	body:   []u8,
}

Respond :: proc(server: ^Server, request: Received) -> Answer

// A cleartext HTTP/1.1 peer on 127.0.0.1, one thread per connection. Set
// answer (or respond) before server_start; the counters are read under mu.
Server :: struct {
	answer:      Answer,
	respond:     Respond,
	// Answer once the request head is in, before its body is read.
	early:       bool,
	user:        rawptr,
	port:        int,
	mu:          sync.Mutex,
	accepts:     int,
	requests:    int,
	// Bytes read from every connection.
	received:    int,
	last:        [dynamic]u8,
	listener:    net.TCP_Socket,
	worker:      ^thread.Thread,
	stop:        bool,
	connections: int,
}

Server_Connection :: struct {
	server: ^Server,
	socket: net.TCP_Socket,
}

server_start :: proc(s: ^Server) -> bool {
	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		return false
	}

	endpoint, bound_error := net.bound_endpoint(listener)
	if bound_error != nil {
		net.close(listener)
		return false
	}

	s.listener = listener
	s.port = endpoint.port
	s.worker = thread.create_and_start_with_poly_data(s, server_accept)

	if s.worker == nil {
		net.close(listener)
		return false
	}

	return true
}

// Stops accepting, waits for every connection thread, and frees the record.
server_stop :: proc(s: ^Server) {
	if s.worker == nil {
		return
	}

	sync.atomic_store(&s.stop, true)
	// accept(2) is not woken by a close from another thread on every platform.
	if wake, e := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = s.port}); e == nil {
		net.close(wake)
	}

	thread.join(s.worker)
	thread.destroy(s.worker)
	s.worker = nil
	net.close(s.listener)

	for sync.atomic_load(&s.connections) > 0 {
		time.sleep(5 * time.Millisecond)
	}

	delete(s.last)
	s.last = nil
}

server_accepts :: proc(s: ^Server) -> int {
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	return s.accepts
}

server_requests :: proc(s: ^Server) -> int {
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	return s.requests
}

server_received :: proc(s: ^Server) -> int {
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	return s.received
}

// A copy of the last request the peer received, head and body.
server_last :: proc(s: ^Server, allocator := context.allocator) -> string {
	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	return strings.clone(string(s.last[:]), allocator)
}

server_accept :: proc(s: ^Server) {
	for {
		socket, _, accept_error := net.accept_tcp(s.listener)

		if sync.atomic_load(&s.stop) {
			if accept_error == nil {
				net.close(socket)
			}

			return
		}

		if accept_error != nil {
			continue
		}

		sync.lock(&s.mu)
		s.accepts += 1
		sync.unlock(&s.mu)
		connection := new(Server_Connection)
		connection^ = {
			server = s,
			socket = socket,
		}
		sync.atomic_add(&s.connections, 1)
		worker := thread.create_and_start_with_poly_data(
			connection,
			server_serve,
			self_cleanup = true,
		)

		if worker == nil {
			net.close(socket)
			free(connection)
			sync.atomic_sub(&s.connections, 1)
		}
	}
}

server_serve :: proc(connection: ^Server_Connection) {
	s := connection.server
	socket := connection.socket
	free(connection)
	defer sync.atomic_sub(&s.connections, 1)

	_ = net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond)
	_ = net.set_option(socket, .TCP_Nodelay, true)
	pending := make([dynamic]u8, 0, 64 * 1024)
	defer delete(pending)
	scratch: [16 * 1024]u8
	closed := false

	for !closed {
		split := -1

		for split < 0 {
			split = strings.index(string(pending[:]), "\r\n\r\n")
			if split >= 0 {
				break
			}

			if !server_fill(s, socket, &pending, scratch[:]) {
				net.close(socket)
				return
			}
		}

		length, _ := content_length(string(pending[:split]))
		consumed := split + 4

		if !s.early {
			for len(pending) < split + 4 + length {
				if len(pending) > SERVER_REQUEST_BYTES ||
				   !server_fill(s, socket, &pending, scratch[:]) {
					net.close(socket)
					return
				}
			}

			consumed += length
		}

		// Parsed only now: reading the body may have moved pending.
		head := string(pending[:split])
		line_end := strings.index(head, "\r\n")
		line := head if line_end < 0 else head[:line_end]
		method, target, _, _ := request_line(line)
		request := Received {
			method = method,
			target = target,
			head   = head,
			body   = pending[split + 4:consumed],
		}
		answer := server_answer(s, request)

		sync.lock(&s.mu)
		s.requests += 1
		clear(&s.last)
		append(&s.last, ..pending[:consumed])
		sync.unlock(&s.mu)
		remove_range(&pending, 0, consumed)

		switch answer.action {
		case .Reply:
			if !write_full(socket, transmute([]u8)answer.wire) || answer.close {
				closed = true
			}
		case .Close:
			closed = true
		case .Reset:
			_ = net.set_option(socket, .Linger, time.Duration(0))
			closed = true
		case .Silent:
			for server_fill(s, socket, &pending, scratch[:]) {
			}

			closed = true
		}

		// The unread body is still on the wire: no next request can be framed.
		if s.early {
			closed = true
		}
	}

	net.close(socket)
}

server_answer :: proc(s: ^Server, request: Received) -> Answer {
	if s.respond != nil {
		return s.respond(s, request)
	}

	return s.answer
}

// False once the client closed, the read failed, or the server is stopping.
server_fill :: proc(
	s: ^Server,
	socket: net.TCP_Socket,
	pending: ^[dynamic]u8,
	scratch: []u8,
) -> bool {
	for {
		if sync.atomic_load(&s.stop) {
			return false
		}

		n, error := net.recv_tcp(socket, scratch)

		if error == .Timeout || error == .Would_Block || error == .Interrupted {
			continue
		}

		if error != nil || n == 0 {
			return false
		}

		append(pending, ..scratch[:n])
		sync.lock(&s.mu)
		s.received += n
		sync.unlock(&s.mu)

		return true
	}
}
