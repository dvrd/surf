// HTTP/1 pool peer. TLS 1.3 is tests/support/loopback: wrong.pem is minted first and
// root.pem last, so the handshake key is the root identity. Records, KeyUpdate,
// and partial ciphertext use that stack; this file does not seal on its own.
package main

import loopback "../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

Event :: struct {
	connection: int,
	order:      int,
	path:       [128]u8,
	path_n:     int,
	method:     [16]u8,
	method_n:   int,
	host:       [256]u8,
	host_n:     int,
	body:       [4096]u8,
	body_n:     int,
	alpn:       [32]u8,
	alpn_n:     int,
	sni:        [256]u8,
	sni_n:      int,
	secure:     bool,
}

Job :: struct {
	fd: net.TCP_Socket,
	id: int,
}

directory: string
mode: string
encrypted: bool
stop: bool
mu: sync.Mutex
events: [512]Event
event_n: int
connections: int
handshake_errors: int
key_updates: int
client_key_updates: int
listener: net.TCP_Socket
second: net.TCP_Socket
dns_socket: net.UDP_Socket
listener_open: bool
second_open: bool
dns_open: bool
listener_mu: sync.Mutex
workers: [32]^thread.Thread
worker_n: int
worker_mu: sync.Mutex

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	defer loopback.identity_clear()
	parse_flags()
	ensure_dir()
	if encrypted && !issue_certificates() {
		fail("certificate")
	}
	listener = listen_tcp()
	listener_open = true
	second = listen_tcp()
	second_open = true
	second_ep := bound(second)
	if !write_endpoint("second.endpoint", second_ep.port) {
		fail("second endpoint")
	}
	dns_socket = listen_udp()
	dns_open = true
	dns_ep := bound_udp(dns_socket)
	if !write_endpoint("dns.endpoint", dns_ep.port) {
		fail("dns endpoint")
	}
	dns_thread := thread.create_and_start(dns_serve)
	second_thread := thread.create_and_start(serve_second)
	if dns_thread == nil || second_thread == nil {
		fail("thread")
	}
	endpoint := bound(listener)
	emit_line(fmt.bprintf(line_buf[:], "127.0.0.1:%d", endpoint.port))
	accept_until_done()
	if !done_exists() {
		fail("native completion not signalled")
	}
	request_stop()
	close_second()
	thread.destroy(second_thread)
	thread.destroy(dns_thread)
	join_workers()
	close_listener()
	close_dns()
	emit_json()
}

parse_flags :: proc() {
	mode = "framing"
	args := os.args
	for i in 1 ..< len(args) {
		arg := args[i]
		if arg == "-tls" {
			encrypted = true
		} else if arg == "-mode" && i + 1 < len(args) {
			mode = args[i + 1]
		} else if arg == "-dir" && i + 1 < len(args) {
			directory = args[i + 1]
		}
	}
	if directory == "" {
		fail("directory required")
	}
}

ensure_dir :: proc() {
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
}

// mint_p256 replaces the one installed identity. wrong.pem is written first;
// the following mint installs the root.pem key used for the handshake.
issue_certificates :: proc() -> bool {
	names := [3]string{"localhost", "a.pool.test", "b.pool.test"}
	raw := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{raw[:]}
	wrong: [4096]u8
	root: [4096]u8
	if !loopback.mint_p256(child(wrong[:], "wrong.pem"), "pool.test", names[:], ips[:]) {
		return false
	}
	return loopback.mint_p256(child(root[:], "root.pem"), "pool.test", names[:], ips[:])
}

listen_tcp :: proc() -> net.TCP_Socket {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	return socket
}

listen_udp :: proc() -> net.UDP_Socket {
	socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if err != nil {
		fail("dns")
	}
	return socket
}

bound :: proc(socket: net.TCP_Socket) -> net.Endpoint {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return endpoint
}

bound_udp :: proc(socket: net.UDP_Socket) -> net.Endpoint {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return endpoint
}

accept_until_done :: proc() {
	if net.set_blocking(listener, false) != nil {
		fail("accept")
	}
	deadline := time.time_add(time.now(), 20 * time.Second)
	for time.diff(deadline, time.now()) <= 0 {
		if done_exists() {
			return
		}
		fd, _, err := net.accept_tcp(listener)
		if err == nil {
			adopt(fd)
			continue
		}
		if err == .Would_Block || err == .Timeout || err == .Interrupted {
			time.sleep(20 * time.Millisecond)
			continue
		}
		if err == .Aborted {
			continue
		}
		fail("accept")
	}
}

serve_second :: proc() {
	for {
		fd, _, err := net.accept_tcp(second)
		if err == nil {
			adopt(fd)
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
}

adopt :: proc(fd: net.TCP_Socket) {
	sync.lock(&mu)
	connections += 1
	id := connections
	sync.unlock(&mu)
	if id > 32 {
		net.close(fd)
		fail("connection fixture cap")
	}
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Send_Timeout, 12 * time.Second)
	loopback.set_recv_timeout(fd, 12 * time.Second)
	// The listening socket is non-blocking, and an accepted socket keeps that.
	// This worker has to wait for the next request on a kept-alive connection.
	if net.set_blocking(fd, true) != nil {
		net.close(fd)
		fail("blocking")
	}
	sync.lock(&worker_mu)
	if worker_n == len(workers) {
		sync.unlock(&worker_mu)
		net.close(fd)
		fail("connection fixture cap")
	}
	sync.unlock(&worker_mu)
	job := new(Job)
	job.fd = fd
	job.id = id
	worker := thread.create_and_start_with_poly_data(job, serve)
	if worker == nil {
		net.close(fd)
		free(job)
		fail("thread")
	}
	sync.lock(&worker_mu)
	if worker_n == len(workers) {
		sync.unlock(&worker_mu)
		fail("connection fixture cap")
	}
	workers[worker_n] = worker
	worker_n += 1
	sync.unlock(&worker_mu)
}

join_workers :: proc() {
	for i in 0 ..< worker_n {
		thread.destroy(workers[i])
	}
}

serve :: proc(job: ^Job) {
	defer free(job)
	storage := new([1 << 16]u8)
	defer free(storage)
	pending := storage[:]
	conn := loopback.Conn {
		fd = job.fd,
	}
	closed := false
	tls_ready := false
	defer {
		if tls_ready && !closed {
			notify := [2]u8{1, 0}
			_ = loopback.seal(&conn, 21, notify[:])
		}
		sync.lock(&mu)
		key_updates += conn.updates
		client_key_updates += conn.client_updates
		sync.unlock(&mu)
		loopback.conn_wipe(&conn)
		if !closed {
			net.close(job.fd)
		}
	}

	secure := encrypted
	if mode == "scheme" {
		first, peeked := peek_byte(job.fd)
		if !peeked {
			return
		}
		secure = first == 22
	}
	if secure {
		loopback.set_recv_timeout(job.fd, 12 * time.Second)
		if !loopback.handshake(&conn, .HTTP1) {
			note_handshake_error()
			return
		}
		loopback.set_recv_timeout(job.fd, 12 * time.Second)
		if string(conn.alpn[:conn.alpn_n]) != "http/1.1" {
			fail("unexpected negotiated protocol")
		}
		tls_ready = true
	}

	n := 0
	manual := false
	for order := 1; order <= 64; order += 1 {
		head: loopback.Head
		for {
			parsed, complete, overflow, ok := loopback.take_request(pending[:n], 1 << 20)
			if !ok || overflow {
				return
			}
			if complete {
				head = parsed
				break
			}
			if n == len(pending) {
				return
			}
			got, err := read_some(secure, &conn, pending[n:])
			if got > 0 {
				n += got
				continue
			}
			if err == .Interrupted {
				continue
			}
			if err == .Would_Block {
				time.sleep(time.Millisecond)
				continue
			}

			if mode == "idle" && n == 0 {
				marker: [32]u8
				_ = write_text(fmt.bprintf(marker[:], "closed-%d", job.id), "closed")
			}

			return
		}
		path_buf: [128]u8
		method_buf: [16]u8
		host_buf: [256]u8
		body_buf: [4096]u8
		path, path_ok := copy_fit(path_buf[:], head.path)
		method, method_ok := copy_fit(method_buf[:], head.method)
		host_header, _ := loopback.header_value(head.headers, "host")
		host, host_ok := copy_fit(host_buf[:], host_header)
		body, body_ok := copy_fit(body_buf[:], string(head.body))
		if !path_ok || !method_ok || !host_ok || !body_ok {
			fail("request field")
		}
		reply: [1024]u8
		wire, close_after := build_response(reply[:], path, method, body, job.id, order)
		record(job.id, order, path, method, host, body, secure, &conn)
		if mode == "keyupdate-inline" && order == 1 {
			if !secure || !loopback.server_key_update(&conn) {
				fail("key update")
			}
			manual = true
		}
		fragmented := mode == "framing-fragmented" && path != "/surplus"
		if !send(&conn, job.fd, secure, manual, fragmented, wire) {
			return
		}
		if path == "/A" && retire_mode() {
			if !wait_file("A.done", 10 * time.Second) {
				fail("fixture coordination timeout")
			}
			if mode == "stale" {
				_ = net.set_option(job.fd, .Linger, time.Duration(0))
				net.close(job.fd)
				closed = true
			} else if mode == "peer-close" {
				if tls_ready {
					notify := [2]u8{1, 0}
					_ = loopback.seal(&conn, 21, notify[:])
				}
				net.close(job.fd)
				closed = true
			} else if mode == "keyupdate" {
				if !secure || !loopback.server_key_update(&conn) {
					fail("key update")
				}
			} else if secure {
				record_buf: [64]u8
				sealed := loopback.seal_wire(
					&conn,
					record_buf[:],
					transmute([]u8)string("OLD"),
					23,
				)
				if sealed < 3 {
					fail("record")
				}
				limit := sealed if mode == "separate" else 3
				if !loopback.write_full(job.fd, record_buf[:limit]) {
					fail("write")
				}
			} else if !write_all(job.fd, transmute([]u8)string("OLD")) {
				fail("write")
			}
			if !write_text("staged", "done") {
				fail("staged")
			}
			if mode == "stale" || mode == "peer-close" {
				return
			}
		}
		if close_after {
			return
		}
		consumed := head.consumed
		if consumed < 0 || consumed > n {
			return
		}
		copy(pending[:], pending[consumed:n])
		n -= consumed
	}
	fail("per-connection fixture request cap")
}

retire_mode :: proc() -> bool {
	return(
		mode == "stale" ||
		mode == "peer-close" ||
		mode == "partial" ||
		mode == "separate" ||
		mode == "keyupdate" \
	)
}

build_response :: proc(
	dst: []u8,
	path, method, body: string,
	id, order: int,
) -> (
	text: string,
	close_after: bool,
) {
	if path == "/head" && method != "HEAD" {
		fail("HEAD vector")
	}
	if path == "/post" && (method != "POST" || body != "payload") {
		fail("POST bytes")
	}
	switch path {
	case "/zero":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 0\r\n\r\n",
			id,
			order,
		)
	case "/head":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 999\r\n\r\n",
			id,
			order,
		)
	case "/204":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 204 No Content\r\nX-Connection: %d\r\nX-Order: %d\r\n\r\n",
			id,
			order,
		)
	case "/304":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 304 Not Modified\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 999\r\n\r\n",
			id,
			order,
		)
	case "/chunked":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\nX-End: yes\r\n\r\n",
			id,
			order,
		)
	case "/interim":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
	case "/http10":
		text = fmt.bprintf(
			dst,
			"HTTP/1.0 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
	case "/close":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
		close_after = true
	case "/http10-close":
		text = fmt.bprintf(
			dst,
			"HTTP/1.0 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
	case "/connection-close":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\ncOnNeCtIoN: keep-alive, , close\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
	case "/eof":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\n\r\nok",
			id,
			order,
		)
		close_after = true
	case "/truncated":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 5\r\n\r\nok",
			id,
			order,
		)
		close_after = true
	case "/malformed":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
			id,
			order,
		)
		close_after = true
	case "/badchunk":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
			id,
			order,
		)
		close_after = true
	case "/101":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 101 Switching Protocols\r\nX-Connection: %d\r\nX-Order: %d\r\n\r\n",
			id,
			order,
		)
		close_after = true
	case "/surplus":
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 2\r\n\r\nokOLD",
			id,
			order,
		)
	case:
		text = fmt.bprintf(
			dst,
			"HTTP/1.1 200 OK\r\nX-Connection: %d\r\nX-Order: %d\r\nContent-Length: 2\r\n\r\nok",
			id,
			order,
		)
	}
	return
}

record :: proc(
	id, order: int,
	path, method, host, body: string,
	secure: bool,
	conn: ^loopback.Conn,
) {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if event_n == len(events) {
		fail("event cap")
	}
	slot := &events[event_n]
	event_n += 1
	slot.connection = id
	slot.order = order
	slot.path_n = copy(slot.path[:], path)
	slot.method_n = copy(slot.method[:], method)
	slot.host_n = copy(slot.host[:], host)
	slot.body_n = copy(slot.body[:], body)
	slot.secure = secure
	if secure {
		slot.alpn_n = copy(slot.alpn[:], conn.alpn[:conn.alpn_n])
		slot.sni_n = copy(slot.sni[:], conn.sni[:conn.sni_n])
	}
}

note_handshake_error :: proc() {
	sync.lock(&mu)
	handshake_errors += 1
	sync.unlock(&mu)
}

read_some :: proc(secure: bool, conn: ^loopback.Conn, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if secure {
		n, status := loopback.tls_read(conn, dst)
		if status == .Ok {
			return n, nil
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		return 0, .Connection_Closed
	}
	return net.recv_tcp(conn.fd, dst)
}

send :: proc(
	conn: ^loopback.Conn,
	fd: net.TCP_Socket,
	secure, manual, fragmented: bool,
	text: string,
) -> bool {
	if manual {
		wire: [2048]u8
		n := loopback.seal_wire(conn, wire[:], transmute([]u8)text, 23)
		if n < 0 {
			return false
		}
		return loopback.write_full(fd, wire[:n])
	}
	if fragmented {
		at := 0
		for at < len(text) {
			step := min(3, len(text) - at)
			chunk := text[at:at + step]
			if secure {
				if !loopback.tls_write(conn, transmute([]u8)chunk) {
					return false
				}
			} else if !write_all(fd, transmute([]u8)chunk) {
				return false
			}
			at += step
		}
		return true
	}
	if secure {
		return loopback.tls_write(conn, transmute([]u8)text)
	}
	return write_all(fd, transmute([]u8)text)
}

write_all :: proc(fd: net.TCP_Socket, src: []u8) -> bool {
	rest := src
	for len(rest) > 0 {
		n, err := net.send_tcp(fd, rest)
		if n > 0 {
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return false
	}
	return true
}

peek_byte :: proc(fd: net.TCP_Socket) -> (value: u8, ok: bool) {
	buf: [1]u8
	for {
		n := posix.recv(posix.FD(fd), &buf[0], 1, {.PEEK})
		if n == 1 {
			return buf[0], true
		}
		if n < 0 && posix.errno() == .EINTR {
			continue
		}
		return 0, false
	}
}

dns_serve :: proc() {
	_ = net.set_option(dns_socket, .Receive_Timeout, 200 * time.Millisecond)
	buf: [4096]u8
	handled := 0
	for handled < 256 {
		if stopping() {
			return
		}
		n, peer, err := net.recv_udp(dns_socket, buf[:])
		if err != nil {
			if err == .Timeout || err == .Would_Block || err == .Interrupted {
				continue
			}
			return
		}
		handled += 1
		if n < 17 {
			continue
		}
		answer_dns(buf[:n], peer)
	}
}

answer_dns :: proc(query: []u8, peer: net.Endpoint) {
	if int(query[4]) << 8 | int(query[5]) != 1 {
		return
	}
	at := 12
	for at < len(query) && query[at] != 0 {
		size := int(query[at])
		if size > 63 || at + 1 + size >= len(query) {
			at = len(query)
			break
		}
		at += size + 1
	}
	if at + 5 > len(query) {
		return
	}
	at += 1
	kind := int(query[at]) << 8 | int(query[at + 1])
	end := at + 4
	out: [4096 + 16]u8
	if end > len(out) {
		return
	}
	copy(out[:], query[:end])
	out[2] = 0x81
	out[3] = 0x80
	for i in 6 ..< 12 {
		out[i] = 0
	}
	total := end
	if kind == 1 {
		out[7] = 1
		answer := [16]u8{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1}
		copy(out[total:], answer[:])
		total += len(answer)
	}
	_, _ = net.send_udp(dns_socket, out[:total], peer)
}

stopping :: proc() -> bool {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	return stop
}

request_stop :: proc() {
	sync.lock(&mu)
	stop = true
	sync.unlock(&mu)
}

close_listener :: proc() {
	sync.lock(&listener_mu)
	defer sync.unlock(&listener_mu)
	if listener_open {
		listener_open = false
		net.close(listener)
	}
}

close_second :: proc() {
	sync.lock(&listener_mu)
	defer sync.unlock(&listener_mu)
	if second_open {
		second_open = false
		net.close(second)
	}
}

close_dns :: proc() {
	sync.lock(&listener_mu)
	defer sync.unlock(&listener_mu)
	if dns_open {
		dns_open = false
		net.close(dns_socket)
	}
}

copy_fit :: proc(dst: []u8, src: string) -> (text: string, ok: bool) {
	if len(src) > len(dst) {
		return "", false
	}
	n := copy(dst, src)
	return string(dst[:n]), true
}

write_endpoint :: proc(name: string, port: int) -> bool {
	scratch: [64]u8
	return write_text(name, fmt.bprintf(scratch[:], "127.0.0.1:%d", port))
}

write_text :: proc(name, text: string) -> bool {
	buf: [4096]u8
	return os.write_entire_file(child(buf[:], name), text, FILE_PERM) == nil
}

wait_file :: proc(name: string, limit: time.Duration) -> bool {
	buf: [4096]u8
	path := child(buf[:], name)
	deadline := time.time_add(time.now(), limit)
	for time.diff(deadline, time.now()) <= 0 {
		if os.exists(path) {
			return true
		}
		time.sleep(time.Millisecond)
	}
	return false
}

done_exists :: proc() -> bool {
	buf: [4096]u8
	return os.exists(child(buf[:], "done"))
}

child :: proc(buf: []u8, name: string) -> string {
	if len(directory) + 1 + len(name) > len(buf) {
		fail("path")
	}
	n := copy(buf, directory)
	buf[n] = '/'
	n += 1
	n += copy(buf[n:], name)
	return string(buf[:n])
}

emit_line :: proc(text: string) {
	_, _ = os.write(os.stdout, transmute([]u8)text)
	newline := [1]u8{'\n'}
	_, _ = os.write(os.stdout, newline[:])
	_ = os.flush(os.stdout)
}

emit_json :: proc() {
	fmt.fprintf(os.stdout, `{{"mode":"`)
	write_escaped(mode)
	fmt.fprintf(
		os.stdout,
		`","tls":%t,"connections":%d,"requests":%d,"events":[`,
		encrypted,
		connections,
		event_n,
	)
	for i in 0 ..< event_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		ev := &events[i]
		fmt.fprintf(os.stdout, `{{"connection":%d,"order":%d,"path":"`, ev.connection, ev.order)
		write_escaped(string(ev.path[:ev.path_n]))
		fmt.fprint(os.stdout, `","method":"`)
		write_escaped(string(ev.method[:ev.method_n]))
		fmt.fprint(os.stdout, `","host":"`)
		write_escaped(string(ev.host[:ev.host_n]))
		fmt.fprint(os.stdout, `","body":"`)
		write_escaped(string(ev.body[:ev.body_n]))
		fmt.fprint(os.stdout, `","alpn":"`)
		write_escaped(string(ev.alpn[:ev.alpn_n]))
		fmt.fprint(os.stdout, `","sni":"`)
		write_escaped(string(ev.sni[:ev.sni_n]))
		fmt.fprintf(os.stdout, `","secure":%t}`, ev.secure)
	}
	fmt.fprintf(
		os.stdout,
		`],"handshake_errors":%d,"key_updates":%d,"client_key_updates":%d}` + "\n",
		handshake_errors,
		key_updates,
		client_key_updates,
	)
	_ = os.flush(os.stdout)
}

write_escaped :: proc(text: string) {
	for i in 0 ..< len(text) {
		c := text[i]
		if c == '"' || c == '\\' {
			pair := [2]u8{'\\', c}
			_, _ = os.write(os.stdout, pair[:])
		} else if c < 0x20 {
			hex := [6]u8{'\\', 'u', '0', '0', HEX[c >> 4], HEX[c & 0x0f]}
			_, _ = os.write(os.stdout, hex[:])
		} else {
			_, _ = os.write(os.stdout, transmute([]u8)text[i:i + 1])
		}
	}
}

HEX := [16]u8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

line_buf: [64]u8

fail :: proc(reason: string) {
	fmt.eprintf("pool101: %s\n", reason)
	os.exit(1)
}
