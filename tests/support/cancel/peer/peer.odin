// Held-phase loopback peer. Barriers, DNS questions, and TLS bytes match the
// Go fixture: dns, tls, write, header, body, redirect, queued, rawconnect.
package main

import loopback "../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}
TLS13 :: 772
HOLD :: 12 * time.Second
MAX_DNS :: 64
BODY_CAP :: 0

Event :: struct {
	id:              int,
	method:          [16]u8,
	method_n:        int,
	path:            [256]u8,
	path_n:          int,
	request_bytes:   int,
	content_length:  int,
	alpn:            [32]u8,
	alpn_n:          int,
	tls:             int,
	clienthello:     int,
	response_bytes:  int,
}

Request :: struct {
	method:         [16]u8,
	method_n:       int,
	path:           [256]u8,
	path_n:         int,
	length:         int,
	request_bytes:  int,
	ok:             bool,
}

directory: string
phase: string
encrypted: bool
minted: bool

mu: sync.Mutex
events: [8]Event
event_n: int
cheap_before_release: bool
redirect_reused: bool

dns_ids: [MAX_DNS]u16
dns_names: [MAX_DNS][64]u8
dns_name_n: [MAX_DNS]int
dns_types: [MAX_DNS]u16
dns_bytes: [MAX_DNS]int
dns_n: int

dns_fd: net.UDP_Socket
dns_open: bool
dns_mu: sync.Mutex
cheap_fd: net.TCP_Socket
cheap_open: bool
cheap_mu: sync.Mutex
held_fd: net.TCP_Socket
held_open: bool
held_mu: sync.Mutex

address_buf: [64]u8

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	parse_flags()
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
	if encrypted {
		raw := [4]u8{127, 0, 0, 1}
		ips := [1][]u8{raw[:]}
		names := [1]string{"held.cancel.test"}
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "cancel101", names[:], ips[:]) {
			fail("certificate")
		}
		minted = true
	}
	defer if minted {
		loopback.identity_clear()
	}

	dns_socket, dns_error := net.make_unbound_udp_socket(.IP4)
	if dns_error != nil || net.bind(dns_socket, {net.IP4_Loopback, 0}) != .None {
		fail("dns")
	}
	dns_fd = dns_socket
	dns_open = true
	defer close_dns()
	dns_bound, dns_bound_error := net.bound_endpoint(dns_fd)
	if dns_bound_error != nil || !write_endpoint("dns.endpoint", dns_bound.port) {
		fail("dns endpoint")
	}

	cheap_socket, cheap_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if cheap_error != nil {
		fail("cheap listen")
	}
	cheap_fd = cheap_socket
	cheap_open = true
	defer close_cheap()
	cheap_bound, cheap_bound_error := net.bound_endpoint(cheap_fd)
	if cheap_bound_error != nil || !write_endpoint("cheap.endpoint", cheap_bound.port) {
		fail("cheap endpoint")
	}

	held_socket, held_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if held_error != nil {
		fail("held listen")
	}
	held_fd = held_socket
	held_open = true
	defer close_held()
	held_bound, held_bound_error := net.bound_endpoint(held_fd)
	if held_bound_error != nil {
		fail("held bound")
	}

	dns_thread := thread.create_and_start(dns_loop)
	cheap_thread := thread.create_and_start(cheap_loop)
	held_thread := thread.create_and_start(held_loop)
	if dns_thread == nil || cheap_thread == nil || held_thread == nil {
		fail("thread")
	}
	emit_line(fmt.bprintf(address_buf[:], "127.0.0.1:%d", held_bound.port))
	if !wait_file("done", HOLD) {
		fail("barrier timeout done")
	}
	if !mark("release") {
		fail("release")
	}
	close_dns()
	close_held()
	close_cheap()
	thread.destroy(dns_thread)
	thread.destroy(held_thread)
	thread.destroy(cheap_thread)
	emit_json()
}

parse_flags :: proc() {
	phase = "body"
	args := os.args
	i := 1
	for i < len(args) {
		switch args[i] {
		case "-tls":
			encrypted = true
			i += 1
		case "-phase":
			if i + 1 >= len(args) {
				fail("phase")
			}
			phase = args[i + 1]
			i += 2
		case "-dir":
			if i + 1 >= len(args) {
				fail("directory")
			}
			directory = args[i + 1]
			i += 2
		case:
			fail("flag")
		}
	}
	switch phase {
	case "dns", "tls", "write", "header", "body", "redirect", "queued", "rawconnect":
	case:
		fail("unsupported owned phase")
	}
	if directory == "" {
		fail("directory")
	}
}

dns_loop :: proc() {
	buf: [4096]u8
	for {
		n, _, err := net.recv_udp(dns_fd, buf[:])
		if err != nil {
			if err == .Interrupted {
				continue
			}
			return
		}
		if n < 17 {
			fail("DNS question too short")
		}
		name_buf: [256]u8
		name_n := 0
		at := 12
		for {
			if at >= n {
				fail("DNS label bound")
			}
			length := int(buf[at])
			at += 1
			if length == 0 {
				break
			}
			if length > 63 || at + length > n {
				fail("DNS label shape")
			}
			if name_n > 0 {
				if name_n >= len(name_buf) {
					fail("DNS label shape")
				}
				name_buf[name_n] = '.'
				name_n += 1
			}
			if name_n + length > len(name_buf) {
				fail("DNS label shape")
			}
			copy(name_buf[name_n:], buf[at:at + length])
			name_n += length
			at += length
		}
		if at + 4 > n {
			fail("DNS question tail")
		}
		name := string(name_buf[:name_n])
		typ := u16(buf[at]) << 8 | u16(buf[at + 1])
		if name != "held.cancel.test" || (typ != 1 && typ != 28) {
			fail("unexpected named query")
		}
		id := u16(buf[0]) << 8 | u16(buf[1])
		sync.lock(&mu)
		if dns_n == MAX_DNS {
			sync.unlock(&mu)
			fail("DNS question cap")
		}
		dns_ids[dns_n] = id
		dns_name_n[dns_n] = copy(dns_names[dns_n][:], name)
		dns_types[dns_n] = typ
		dns_bytes[dns_n] = n
		dns_n += 1
		sync.unlock(&mu)
		if phase != "dns" {
			fail("unexpected external DNS")
		}
		if !mark("held") {
			fail("held")
		}
	}
}

cheap_loop :: proc() {
	fd := accept_one(cheap_fd, "cheap accept")
	defer net.close(fd)
	arm_deadline(fd)
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	secure := phase == "rawconnect" && encrypted
	if secure {
		loopback.set_recv_timeout(fd, HOLD)
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
	}
	req := read_request(fd, &conn, secure)
	if !req.ok || string(req.method[:req.method_n]) != "GET" || string(req.path[:req.path_n]) != "/cheap" || req.length != 0 {
		fail("cheap request")
	}
	release: [1024]u8
	if os.exists(child(release[:], "release")) {
		fail("cheap completed after held release")
	}
	text := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
	if !write_stream(fd, &conn, secure, text) {
		fail("cheap response")
	}
	ev: Event
	ev.id = 100
	ev.method_n = copy(ev.method[:], req.method[:req.method_n])
	ev.path_n = copy(ev.path[:], req.path[:req.path_n])
	ev.request_bytes = req.request_bytes
	ev.content_length = req.length
	ev.response_bytes = len(text)
	if secure {
		ev.alpn_n = copy(ev.alpn[:], conn.alpn[:conn.alpn_n])
		ev.tls = TLS13
	}
	sync.lock(&mu)
	cheap_before_release = true
	push_locked(&ev)
	sync.unlock(&mu)
}

held_loop :: proc() {
	if phase == "dns" {
		if !wait_file("done", HOLD) {
			fail("barrier timeout done")
		}
		return
	}
	limit := 1
	if phase == "redirect" {
		limit = 2
	}
	for id in 1 ..= limit {
		fd := accept_one(held_fd, "held accept")
		if !serve_held(fd, id) || redirect_reused {
			return
		}
	}
}

serve_held :: proc(fd: net.TCP_Socket, id: int) -> bool {
	defer net.close(fd)
	arm_deadline(fd)
	if phase == "write" && net.set_option(fd, .Receive_Buffer_Size, 1024) != nil {
		fail("read buffer")
	}
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	ev := Event{id = id}
	if phase == "rawconnect" {
		if !mark("held") {
			fail("held")
		}
		if !wait_file("done", HOLD) {
			fail("barrier timeout done")
		}
		if !quiet_close(fd, &conn, false) {
			fail("raw Connecting slot sent unexpected application bytes")
		}
		push_event(&ev)
		return true
	}
	if phase == "tls" {
		ev.clienthello = read_client_hello(fd)
	} else {
		secure := encrypted
		if secure {
			loopback.set_recv_timeout(fd, HOLD)
			if !loopback.handshake(&conn, .HTTP1) {
				return false
			}
			ev.alpn_n = copy(ev.alpn[:], conn.alpn[:conn.alpn_n])
			ev.tls = TLS13
		}
		req := read_request(fd, &conn, secure)
		if !req.ok {
			fail("held request")
		}
		ev.method_n = copy(ev.method[:], req.method[:req.method_n])
		ev.path_n = copy(ev.path[:], req.path[:req.path_n])
		ev.content_length = req.length
		ev.request_bytes = req.request_bytes
		path := string(ev.path[:ev.path_n])
		if path != "/held" && path != "/redirected" {
			fail("held path")
		}
		if phase == "write" && req.length < 16 << 20 {
			fail("write fixture not large")
		}
		if phase == "redirect" && id == 1 {
			text := "HTTP/1.1 307 Redirect\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
			if !write_stream(fd, &conn, secure, text) {
				fail("redirect response")
			}
			ev.response_bytes = len(text)
			push_event(&ev)
			// The client may send the redirected request on this kept-alive
			// connection or close it and dial again.
			next := read_request(fd, &conn, secure)
			if !next.ok {
				return true
			}
			redirect_reused = true
			ev = Event{id = 2, tls = ev.tls, alpn = ev.alpn, alpn_n = ev.alpn_n}
			ev.method_n = copy(ev.method[:], next.method[:next.method_n])
			ev.path_n = copy(ev.path[:], next.path[:next.path_n])
			ev.content_length = next.length
			ev.request_bytes = next.request_bytes
			if string(ev.path[:ev.path_n]) != "/redirected" {
				fail("redirect replayed the old request")
			}
		}
		if phase == "body" || phase == "queued" {
			text := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhe"
			if !write_stream(fd, &conn, secure, text) {
				fail("body response")
			}
			ev.response_bytes = len(text)
		}
	}
	push_event(&ev)
	if !mark("held") {
		fail("held")
	}
	if !wait_file("done", HOLD) {
		fail("barrier timeout done")
	}
	return true
}

read_client_hello :: proc(fd: net.TCP_Socket) -> int {
	head: [5]u8
	if !read_full(fd, head[:]) || head[0] != 22 {
		fail("not ClientHello TLS record")
	}
	length := int(head[3]) << 8 | int(head[4])
	if length < 4 || length > 16384 {
		fail("hello bound")
	}
	first: [1]u8
	if !read_full(fd, first[:]) || first[0] != 1 {
		fail("not ClientHello message")
	}
	left := length - 1
	scratch: [256]u8
	for left > 0 {
		n := min(left, len(scratch))
		if !read_full(fd, scratch[:n]) {
			fail("not ClientHello message")
		}
		left -= n
	}
	return length + 5
}

read_request :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, secure: bool) -> Request {
	pending: [8192]u8
	n := 0
	for {
		head, complete, overflow, parsed := loopback.take_request(pending[:n], BODY_CAP)
		// Overflow is reported as not-ok once the header block is valid and the
		// body exceeds body_cap. Hold a large upload there; do not drain it.
		if overflow || (phase == "write" && strings.index(string(pending[:n]), "\r\n\r\n") >= 0) {
			return request_from_headers(pending[:n])
		}
		if !parsed {
			return {}
		}
		if complete {
			return request_from_head(head, n)
		}
		if n == len(pending) {
			return {}
		}
		got, err := read_some(fd, conn, secure, pending[n:])
		if got > 0 {
			n += got
			continue
		}
		if err == .Interrupted {
			continue
		}
		return {}
	}
}

request_from_head :: proc(head: loopback.Head, n: int) -> Request {
	req: Request
	if len(head.method) > len(req.method) || len(head.target) > len(req.path) {
		return {}
	}
	value, found := loopback.header_value(head.headers, "content-length")
	if found {
		parsed, valid := strconv.parse_int(value, 10)
		if !valid || parsed < 0 {
			return {}
		}
		req.length = parsed
	}
	req.method_n = copy(req.method[:], head.method)
	req.path_n = copy(req.path[:], head.target)
	req.request_bytes = n
	req.ok = true
	return req
}

request_from_headers :: proc(pending: []u8) -> Request {
	req: Request
	text := string(pending)
	split := strings.index(text, "\r\n\r\n")
	if split < 0 {
		return {}
	}
	headers := text[:split]
	line_end := strings.index(headers, "\r\n")
	line := headers if line_end < 0 else headers[:line_end]
	method, target, ok := request_target(line)
	if !ok || len(method) > len(req.method) || len(target) > len(req.path) {
		return {}
	}
	value, found := loopback.header_value(headers, "content-length")
	if found {
		parsed, valid := strconv.parse_int(value, 10)
		if !valid || parsed < 0 {
			return {}
		}
		req.length = parsed
	}
	req.method_n = copy(req.method[:], method)
	req.path_n = copy(req.path[:], target)
	req.request_bytes = len(pending)
	req.ok = true
	return req
}

request_target :: proc(line: string) -> (method, target: string, ok: bool) {
	first := strings.index(line, " ")
	if first <= 0 {
		return
	}
	second := strings.index(line[first + 1:], " ")
	if second <= 0 {
		return
	}
	second += first + 1
	method = line[:first]
	target = line[first + 1:second]
	if len(target) == 0 || second + 1 >= len(line) {
		return
	}
	return method, target, true
}

read_some :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, secure: bool, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if secure {
		n, status := loopback.tls_read(conn, dst)
		if status == .Ok {
			return n, nil
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		if status == .Closed {
			return 0, nil
		}
		return 0, .Connection_Closed
	}
	return net.recv_tcp(fd, dst)
}

write_stream :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, secure: bool, text: string) -> bool {
	if secure {
		return loopback.tls_write(conn, transmute([]u8)text)
	}
	rest := transmute([]u8)text
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

read_full :: proc(fd: net.TCP_Socket, dst: []u8) -> bool {
	at := 0
	for at < len(dst) {
		n, err := net.recv_tcp(fd, dst[at:])
		if n > 0 {
			at += n
			continue
		}
		if err == .Interrupted {
			continue
		}
		return false
	}
	return true
}

// Go reports io.EOF. A blocking Odin recv reports that close as 0, nil.
quiet_close :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, secure: bool) -> bool {
	one: [1]u8
	for {
		if secure {
			n, _ := loopback.tls_read(conn, one[:])
			return n == 0
		}
		n, err := net.recv_tcp(fd, one[:])
		if n != 0 {
			return false
		}
		if err == .Interrupted {
			continue
		}
		return true
	}
}

accept_one :: proc(listener: net.TCP_Socket, what: string) -> net.TCP_Socket {
	for {
		fd, _, err := net.accept_tcp(listener)
		if err == nil {
			return fd
		}
		if err == .Interrupted {
			continue
		}
		fail(what)
	}
}

arm_deadline :: proc(fd: net.TCP_Socket) {
	loopback.set_recv_timeout(fd, HOLD)
	if net.set_option(fd, .Send_Timeout, HOLD) != nil {
		fail("deadline")
	}
}

push_event :: proc(ev: ^Event) {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	push_locked(ev)
}

push_locked :: proc(ev: ^Event) {
	if event_n == len(events) {
		fail("event cap")
	}
	events[event_n] = ev^
	event_n += 1
}

close_dns :: proc() {
	sync.lock(&dns_mu)
	defer sync.unlock(&dns_mu)
	if dns_open {
		dns_open = false
		net.close(dns_fd)
	}
}

close_cheap :: proc() {
	sync.lock(&cheap_mu)
	defer sync.unlock(&cheap_mu)
	if cheap_open {
		cheap_open = false
		net.close(cheap_fd)
	}
}

close_held :: proc() {
	sync.lock(&held_mu)
	defer sync.unlock(&held_mu)
	if held_open {
		held_open = false
		net.close(held_fd)
	}
}

mark :: proc(name: string) -> bool {
	buf: [1024]u8
	return os.write_entire_file(child(buf[:], name), name, FILE_PERM) == nil
}

write_endpoint :: proc(name: string, port: int) -> bool {
	path_buf: [1024]u8
	path := child(path_buf[:], name)
	text_buf: [64]u8
	text := fmt.bprintf(text_buf[:], "127.0.0.1:%d", port)
	return os.write_entire_file(path, text, FILE_PERM) == nil
}

wait_file :: proc(name: string, limit: time.Duration) -> bool {
	buf: [1024]u8
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
	sync.lock(&mu)
	defer sync.unlock(&mu)
	fmt.fprintf(os.stdout, "{{")
	fmt.fprintf(os.stdout, `"cheap_before_release":%t,"dns_bytes":[`, cheap_before_release)
	for i in 0 ..< dns_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		fmt.fprintf(os.stdout, "%d", dns_bytes[i])
	}
	fmt.fprint(os.stdout, `],"dns_ids":[`)
	for i in 0 ..< dns_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		fmt.fprintf(os.stdout, "%d", dns_ids[i])
	}
	fmt.fprint(os.stdout, `],"dns_names":[`)
	for i in 0 ..< dns_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		fmt.fprint(os.stdout, `"`)
		write_escaped(string(dns_names[i][:dns_name_n[i]]))
		fmt.fprint(os.stdout, `"`)
	}
	fmt.fprint(os.stdout, `],"dns_types":[`)
	for i in 0 ..< dns_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		fmt.fprintf(os.stdout, "%d", dns_types[i])
	}
	fmt.fprint(os.stdout, `],"events":[`)
	for i in 0 ..< event_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		ev := &events[i]
		fmt.fprintf(os.stdout, `{{"connection_id":%d,"method":"`, ev.id)
		write_escaped(string(ev.method[:ev.method_n]))
		fmt.fprint(os.stdout, `","path":"`)
		write_escaped(string(ev.path[:ev.path_n]))
		fmt.fprintf(os.stdout, `","request_bytes":%d,"content_length":%d,"alpn":"`, ev.request_bytes, ev.content_length)
		write_escaped(string(ev.alpn[:ev.alpn_n]))
		fmt.fprintf(
			os.stdout,
			`","negotiated_tls":%d,"clienthello_bytes":%d,"response_bytes":%d}}`,
			ev.tls,
			ev.clienthello,
			ev.response_bytes,
		)
	}
	fmt.fprint(os.stdout, `],"phase":"`)
	write_escaped(phase)
	fmt.fprintf(os.stdout, `","tls":%t}}`, encrypted)
	fmt.fprint(os.stdout, "\n")
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

fail :: proc(reason: string) {
	fmt.eprintf("cancel101: %s\n", reason)
	os.exit(1)
}
