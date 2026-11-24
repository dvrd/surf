// Owned Actor18 loopback peer. Schedules, barrier files, and JSON match the
// Go peer. TLS 1.3 is tests/loopback; it cannot pause inside one record, so
// partial mode seals the application record here and splits that write.
package main

import loopback "../../../loopback"

import "core:c"
import "core:crypto/aead"
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
CIPHER_AES_128_GCM :: 0x1301
BODY_CAP :: 2 << 20

Event_Kind :: enum {
	accept,
	handshake,
	handshake_error,
	read_terminal,
	request_head,
	uncertain_post_reset,
	body_error,
	write_error,
	body_held,
	response,
	coordination_timeout,
	stale_close,
	partial_record_staged,
	partial_raw_staged,
	stale_write_error,
	dns_query,
	dns_reply,
	server_record_held,
}

Event :: struct {
	kind:           Event_Kind,
	at_ns:          i64,
	connection:     int,
	path:           [64]u8,
	path_n:         int,
	method:         [16]u8,
	method_n:       int,
	body:           [8]u8,
	body_n:         int,
	error:          [160]u8,
	error_n:        int,
	alpn:           [32]u8,
	alpn_n:         int,
	server_name:    [256]u8,
	server_name_n:  int,
	name:           [256]u8,
	name_n:         int,
	content_length: i64,
	body_bytes:     i64,
	body_first:     int,
	version:        int,
	cipher:         int,
	bytes:          int,
	record_type:    int,
	full_bytes:     int,
	qtype:          int,
	id:             int,
}

Request :: struct {
	connection: int,
	path:       [64]u8,
	path_n:     int,
	method:     [16]u8,
	method_n:   int,
	body_bytes: i64,
	at_ns:      i64,
}

DNS_Fact :: struct {
	name:   [256]u8,
	name_n: int,
	qtype:  int,
	id:     int,
	at_ns:  i64,
}

Job :: struct {
	fd:          net.TCP_Socket,
	id:          int,
	name:        [256]u8,
	name_n:      int,
	record_held: bool,
}

Hello_Scan :: enum {
	Need_More,
	Ready,
	Invalid,
}

directory: string
mode: string
encrypted: bool
started: time.Time

state_mu: sync.Mutex
events: [96]Event
event_n: int
requests: [16]Request
request_n: int
dns_facts: [32]DNS_Fact
dns_n: int
connections: int
handshakes: int

listener: net.TCP_Socket
dns_fd: net.UDP_Socket
gate_mu: sync.Mutex
listener_open: bool
dns_open: bool

workers: [8]^thread.Thread
worker_n: int

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	started = time.now()
	parse_flags()
	// make_directory_all rejects a path that already exists. MkdirAll does not.
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
	if encrypted {
		raw := [4]u8{127, 0, 0, 1}
		ips := [1][]u8{raw[:]}
		names := [3]string{"actor.test", "cheap.actor.test", "stall.actor.test"}
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "actor.test", names[:], ips[:]) {
			fail("certificate")
		}
	}
	defer loopback.identity_clear()

	socket, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fail("listen")
	}
	listener = socket
	udp, udp_error := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if udp_error != nil {
		fail("dns")
	}
	dns_fd = udp
	_ = net.set_option(dns_fd, .Receive_Timeout, 200 * time.Millisecond)
	tcp_ep, tcp_error := net.bound_endpoint(listener)
	if tcp_error != nil {
		fail("bound")
	}
	dns_ep, dns_error := net.bound_endpoint(dns_fd)
	if dns_error != nil {
		fail("bound")
	}
	listener_open = true
	dns_open = true
	emit_ready(tcp_ep.port, dns_ep.port)

	dns_thread := thread.create_and_start(dns_serve)
	if dns_thread == nil {
		fail("dns thread")
	}
	watch_thread := thread.create_and_start(watch)
	if watch_thread == nil {
		fail("watch")
	}

	for {
		fd, _, accept_error := net.accept_tcp(listener)
		if accept_error != nil {
			break
		}
		connections += 1
		id := connections
		_ = net.set_option(fd, .TCP_Nodelay, true)
		_ = net.set_option(fd, .Send_Timeout, 10 * time.Second)
		loopback.set_recv_timeout(fd, 10 * time.Second)
		push_event(Event{kind = .accept, connection = id})
		if worker_n == len(workers) {
			net.close(fd)
			fail("connection bound")
		}
		job := new(Job)
		job.fd = fd
		job.id = id
		worker := thread.create_and_start_with_poly_data(job, serve)
		if worker == nil {
			net.close(fd)
			free(job)
			fail("thread")
		}
		workers[worker_n] = worker
		worker_n += 1
	}

	thread.destroy(watch_thread)
	for i in 0 ..< worker_n {
		thread.destroy(workers[i])
	}
	shutdown_listeners()
	thread.destroy(dns_thread)
	emit_summary()
}

parse_flags :: proc() {
	mode = "healthy"
	args := os.args
	for i in 1 ..< len(args) {
		if args[i] == "-tls" {
			encrypted = true
		} else if args[i] == "-mode" && i + 1 < len(args) {
			mode = args[i + 1]
		} else if args[i] == "-dir" && i + 1 < len(args) {
			directory = args[i + 1]
		}
	}
	if directory == "" {
		fail("directory required")
	}
}

emit_ready :: proc(tcp_port, dns_port: int) {
	fmt.fprintf(os.stdout, `{{"event":"ready","tcp":"127.0.0.1:%d","dns":"127.0.0.1:%d","mode":"`, tcp_port, dns_port)
	write_escaped(mode)
	fmt.fprintf(os.stdout, `","tls":%t,"go":"`, encrypted)
	write_escaped(ODIN_VERSION)
	fmt.fprint(os.stdout, "\"}\n")
	_ = os.flush(os.stdout)
}

watch :: proc() {
	_ = wait_file("finish", 15 * time.Second)
	shutdown_listeners()
}

shutdown_listeners :: proc() {
	sync.lock(&gate_mu)
	defer sync.unlock(&gate_mu)
	if listener_open {
		listener_open = false
		net.close(listener)
	}
	if dns_open {
		dns_open = false
		net.close(dns_fd)
	}
}

dns_open_now :: proc() -> bool {
	sync.lock(&gate_mu)
	defer sync.unlock(&gate_mu)
	return dns_open
}

serve :: proc(job: ^Job) {
	defer free(job)
	defer net.close(job.fd)
	conn := loopback.Conn{fd = job.fd}
	defer loopback.conn_wipe(&conn)
	if encrypted {
		session_n, peeked := peek_server_name(job)
		if mode == "setup-deadline" || mode == "body-deadline" {
			// First server bytes are the ServerHello record. Hold them before
			// handshake; loopback writes that record internally.
			bytes := 127
			if peeked {
				bytes = 95 + session_n
			}
			hold_record(job, 22, bytes)
		}
		loopback.set_recv_timeout(job.fd, 10 * time.Second)
		if !loopback.handshake(&conn, .HTTP1) {
			reason := conn.reason
			if reason == "" {
				reason = "handshake"
			}
			emit_error(.handshake_error, job.id, reason)
			return
		}
		loopback.set_recv_timeout(job.fd, 10 * time.Second)
		sync.lock(&state_mu)
		handshakes += 1
		sync.unlock(&state_mu)
		ev := Event {
			kind       = .handshake,
			connection = job.id,
			version    = TLS13,
			cipher     = CIPHER_AES_128_GCM,
		}
		ev.alpn_n = copy(ev.alpn[:], conn.alpn[:conn.alpn_n])
		ev.server_name_n = copy(ev.server_name[:], job.name[:job.name_n])
		push_event(ev)
	}
	read_http(job, &conn)
}

// 95-byte ServerHello record plus the echoed legacy session id.
hold_record :: proc(job: ^Job, record_type, bytes: int) {
	if job.record_held {
		return
	}
	if mode != "setup-deadline" && mode != "body-deadline" {
		return
	}
	job.record_held = true
	push_event(Event{kind = .server_record_held, connection = job.id, record_type = record_type, bytes = bytes})
	if mode == "body-deadline" {
		time.sleep(80 * time.Millisecond)
	} else {
		time.sleep(200 * time.Millisecond)
	}
}

read_http :: proc(job: ^Job, conn: ^loopback.Conn) {
	pending: [8192]u8
	n := 0
	for {
		if mode == "uncertain" {
			text := string(pending[:n])
			if split := strings.index(text, "\r\n\r\n"); split >= 0 {
				headers := text[:split]
				method, target, parsed := request_start(headers)
				if parsed && method == "POST" {
					cl, cl_ok := content_len(headers)
					if !cl_ok {
						emit_error(.read_terminal, job.id, "bad content-length")
						return
					}
					have := n - (split + 4)
					if cl > 0 && have < 1 {
						got, term, again := read_some(job, conn, pending[n:])
						if again {
							continue
						}
						if got > 0 {
							n += got
							continue
						}
						_ = term
						uncertain_reset(job, method, target, cl, 0, 0)
						return
					}
					body_n := 0
					body_first := 0
					if cl > 0 {
						body_n = 1
						body_first = int(pending[split + 4])
					}
					uncertain_reset(job, method, target, cl, body_n, body_first)
					return
				}
			}
		}

		// take_request aliases `pending`. Copy method and path before sliding.
		head, complete, overflow, ok := loopback.take_request(pending[:n], BODY_CAP)
		if !ok || overflow {
			emit_error(.read_terminal, job.id, "bad request")
			return
		}
		if !complete {
			if n == len(pending) {
				emit_error(.read_terminal, job.id, "request")
				return
			}
			got, term, again := read_some(job, conn, pending[n:])
			if again {
				continue
			}
			if got > 0 {
				n += got
				continue
			}
			msg := term
			if n > 0 && msg == "EOF" {
				msg = "unexpected EOF"
			}
			emit_error(.read_terminal, job.id, msg)
			return
		}

		method_buf: [16]u8
		path_buf: [64]u8
		method_n := copy(method_buf[:], head.method)
		path_n := copy(path_buf[:], head.path)
		body_n := len(head.body)
		consumed := head.consumed
		cl, _ := content_len(head.headers)
		method := string(method_buf[:method_n])
		path := string(path_buf[:path_n])
		at := now_ns()
		if consumed < 0 || consumed > n {
			emit_error(.read_terminal, job.id, "bad request")
			return
		}
		for i in 0 ..< n - consumed {
			pending[i] = pending[consumed + i]
		}
		n -= consumed

		ev := Event {
			kind           = .request_head,
			connection     = job.id,
			content_length = i64(cl),
		}
		ev.method_n = copy(ev.method[:], method)
		ev.path_n = copy(ev.path[:], path)
		push_event(ev)
		save_request(job.id, path, method, i64(body_n), at)
		if !write_response(job, conn, method, path) {
			return
		}
	}
}

uncertain_reset :: proc(job: ^Job, method, target: string, cl, body_n, body_first: int) {
	path := target
	if query := strings.index(target, "?"); query >= 0 {
		path = target[:query]
	}
	at := now_ns()
	ev := Event {
		kind           = .request_head,
		connection     = job.id,
		content_length = i64(cl),
	}
	ev.method_n = copy(ev.method[:], method)
	ev.path_n = copy(ev.path[:], path)
	push_event(ev)
	save_request(job.id, path, method, i64(body_n), at)
	push_event(Event{kind = .uncertain_post_reset, connection = job.id, body_bytes = i64(body_n), body_first = body_first})
	mark("uncertain")
	_ = net.set_option(job.fd, .Linger, time.Duration(0))
}

write_response :: proc(job: ^Job, conn: ^loopback.Conn, method, path: string) -> bool {
	body := "A"
	if path == "/B" {
		body = "B"
	}
	if path == "/C" {
		body = "C"
	}
	head_buf: [256]u8
	head := fmt.bprintf(head_buf[:], "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Connection: %d\r\nConnection: keep-alive\r\n\r\n", job.id)
	if !write_out(job, conn, transmute([]u8)head) {
		emit_error(.write_error, job.id, "write")
		return false
	}
	if path == "/A" &&
	   (mode == "body-deadline" || mode == "cancel-read" || mode == "one-worker" || mode == "lifetime" || mode == "reuse-waiter") {
		push_event(Event{kind = .body_held, connection = job.id})
		mark("A.stalled")
		if mode == "reuse-waiter" {
			if !wait_file("releaseA", 5 * time.Second) {
				fail("releaseA timeout")
			}
		} else {
			delay := 600 * time.Millisecond
			if mode == "body-deadline" {
				delay = 300 * time.Millisecond
			}
			time.sleep(delay)
		}
	}
	if method != "HEAD" {
		if !write_out(job, conn, transmute([]u8)body) {
			emit_error(.write_error, job.id, "write")
			return false
		}
	}
	ev := Event{kind = .response, connection = job.id}
	ev.path_n = copy(ev.path[:], path)
	ev.body_n = copy(ev.body[:], body)
	push_event(ev)
	if path == "/A" && (mode == "stale" || mode == "partial" || mode == "close") {
		if !wait_file("A.done", 5 * time.Second) {
			push_event(Event{kind = .coordination_timeout, connection = job.id})
			return false
		}
		if mode == "close" {
			push_event(Event{kind = .stale_close, connection = job.id})
			mark("staged")
			return false
		}
		ok: bool
		old := "OLD"
		if mode == "partial" && !encrypted {
			one := [1]u8{'O'}
			ok = write_raw(job.fd, one[:])
			push_event(Event{kind = .partial_raw_staged, connection = job.id, bytes = 1})
			mark("staged")
		} else if mode == "partial" && encrypted {
			ok = write_split_record(conn, job.fd, transmute([]u8)old, job.id)
		} else {
			ok = write_out(job, conn, transmute([]u8)old)
			if mode != "partial" {
				mark("staged")
			}
		}
		if !ok {
			emit_error(.stale_write_error, job.id, "write")
		}
	}
	return true
}

write_out :: proc(job: ^Job, conn: ^loopback.Conn, data: []u8) -> bool {
	if len(data) == 0 {
		return true
	}
	if !encrypted {
		hold_record(job, int(data[0]), len(data))
		return write_raw(job.fd, data)
	}
	return loopback.tls_write(conn, data)
}

write_raw :: proc(fd: net.TCP_Socket, data: []u8) -> bool {
	rest := data
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

// One TLS application record for `plain`, then a one-byte TCP write, 500ms,
// and the remainder. record_type 23 is the outer header byte.
write_split_record :: proc(conn: ^loopback.Conn, fd: net.TCP_Socket, plain: []u8, id: int) -> bool {
	if len(plain) < 1 || len(plain) + 1 > 32 {
		return false
	}
	inner_n := len(plain) + 1
	wire_n := inner_n + 16
	total := 5 + wire_n
	buf: [64]u8
	inner: [40]u8
	copy(inner[:], plain)
	inner[len(plain)] = 23
	buf[0] = 23
	buf[1] = 3
	buf[2] = 3
	buf[3] = u8(wire_n >> 8)
	buf[4] = u8(wire_n)
	nonce := nonce_of(conn.out_iv, conn.out_seq)
	aead.seal_oneshot(.AES_GCM_128, buf[5:][:inner_n], buf[5 + inner_n:][:16], conn.out_key[:], nonce[:], buf[:5], inner[:inner_n])
	conn.out_seq += 1
	if !write_raw(fd, buf[:1]) {
		return false
	}
	push_event(Event{kind = .partial_record_staged, connection = id, bytes = 1, record_type = int(buf[0]), full_bytes = total})
	mark("staged")
	time.sleep(500 * time.Millisecond)
	return write_raw(fd, buf[1:total])
}

nonce_of :: proc(iv: [12]u8, seq: u64) -> [12]u8 {
	nonce := iv
	rest := seq
	for i in 0 ..< 8 {
		nonce[11 - i] ~= u8(rest)
		rest >>= 8
	}
	return nonce
}

read_some :: proc(job: ^Job, conn: ^loopback.Conn, dst: []u8) -> (n: int, terminal: string, again: bool) {
	if len(dst) == 0 {
		return 0, "request", false
	}
	if encrypted {
		got, status := loopback.tls_read(conn, dst)
		if got > 0 {
			return got, "", false
		}
		switch status {
		case .Ok:
			return 0, "read", false
		case .Timeout:
			return 0, "i/o timeout", false
		case .Closed:
			return 0, "EOF", false
		case .Failed:
			return 0, "read", false
		}
	}
	got, err := net.recv_tcp(job.fd, dst)
	if got > 0 {
		return got, "", false
	}
	if err == .Interrupted || err == .Would_Block {
		return 0, "", true
	}
	if err == .Timeout {
		return 0, "i/o timeout", false
	}
	if err == nil || err == .Connection_Closed {
		return 0, "EOF", false
	}
	return 0, "read", false
}

request_start :: proc(headers: string) -> (method, target: string, ok: bool) {
	line_end := strings.index(headers, "\r\n")
	line := headers if line_end < 0 else headers[:line_end]
	first := strings.index(line, " ")
	if first <= 0 {
		return
	}
	rest := line[first + 1:]
	second := strings.index(rest, " ")
	if second <= 0 {
		return
	}
	method = line[:first]
	target = rest[:second]
	if len(method) == 0 || len(target) == 0 || len(rest[second + 1:]) == 0 {
		return
	}
	return method, target, true
}

content_len :: proc(headers: string) -> (length: int, ok: bool) {
	text, found := loopback.header_value(headers, "content-length")
	if !found {
		return 0, true
	}
	parsed, valid := strconv.parse_int(text, 10)
	if !valid || parsed < 0 {
		return 0, false
	}
	return parsed, true
}

peek_server_name :: proc(job: ^Job) -> (session_n: int, ok: bool) {
	buf: [8192]u8
	deadline := time.time_add(time.now(), 10 * time.Second)
	for time.diff(deadline, time.now()) <= 0 {
		got := posix.recv(auto_cast job.fd, raw_data(buf[:]), c.size_t(len(buf)), {.PEEK})
		if got < 0 {
			err := posix.errno()
			if err == .EINTR || err == .EAGAIN || err == .EWOULDBLOCK || err == .ETIMEDOUT {
				time.sleep(time.Millisecond)
				continue
			}
			return
		}
		if got == 0 {
			return
		}
		name_n, sid, status := scan_hello(buf[:int(got)], job.name[:])
		if status == .Ready {
			job.name_n = name_n
			return sid, true
		}
		if status == .Invalid {
			return
		}
		time.sleep(time.Millisecond)
	}
	return
}

scan_hello :: proc(wire, name: []u8) -> (name_n, session_n: int, status: Hello_Scan) {
	hs: [8192]u8
	hs_n := 0
	at := 0
	for {
		if at == len(wire) {
			return 0, 0, .Need_More
		}
		if at + 5 > len(wire) {
			return 0, 0, .Need_More
		}
		if wire[at] != 22 {
			return 0, 0, .Invalid
		}
		rec_len := int(wire[at + 3]) << 8 | int(wire[at + 4])
		if rec_len < 0 || at + 5 + rec_len > len(wire) {
			return 0, 0, .Need_More
		}
		if hs_n + rec_len > len(hs) {
			return 0, 0, .Invalid
		}
		copy(hs[hs_n:], wire[at + 5:][:rec_len])
		hs_n += rec_len
		at += 5 + rec_len
		if hs_n < 4 {
			continue
		}
		if hs[0] != 1 {
			return 0, 0, .Invalid
		}
		need := 4 + (int(hs[1]) << 16 | int(hs[2]) << 8 | int(hs[3]))
		if need < 4 || need > len(hs) {
			return 0, 0, .Invalid
		}
		if hs_n < need {
			continue
		}
		name_n, session_n, parsed := parse_sni(hs[:need], name)
		if !parsed {
			return 0, 0, .Invalid
		}
		return name_n, session_n, .Ready
	}
}

parse_sni :: proc(msg, name: []u8) -> (name_n, session_n: int, ok: bool) {
	if len(msg) < 44 || msg[0] != 1 {
		return
	}
	at := 38
	session_n = int(msg[at])
	at += 1
	if session_n > 32 || at + session_n + 2 > len(msg) {
		return
	}
	at += session_n
	suites_n := int(msg[at]) << 8 | int(msg[at + 1])
	at += 2
	if suites_n < 2 || suites_n % 2 != 0 || at + suites_n + 1 > len(msg) {
		return
	}
	at += suites_n
	methods_n := int(msg[at])
	at += 1 + methods_n
	if at + 2 > len(msg) {
		return
	}
	ext_n := int(msg[at]) << 8 | int(msg[at + 1])
	at += 2
	if ext_n < 0 || at + ext_n != len(msg) {
		return
	}
	end := at + ext_n
	for at + 4 <= end {
		kind := int(msg[at]) << 8 | int(msg[at + 1])
		size := int(msg[at + 2]) << 8 | int(msg[at + 3])
		at += 4
		if size > end - at {
			return
		}
		data := msg[at:][:size]
		at += size
		if kind != 0 || len(data) < 5 {
			continue
		}
		pos := 2
		if pos + 3 > len(data) {
			continue
		}
		name_type := data[pos]
		pos += 1
		host_n := int(data[pos]) << 8 | int(data[pos + 1])
		pos += 2
		if name_type != 0 || host_n > len(data) - pos || host_n > len(name) {
			continue
		}
		name_n = copy(name[:host_n], data[pos:][:host_n])
		return name_n, session_n, true
	}
	return 0, session_n, true
}

dns_serve :: proc() {
	buf: [4096]u8
	for {
		n, source, err := net.recv_udp(dns_fd, buf[:])
		if err == .Timeout || err == .Interrupted {
			if !dns_open_now() {
				return
			}
			continue
		}
		if err != nil || n <= 0 {
			return
		}
		name_buf: [256]u8
		name_n, qtype, id, end, ok := dns_question(buf[:n], name_buf[:])
		if !ok {
			fail("dns")
		}
		name := string(name_buf[:name_n])
		push_dns(name, qtype, id)
		mark("DNS.seen")
		if mode == "setup-deadline" {
			time.sleep(150 * time.Millisecond)
		} else if mode == "body-deadline" {
			time.sleep(80 * time.Millisecond)
		}
		reply: [512]u8
		if end > len(reply) {
			fail("dns")
		}
		copy(reply[:], buf[:end])
		reply[2] = 0x81
		reply[3] = 0x80
		total := end
		if qtype == 1 {
			reply[6] = 0
			reply[7] = 1
			answer := [16]u8{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1}
			if end + len(answer) > len(reply) {
				fail("dns")
			}
			copy(reply[end:], answer[:])
			total = end + len(answer)
		}
		sent, send_error := net.send_udp(dns_fd, reply[:total], source)
		if send_error != nil || sent != total {
			return
		}
		ev := Event{kind = .dns_reply, qtype = qtype}
		ev.name_n = copy(ev.name[:], name)
		push_event(ev)
	}
}

dns_question :: proc(wire, name_buf: []u8) -> (name_n, qtype, id, end: int, ok: bool) {
	if len(wire) < 12 || int(wire[4]) << 8 | int(wire[5]) != 1 {
		return
	}
	id = int(wire[0]) << 8 | int(wire[1])
	at := 12
	for {
		if at >= len(wire) {
			return
		}
		label := int(wire[at])
		at += 1
		if label == 0 {
			break
		}
		if label > 63 || at + label > len(wire) {
			return
		}
		if name_n > 0 {
			if name_n >= len(name_buf) {
				return
			}
			name_buf[name_n] = '.'
			name_n += 1
		}
		if name_n + label > len(name_buf) {
			return
		}
		copy(name_buf[name_n:], wire[at:][:label])
		name_n += label
		at += label
	}
	if at + 4 != len(wire) {
		return
	}
	qtype = int(wire[at]) << 8 | int(wire[at + 1])
	end = at + 4
	return name_n, qtype, id, end, true
}

push_dns :: proc(name: string, qtype, id: int) {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	at := now_ns()
	if dns_n >= len(dns_facts) || event_n >= len(events) {
		fail("dns")
	}
	fact := &dns_facts[dns_n]
	dns_n += 1
	fact.name_n = copy(fact.name[:], name)
	fact.qtype = qtype
	fact.id = id
	fact.at_ns = at
	ev := &events[event_n]
	event_n += 1
	ev^ = Event {
		kind  = .dns_query,
		at_ns = at,
		qtype = qtype,
		id    = id,
	}
	ev.name_n = copy(ev.name[:], name)
	write_line(ev)
}

save_request :: proc(connection: int, path, method: string, body_bytes, at_ns: i64) {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	if request_n >= len(requests) {
		fail("requests")
	}
	row := &requests[request_n]
	request_n += 1
	row.connection = connection
	row.path_n = copy(row.path[:], path)
	row.method_n = copy(row.method[:], method)
	row.body_bytes = body_bytes
	row.at_ns = at_ns
}

push_event :: proc(ev: Event) {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	if event_n >= len(events) {
		fail("events")
	}
	stored := ev
	stored.at_ns = now_ns()
	events[event_n] = stored
	event_n += 1
	write_line(&events[event_n - 1])
}

emit_error :: proc(kind: Event_Kind, connection: int, text: string) {
	ev := Event{kind = kind, connection = connection}
	ev.error_n = copy(ev.error[:], text)
	push_event(ev)
}

write_line :: proc(ev: ^Event) {
	write_event(ev)
	newline := [1]u8{'\n'}
	_, _ = os.write(os.stdout, newline[:])
	_ = os.flush(os.stdout)
}

write_event :: proc(ev: ^Event) {
	fmt.fprintf(os.stdout, `{{"event":"%s","at_ns":%d`, event_name(ev.kind), ev.at_ns)
	#partial switch ev.kind {
	case .accept, .body_held, .coordination_timeout, .stale_close:
		fmt.fprintf(os.stdout, `,"connection":%d`, ev.connection)
	case .handshake:
		fmt.fprintf(os.stdout, `,"connection":%d,"version":%d,"cipher":%d,"alpn":"`, ev.connection, ev.version, ev.cipher)
		write_escaped(string(ev.alpn[:ev.alpn_n]))
		fmt.fprint(os.stdout, `","server_name":"`)
		write_escaped(string(ev.server_name[:ev.server_name_n]))
		fmt.fprint(os.stdout, `"`)
	case .handshake_error, .read_terminal, .body_error, .write_error, .stale_write_error:
		fmt.fprintf(os.stdout, `,"connection":%d,"error":"`, ev.connection)
		write_escaped(string(ev.error[:ev.error_n]))
		fmt.fprint(os.stdout, `"`)
	case .request_head:
		fmt.fprintf(os.stdout, `,"connection":%d,"path":"`, ev.connection)
		write_escaped(string(ev.path[:ev.path_n]))
		fmt.fprint(os.stdout, `","method":"`)
		write_escaped(string(ev.method[:ev.method_n]))
		fmt.fprintf(os.stdout, `","content_length":%d`, ev.content_length)
	case .uncertain_post_reset:
		fmt.fprintf(os.stdout, `,"connection":%d,"body_bytes":%d,"body_first":%d`, ev.connection, ev.body_bytes, ev.body_first)
	case .response:
		fmt.fprintf(os.stdout, `,"connection":%d,"path":"`, ev.connection)
		write_escaped(string(ev.path[:ev.path_n]))
		fmt.fprint(os.stdout, `","body":"`)
		write_escaped(string(ev.body[:ev.body_n]))
		fmt.fprint(os.stdout, `"`)
	case .partial_record_staged:
		fmt.fprintf(os.stdout, `,"connection":%d,"bytes":%d,"record_type":%d,"full_bytes":%d`, ev.connection, ev.bytes, ev.record_type, ev.full_bytes)
	case .partial_raw_staged:
		fmt.fprintf(os.stdout, `,"connection":%d,"bytes":%d`, ev.connection, ev.bytes)
	case .server_record_held:
		fmt.fprintf(os.stdout, `,"connection":%d,"bytes":%d,"record_type":%d`, ev.connection, ev.bytes, ev.record_type)
	case .dns_query:
		fmt.fprint(os.stdout, `,"name":"`)
		write_escaped(string(ev.name[:ev.name_n]))
		fmt.fprintf(os.stdout, `","type":%d,"id":%d`, ev.qtype, ev.id)
	case .dns_reply:
		fmt.fprint(os.stdout, `,"name":"`)
		write_escaped(string(ev.name[:ev.name_n]))
		fmt.fprintf(os.stdout, `","type":%d`, ev.qtype)
	}
	fmt.fprint(os.stdout, "}")
}

event_name :: proc(kind: Event_Kind) -> string {
	switch kind {
	case .accept:
		return "accept"
	case .handshake:
		return "handshake"
	case .handshake_error:
		return "handshake_error"
	case .read_terminal:
		return "read_terminal"
	case .request_head:
		return "request_head"
	case .uncertain_post_reset:
		return "uncertain_post_reset"
	case .body_error:
		return "body_error"
	case .write_error:
		return "write_error"
	case .body_held:
		return "body_held"
	case .response:
		return "response"
	case .coordination_timeout:
		return "coordination_timeout"
	case .stale_close:
		return "stale_close"
	case .partial_record_staged:
		return "partial_record_staged"
	case .partial_raw_staged:
		return "partial_raw_staged"
	case .stale_write_error:
		return "stale_write_error"
	case .dns_query:
		return "dns_query"
	case .dns_reply:
		return "dns_reply"
	case .server_record_held:
		return "server_record_held"
	}
	return "event"
}

emit_summary :: proc() {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	fmt.fprint(os.stdout, `{"event":"summary","mode":"`)
	write_escaped(mode)
	fmt.fprintf(os.stdout, `","tls":%t,"connections":%d,"handshakes":%d,"requests":`, encrypted, connections, handshakes)
	if request_n == 0 {
		fmt.fprint(os.stdout, "null")
	} else {
		fmt.fprint(os.stdout, "[")
		for i in 0 ..< request_n {
			if i > 0 {
				fmt.fprint(os.stdout, ",")
			}
			row := &requests[i]
			fmt.fprintf(os.stdout, `{{"connection":%d,"path":"`, row.connection)
			write_escaped(string(row.path[:row.path_n]))
			fmt.fprint(os.stdout, `","method":"`)
			write_escaped(string(row.method[:row.method_n]))
			fmt.fprintf(os.stdout, `","body_bytes":%d,"at_ns":%d}`, row.body_bytes, row.at_ns)
		}
		fmt.fprint(os.stdout, "]")
	}
	fmt.fprint(os.stdout, `,"dns":`)
	if dns_n == 0 {
		fmt.fprint(os.stdout, "null")
	} else {
		fmt.fprint(os.stdout, "[")
		for i in 0 ..< dns_n {
			if i > 0 {
				fmt.fprint(os.stdout, ",")
			}
			fact := &dns_facts[i]
			fmt.fprint(os.stdout, `{"name":"`)
			write_escaped(string(fact.name[:fact.name_n]))
			fmt.fprintf(os.stdout, `","type":%d,"id":%d,"at_ns":%d,"event":"dns_query"}`, fact.qtype, fact.id, fact.at_ns)
		}
		fmt.fprint(os.stdout, "]")
	}
	fmt.fprint(os.stdout, `,"events":`)
	if event_n == 0 {
		fmt.fprint(os.stdout, "null")
	} else {
		fmt.fprint(os.stdout, "[")
		for i in 0 ..< event_n {
			if i > 0 {
				fmt.fprint(os.stdout, ",")
			}
			write_event(&events[i])
		}
		fmt.fprint(os.stdout, "]")
	}
	fmt.fprint(os.stdout, "}\n")
	_ = os.flush(os.stdout)
}

now_ns :: proc() -> i64 {
	return time.duration_nanoseconds(time.since(started))
}

mark :: proc(name: string) {
	buf: [1024]u8
	path := child(buf[:], name)
	if os.write_entire_file(path, name, FILE_PERM) != nil {
		fail("marker")
	}
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

write_escaped :: proc(text: string) {
	for i in 0 ..< len(text) {
		ch := text[i]
		if ch == '"' || ch == '\\' {
			pair := [2]u8{'\\', ch}
			_, _ = os.write(os.stdout, pair[:])
		} else if ch < 0x20 {
			hex := [6]u8{'\\', 'u', '0', '0', HEX[ch >> 4], HEX[ch & 0x0f]}
			_, _ = os.write(os.stdout, hex[:])
		} else {
			_, _ = os.write(os.stdout, transmute([]u8)text[i:i + 1])
		}
	}
}

HEX := [16]u8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

fail :: proc(reason: string) {
	fmt.eprintf("session_actor101: %s\n", reason)
	os.exit(1)
}
