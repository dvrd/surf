// Owned literal HTTP/1 peer for the redirect matrix. Optional TLS 1.3,
// a second listener, and a loopback DNS fixture. One request per accepted
// connection, plus the TLS cutoff warmup on that same connection.
package main

import loopback "../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}
TLS13 :: 772
EVENT_CAP :: 32
WARMUP_CAP :: 4
NAME_CAP :: 256
NAME_LEN :: 253
BODY_CAP :: 1024
HEADER_CAP :: 4096
TARGET_CAP :: 512
HOST_CAP :: 256
METHOD_CAP :: 16
DEADLINE :: 12 * time.Second
DONE_LIMIT :: 18 * time.Second
DRAIN_LIMIT :: 3 * time.Second

Read_Kind :: enum {
	Data,
	Retry,
	Timeout,
	Closed,
	Failed,
}

Event :: struct {
	id:              int,
	order:           int,
	method:          [METHOD_CAP]u8,
	method_n:        int,
	host:            [HOST_CAP]u8,
	host_n:          int,
	path:            [TARGET_CAP]u8,
	path_n:          int,
	route:           [TARGET_CAP]u8,
	route_n:         int,
	body:            [BODY_CAP]u8,
	body_n:          int,
	alpn:            [32]u8,
	alpn_n:          int,
	tls:             int,
	response_bytes:  int,
	request_bytes:   int,
	headers:         [HEADER_CAP]u8,
	headers_n:       int,
	old_closed:      bool,
	status:          int,
}

Request :: struct {
	method:    [METHOD_CAP]u8,
	method_n:  int,
	host:      [HOST_CAP]u8,
	host_n:    int,
	target:    [TARGET_CAP]u8,
	target_n:  int,
	route:     [TARGET_CAP]u8,
	route_n:   int,
	body:      [BODY_CAP]u8,
	body_n:    int,
	headers:   [HEADER_CAP]u8,
	headers_n: int,
	consumed:  int,
}

Name :: struct {
	text: [NAME_LEN]u8,
	n:    int,
}

Job :: struct {
	fd: net.TCP_Socket,
	id: int,
}

Field :: struct {
	key:   [128]u8,
	key_n: int,
	val:   [1024]u8,
	val_n: int,
}

directory: string
mode: string
encrypted: bool
first_port: int
other_buf: [64]u8
other_addr: string

mu: sync.Mutex
next_id: int
handlers: int
events: [EVENT_CAP]Event
event_n: int
warmups: [WARMUP_CAP]Event
warmup_n: int
names: [NAME_CAP]Name
name_n: int

first_fd: net.TCP_Socket
other_fd: net.TCP_Socket
first_open: bool
other_open: bool
first_mu: sync.Mutex
other_mu: sync.Mutex
dns_fd: net.UDP_Socket
dns_open: bool
dns_mu: sync.Mutex

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	parse_flags()
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
	socket, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fail("listen")
	}
	first_fd = socket
	first_open = true
	other_socket, other_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if other_error != nil {
		fail("listen")
	}
	other_fd = other_socket
	other_open = true
	first_ep, first_bound := net.bound_endpoint(first_fd)
	if first_bound != nil {
		fail("bound")
	}
	other_ep, other_bound := net.bound_endpoint(other_fd)
	if other_bound != nil {
		fail("bound")
	}
	first_port = first_ep.port
	other_addr = fmt.bprintf(other_buf[:], "127.0.0.1:%d", other_ep.port)
	if encrypted {
		raw := [4]u8{127, 0, 0, 1}
		ips := [1][]u8{raw[:]}
		dns_names := [3]string{"one.redirect.test", "two.redirect.test", "three.redirect.test"}
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "redirect101", dns_names[:], ips[:]) {
			fail("certificate")
		}
	}
	if !write_file("other.endpoint", other_addr) {
		fail("other.endpoint")
	}
	udp, udp_error := net.make_unbound_udp_socket(.IP4)
	if udp_error != nil {
		fail("dns")
	}
	dns_fd = udp
	if net.bind(dns_fd, {address = net.IP4_Loopback, port = 0}) != nil {
		fail("dns")
	}
	if net.set_option(dns_fd, .Receive_Timeout, 100 * time.Millisecond) != nil {
		fail("dns")
	}
	dns_ep, dns_bound := net.bound_endpoint(dns_fd)
	if dns_bound != nil {
		fail("dns")
	}
	dns_text: [64]u8
	if !write_file("dns.endpoint", fmt.bprintf(dns_text[:], "127.0.0.1:%d", dns_ep.port)) {
		fail("dns.endpoint")
	}
	dns_open = true
	dns_thread := thread.create_and_start(dns_loop)
	if dns_thread == nil {
		fail("dns thread")
	}
	first_thread := thread.create_and_start_with_poly_data(0, accept_loop)
	other_thread := thread.create_and_start_with_poly_data(1, accept_loop)
	if first_thread == nil || other_thread == nil {
		fail("accept thread")
	}
	emit_line(fmt.bprintf(dns_text[:], "127.0.0.1:%d", first_port))
	if !wait_file("done", DONE_LIMIT) {
		fail("native completion timeout")
	}
	shutdown_tcp(&first_fd, &first_open, &first_mu)
	shutdown_tcp(&other_fd, &other_open, &other_mu)
	thread.destroy(first_thread)
	thread.destroy(other_thread)
	shutdown_dns()
	thread.destroy(dns_thread)
	if !wait_handlers(DRAIN_LIMIT) {
		fail("peer handlers failed to drain")
	}
	if encrypted {
		loopback.identity_clear()
	}
	emit_json()
}

parse_flags :: proc() {
	mode = "get301"
	args := os.args
	i := 1
	for i < len(args) {
		arg := args[i]
		if arg == "-tls" {
			encrypted = true
			i += 1
		} else if arg == "-tls=true" || arg == "-tls=1" {
			encrypted = true
			i += 1
		} else if arg == "-tls=false" || arg == "-tls=0" {
			encrypted = false
			i += 1
		} else if arg == "-mode" && i + 1 < len(args) {
			mode = args[i + 1]
			i += 2
		} else if arg == "-dir" && i + 1 < len(args) {
			directory = args[i + 1]
			i += 2
		} else if strings.has_prefix(arg, "-mode=") {
			mode = arg[len("-mode="):]
			i += 1
		} else if strings.has_prefix(arg, "-dir=") {
			directory = arg[len("-dir="):]
			i += 1
		} else {
			fail("flag")
		}
	}
	if directory == "" {
		fail("directory required")
	}
}

accept_loop :: proc(which: int) {
	fd := first_fd if which == 0 else other_fd
	for {
		client, _, accept_error := net.accept_tcp(fd)
		if accept_error != nil {
			if accept_error == .Interrupted || accept_error == .Aborted {
				continue
			}
			return
		}
		start_handler(client)
	}
}

start_handler :: proc(fd: net.TCP_Socket) {
	sync.lock(&mu)
	next_id += 1
	id := next_id
	handlers += 1
	sync.unlock(&mu)
	job := new(Job)
	if job == nil {
		abandon(fd)
		fail("thread")
	}
	job.fd = fd
	job.id = id
	worker := thread.create_and_start_with_poly_data(job, serve, self_cleanup = true)
	if worker == nil {
		free(job)
		abandon(fd)
		fail("thread")
	}
}

abandon :: proc(fd: net.TCP_Socket) {
	net.close(fd)
	sync.lock(&mu)
	handlers -= 1
	sync.unlock(&mu)
}

serve :: proc(job: ^Job) {
	// Defer arguments are read when the defer runs. Copy the descriptor first
	// so freeing the job cannot close a different socket.
	fd := job.fd
	defer handler_finish()
	defer free(job)
	defer net.close(fd)
	if net.set_option(job.fd, .Send_Timeout, DEADLINE) != nil ||
	   net.set_option(job.fd, .Receive_Timeout, DEADLINE) != nil {
		fail("deadline")
	}
	_ = net.set_option(job.fd, .TCP_Nodelay, true)
	conn := loopback.Conn{fd = job.fd}
	defer loopback.conn_wipe(&conn)
	alpn: [32]u8
	alpn_n := 0
	version := 0
	if encrypted {
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
		alpn_n = conn.alpn_n
		if alpn_n > len(alpn) {
			fail("ALPN")
		}
		copy(alpn[:], conn.alpn[:alpn_n])
		if string(alpn[:alpn_n]) != "http/1.1" {
			fail("ALPN")
		}
		version = TLS13
	}
	buf: [1 << 16]u8
	filled := 0
	req: Request
	warmed := false
	for {
		if !read_request(&conn, buf[:], &filled, &req) {
			return
		}
		route := string(req.route[:req.route_n])
		if !warmed && encrypted && mode == "cutoff" && route == "/warmup" {
			warmed = true
			if string(req.method[:req.method_n]) != "GET" || req.body_n != 0 {
				fail("invalid warmup")
			}
			wire := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
			wrote, wrote_ok := write_all(&conn, wire)
			if !wrote_ok {
				fail("warmup")
			}
			record_warmup(job.id, version, alpn[:alpn_n], &req, wrote)
			shift(buf[:], &filled, req.consumed)
			continue
		}
		break
	}
	index := record_event(job.id, version, alpn[:alpn_n], &req)
	order := index + 1
	status := redirect_status()
	target_buf: [512]u8
	target := redirect_target(target_buf[:], order, string(req.target[:req.target_n]))
	final := strings.has_prefix(string(req.route[:req.route_n]), "/final")
	if mode == "cutoff" {
		time.sleep(80 * time.Millisecond)
		final = order >= 3
		target = fmt.bprintf(target_buf[:], "/hop/%d", order)
	}
	if mode == "cancel" || mode == "close" {
		final = order == 2
		if final {
			if !write_file("target-held", "headers") {
				fail("target-held")
			}
			for {
				if file_exists("done") {
					return
				}
				time.sleep(time.Millisecond)
			}
		}
	}
	payload := "intermediate"
	xs: [65]u8
	if mode == "bodycap" {
		for &c in xs {
			c = 'x'
		}
		payload = string(xs[:])
	}
	wire_buf: [1024]u8
	wire := response_wire(wire_buf[:], final, status, target, payload, string(req.method[:req.method_n]))
	wrote, wrote_ok := write_all(&conn, wire)
	if !wrote_ok && mode != "cutoff" {
		fail("write")
	}
	sync.lock(&mu)
	events[index].response_bytes = wrote
	events[index].status = 200 if final else status
	sync.unlock(&mu)
	if !final {
		probe_old_stream(&conn, buf[:], filled, req.consumed, index)
	}
}

read_request :: proc(conn: ^loopback.Conn, buf: []u8, filled: ^int, req: ^Request) -> bool {
	req^ = {}
	for {
		head, complete, _, ok := loopback.take_request(buf[:filled^], 1 << 20)
		if !ok {
			return false
		}
		if !complete {
			if filled^ == len(buf) {
				return false
			}
			got, kind := read_some(conn, buf[filled^:])
			if got > 0 {
				filled^ += got
				continue
			}
			if kind == .Retry {
				continue
			}
			if kind == .Closed && strings.index(string(buf[:filled^]), "\r\n\r\n") >= 0 {
				fail("body")
			}
			return false
		}
		if !copy_text(req.method[:], &req.method_n, head.method) ||
		   !copy_text(req.target[:], &req.target_n, head.target) ||
		   !copy_text(req.route[:], &req.route_n, head.path) ||
		   !copy_text(req.body[:], &req.body_n, string(head.body)) ||
		   !copy_text(req.headers[:], &req.headers_n, head.headers) {
			fail("request")
		}
		if host, found := loopback.header_value(head.headers, "host"); found {
			if !copy_text(req.host[:], &req.host_n, host) {
				fail("host")
			}
		}
		req.consumed = head.consumed
		return true
	}
}

copy_text :: proc(dst: []u8, n: ^int, src: string) -> bool {
	if len(src) > len(dst) {
		return false
	}
	n^ = copy(dst, src)
	return true
}

shift :: proc(buf: []u8, filled: ^int, consumed: int) {
	if consumed < 0 || consumed > filled^ {
		fail("request")
	}
	copy(buf, buf[consumed:filled^])
	filled^ -= consumed
}

redirect_status :: proc() -> int {
	status := 302
	if strings.has_suffix(mode, "301") {
		status = 301
	}
	if strings.has_suffix(mode, "302") {
		status = 302
	}
	if strings.has_suffix(mode, "303") {
		status = 303
	}
	if strings.has_suffix(mode, "307") {
		status = 307
	}
	if strings.has_suffix(mode, "308") {
		status = 308
	}
	return status
}

redirect_target :: proc(buf: []u8, order: int, request_uri: string) -> string {
	scheme := "https" if encrypted else "http"
	target := "/final"
	if strings.has_prefix(mode, "cross-") {
		target = fmt.bprintf(buf, "%s://%s/final", scheme, other_addr)
	}
	if mode == "downgrade" {
		target = fmt.bprintf(buf, "http://%s/final", other_addr)
	}
	if mode == "relative" {
		target = "../final?proof=relative"
	}
	if mode == "loop" {
		target = request_uri
	}
	if mode == "hopcap" {
		target = fmt.bprintf(buf, "/hop/%d", order)
	}
	if mode == "dns32" {
		host := "two.redirect.test"
		if order > 1 {
			host = "three.redirect.test"
		}
		target = fmt.bprintf(buf, "%s://%s:%d/start", scheme, host, first_port)
	}
	return target
}

response_wire :: proc(buf: []u8, final: bool, status: int, target, payload, method: string) -> string {
	if final {
		if method != "HEAD" {
			return fmt.bprintf(buf, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal")
		}
		return "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
	}
	if method != "HEAD" {
		return fmt.bprintf(
			buf,
			"HTTP/1.1 %d Redirect\r\nLocation: %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
			status,
			target,
			len(payload),
			payload,
		)
	}
	// A HEAD redirect is complete at its head, and a client may reuse the
	// connection for the next hop. This peer answers one request per connection.
	return fmt.bprintf(
		buf,
		"HTTP/1.1 %d Redirect\r\nLocation: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status,
		target,
		len(payload),
	)
}

probe_old_stream :: proc(conn: ^loopback.Conn, buf: []u8, filled, consumed, index: int) {
	if filled > consumed {
		fail("redirect old stream received replay bytes")
	}
	one: [1]u8
	for {
		got, kind := read_some(conn, one[:])
		if kind == .Retry {
			continue
		}
		if got != 0 {
			fail("redirect old stream received replay bytes")
		}
		if kind == .Data {
			fail("redirect old stream did not terminate")
		}
		if kind == .Timeout {
			fail("redirect old stream was not physically closed")
		}
		sync.lock(&mu)
		events[index].old_closed = true
		sync.unlock(&mu)
		return
	}
}

read_some :: proc(conn: ^loopback.Conn, dst: []u8) -> (int, Read_Kind) {
	if len(dst) == 0 {
		return 0, .Data
	}
	if encrypted {
		n, status := loopback.tls_read(conn, dst)
		if status == .Ok {
			return n, .Data
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		if status == .Closed {
			return 0, .Closed
		}
		return 0, .Failed
	}
	n, err := net.recv_tcp(conn.fd, dst)
	if n > 0 {
		return n, .Data
	}
	if err == nil {
		return 0, .Closed
	}
	if err == .Interrupted {
		return 0, .Retry
	}
	if err == .Timeout || err == .Would_Block {
		return 0, .Timeout
	}
	return 0, .Failed
}

write_all :: proc(conn: ^loopback.Conn, text: string) -> (int, bool) {
	if encrypted {
		if !loopback.tls_write(conn, transmute([]u8)text) {
			return 0, false
		}
		return len(text), true
	}
	rest := transmute([]u8)text
	sent := 0
	for len(rest) > 0 {
		n, err := net.send_tcp(conn.fd, rest)
		if n > 0 {
			sent += n
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return sent, false
	}
	return sent, true
}

record_event :: proc(id, version: int, alpn: []u8, req: ^Request) -> int {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if event_n == len(events) {
		fail("events")
	}
	slot := &events[event_n]
	event_n += 1
	fill_event(slot, id, event_n, version, alpn, req, req.consumed, 0, 0)
	return event_n - 1
}

record_warmup :: proc(id, version: int, alpn: []u8, req: ^Request, wrote: int) {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if warmup_n == len(warmups) {
		fail("warmups")
	}
	slot := &warmups[warmup_n]
	warmup_n += 1
	fill_event(slot, id, warmup_n, version, alpn, req, req.consumed, wrote, 200)
	slot.body_n = 0
}

fill_event :: proc(slot: ^Event, id, order, version: int, alpn: []u8, req: ^Request, request_bytes, response_bytes, status: int) {
	slot.id = id
	slot.order = order
	slot.method_n = copy(slot.method[:], req.method[:req.method_n])
	slot.host_n = copy(slot.host[:], req.host[:req.host_n])
	slot.path_n = copy(slot.path[:], req.target[:req.target_n])
	slot.route_n = copy(slot.route[:], req.route[:req.route_n])
	slot.body_n = copy(slot.body[:], req.body[:req.body_n])
	slot.alpn_n = copy(slot.alpn[:], alpn)
	slot.tls = version
	slot.request_bytes = request_bytes
	slot.response_bytes = response_bytes
	slot.headers_n = copy(slot.headers[:], req.headers[:req.headers_n])
	slot.status = status
}

dns_loop :: proc() {
	packet: [4096]u8
	for {
		if !dns_is_open() {
			return
		}
		n, addr, err := net.recv_udp(dns_fd, packet[:])
		if err != nil {
			if err == .Interrupted || err == .Timeout || err == .Would_Block {
				continue
			}
			if err == .Excess_Truncated {
				fail("DNS bounds")
			}
			return
		}
		if n < 17 {
			fail("short DNS")
		}
		end := 12
		name_buf: [NAME_LEN]u8
		name_len := 0
		for {
			if end >= n {
				fail("DNS bounds")
			}
			length := int(packet[end])
			if length == 0 {
				end += 1
				break
			}
			end += 1
			if end + length >= n {
				fail("DNS bounds")
			}
			if name_len > 0 {
				if name_len == len(name_buf) {
					fail("DNS bounds")
				}
				name_buf[name_len] = '.'
				name_len += 1
			}
			if name_len + length > len(name_buf) {
				fail("DNS bounds")
			}
			copy(name_buf[name_len:], packet[end:end + length])
			name_len += length
			end += length
		}
		if end + 4 > n {
			fail("DNS question")
		}
		typ := int(packet[end]) << 8 | int(packet[end + 1])
		question_end := end + 4
		remember_name(name_buf[:name_len])
		reply: [4128]u8
		copy(reply[:], packet[:question_end])
		reply[2] = 0x81
		reply[3] = 0x80
		reply[6] = 0
		reply[7] = 0
		reply_n := question_end
		if typ == 1 {
			reply[7] = 1
			extra := [?]u8{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1}
			copy(reply[reply_n:], extra[:])
			reply_n += len(extra)
		}
		if _, send_error := net.send_udp(dns_fd, reply[:reply_n], addr); send_error != nil {
			if !dns_is_open() {
				return
			}
			fail("dns write")
		}
	}
}

remember_name :: proc(text: []u8) {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if name_n == len(names) || len(text) > NAME_LEN {
		fail("dns names")
	}
	names[name_n].n = copy(names[name_n].text[:], text)
	name_n += 1
}

dns_is_open :: proc() -> bool {
	sync.lock(&dns_mu)
	defer sync.unlock(&dns_mu)
	return dns_open
}

shutdown_tcp :: proc(fd: ^net.TCP_Socket, open: ^bool, guard: ^sync.Mutex) {
	sync.lock(guard)
	defer sync.unlock(guard)
	if open^ {
		open^ = false
		net.close(fd^)
	}
}

shutdown_dns :: proc() {
	sync.lock(&dns_mu)
	open := dns_open
	dns_open = false
	sync.unlock(&dns_mu)
	if open {
		net.close(dns_fd)
	}
}

handler_finish :: proc() {
	sync.lock(&mu)
	handlers -= 1
	sync.unlock(&mu)
}

wait_handlers :: proc(limit: time.Duration) -> bool {
	deadline := time.time_add(time.now(), limit)
	for {
		sync.lock(&mu)
		left := handlers
		sync.unlock(&mu)
		if left == 0 {
			return true
		}
		if time.diff(deadline, time.now()) > 0 {
			return false
		}
		time.sleep(time.Millisecond)
	}
}

write_file :: proc(name, text: string) -> bool {
	buf: [4096]u8
	return os.write_entire_file(child(buf[:], name), text, FILE_PERM) == nil
}

file_exists :: proc(name: string) -> bool {
	buf: [4096]u8
	return os.exists(child(buf[:], name))
}

wait_file :: proc(name: string, limit: time.Duration) -> bool {
	deadline := time.time_add(time.now(), limit)
	for time.diff(deadline, time.now()) <= 0 {
		if file_exists(name) {
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
	stdout_write(text)
	stdout_write("\n")
	_ = os.flush(os.stdout)
}

emit_json :: proc() {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	stdout_write("{")
	stdout_write("\"dns_names\":")
	emit_names()
	stdout_write(",\"events\":")
	emit_events(events[:], event_n)
	stdout_write(",\"mode\":\"")
	write_escaped(mode)
	stdout_write("\",\"tls\":")
	stdout_write("true" if encrypted else "false")
	stdout_write(",\"warmups\":")
	emit_events(warmups[:], warmup_n)
	stdout_write("}\n")
	_ = os.flush(os.stdout)
}

emit_names :: proc() {
	if name_n == 0 {
		stdout_write("null")
		return
	}
	stdout_write("[")
	for i in 0 ..< name_n {
		if i > 0 {
			stdout_write(",")
		}
		stdout_write("\"")
		write_escaped(string(names[i].text[:names[i].n]))
		stdout_write("\"")
	}
	stdout_write("]")
}

emit_events :: proc(rows: []Event, n: int) {
	if n == 0 {
		stdout_write("null")
		return
	}
	stdout_write("[")
	for i in 0 ..< n {
		if i > 0 {
			stdout_write(",")
		}
		emit_event(&rows[i])
	}
	stdout_write("]")
}

emit_event :: proc(row: ^Event) {
	stdout_write("{\"connection_id\":")
	write_int(row.id)
	stdout_write(",\"order\":")
	write_int(row.order)
	stdout_write(",\"method\":\"")
	write_escaped(string(row.method[:row.method_n]))
	stdout_write("\",\"host\":\"")
	write_escaped(string(row.host[:row.host_n]))
	stdout_write("\",\"path\":\"")
	write_escaped(string(row.path[:row.path_n]))
	stdout_write("\",\"body\":\"")
	write_escaped(string(row.body[:row.body_n]))
	stdout_write("\",\"alpn\":\"")
	write_escaped(string(row.alpn[:row.alpn_n]))
	stdout_write("\",\"negotiated_tls\":")
	write_int(row.tls)
	stdout_write(",\"response_bytes\":")
	write_int(row.response_bytes)
	stdout_write(",\"request_bytes\":")
	write_int(row.request_bytes)
	stdout_write(",\"headers\":")
	emit_headers(string(row.headers[:row.headers_n]))
	stdout_write(",\"old_stream_closed\":")
	stdout_write("true" if row.old_closed else "false")
	stdout_write(",\"response_status\":")
	write_int(row.status)
	stdout_write("}")
}

emit_headers :: proc(headers: string) {
	fields: [32]Field
	count := 0
	rest := headers
	if cut := strings.index(rest, "\r\n"); cut >= 0 {
		rest = rest[cut + 2:]
	} else {
		rest = ""
	}
	for len(rest) > 0 {
		line := rest
		if cut := strings.index(rest, "\r\n"); cut >= 0 {
			line = rest[:cut]
			rest = rest[cut + 2:]
		} else {
			rest = ""
		}
		colon := strings.index(line, ":")
		if colon <= 0 {
			continue
		}
		name := strings.trim_space(line[:colon])
		value := strings.trim_space(line[colon + 1:])
		if strings.equal_fold(name, "host") {
			continue
		}
		if count == len(fields) || len(value) > len(fields[0].val) {
			fail("headers")
		}
		field := &fields[count]
		field.key_n = canonical_key(field.key[:], name)
		if field.key_n < 0 {
			fail("headers")
		}
		field.val_n = copy(field.val[:], value)
		count += 1
	}
	for i in 1 ..< count {
		j := i
		for j > 0 && strings.compare(string(fields[j].key[:fields[j].key_n]), string(fields[j - 1].key[:fields[j - 1].key_n])) < 0 {
			fields[j], fields[j - 1] = fields[j - 1], fields[j]
			j -= 1
		}
	}
	stdout_write("{")
	i := 0
	first := true
	for i < count {
		if !first {
			stdout_write(",")
		}
		first = false
		stdout_write("\"")
		write_escaped(string(fields[i].key[:fields[i].key_n]))
		stdout_write("\":[")
		key := string(fields[i].key[:fields[i].key_n])
		k := i
		for k < count && string(fields[k].key[:fields[k].key_n]) == key {
			if k > i {
				stdout_write(",")
			}
			stdout_write("\"")
			write_escaped(string(fields[k].val[:fields[k].val_n]))
			stdout_write("\"")
			k += 1
		}
		stdout_write("]")
		i = k
	}
	stdout_write("}")
}

canonical_key :: proc(dst: []u8, src: string) -> int {
	if len(src) > len(dst) {
		return -1
	}
	for i in 0 ..< len(src) {
		if !header_token(src[i]) {
			return copy(dst, src)
		}
	}
	upper := true
	for i in 0 ..< len(src) {
		c := src[i]
		if upper && c >= 'a' && c <= 'z' {
			c -= 32
		} else if !upper && c >= 'A' && c <= 'Z' {
			c += 32
		}
		dst[i] = c
		upper = c == '-'
	}
	return len(src)
}

header_token :: proc(c: u8) -> bool {
	switch c {
	case '0' ..= '9', 'A' ..= 'Z', 'a' ..= 'z', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

write_int :: proc(value: int) {
	buf: [32]u8
	stdout_write(fmt.bprintf(buf[:], "%d", value))
}

stdout_write :: proc(text: string) {
	if len(text) == 0 {
		return
	}
	_, _ = os.write(os.stdout, transmute([]u8)text)
}

write_escaped :: proc(text: string) {
	for i in 0 ..< len(text) {
		c := text[i]
		switch c {
		case '"', '\\':
			pair := [2]u8{'\\', c}
			_, _ = os.write(os.stdout, pair[:])
		case '\n':
			stdout_write("\\n")
		case '\r':
			stdout_write("\\r")
		case '\t':
			stdout_write("\\t")
		case '&':
			stdout_write("\\u0026")
		case '<':
			stdout_write("\\u003c")
		case '>':
			stdout_write("\\u003e")
		case:
			if c < 0x20 {
				hex := [6]u8{'\\', 'u', '0', '0', HEX[c >> 4], HEX[c & 0x0f]}
				_, _ = os.write(os.stdout, hex[:])
			} else {
				_, _ = os.write(os.stdout, transmute([]u8)text[i:i + 1])
			}
		}
	}
}

HEX := [16]u8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

fail :: proc(reason: string) -> ! {
	fmt.eprintf("redirect101: %s\n", reason)
	os.exit(1)
}
