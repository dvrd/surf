// HTTP/1 peer for the concurrency matrix. Optional TLS 1.3 uses a generated
// P-256 root at dir/root.pem. POST /work/N must echo N in the body and X-Id.
// success expects 64 distinct rows and at most two connections. shutdown writes
// the response headers, waits for dir/release, then writes the body.
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

Row :: struct {
	id:          int,
	connection:  int,
	method:      [8]u8,
	method_n:    int,
	path:        [32]u8,
	path_n:      int,
	body:        [32]u8,
	body_n:      int,
	tls_version: int,
	alpn:        [16]u8,
	alpn_n:      int,
}

Job :: struct {
	fd:          net.TCP_Socket,
	id:          int,
	encrypted:   bool,
	tls_version: int,
	alpn:        string,
}

directory: string
mode: string
encrypted: bool
mu: sync.Mutex
rows: [64]Row
row_n: int
seen: [64]bool
connections: int
peak: int
active: int
closed: bool
listener: net.TCP_Socket
listener_mu: sync.Mutex
listener_open: bool

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
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "owned concurrency peer", nil, ips[:]) {
			fail("certificate")
		}
	}
	defer loopback.identity_clear()
	socket, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fail("listen")
	}
	listener = socket
	listener_open = true
	endpoint, endpoint_error := net.bound_endpoint(listener)
	if endpoint_error != nil {
		fail("bound")
	}
	accept_thread := thread.create_and_start(accept_loop)
	if accept_thread == nil {
		fail("accept thread")
	}
	emit_line(fmt.bprintf(address_buf[:], "127.0.0.1:%d", endpoint.port))
	if !wait_file("done", 20 * time.Second) {
		fail("host not done")
	}
	sync.lock(&mu)
	closed = true
	sync.unlock(&mu)
	shutdown_listener()
	thread.destroy(accept_thread)
	for i in 0 ..< worker_n {
		thread.destroy(workers[i])
	}
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if connections > 2 || peak > 2 {
		fail("connection capacity exceeded")
	}
	if mode == "success" && row_n != 64 {
		fail("missing requests")
	}
	if mode == "shutdown" && row_n == 0 {
		fail("shutdown had no actual request")
	}
	emit_json()
}

address_buf: [64]u8
workers: [8]^thread.Thread
worker_n: int
worker_mu: sync.Mutex

parse_flags :: proc() {
	mode = "success"
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

accept_loop :: proc() {
	for {
		fd, _, accept_error := net.accept_tcp(listener)
		if accept_error != nil {
			sync.lock(&mu)
			end := closed
			sync.unlock(&mu)
			if !end {
				fail("accept")
			}
			return
		}
		sync.lock(&mu)
		connections += 1
		id := connections
		active += 1
		if active > peak {
			peak = active
		}
		sync.unlock(&mu)
		_ = net.set_option(fd, .TCP_Nodelay, true)
		_ = net.set_option(fd, .Send_Timeout, 20 * time.Second)
		_ = net.set_option(fd, .Receive_Timeout, 20 * time.Second)
		job := new(Job)
		job.fd = fd
		job.id = id
		job.encrypted = encrypted
		sync.lock(&worker_mu)
		if worker_n == len(workers) {
			sync.unlock(&worker_mu)
			net.close(fd)
			free(job)
			fail("connection capacity exceeded")
		}
		worker := thread.create_and_start_with_poly_data(job, serve)
		if worker == nil {
			sync.unlock(&worker_mu)
			net.close(fd)
			free(job)
			fail("thread")
		}
		workers[worker_n] = worker
		worker_n += 1
		sync.unlock(&worker_mu)
	}
}

serve :: proc(job: ^Job) {
	defer free(job)
	defer net.close(job.fd)
	defer drop_active()
	conn := loopback.Conn{fd = job.fd}
	defer loopback.conn_wipe(&conn)
	version := 0
	alpn := ""
	if job.encrypted {
		loopback.set_recv_timeout(job.fd, 20 * time.Second)
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
		alpn = string(conn.alpn[:conn.alpn_n])
		if alpn != "http/1.1" {
			fail("authentication protocol")
		}
		version = TLS13
	}
	pending: [1 << 16]u8
	n := 0
	for {
		head, complete, overflow, ok := loopback.take_request(pending[:n], 128)
		if !ok || overflow {
			fail("request clone or identity")
		}
		if !complete {
			got, err := read_some(job, &conn, pending[n:])
			if got > 0 {
				n += got
				continue
			}
			if err == .Interrupted {
				continue
			}
			return
		}
		text, id, valid := work_id(head)
		if !valid {
			fail("request clone or identity")
		}
		record(job.id, version, alpn, head, text, id)
		reply: [128]u8
		wrote := fmt.bprintf(reply[:], "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Connection: %d\r\n\r\n", len(text), job.id)
		if !write_some(job, &conn, wrote) {
			return
		}
		if mode == "shutdown" {
			if !write_marker("held", "held") {
				fail("held")
			}
			if !wait_file("release", 15 * time.Second) {
				fail("held peer not released")
			}
		}
		if !write_some(job, &conn, text) {
			return
		}
		consumed := head.consumed
		copy(pending[:], pending[consumed:n])
		n -= consumed
	}
}

work_id :: proc(head: loopback.Head) -> (text: string, id: int, ok: bool) {
	if !strings.has_prefix(head.path, "/work/") || head.method != "POST" {
		return
	}
	text = head.path[len("/work/"):]
	parsed, valid := strconv.parse_int(text, 10)
	if !valid || parsed < 0 || parsed >= 64 || string(head.body) != text {
		return
	}
	xid, found := loopback.header_value(head.headers, "x-id")
	if !found || xid != text {
		return
	}
	return text, parsed, true
}

record :: proc(connection, version: int, alpn: string, head: loopback.Head, text: string, id: int) {
	sync.lock(&mu)
	defer sync.unlock(&mu)
	if seen[id] {
		fail("duplicate accepted request")
	}
	seen[id] = true
	row := &rows[row_n]
	row_n += 1
	row.id = id
	row.connection = connection
	row.method_n = copy(row.method[:], head.method)
	row.path_n = copy(row.path[:], head.path)
	row.body_n = copy(row.body[:], head.body)
	row.tls_version = version
	row.alpn_n = copy(row.alpn[:], alpn)
}

read_some :: proc(job: ^Job, conn: ^loopback.Conn, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if job.encrypted {
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
	return net.recv_tcp(job.fd, dst)
}

write_some :: proc(job: ^Job, conn: ^loopback.Conn, text: string) -> bool {
	if job.encrypted {
		return loopback.tls_write(conn, transmute([]u8)text)
	}
	rest := transmute([]u8)text
	for len(rest) > 0 {
		n, err := net.send_tcp(job.fd, rest)
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

drop_active :: proc() {
	sync.lock(&mu)
	active -= 1
	sync.unlock(&mu)
}

shutdown_listener :: proc() {
	sync.lock(&listener_mu)
	defer sync.unlock(&listener_mu)
	if listener_open {
		listener_open = false
		net.close(listener)
	}
}

write_marker :: proc(name, text: string) -> bool {
	buf: [1024]u8
	return os.write_entire_file(child(buf[:], name), text, FILE_PERM) == nil
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
	fmt.fprintf(os.stdout, `{{"requests":[`)
	for i in 0 ..< row_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		row := &rows[i]
		fmt.fprintf(os.stdout, `{{"id":%d,"connection":%d,"method":"`, row.id, row.connection)
		write_escaped(string(row.method[:row.method_n]))
		fmt.fprint(os.stdout, `","path":"`)
		write_escaped(string(row.path[:row.path_n]))
		fmt.fprint(os.stdout, `","body":"`)
		write_escaped(string(row.body[:row.body_n]))
		fmt.fprintf(os.stdout, `","tls_version":%d,"alpn":"`, row.tls_version)
		write_escaped(string(row.alpn[:row.alpn_n]))
		fmt.fprint(os.stdout, `"}`)
	}
	fmt.fprintf(os.stdout, `],"connections":%d,"peak":%d,"tls":%t,"mode":"`, connections, peak, encrypted)
	write_escaped(mode)
	fmt.fprint(os.stdout, "\"}\n")
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
	fmt.eprintf("concurrency101: %s\n", reason)
	os.exit(1)
}
