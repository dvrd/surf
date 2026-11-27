// Owned loopback for the native and legacy outcome fixtures. TLS 1.3 is
// tests/support/loopback. The client is given a different root, so the handshake
// is expected to fail before any HTTP request is counted.

package main

import "../support/loopback"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

seen_mu: sync.Mutex
seen: [dynamic]string

run_outcomes :: proc() {
	gate_label = "outcomes"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, report_path, sanitize := outcomes_parse_args()
	root := fmt.aprintf("/tmp/okami-outcomes-%d", posix.getpid())
	defer delete(root)
	if err := os.make_directory_all(root, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	wrong := join(root, "wrong-root.pem")
	server := join(root, "server.pem")
	defer delete(wrong)
	defer delete(server)
	if !loopback.mint_p256(wrong, "wrong-root", nil, nil) {
		fail("wrong root")
	}
	dns := [1]string{"localhost"}
	raw := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{raw[:]}
	if !loopback.mint_p256(server, "server", dns[:], ips[:]) {
		fail("server certificate")
	}
	defer loopback.identity_clear()
	resolv := join(root, "empty-resolv.conf")
	defer delete(resolv)
	if os.write_entire_file(
		   resolv,
		   "# Deliberately no resolver for the native DNS failure fixture.\n",
		   FILE_PERM,
	   ) !=
	   nil {
		fail("resolver file")
	}

	plain := listen()
	secure := listen()
	refused := reserve_refused()
	plain_job := Job {
		listener = plain,
	}
	secure_job := Job {
		listener  = secure,
		encrypted = true,
	}
	plain_thread := thread.create_and_start_with_poly_data(&plain_job, outcomes_serve)
	secure_thread := thread.create_and_start_with_poly_data(&secure_job, outcomes_serve)
	if plain_thread == nil || secure_thread == nil {
		fail("thread")
	}

	plain_port := port_of(plain)
	secure_port := port_of(secure)
	refused_port := refused_port_of(refused)
	binary := join(root, "outcomes.bin")
	defer delete(binary)
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	command := make([dynamic]string)
	defer delete(command)
	append(
		&command,
		compiler,
		"build",
		"tests/support/outcomes",
		"-thread-count:1",
		"-warnings-as-errors",
		out_flag,
	)
	if sanitize {
		append(&command, "-sanitize:address")
	}
	if !outcomes_run(command[:], nil) {
		fail("build")
	}
	env := outcomes_child_env(plain_port, secure_port, refused_port, wrong, resolv)
	defer delete_env(env)
	if !outcomes_run({binary}, env) {
		fail("fixture")
	}

	net.close(plain)
	net.close(secure)
	posix.close(refused)
	thread.destroy(plain_thread)
	thread.destroy(secure_thread)
	expect := [?]string {
		"/native-reset",
		"/native-large",
		"/native-malformed",
		"/native-slow",
		"/native-redirect",
		"/native-redirected-reset",
		"/native-unsafe-redirect",
	}
	sync.lock(&seen_mu)
	defer sync.unlock(&seen_mu)
	if len(seen) != len(expect) {
		fail(fmt.tprintf("request count %d", len(seen)))
	}
	for want in expect {
		found := false
		for got in seen {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			fail(want)
		}
	}
	fmt.println("Only owned loopback peers used; each POST reached the peer exactly once.")
	text := fmt.aprintf("{{\"passed\":true,\"requests\":%d}}\n", len(expect))
	defer delete(text)
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
}

outcomes_serve :: proc(job: ^Job) {
	for {
		fd, _, err := net.accept_tcp(job.listener)
		if err != nil {
			return
		}
		box := new(Conn)
		box.fd = fd
		box.encrypted = job.encrypted
		if thread.create_and_start_with_poly_data(
			   box,
			   outcomes_handle_conn,
			   self_cleanup = true,
		   ) ==
		   nil {
			free(box)
			net.close(fd)
		}
	}
}

outcomes_handle_conn :: proc(box: ^Conn) {
	fd := box.fd
	encrypted := box.encrypted
	free(box)
	outcomes_handle(fd, encrypted)
}

outcomes_handle :: proc(fd: net.TCP_Socket, encrypted: bool) {
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 3 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 3 * time.Second)
	conn := loopback.Conn {
		fd = fd,
	}
	// Wipe when handle returns. A defer inside the TLS branch runs when that
	// branch ends, which is before the request is read.
	defer loopback.conn_wipe(&conn)
	if encrypted {
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
	}
	buf: [16384]u8
	n := 0
	for !outcomes_bytes_contains(buf[:n], "\r\n\r\n") {
		if n == len(buf) {
			return
		}
		got, err := read_some(fd, &conn, encrypted, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
	head_n := outcomes_bytes_index(buf[:n], "\r\n\r\n")
	head := string(buf[:head_n])
	body := buf[head_n + 4:n]
	length := outcomes_content_length(head)
	for len(body) < length {
		if n == len(buf) {
			return
		}
		got, err := read_some(fd, &conn, encrypted, buf[n:])
		if got > 0 {
			n += got
			body = buf[head_n + 4:n]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
	path := request_path(head)
	if path == "" {
		return
	}
	record(path)
	if path == "/native-redirect" {
		_ = write_all(
			fd,
			&conn,
			encrypted,
			"HTTP/1.1 307 Temporary Redirect\r\nLocation: /native-redirected-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		)
		return
	}
	if path == "/native-unsafe-redirect" {
		_ = write_all(
			fd,
			&conn,
			encrypted,
			"HTTP/1.1 302 Found\r\nLocation: /never-follow-this-post\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		)
		return
	}
	if strings.has_suffix(path, "reset") || strings.has_suffix(path, "slow") {
		if strings.has_suffix(path, "slow") {
			time.sleep(600 * time.Millisecond)
		}
		return
	}
	if strings.has_suffix(path, "malformed") {
		_ = write_all(fd, &conn, encrypted, "HTTP/1.1 bad status\r\n\r\n")
		return
	}
	if strings.has_suffix(path, "large") {
		_ = write_large(fd, &conn, encrypted)
		return
	}
	_ = write_all(
		fd,
		&conn,
		encrypted,
		"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
	)
}

record :: proc(path: string) {
	kept := strings.clone(path)
	sync.lock(&seen_mu)
	append(&seen, kept)
	sync.unlock(&seen_mu)
}

write_large :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool) -> bool {
	if !write_all(
		fd,
		conn,
		encrypted,
		"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n",
	) {
		return false
	}
	chunk: [4096]u8
	for &b in chunk {
		b = 'x'
	}
	left := 65537
	for left > 0 {
		n := left if left < len(chunk) else len(chunk)
		if !write_all(fd, conn, encrypted, string(chunk[:n])) {
			return false
		}
		left -= n
	}
	return true
}

outcomes_content_length :: proc(head: string) -> int {
	rest := head
	for len(rest) > 0 {
		cut := strings.index(rest, "\r\n")
		line := rest if cut < 0 else rest[:cut]
		if cut < 0 {
			rest = ""
		} else {
			rest = rest[cut + 2:]
		}
		if len(line) >= len("content-length:") &&
		   strings.equal_fold(line[:len("content-length:")], "content-length:") {
			value := strings.trim_space(line[len("content-length:"):])
			parsed, ok := strconv.parse_int(value)
			if ok {
				return parsed
			}
		}
	}
	return 0
}


request_path :: proc(head: string) -> string {
	line := head
	if cut := strings.index(head, "\r\n"); cut >= 0 {
		line = head[:cut]
	}
	first := strings.index(line, " ")
	if first < 0 {
		return ""
	}
	rest := line[first + 1:]
	second := strings.index(rest, " ")
	if second < 0 {
		return ""
	}
	return rest[:second]
}

outcomes_bytes_contains :: proc(buf: []u8, needle: string) -> bool {
	return outcomes_bytes_index(buf, needle) >= 0
}

outcomes_bytes_index :: proc(buf: []u8, needle: string) -> int {
	if len(needle) == 0 || len(buf) < len(needle) {
		return -1
	}
	for i in 0 ..= len(buf) - len(needle) {
		match := true
		for j in 0 ..< len(needle) {
			if buf[i + j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// Bind without listen so connect is refused and the port stays reserved.
listen :: proc() -> net.TCP_Socket {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	return socket
}

outcomes_run :: proc(command: []string, env: []string) -> bool {
	process, start_error := os.process_start(
		{command = command, env = env, stdout = os.stdout, stderr = os.stderr},
	)
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	if wait_error != nil || state.exit_code != 0 {
		fmt.eprintf("outcomes: command failed exit=%d wait=%v\n", state.exit_code, wait_error)
		return false
	}
	return true
}

outcomes_child_env :: proc(plain, secure, refused: int, wrong, resolv: string) -> []string {
	base, err := os.environ(context.allocator)
	if err != nil {
		fail("environ")
	}
	out := make([dynamic]string, context.allocator)
	for row in base {
		if strings.has_prefix(row, "SURF_OUTCOME_") {
			continue
		}
		append(&out, row)
	}
	append(&out, fmt.aprintf("SURF_OUTCOME_HTTP=http://127.0.0.1:%d", plain))
	append(&out, fmt.aprintf("SURF_OUTCOME_TLS=https://127.0.0.1:%d", secure))
	append(&out, fmt.aprintf("SURF_OUTCOME_REFUSED=http://127.0.0.1:%d", refused))
	append(&out, fmt.aprintf("SURF_OUTCOME_WRONG_ROOT=%s", wrong))
	append(&out, fmt.aprintf("SURF_OUTCOME_EMPTY_RESOLVER=%s", resolv))
	return out[:]
}

delete_env :: proc(env: []string) {
	for row in env {
		if strings.has_prefix(row, "SURF_OUTCOME_") {
			delete(row)
		}
	}
	delete(env)
}

outcomes_parse_args :: proc() -> (compiler, report: string, sanitize: bool) {
	compiler = ""
	for i in 1 ..< len(os.args) {
		arg := os.args[i]
		if arg == "--sanitize" {
			sanitize = true
		} else if arg == "--odin" && i + 1 < len(os.args) {
			compiler = os.args[i + 1]
		} else if arg == "--report" && i + 1 < len(os.args) {
			report = os.args[i + 1]
		}
	}
	if compiler == "" {
		fail("odin required")
	}
	if report == "" {
		fail("report required")
	}
	return
}
