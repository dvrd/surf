// Owned HTTP/1 peer for the upload matrix. TLS 1.3 is tests/support/loopback.
// Bodies are hashed as they arrive. A stall records the declared length
// and then stops reading.

package main

import "../support/loopback"
import "core:crypto/hash"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

uploads_Record :: struct {
	method:    string,
	path:      string,
	declared:  int,
	consumed:  int,
	digest:    [32]u8,
	stalled:   bool,
}

uploads_Peer :: struct {
	listener:  net.TCP_Socket,
	encrypted: bool,
	mu:        sync.Mutex,
	records:   [dynamic]uploads_Record,
}

uploads_Job :: struct {
	peer: ^uploads_Peer,
	fd:   net.TCP_Socket,
}

Expect :: struct {
	path:     string,
	method:   string,
	declared: int,
}

run_uploads :: proc() {
	gate_label = "uploads"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := uploads_parse_args()
	root := fmt.aprintf("/tmp/okami-uploads-%d", posix.getpid())
	defer delete(root)
	if err := os.make_directory_all(root, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	cert := join(root, "root.pem")
	defer delete(cert)
	dns := [1]string{"localhost"}
	raw := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{raw[:]}
	if !loopback.mint_p256(cert, "localhost", dns[:], ips[:]) {
		fail("certificate")
	}
	defer loopback.identity_clear()
	file_path := join(root, "upload.bin")
	short_path := join(root, "short.bin")
	defer delete(file_path)
	defer delete(short_path)
	uploads_write_payload(file_path, 65 * 16, true)
	if os.write_entire_file(short_path, []u8{'Z', 'Z'}, FILE_PERM) != nil {
		fail("short")
	}
	plain := uploads_start_peer(false)
	secure := uploads_start_peer(true)
	binary := join(root, "uploads")
	defer delete(binary)
	if !uploads_build(compiler, shared, binary, sanitizer) {
		fail("build")
	}
	env := uploads_child_env(plain, secure, file_path, short_path, cert)
	defer {
		for item in env {
			delete(item)
		}
		delete(env)
	}
	if !run_fixture(binary, env) {
		fail("fixture")
	}
	uploads_check(plain, secure)
	uploads_stop_peer(plain)
	uploads_stop_peer(secure)
	text := "{\"passed\":true,\"scenarios\":10}\n"
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.println("Methods, declared lengths, SHA-256 bodies, prefix cursor and no redirect replay verified.")
}

uploads_start_peer :: proc(encrypted: bool) -> ^uploads_Peer {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	peer := new(uploads_Peer)
	peer.listener = socket
	peer.encrypted = encrypted
	worker := thread.create_and_start_with_poly_data(peer, uploads_serve)
	if worker == nil {
		fail("thread")
	}
	if encrypted {
		secure_thread = worker
	} else {
		plain_thread = worker
	}
	return peer
}

uploads_serve :: proc(peer: ^uploads_Peer) {
	for {
		fd, _, err := net.accept_tcp(peer.listener)
		if err != nil {
			return
		}
		job := new(uploads_Job)
		job.peer = peer
		job.fd = fd
		worker := thread.create_and_start_with_poly_data(job, uploads_handle, self_cleanup = true)
		if worker == nil {
			net.close(fd)
			free(job)
		}
	}
}

uploads_handle :: proc(job: ^uploads_Job) {
	peer := job.peer
	fd := job.fd
	free(job)
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 25 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 25 * time.Second)
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	if peer.encrypted {
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
	}
	buf: [64 * 1024]u8
	n := 0
	for index_of(buf[:n], "\r\n\r\n") < 0 {
		if n == len(buf) {
			return
		}
		got, err := read_some(fd, &conn, peer.encrypted, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
	split := index_of(buf[:n], "\r\n\r\n")
	head := string(buf[:split])
	method, path, length, ok := request_of(head)
	if !ok {
		return
	}
	body_at := split + 4
	if path == "/stall" {
		_ = net.set_option(fd, .Receive_Buffer_Size, 4096)
		uploads_note(peer, method, path, length, body_at, n, {}, true)
		time.sleep(800 * time.Millisecond)
		return
	}
	digest: hash.Context
	hash.init(&digest, .SHA256)
	consumed := 0
	if n > body_at {
		take := min(n - body_at, length)
		hash.update(&digest, buf[body_at:][:take])
		consumed = take
	}
	chunk: [64 * 1024]u8
	for consumed < length {
		got, err := read_some(fd, &conn, peer.encrypted, chunk[:])
		if got > 0 {
			take := got if consumed + got <= length else length - consumed
			hash.update(&digest, chunk[:take])
			consumed += take
			continue
		}
		if err == .Interrupted {
			continue
		}
		break
	}
	sum: [32]u8
	hash.final(&digest, sum[:])
	uploads_note(peer, method, path, length, consumed, consumed, sum, false)
	if consumed != length {
		return
	}
	status := "200 OK"
	location := ""
	if path == "/redirect" {
		status = "307 Temporary Redirect"
		location = "Location: /must-not-replay\r\n"
	}
	header: [160]u8
	text := fmt.bprintf(header[:], "HTTP/1.1 %s\r\n%sContent-Length: 2\r\nConnection: close\r\n\r\nok", status, location)
	_ = write_all(fd, &conn, peer.encrypted, text)
}

uploads_note :: proc(peer: ^uploads_Peer, method, path: string, declared, consumed, _: int, digest: [32]u8, stalled: bool) {
	sync.lock(&peer.mu)
	append(&peer.records, uploads_Record{
		method = strings.clone(method),
		path = strings.clone(path),
		declared = declared,
		consumed = consumed,
		digest = digest,
		stalled = stalled,
	})
	sync.unlock(&peer.mu)
}

request_of :: proc(head: string) -> (method, path: string, length: int, ok: bool) {
	line_end := strings.index(head, "\r\n")
	line := head if line_end < 0 else head[:line_end]
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
	path = line[first + 1:second]
	rest := head
	if line_end >= 0 {
		rest = head[line_end + 2:]
	} else {
		rest = ""
	}
	seen := false
	for len(rest) > 0 {
		field := rest
		if cut := strings.index(rest, "\r\n"); cut >= 0 {
			field = rest[:cut]
			rest = rest[cut + 2:]
		} else {
			rest = ""
		}
		colon := strings.index(field, ":")
		if colon <= 0 {
			continue
		}
		if !strings.equal_fold(strings.trim_space(field[:colon]), "content-length") {
			continue
		}
		parsed, valid := strconv.parse_int(strings.trim_space(field[colon + 1:]))
		if !valid || parsed < 0 || seen {
			return
		}
		length = parsed
		seen = true
	}
	if !seen || len(path) == 0 || len(method) == 0 {
		return
	}
	return method, path, length, true
}

uploads_check :: proc(plain, secure: ^uploads_Peer) {
	expected := [?]Expect{
		{"/put", "PUT", 65 * 1024 * 1024},
		{"/post", "POST", 17},
		{"/delete", "DELETE", 0},
		{"/prefix", "PUT", 3},
		{"/redirect", "POST", 17},
		{"/short", "PUT", 3},
		{"/stall", "PUT", 65 * 1024 * 1024},
		{"/tls-put", "PUT", 2 * 1024 * 1024},
		{"/tls-post", "POST", 17},
		{"/tls-delete", "DELETE", 9},
	}
	all := make([dynamic]uploads_Record)
	defer delete(all)
	sync.lock(&plain.mu)
	append(&all, ..plain.records[:])
	sync.unlock(&plain.mu)
	sync.lock(&secure.mu)
	append(&all, ..secure.records[:])
	sync.unlock(&secure.mu)
	if len(all) != len(expected) {
		fail(fmt.tprintf("records %d", len(all)))
	}
	for want in expected {
		found := false
		for &row in all {
			if row.path != want.path {
				continue
			}
			if found || row.method != want.method || row.declared != want.declared {
				fail(want.path)
			}
			found = true
			if row.stalled {
				continue
			}
			want_n := 2 if want.path == "/short" else want.declared
			if row.consumed != want_n || row.digest != digest_of(want_n) {
				fail(want.path)
			}
		}
		if !found {
			fail(want.path)
		}
	}
}

digest_of :: proc(n: int) -> [32]u8 {
	ctx: hash.Context
	hash.init(&ctx, .SHA256)
	chunk: [4096]u8
	for &b in chunk {
		b = 'Z'
	}
	left := n
	for left > 0 {
		part := left if left < len(chunk) else len(chunk)
		hash.update(&ctx, chunk[:part])
		left -= part
	}
	out: [32]u8
	hash.final(&ctx, out[:])
	return out
}

uploads_write_payload :: proc(path: string, chunks: int, extra: bool) {
	file, err := os.open(path, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, FILE_PERM)
	if err != nil {
		fail("payload")
	}
	defer os.close(file)
	chunk: [65536]u8
	for &b in chunk {
		b = 'Z'
	}
	for _ in 0 ..< chunks {
		wrote, write_err := os.write(file, chunk[:])
		if write_err != nil || wrote != len(chunk) {
			fail("payload write")
		}
	}
	if extra {
		wrote, write_err := os.write(file, transmute([]u8)string("extra"))
		if write_err != nil || wrote != 5 {
			fail("payload extra")
		}
	}
}

uploads_child_env :: proc(plain, secure: ^uploads_Peer, file_path, short_path, cert: string) -> [dynamic]string {
	base, err := os.environ(context.allocator)
	if err != nil {
		fail("environ")
	}
	env := make([dynamic]string, 0, len(base) + 5)
	append(&env, ..base[:])
	delete(base)
	append(&env, fmt.aprintf("SURF_UPLOAD_HTTP=http://127.0.0.1:%d", port_of(plain.listener)))
	append(&env, fmt.aprintf("SURF_UPLOAD_TLS=https://127.0.0.1:%d", port_of(secure.listener)))
	append(&env, fmt.aprintf("SURF_UPLOAD_FILE=%s", file_path))
	append(&env, fmt.aprintf("SURF_UPLOAD_SHORT=%s", short_path))
	append(&env, fmt.aprintf("SURF_UPLOAD_ROOT=%s", cert))
	return env
}

run_fixture :: proc(binary: string, env: [dynamic]string) -> bool {
	process, start_error := os.process_start({
		command = []string{binary},
		env = env[:],
		stdout = os.stdout,
		stderr = os.stderr,
	})
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 120 * time.Second)
	return wait_error == nil && state.exit_code == 0
}

uploads_build :: proc(compiler, shared, binary, sanitizer: string) -> bool {
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, compiler, "build", "tests/support/uploads", "-thread-count:1", "-warnings-as-errors", collection, out_flag)
	if sanitizer != "" && sanitizer != "none" {
		append(&command, fmt.aprintf("-sanitize:%s", sanitizer))
	}
	process, start_error := os.process_start({command = command[:], stdout = os.stdout, stderr = os.stderr})
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	return wait_error == nil && state.exit_code == 0
}

uploads_stop_peer :: proc(peer: ^uploads_Peer) {
	net.close(peer.listener)
	worker := secure_thread if peer.encrypted else plain_thread
	if worker != nil {
		thread.join(worker)
		thread.destroy(worker)
	}
	if peer.encrypted {
		secure_thread = nil
	} else {
		plain_thread = nil
	}
	for row in peer.records {
		delete(row.method)
		delete(row.path)
	}
	delete(peer.records)
	free(peer)
}

index_of :: proc(buf: []u8, needle: string) -> int {
	if len(needle) == 0 || len(buf) < len(needle) {
		return -1
	}
	for i in 0 ..= len(buf) - len(needle) {
		ok := true
		for j in 0 ..< len(needle) {
			if buf[i + j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

uploads_parse_args :: proc() -> (compiler, shared, report, sanitizer: string) {
	for i in 1 ..< len(os.args) {
		arg := os.args[i]
		if i + 1 >= len(os.args) {
			break
		}
		next := os.args[i + 1]
		if arg == "--odin" {
			compiler = next
		} else if arg == "--shared" {
			shared = next
		} else if arg == "--report" {
			report = next
		} else if arg == "--sanitize" {
			sanitizer = next
		}
	}
	if compiler == "" || shared == "" || report == "" {
		fail("usage: --odin <compiler> --shared <collection> --report <path> [--sanitize address|thread]")
	}
	return
}

