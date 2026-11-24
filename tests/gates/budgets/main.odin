// Owned HTTP/1 peer for the budget fixture. TLS 1.3 is tests/loopback.
// tls-deny is a client budget rejection during the handshake: the warm
// GET still completes, and the denied attempt must not become a request.
package main

import loopback "../../loopback"

import "core:encoding/json"
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

Peer :: struct {
	listener:           net.TCP_Socket,
	encrypted:          bool,
	allow_handshake_fail: bool,
	size:               int,
	stop:               bool,
	requests:           int,
	handshake_failures: int,
	mu:                 sync.Mutex,
	errors:             [dynamic]string,
}

Receipt :: struct {
	calls: int `json:"calls"`,
	limit: u64 `json:"limit"`,
	peak:  u64 `json:"peak"`,
}

Check :: struct {
	mode:     string `json:"mode"`,
	scenario: string `json:"scenario"`,
	calls:    int `json:"calls"`,
	peak:     u64 `json:"peak"`,
	limit:    u64 `json:"limit"`,
}

Report :: struct {
	passed:    bool `json:"passed"`,
	sanitizer: string `json:"sanitizer"`,
	checks:    [dynamic]Check `json:"checks"`,
}

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-budgets-%d", posix.getpid())
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
	binary := join(root, "fixture")
	defer delete(binary)
	if !build(compiler, shared, binary, sanitizer) {
		fail("build")
	}
	report := Report{sanitizer = sanitizer if sanitizer != "" else "none"}
	cases := [?]struct{mode, scenario: string, size: int}{
		{"native", "retained", 1024},
		{"curl", "retained", 1024},
		{"native", "oversize", 65537},
		{"curl", "oversize", 65537},
		{"curl", "legacy", 1024},
		{"curl", "empty", 0},
		{"tls", "tls-allow", 1024},
		{"tls", "tls-deny", 1024},
	}
	for item in cases {
		peer := start_peer(item.size, item.mode == "tls", item.scenario == "tls-deny")
		url := fmt.aprintf("%s://127.0.0.1:%d/budget", "https" if item.mode == "tls" else "http", port_of(peer.listener))
		defer delete(url)
		command := make([dynamic]string)
		append(&command, binary, item.mode, url, item.scenario)
		if item.mode == "tls" {
			append(&command, cert)
		}
		text := run_text(command[:])
		delete(command)
		stop_peer(peer)
		if text == "" {
			fail(item.scenario)
		}
		receipt: Receipt
		if json.unmarshal(transmute([]u8)text, &receipt) != nil {
			fail(item.scenario)
		}
		if receipt.calls != peer.requests || receipt.peak > receipt.limit {
			fail(fmt.tprintf("%s calls %d peer %d", item.scenario, receipt.calls, peer.requests))
		}
		want_fail := 1 if item.scenario == "tls-deny" else 0
		if peer.handshake_failures != want_fail || len(peer.errors) != 0 {
			fail(item.scenario)
		}
		append(&report.checks, Check{mode = item.mode, scenario = item.scenario, calls = receipt.calls, peak = receipt.peak, limit = receipt.limit})
		delete(peer.errors)
		free(peer)
	}
	report.passed = len(report.checks) == len(cases)
	encoded, err := json.marshal(report, {pretty = true, spec = json.Specification.JSON})
	if err != nil {
		fail("report")
	}
	defer delete(encoded)
	if os.write_entire_file(report_path, encoded, FILE_PERM) != nil {
		fail("report write")
	}
	fmt.printf(`{{"passed":%t,"checks":%d}}` + "\n", report.passed, len(report.checks))
}

start_peer :: proc(size: int, encrypted, allow_fail: bool) -> ^Peer {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	peer := new(Peer)
	peer.listener = socket
	peer.encrypted = encrypted
	peer.allow_handshake_fail = allow_fail
	peer.size = size
	worker := thread.create_and_start_with_poly_data(peer, serve)
	if worker == nil {
		fail("thread")
	}
	peer_thread = worker
	return peer
}

peer_thread: ^thread.Thread

serve :: proc(peer: ^Peer) {
	for {
		fd, _, err := net.accept_tcp(peer.listener)
		if err != nil {
			return
		}
		handle(peer, fd)
	}
}

handle :: proc(peer: ^Peer, fd: net.TCP_Socket) {
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 4 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 4 * time.Second)
	conn := loopback.Conn{fd = fd}
	// Wipe when handle returns. A defer inside the TLS branch runs when that
	// branch ends, which is before the request is read.
	defer loopback.conn_wipe(&conn)
	if peer.encrypted {
		ok := loopback.handshake(&conn, .HTTP1)
		if !ok {
			if !peer.allow_handshake_fail {
				note(peer, "handshake")
			}
			sync.lock(&peer.mu)
			peer.handshake_failures += 1
			sync.unlock(&peer.mu)
			return
		}
	}
	buf: [16384]u8
	n := 0
	for !contains(buf[:n], "\r\n\r\n") {
		if n == len(buf) {
			note(peer, "head")
			return
		}
		got, read_err := read_some(fd, &conn, peer.encrypted, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if read_err == .Interrupted {
			continue
		}
		note(peer, "read")
		return
	}
	head := string(buf[:index(buf[:n], "\r\n\r\n")])
	if !strings.has_prefix(head, "GET /budget HTTP/1.1\r\n") {
		note(peer, "request")
		return
	}
	sync.lock(&peer.mu)
	peer.requests += 1
	count := peer.requests
	sync.unlock(&peer.mu)
	if count > 32 {
		note(peer, "bound")
		return
	}
	// The accept thread shares the process temp allocator. Keep this header on the stack.
	header: [128]u8
	text := fmt.bprintf(header[:], "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", peer.size)
	if !write_all(fd, &conn, peer.encrypted, text) {
		return
	}
	chunk: [4096]u8
	for &b in chunk {
		b = 'B'
	}
	left := peer.size
	for left > 0 {
		part := left if left < len(chunk) else len(chunk)
		if !write_all(fd, &conn, peer.encrypted, string(chunk[:part])) {
			return
		}
		left -= part
	}
}

note :: proc(peer: ^Peer, text: string) {
	sync.lock(&peer.mu)
	append(&peer.errors, strings.clone(text))
	sync.unlock(&peer.mu)
}

stop_peer :: proc(peer: ^Peer) {
	net.close(peer.listener)
	if peer_thread != nil {
		thread.destroy(peer_thread)
		peer_thread = nil
	}
}

build :: proc(compiler, shared, binary, sanitizer: string) -> bool {
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, compiler, "build", "tests/testdata/budgets", "-thread-count:1", "-warnings-as-errors", collection, out_flag)
	if sanitizer != "" {
		append(&command, fmt.aprintf("-sanitize:%s", sanitizer))
	}
	return run(command[:], false)
}

run :: proc(command: []string, capture: bool) -> bool {
	process, start_error := os.process_start({command = command, stdout = os.stdout, stderr = os.stderr})
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	return wait_error == nil && state.exit_code == 0
}

run_text :: proc(command: []string) -> string {
	read_end, write_end, pipe_error := os.pipe()
	if pipe_error != nil {
		return ""
	}
	process, start_error := os.process_start({command = command, stdout = write_end, stderr = os.stderr})
	os.close(write_end)
	if start_error != nil {
		os.close(read_end)
		return ""
	}
	buf: [4096]u8
	n := 0
	for n < len(buf) {
		got, err := os.read(read_end, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if err == os.ERROR_NONE {
			break
		}
		break
	}
	os.close(read_end)
	state, wait_error := os.process_wait(process, 30 * time.Second)
	if wait_error != nil || state.exit_code != 0 {
		return ""
	}
	return strings.clone(string(buf[:n]))
}

read_some :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if encrypted {
		n, status := loopback.tls_read(conn, dst)
		if status == .Ok {
			return n, nil
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		return 0, .Connection_Closed
	}
	return net.recv_tcp(fd, dst)
}

write_all :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, text: string) -> bool {
	if encrypted {
		return loopback.tls_write(conn, transmute([]u8)text)
	}
	return loopback.write_full(fd, transmute([]u8)text)
}

contains :: proc(buf: []u8, needle: string) -> bool {
	return index(buf, needle) >= 0
}

index :: proc(buf: []u8, needle: string) -> int {
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

port_of :: proc(socket: net.TCP_Socket) -> int {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return int(endpoint.port)
}

join :: proc(dir, name: string) -> string {
	return fmt.aprintf("%s/%s", dir, name)
}

parse_args :: proc() -> (compiler, shared, report, sanitizer: string) {
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
		fail("odin, shared, and report are required")
	}
	if sanitizer != "" && sanitizer != "address" && sanitizer != "thread" {
		fail("sanitizer")
	}
	return
}

fail :: proc(reason: string) {
	fmt.eprintf("budgets: %s\n", reason)
	os.exit(1)
}
