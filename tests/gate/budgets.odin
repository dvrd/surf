// Owned HTTP/1 peer for the budget fixture. TLS 1.3 is tests/support/loopback.
// tls-deny refuses the response under the request scope after a completed
// handshake, so every handshake the peer sees must succeed.

package main

import "../support/loopback"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

budgets_Peer :: struct {
	listener:  net.TCP_Socket,
	encrypted: bool,
	size:      int,
	stop:      bool,
	requests:  int,
	mu:        sync.Mutex,
	errors:    [dynamic]string,
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

run_budgets :: proc() {
	gate_label = "budgets"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := budgets_parse_args()
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
	if !budgets_build(compiler, shared, binary, sanitizer) {
		fail("build")
	}
	report := Report {
		sanitizer = sanitizer if sanitizer != "" else "none",
	}
	cases := [?]struct {
		mode, scenario: string,
		size:           int,
	} {
		{"native", "retained", 1024},
		{"native", "oversize", 65537},
		{"native", "managed", 1024},
		{"native", "empty", 0},
		{"tls", "tls-allow", 1024},
		{"tls", "tls-deny", 1024},
	}
	for item in cases {
		peer := budgets_start_peer(item.size, item.mode == "tls")
		url := fmt.aprintf(
			"%s://127.0.0.1:%d/budget",
			"https" if item.mode == "tls" else "http",
			port_of(peer.listener),
		)
		defer delete(url)
		command := make([dynamic]string)
		append(&command, binary, item.mode, url, item.scenario)
		if item.mode == "tls" {
			append(&command, cert)
		}
		text := run_text(command[:])
		delete(command)
		budgets_stop_peer(peer)
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
		if len(peer.errors) != 0 {
			fail(item.scenario)
		}
		append(
			&report.checks,
			Check {
				mode = item.mode,
				scenario = item.scenario,
				calls = receipt.calls,
				peak = receipt.peak,
				limit = receipt.limit,
			},
		)
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

budgets_start_peer :: proc(size: int, encrypted: bool) -> ^budgets_Peer {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	peer := new(budgets_Peer)
	peer.listener = socket
	peer.encrypted = encrypted
	peer.size = size
	worker := thread.create_and_start_with_poly_data(peer, budgets_serve)
	if worker == nil {
		fail("thread")
	}
	peer_thread = worker
	return peer
}

peer_thread: ^thread.Thread

budgets_serve :: proc(peer: ^budgets_Peer) {
	for {
		fd, _, err := net.accept_tcp(peer.listener)
		if err != nil {
			return
		}
		budgets_handle(peer, fd)
	}
}

budgets_handle :: proc(peer: ^budgets_Peer, fd: net.TCP_Socket) {
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 4 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 4 * time.Second)
	conn := loopback.Conn {
		fd = fd,
	}
	// Wipe when handle returns. A defer inside the TLS branch runs when that
	// branch ends, which is before the request is read.
	defer loopback.conn_wipe(&conn)
	if peer.encrypted {
		if !loopback.handshake(&conn, .HTTP1) {
			budgets_note(peer, "handshake")
			return
		}
	}
	buf: [16384]u8
	n := 0
	for !contains(buf[:n], "\r\n\r\n") {
		if n == len(buf) {
			budgets_note(peer, "head")
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
		budgets_note(peer, "read")
		return
	}
	head := string(buf[:index(buf[:n], "\r\n\r\n")])
	if !strings.has_prefix(head, "GET /budget HTTP/1.1\r\n") {
		budgets_note(peer, "request")
		return
	}
	sync.lock(&peer.mu)
	peer.requests += 1
	count := peer.requests
	sync.unlock(&peer.mu)
	if count > 32 {
		budgets_note(peer, "bound")
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

budgets_note :: proc(peer: ^budgets_Peer, text: string) {
	sync.lock(&peer.mu)
	append(&peer.errors, strings.clone(text))
	sync.unlock(&peer.mu)
}

budgets_stop_peer :: proc(peer: ^budgets_Peer) {
	net.close(peer.listener)
	if peer_thread != nil {
		thread.destroy(peer_thread)
		peer_thread = nil
	}
}

budgets_build :: proc(compiler, shared, binary, sanitizer: string) -> bool {
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(
		&command,
		compiler,
		"build",
		"tests/support/budgets",
		"-thread-count:1",
		"-warnings-as-errors",
		collection,
		out_flag,
	)
	if sanitizer != "" {
		append(&command, fmt.aprintf("-sanitize:%s", sanitizer))
	}
	return budgets_run(command[:], false)
}

budgets_run :: proc(command: []string, capture: bool) -> bool {
	process, start_error := os.process_start(
		{command = command, stdout = os.stdout, stderr = os.stderr},
	)
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
	process, start_error := os.process_start(
		{command = command, stdout = write_end, stderr = os.stderr},
	)
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

budgets_parse_args :: proc() -> (compiler, shared, report, sanitizer: string) {
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
