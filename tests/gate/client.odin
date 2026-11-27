// Public Client HTTP/1 matrix. The peer is tests/support/client/peer.
// TLS 1.3 is tests/support/loopback. Six cells: healthy, fragmented, and progress,
// each on TCP and TLS.

package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

run_client :: proc() {
	gate_label = "client"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-client-%d", posix.getpid())
	defer delete(root)
	if err := os.make_directory_all(root, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(root) {
		fail("directory")
	}
	peer_bin := fmt.aprintf("%s/peer", root)
	defer delete(peer_bin)
	fixture_bin := fmt.aprintf("%s/fixture", root)
	defer delete(fixture_bin)
	if !build(compiler, shared, "tests/support/client/peer", peer_bin, "") {
		fail("peer build")
	}
	if !build(compiler, shared, "tests/support/client", fixture_bin, sanitizer) {
		fail("fixture build")
	}
	transports := [?]string{"tcp", "tls"}
	modes := [?]string{"healthy", "fragmented", "progress"}
	for transport in transports {
		for mode in modes {
			client_cell(peer_bin, fixture_bin, root, transport, mode)
		}
	}
	text := "{\"passed\":true,\"cells\":6}\n"
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.println("6 client HTTP/1 reuse and progress cells passed")
}

client_session_abort :: proc(s: ^Session, reason: string) {
	session_cleanup(s)
	fmt.eprintf("client: %s %s: %s\n", s.transport, s.mode, reason)
	if len(s.fixture_err.buf) > 0 {
		fmt.eprintf("fixture: %s\n", clip(string(s.fixture_err.buf[:])))
	}
	if len(s.peer_err.buf) > 0 {
		fmt.eprintf("peer: %s\n", clip(string(s.peer_err.buf[:])))
	}
	_ = os.flush(os.stderr)
	os.exit(1)
}

client_cell :: proc(peer_bin, fixture_bin, root, transport, mode: string) {
	fmt.eprintf("client: %s %s\n", transport, mode)
	_ = os.flush(os.stderr)
	dir := fmt.aprintf("%s/%s-%s", root, transport, mode)
	defer delete(dir)
	s := Session {
		transport = transport,
		mode = mode,
		peer_out = {buf = make([dynamic]u8, 0, 4096)},
		peer_err = {buf = make([dynamic]u8, 0, 1024)},
		fixture_out = {buf = make([dynamic]u8, 0, 4096)},
		fixture_err = {buf = make([dynamic]u8, 0, 4096)},
	}
	defer delete(s.peer_out.buf)
	defer delete(s.peer_err.buf)
	defer delete(s.fixture_out.buf)
	defer delete(s.fixture_err.buf)
	defer session_cleanup(&s)

	pipe_err: os.Error
	s.out_r, s.out_w, pipe_err = os.pipe()
	if pipe_err != nil {
		client_session_abort(&s, "pipe")
	}
	s.err_r, s.err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		client_session_abort(&s, "pipe")
	}
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-mode", mode, "-dir", dir)
	if transport == "tls" {
		append(&command, "-tls")
	}
	start_error: os.Error
	s.peer, start_error = os.process_start(
		{command = command[:], stdout = s.out_w, stderr = s.err_w},
	)
	close_file(&s.out_w)
	close_file(&s.err_w)
	if start_error != nil {
		client_session_abort(&s, "peer start")
	}
	s.peer_live = true
	s.peer_out.file = s.out_r
	s.peer_err.file = s.err_r
	endpoint_buf: [128]u8
	endpoint_n := wait_line(
		s.peer,
		&s.peer_out,
		&s.peer_err,
		&s.peer_live,
		endpoint_buf[:],
		10 * time.Second,
	)
	if endpoint_n <= 0 {
		client_session_abort(&s, "readiness")
	}
	endpoint := string(endpoint_buf[:endpoint_n])
	if !strings.has_prefix(endpoint, "127.0.0.1:") {
		client_session_abort(&s, "endpoint")
	}

	s.fix_r, s.fix_w, pipe_err = os.pipe()
	if pipe_err != nil {
		client_session_abort(&s, "pipe")
	}
	s.fix_err_r, s.fix_err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		client_session_abort(&s, "pipe")
	}
	fixture_command := make([dynamic]string)
	defer delete(fixture_command)
	append(&fixture_command, fixture_bin, endpoint, mode, transport, dir)
	s.fixture, start_error = os.process_start(
		{command = fixture_command[:], stdout = s.fix_w, stderr = s.fix_err_w},
	)
	close_file(&s.fix_w)
	close_file(&s.fix_err_w)
	if start_error != nil {
		client_session_abort(&s, "fixture start")
	}
	s.fixture_live = true
	s.fixture_out.file = s.fix_r
	s.fixture_err.file = s.fix_err_r
	fixture_state, fixture_ok := wait_proc(
		s.fixture,
		&s.fixture_out,
		&s.fixture_err,
		&s.fixture_live,
		25 * time.Second,
	)
	if !fixture_ok || fixture_state.exit_code != 0 {
		client_session_abort(&s, "fixture")
	}
	peer_state, peer_ok := wait_proc(
		s.peer,
		&s.peer_out,
		&s.peer_err,
		&s.peer_live,
		8 * time.Second,
	)
	if !peer_ok || peer_state.exit_code != 0 {
		client_session_abort(&s, "peer")
	}
	native, native_ok := object(string(s.fixture_out.buf[:]))
	oracle, oracle_ok := object(string(s.peer_out.buf[:]))
	if !native_ok || !oracle_ok {
		client_session_abort(&s, "json")
	}
	client_check(native, oracle, transport == "tls", mode)
}

client_check :: proc(native, oracle: string, encrypted: bool, mode: string) {
	completed, completed_ok := field_int(native, "completed")
	want := 4 if mode == "progress" else 2
	if !completed_ok || completed != want {
		fail(fmt.tprintf("%s completed %d", mode, completed))
	}
	tls, tls_ok := field_bool(native, "tls")
	if !tls_ok || tls != encrypted {
		fail("native tls")
	}
	if mode == "progress" {
		workers, workers_ok := field_int(native, "workers")
		if !workers_ok || workers != 1 {
			fail("workers")
		}
		facts := [?]string {
			"held_body",
			"cheap_before_release",
			"waiting_expired",
			"waiting_cancelled",
			"heap_zero",
			"scope_zero",
			"fd_zero",
		}
		for fact in facts {
			if !field_true(native, fact) {
				fail(fact)
			}
		}
	} else {
		facts := [?]string {
			"old_cutoff_expired",
			"copied_input",
			"late_response",
			"heap_zero",
			"scope_zero",
			"fd_zero",
		}
		for fact in facts {
			if !field_true(native, fact) {
				fail(fact)
			}
		}
	}
	requests, requests_ok := field_int(oracle, "requests")
	if !requests_ok || requests != 2 {
		fail("peer requests")
	}
	alpn, alpn_ok := field_string(oracle, "alpn")
	want_alpn := "http/1.1" if encrypted else ""
	if !alpn_ok || alpn != want_alpn {
		fail("alpn")
	}
	peer_tls, peer_tls_ok := field_bool(oracle, "tls")
	if !peer_tls_ok || peer_tls != encrypted {
		fail("peer tls")
	}
	if mode == "progress" {
		named, named_ok := field_int(oracle, "named_requests")
		if !named_ok || named != 0 || !field_true(oracle, "cheap_before_release") {
			fail("progress oracle")
		}
		return
	}
	method, method_ok := field_string(oracle, "first_method")
	copied, copied_ok := field_string(oracle, "first_copy_header")
	body_n, body_ok := field_int(oracle, "first_body_bytes")
	if !method_ok ||
	   method != "POST" ||
	   !copied_ok ||
	   copied != "original" ||
	   !body_ok ||
	   body_n != 11 {
		fail("copied request")
	}
}

object :: proc(text: string) -> (string, bool) {
	start := -1
	for i := len(text) - 1; i >= 0; i -= 1 {
		if text[i] == '{' {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	for i in start ..< len(text) {
		if text[i] == '}' {
			return text[start:i + 1], true
		}
	}
	return "", false
}
