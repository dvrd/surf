// Public exchange matrix. The peer is tests/support/exchange/peer.
// TLS 1.3 is tests/support/loopback. TCP covers six framing modes. TLS adds the
// two KeyUpdate modes. The exchange package tests stay an odin test.

package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

run_exchange :: proc() {
	gate_label = "exchange101"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-exchange101-%d", posix.getpid())
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
	if !build(compiler, shared, "tests/support/exchange/peer", peer_bin, "") {
		fail("peer build")
	}
	if !build(compiler, shared, "tests/support/exchange", fixture_bin, sanitizer) {
		fail("fixture build")
	}
	tcp_modes := [?]string{"healthy", "fragmented", "same-read", "separate", "partial", "close"}
	tls_modes := [?]string{"healthy", "fragmented", "same-read", "separate", "partial", "close", "keyupdate", "keyupdate-inline"}
	for mode in tcp_modes {
		exchange_cell(peer_bin, fixture_bin, root, "tcp", mode)
	}
	for mode in tls_modes {
		exchange_cell(peer_bin, fixture_bin, root, "tls", mode)
	}
	if !exchange_units(compiler, shared, sanitizer) {
		fail("exchange tests")
	}
	text := "{{\"passed\":true,\"cells\":14,\"units\":17}}\n"
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.println("14 exchange framing cells passed; 17 exchange tests passed")
}

exchange_session_abort :: proc(s: ^Session, reason: string) {
	session_cleanup(s)
	fmt.eprintf("exchange101: %s %s: %s\n", s.transport, s.mode, reason)
	if len(s.fixture_err.buf) > 0 {
		fmt.eprintf("fixture: %s\n", clip(string(s.fixture_err.buf[:])))
	}
	if len(s.peer_err.buf) > 0 {
		fmt.eprintf("peer: %s\n", clip(string(s.peer_err.buf[:])))
	}
	_ = os.flush(os.stderr)
	os.exit(1)
}

exchange_cell :: proc(peer_bin, fixture_bin, root, transport, mode: string) {
	fmt.eprintf("exchange101: %s %s\n", transport, mode)
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
		exchange_session_abort(&s, "pipe")
	}
	s.err_r, s.err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		exchange_session_abort(&s, "pipe")
	}
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-mode", mode, "-dir", dir)
	if transport == "tls" {
		append(&command, "-tls")
	}
	start_error: os.Error
	s.peer, start_error = os.process_start({command = command[:], stdout = s.out_w, stderr = s.err_w})
	close_file(&s.out_w)
	close_file(&s.err_w)
	if start_error != nil {
		exchange_session_abort(&s, "peer start")
	}
	s.peer_live = true
	s.peer_out.file = s.out_r
	s.peer_err.file = s.err_r
	endpoint_buf: [128]u8
	endpoint_n := wait_line(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, endpoint_buf[:], 10 * time.Second)
	if endpoint_n <= 0 {
		exchange_session_abort(&s, "readiness")
	}
	endpoint := string(endpoint_buf[:endpoint_n])
	if !strings.has_prefix(endpoint, "127.0.0.1:") {
		exchange_session_abort(&s, "endpoint")
	}

	s.fix_r, s.fix_w, pipe_err = os.pipe()
	if pipe_err != nil {
		exchange_session_abort(&s, "pipe")
	}
	s.fix_err_r, s.fix_err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		exchange_session_abort(&s, "pipe")
	}
	fixture_command := make([dynamic]string)
	defer delete(fixture_command)
	append(&fixture_command, fixture_bin, endpoint, mode, transport, dir)
	s.fixture, start_error = os.process_start({command = fixture_command[:], stdout = s.fix_w, stderr = s.fix_err_w})
	close_file(&s.fix_w)
	close_file(&s.fix_err_w)
	if start_error != nil {
		exchange_session_abort(&s, "fixture start")
	}
	s.fixture_live = true
	s.fixture_out.file = s.fix_r
	s.fixture_err.file = s.fix_err_r
	fixture_state, fixture_ok := wait_proc(s.fixture, &s.fixture_out, &s.fixture_err, &s.fixture_live, 25 * time.Second)
	if !fixture_ok || fixture_state.exit_code != 0 {
		exchange_session_abort(&s, "fixture")
	}
	peer_state, peer_ok := wait_proc(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, 8 * time.Second)
	if !peer_ok || peer_state.exit_code != 0 {
		exchange_session_abort(&s, "peer")
	}
	native, native_ok := document(string(s.fixture_out.buf[:]))
	oracle, oracle_ok := document(string(s.peer_out.buf[:]))
	if !strings.contains(string(s.fixture_out.buf[:]), "{\"heap_zero\":true}") {
		exchange_session_abort(&s, "heap")
	}
	if !native_ok || !oracle_ok {
		exchange_session_abort(&s, "json")
	}
	exchange_check(native, oracle, transport == "tls", mode)
}

exchange_check :: proc(native, oracle: string, encrypted: bool, mode: string) {
	completed, completed_ok := field_int(native, "completed")
	healthy := mode == "healthy" || mode == "fragmented" || mode == "keyupdate-inline"
	want := 2 if healthy else 1
	if !completed_ok || completed != want {
		fail(fmt.tprintf("%s completed %d", mode, completed))
	}
	tls, tls_ok := field_bool(native, "tls")
	if !tls_ok || tls != encrypted || !field_true(native, "old_cutoff_expired") {
		fail("native tls")
	}
	idle, idle_ok := field_string(native, "idle")
	probe, probe_ok := field_string(native, "probe")
	close_error, close_ok := field_string(native, "close_error")
	if !idle_ok || !probe_ok || !close_ok {
		fail("checkout")
	}
	if healthy {
		if idle != "Ready" || probe != "Empty" || close_error != "None" {
			fail("checkout")
		}
	} else if probe == "Empty" && idle == "Ready" {
		fail("contaminated checkout")
	}
	requests, requests_ok := field_int(oracle, "requests")
	if !requests_ok || requests != completed {
		fail("peer requests")
	}
	if mode != "keyupdate-inline" {
		return
	}
	updates, updates_ok := field_int(oracle, "key_updates")
	client_updates, client_ok := field_int(oracle, "client_key_updates")
	if !updates_ok || !client_ok || updates != 1 || client_updates != 1 || !strings.contains(oracle, "\"manual_sequences\":[0,0,1]") {
		fail("key update")
	}
}

exchange_units :: proc(compiler, shared, sanitizer: string) -> bool {
	fmt.eprintf("exchange101: exchange tests\n")
	_ = os.flush(os.stderr)
	base, env_error := os.environ(context.allocator)
	if env_error != nil {
		return false
	}
	env := make([dynamic]string, 0, len(base) + 2)
	defer {
		for item in env {
			delete(item)
		}
		delete(env)
	}
	for item in base {
		if strings.has_prefix(item, "ODIN=") || strings.has_prefix(item, "WEBTOOLS_SHARED=") {
			delete(item)
			continue
		}
		append(&env, item)
	}
	delete(base)
	append(&env, fmt.aprintf("ODIN=%s", compiler))
	append(&env, fmt.aprintf("WEBTOOLS_SHARED=%s", shared))
	command := make([dynamic]string)
	defer delete(command)
	append(&command, "task", "test", "INTERNAL=1", "PACKAGE=async/exchange", "--", "-define:ODIN_TEST_THREADS=1", "-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true")
	if sanitizer != "" && sanitizer != "none" {
		append(&command, fmt.aprintf("-sanitize:%s", sanitizer))
	}
	out := Capture{buf = make([dynamic]u8, 0, 8192)}
	err := Capture{buf = make([dynamic]u8, 0, 8192)}
	defer delete(out.buf)
	defer delete(err.buf)
	out_r, out_w, pipe_err := os.pipe()
	if pipe_err != nil {
		return false
	}
	defer os.close(out_r)
	err_r, err_w, pipe_err2 := os.pipe()
	if pipe_err2 != nil {
		os.close(out_w)
		return false
	}
	defer os.close(err_r)
	process, start_error := os.process_start({command = command[:], env = env[:], stdout = out_w, stderr = err_w})
	_ = os.close(out_w)
	_ = os.close(err_w)
	if start_error != nil {
		return false
	}
	out.file = out_r
	err.file = err_r
	live := true
	state, ok := wait_proc(process, &out, &err, &live, 300 * time.Second)
	text := string(out.buf[:])
	diag := string(err.buf[:])
	finished := strings.contains(text, "Finished 17 tests") || strings.contains(diag, "Finished 17 tests")
	succeeded := strings.contains(text, "All tests were successful") || strings.contains(diag, "All tests were successful")
	missing := strings.contains(text, "No test found") || strings.contains(diag, "No test found") || strings.contains(text, "No tests to run") || strings.contains(diag, "No tests to run")
	if !ok || state.exit_code != 0 || !finished || !succeeded || missing {
		fmt.eprintf("exchange101 units: ok=%t exit=%d\n%s\n%s\n", ok, state.exit_code, clip(text), clip(diag))
		_ = os.flush(os.stderr)
		return false
	}
	return true
}

