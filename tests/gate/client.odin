// Public Client HTTP/1 matrix. The peer is tests/support/client/peer.
// TLS 1.3 is tests/support/loopback. Six cells: healthy, fragmented, and progress,
// each on TCP and TLS. The client20 procedures stay an odin test.

package main

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

client_UNIT_FILTER :: "-define:ODIN_TEST_NAMES=client20_atomic_group_rejection_leaves_no_registered_partial_client,client20_prestart_close_keeps_terminal_results_until_release,client20_results_survive_runtime_destroy_before_start_and_physical_header_free,client20_rejected_submit_preserves_source_and_foreign_handles_are_rejected,client20_malformed_descriptors_reject_without_allocation_or_source_mutation,client20_constructor_reentry_rejects_and_failed_registration_clears_before_final_free"

run_client :: proc() {
	gate_label = "client101"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-client101-%d", posix.getpid())
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
	if !client_units(compiler, shared, sanitizer) {
		fail("client20 tests")
	}
	text := "{{\"passed\":true,\"cells\":6,\"units\":6}}\n"
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.println("6 client HTTP/1 reuse and progress cells passed; 6 client20 tests passed")
}

client_session_abort :: proc(s: ^Session, reason: string) {
	session_cleanup(s)
	fmt.eprintf("client101: %s %s: %s\n", s.transport, s.mode, reason)
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
	fmt.eprintf("client101: %s %s\n", transport, mode)
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
	s.peer, start_error = os.process_start({command = command[:], stdout = s.out_w, stderr = s.err_w})
	close_file(&s.out_w)
	close_file(&s.err_w)
	if start_error != nil {
		client_session_abort(&s, "peer start")
	}
	s.peer_live = true
	s.peer_out.file = s.out_r
	s.peer_err.file = s.err_r
	endpoint_buf: [128]u8
	endpoint_n := wait_line(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, endpoint_buf[:], 10 * time.Second)
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
	s.fixture, start_error = os.process_start({command = fixture_command[:], stdout = s.fix_w, stderr = s.fix_err_w})
	close_file(&s.fix_w)
	close_file(&s.fix_err_w)
	if start_error != nil {
		client_session_abort(&s, "fixture start")
	}
	s.fixture_live = true
	s.fixture_out.file = s.fix_r
	s.fixture_err.file = s.fix_err_r
	fixture_state, fixture_ok := wait_proc(s.fixture, &s.fixture_out, &s.fixture_err, &s.fixture_live, 25 * time.Second)
	if !fixture_ok || fixture_state.exit_code != 0 {
		client_session_abort(&s, "fixture")
	}
	peer_state, peer_ok := wait_proc(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, 8 * time.Second)
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
		facts := [?]string{
			"held_body",
			"cheap_before_release",
			"bank_empty_expired",
			"bank_empty_cancelled",
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
		reuse, reuse_ok := field_int(native, "reuse_count")
		if !reuse_ok || reuse < 1 {
			fail("reuse")
		}
		facts := [?]string{
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
	if !method_ok || method != "POST" || !copied_ok || copied != "original" || !body_ok || body_n != 11 {
		fail("copied request")
	}
}

client_units :: proc(compiler, shared, sanitizer: string) -> bool {
	fmt.eprintf("client101: client20 tests\n")
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
	append(&command, "task", "test", "INTERNAL=1", "PACKAGE=async", "--", "-define:ODIN_TEST_THREADS=1", "-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true", client_UNIT_FILTER)
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
	finished := strings.contains(text, "Finished 6 tests") || strings.contains(diag, "Finished 6 tests")
	succeeded := strings.contains(text, "All tests were successful") || strings.contains(diag, "All tests were successful")
	missing := strings.contains(text, "No test found") || strings.contains(diag, "No test found") || strings.contains(text, "No tests to run") || strings.contains(diag, "No tests to run")
	if !ok || state.exit_code != 0 || !finished || !succeeded || missing {
		fmt.eprintf("client101 units: ok=%t exit=%d\n%s\n%s\n", ok, state.exit_code, clip(text), clip(diag))
		_ = os.flush(os.stderr)
		return false
	}
	return true
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

