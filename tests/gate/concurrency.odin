// Public Client producer/consumer matrix. The peer is
// tests/support/concurrency/peer. TLS 1.3 is tests/support/loopback.
// Four cells: success and shutdown, each on TCP and TLS.

package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

run_concurrency :: proc() {
	gate_label = "concurrency"

	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-concurrency-%d", posix.getpid())
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
	if !build(compiler, shared, "tests/support/concurrency/peer", peer_bin, "") {
		fail("peer build")
	}
	if !build(compiler, shared, "tests/support/concurrency", fixture_bin, sanitizer) {
		fail("fixture build")
	}
	transports := [?]string{"tcp", "tls"}
	modes := [?]string{"success", "shutdown"}
	for transport in transports {
		for mode in modes {
			concurrency_cell(peer_bin, fixture_bin, root, transport, mode)
		}
	}
	text := "{\"passed\":true,\"cells\":4}\n"
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.println("4 client concurrency cells passed")
}

concurrency_session_abort :: proc(s: ^Session, reason: string) {
	session_cleanup(s)
	fmt.eprintf("concurrency: %s %s: %s\n", s.transport, s.mode, reason)
	if len(s.fixture_err.buf) > 0 {
		fmt.eprintf("fixture: %s\n", clip(string(s.fixture_err.buf[:])))
	}
	if len(s.peer_err.buf) > 0 {
		fmt.eprintf("peer: %s\n", clip(string(s.peer_err.buf[:])))
	}
	_ = os.flush(os.stderr)
	os.exit(1)
}

concurrency_cell :: proc(peer_bin, fixture_bin, root, transport, mode: string) {
	fmt.eprintf("concurrency: %s %s\n", transport, mode)
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
		concurrency_session_abort(&s, "pipe")
	}
	s.err_r, s.err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		concurrency_session_abort(&s, "pipe")
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
		concurrency_session_abort(&s, "peer start")
	}
	s.peer_live = true
	s.peer_out.file = s.out_r
	s.peer_err.file = s.err_r
	endpoint_buf: [128]u8
	endpoint_n := wait_line(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, endpoint_buf[:], 10 * time.Second)
	if endpoint_n <= 0 {
		concurrency_session_abort(&s, "readiness")
	}
	endpoint := string(endpoint_buf[:endpoint_n])
	if !strings.has_prefix(endpoint, "127.0.0.1:") {
		concurrency_session_abort(&s, "endpoint")
	}

	s.fix_r, s.fix_w, pipe_err = os.pipe()
	if pipe_err != nil {
		concurrency_session_abort(&s, "pipe")
	}
	s.fix_err_r, s.fix_err_w, pipe_err = os.pipe()
	if pipe_err != nil {
		concurrency_session_abort(&s, "pipe")
	}
	fixture_command := make([dynamic]string)
	defer delete(fixture_command)
	append(&fixture_command, fixture_bin, endpoint, mode, transport, dir)
	s.fixture, start_error = os.process_start({command = fixture_command[:], stdout = s.fix_w, stderr = s.fix_err_w})
	close_file(&s.fix_w)
	close_file(&s.fix_err_w)
	if start_error != nil {
		concurrency_session_abort(&s, "fixture start")
	}
	s.fixture_live = true
	s.fixture_out.file = s.fix_r
	s.fixture_err.file = s.fix_err_r
	fixture_state, fixture_ok := wait_proc(s.fixture, &s.fixture_out, &s.fixture_err, &s.fixture_live, 30 * time.Second)
	if !fixture_ok || fixture_state.exit_code != 0 {
		concurrency_session_abort(&s, "fixture")
	}
	peer_state, peer_ok := wait_proc(s.peer, &s.peer_out, &s.peer_err, &s.peer_live, 10 * time.Second)
	if !peer_ok || peer_state.exit_code != 0 {
		concurrency_session_abort(&s, "peer")
	}
	native_doc, native_ok := document(string(s.fixture_out.buf[:]))
	oracle_doc, oracle_ok := document(string(s.peer_out.buf[:]))
	if !native_ok || !oracle_ok {
		concurrency_session_abort(&s, "json")
	}
	concurrency_check(native_doc, oracle_doc, transport == "tls", mode)
}

Native_Record :: struct {
	id:         int,
	connection: int,
	kind:       string,
	phase:      string,
	effect:     string,
	status:     int,
	transport:  string,
}

Native :: struct {
	mode:                         string,
	tls:                          bool,
	workers:                      int,
	producer_threads:             int,
	consumer_threads:             int,
	accepted:                     int,
	completed:                    int,
	admission_rejections:         int,
	runtime_gone_before_results:  bool,
	late_response:                bool,
	heap_zero:                    bool,
	scope_zero:                   bool,
	fd_zero:                      bool,
	records:                      [dynamic]Native_Record,
}

concurrency_Wire :: struct {
	id:          int,
	connection:  int,
	method:      string,
	path:        string,
	body:        string,
	tls_version: int,
	alpn:        string,
}

Oracle :: struct {
	requests:    [dynamic]concurrency_Wire,
	connections: int,
	peak:        int,
	tls:         bool,
	mode:        string,
}

concurrency_check :: proc(native_doc, oracle_doc: string, encrypted: bool, mode: string) {
	native: Native
	if json.unmarshal_string(native_doc, &native) != nil {
		fail("native json")
	}
	defer release_native(&native)
	oracle: Oracle
	if json.unmarshal_string(oracle_doc, &oracle) != nil {
		fail("peer json")
	}
	defer release_oracle(&oracle)
	if native.mode != mode || oracle.mode != mode || native.tls != encrypted || oracle.tls != encrypted {
		fail("identity")
	}
	if native.workers != 1 || native.producer_threads != 4 || native.consumer_threads != 2 {
		fail("threads")
	}
	if !native.heap_zero || !native.scope_zero || !native.fd_zero {
		fail("cleanup")
	}
	if native.accepted != native.completed || native.accepted != len(native.records) {
		fail("terminals")
	}
	if oracle.connections < 1 || oracle.connections > 2 || oracle.peak < 1 || oracle.peak > 2 {
		fail("sockets")
	}
	native_seen: [64]bool
	for rec in native.records {
		if rec.id < 0 || rec.id >= 64 || native_seen[rec.id] {
			fail("native id")
		}
		native_seen[rec.id] = true
		if mode == "shutdown" {
			if rec.kind != "IO_Failed" || rec.phase != "Cancellation" {
				fail("cancellation")
			}
		}
	}
	wire_at: [64]int
	for i in 0 ..< 64 {
		wire_at[i] = -1
	}
	want_alpn := "http/1.1" if encrypted else ""
	want_version := 772 if encrypted else 0
	for row, index in oracle.requests {
		if row.id < 0 || row.id >= 64 || wire_at[row.id] >= 0 || !native_seen[row.id] {
			fail("wire id")
		}
		wire_at[row.id] = index
		path_buf: [32]u8
		body_buf: [16]u8
		path := fmt.bprintf(path_buf[:], "/work/%d", row.id)
		body := fmt.bprintf(body_buf[:], "%d", row.id)
		if row.method != "POST" || row.path != path || row.body != body {
			fail("request bytes")
		}
		if row.tls_version != want_version || row.alpn != want_alpn {
			fail("protocol")
		}
	}
	if mode == "success" {
		if len(native.records) != 64 || len(oracle.requests) != 64 || native.runtime_gone_before_results || !native.late_response {
			fail("success set")
		}
		for rec in native.records {
			row := oracle.requests[wire_at[rec.id]]
			if rec.kind != "None" || rec.connection != row.connection {
				fail("response identity")
			}
		}
		return
	}
	if mode != "shutdown" || len(native.records) < 1 || len(native.records) > 8 || len(oracle.requests) < 1 || !native.runtime_gone_before_results {
		fail("shutdown")
	}
}

release_native :: proc(native: ^Native) {
	delete(native.mode)
	for rec in native.records {
		delete(rec.kind)
		delete(rec.phase)
		delete(rec.effect)
		delete(rec.transport)
	}
	delete(native.records)
}

release_oracle :: proc(oracle: ^Oracle) {
	delete(oracle.mode)
	for row in oracle.requests {
		delete(row.method)
		delete(row.path)
		delete(row.body)
		delete(row.alpn)
	}
	delete(oracle.requests)
}
