package surf

import http "../http"
import "core:crypto/tls"
import x509 "core:crypto/x509"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

Http102_Log :: struct {
	mu:   sync.Mutex,
	text: [1 << 16]u8,
	n:    int,
	file: ^os.File,
}

Http102_Peer :: struct {
	process: os.Process,
	log:     Http102_Log,
	worker:  ^thread.Thread,
	port:    int,
	up:      bool,
}

Http102_Call :: struct {
	client:   ^HTTP_Client,
	url:      string,
	response: Response,
	error:    HTTP_Error,
}

@(test)
http2_alpn_maps_requests_onto_bounded_streams :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 180 * time.Second)
	peer := http102_start(t, "h2")

	if peer == nil {
		return
	}

	defer free(peer)
	defer http102_stop(peer)
	pool := http102_roots(t, "async/tests/connection/testdata/peer/credentials/root.pem")

	if pool == nil {
		return
	}

	defer free(pool)
	defer tls.root_pool_destroy(pool)
	offered := [?]string{"http/1.1", "h2"}
	echo_buf, blob_buf, again_buf: [96]u8
	echo_url := http102_url(echo_buf[:], peer.port, "/echo")
	blob_url := http102_url(blob_buf[:], peer.port, "/blob?n=70000")
	again_url := http102_url(again_buf[:], peer.port, "/again")
	cfg := http102_config(pool.roots[:pool.count], offered[:], 8 * time.Second)
	once, once_error := execute({method = .GET, url = echo_url}, cfg)
	testing.expect_value(t, once_error.kind, .None)
	testing.expect_value(t, once.status, 200)
	testing.expect(t, string(once.body) == "/echo")
	response_destroy(&once)

	if testing.failed(t) {
		return
	}

	client := http102_client(t, cfg, {})

	if client == nil {
		return
	}

	defer free(client)
	defer http_client_close(client)
	before_conn := http102_count(&peer.log, "\"event\":\"conn\"")
	requests := [2]http.Request{{method = .GET, url = echo_url}, {method = .GET, url = blob_url}}
	results: [2]HTTP_Result
	mux_error := http_client_multiplex(client, requests[:], results[:])
	testing.expect_value(t, mux_error.kind, .None)
	testing.expect_value(t, results[0].error.kind, .None)
	testing.expect_value(t, results[0].response.status, 200)
	testing.expect(t, string(results[0].response.body) == "/echo")
	testing.expect_value(t, results[1].error.kind, .None)
	testing.expect_value(t, results[1].response.status, 200)
	testing.expect(t, http102_body_is(results[1].response.body, 70000, 'a'))
	response_destroy(&results[0].response)
	response_destroy(&results[1].response)
	testing.expect_value(t, http_client_dials(client), 1)
	testing.expect_value(t, http102_count(&peer.log, "\"event\":\"conn\"") - before_conn, 1)
	again, again_error := http_client_exchange(client, {method = .GET, url = again_url})
	testing.expect_value(t, again_error.kind, .None)
	testing.expect(t, string(again.body) == "/again")
	response_destroy(&again)
	testing.expect_value(t, http_client_dials(client), 1)

	if testing.failed(t) {
		return
	}

	reset_buf, after_buf: [96]u8
	reset_url := http102_url(reset_buf[:], peer.port, "/reset")
	after_url := http102_url(after_buf[:], peer.port, "/after-reset")
	resets_before := http102_count(&peer.log, "\"path\":\"/reset\"")
	reset_response, reset_error := http_client_exchange(client, {method = .GET, url = reset_url})
	response_destroy(&reset_response)
	testing.expect(t, reset_error.kind != .None)
	testing.expect_value(t, reset_error.write_effect, .Unknown)
	after, after_error := http_client_exchange(client, {method = .GET, url = after_url})
	testing.expect_value(t, after_error.kind, .None)
	testing.expect(t, string(after.body) == "/after-reset")
	response_destroy(&after)
	testing.expect_value(t, http102_count(&peer.log, "\"path\":\"/reset\"") - resets_before, 1)

	if testing.failed(t) {
		return
	}

	stall := http102_client(t, http102_config(pool.roots[:pool.count], offered[:], 1500 * time.Millisecond), {})

	if stall == nil {
		return
	}

	defer free(stall)
	defer http_client_close(stall)
	stall_buf: [96]u8
	stall_url := http102_url(stall_buf[:], peer.port, "/stall")
	started := time.now()
	stall_response, stall_error := http_client_exchange(stall, {method = .GET, url = stall_url})
	elapsed := time.diff(started, time.now())
	response_destroy(&stall_response)
	testing.expect_value(t, stall_error.kind, .Deadline_Failed)
	testing.expect_value(t, stall_error.phase, .Deadline)
	testing.expect_value(t, stall_error.write_effect, .Unknown)
	testing.expect_value(t, http_client_dials(stall), 1)
	testing.expect(t, elapsed < 4 * time.Second)

	if testing.failed(t) {
		return
	}

	canceller := http102_client(t, http102_config(pool.roots[:pool.count], offered[:], 8 * time.Second), {})

	if canceller == nil {
		return
	}

	defer free(canceller)
	defer http_client_close(canceller)
	cancel_buf: [96]u8
	cancel_url := http102_url(cancel_buf[:], peer.port, "/cancel")
	seen := http102_count(&peer.log, "\"path\":\"/cancel\"")
	call := Http102_Call {
		client = canceller,
		url    = cancel_url,
	}

	worker := thread.create_and_start_with_poly_data(&call, http102_call)
	testing.expect(t, worker != nil)

	if worker == nil {
		return
	}

	cancel_started := time.now()
	armed := false

	for time.diff(time.now(), time.time_add(cancel_started, 5 * time.Second)) > 0 {
		if http102_count(&peer.log, "\"path\":\"/cancel\"") > seen {
			armed = true
			break
		}

		time.sleep(20 * time.Millisecond)
	}

	testing.expect(t, armed)
	http_client_cancel(canceller)
	thread.join(worker)
	thread.destroy(worker)
	response_destroy(&call.response)
	testing.expect_value(t, call.error.phase, .Cancellation)
	testing.expect_value(t, call.error.write_effect, .Unknown)
	testing.expect_value(t, http_client_dials(canceller), 1)
	testing.expect(t, time.diff(cancel_started, time.now()) < 4 * time.Second)

	if testing.failed(t) {
		return
	}

	limited := http102_client(t, cfg, {max_streams = 1})

	if limited == nil {
		return
	}

	defer free(limited)
	defer http_client_close(limited)
	a_buf, b_buf: [96]u8
	a_url := http102_url(a_buf[:], peer.port, "/limit-a")
	b_url := http102_url(b_buf[:], peer.port, "/limit-b")
	a_before := http102_count(&peer.log, "\"path\":\"/limit-a\"")
	b_before := http102_count(&peer.log, "\"path\":\"/limit-b\"")
	pair := [2]http.Request{{method = .GET, url = a_url}, {method = .GET, url = b_url}}
	pair_results: [2]HTTP_Result
	_ = http_client_multiplex(limited, pair[:], pair_results[:])
	admitted, refused := 0, 0

	for &result in pair_results {
		if result.error.kind == .None && result.response.status == 200 {
			admitted += 1
		} else if result.error.kind == .IO_Failed &&
		   result.error.phase == .Admission &&
		   result.error.write_effect == .Not_Sent {
			refused += 1
		}

		response_destroy(&result.response)
	}

	testing.expect_value(t, admitted, 1)
	testing.expect_value(t, refused, 1)
	testing.expect_value(t, http_client_dials(limited), 1)
	testing.expect_value(
		t,
		http102_count(&peer.log, "\"path\":\"/limit-a\"") -
		a_before +
		http102_count(&peer.log, "\"path\":\"/limit-b\"") -
		b_before,
		1,
	)

	if testing.failed(t) {
		return
	}

	capped := http102_client(t, cfg, {max_bytes = 64})

	if capped == nil {
		return
	}

	defer free(capped)
	defer http_client_close(capped)
	big_buf: [96]u8
	big_url := http102_url(big_buf[:], peer.port, "/blob?n=2000")
	big, big_error := http_client_exchange(capped, {method = .GET, url = big_url})
	response_destroy(&big)
	testing.expect_value(t, big_error.kind, .Body_Oversized)
	testing.expect_value(t, big_error.phase, .Body_Limit)
	testing.expect(t, len(big.body) == 0)
	testing.expect_value(t, http_client_dials(capped), 1)

	if testing.failed(t) {
		return
	}

	requests_before := http102_count(&peer.log, "\"event\":\"request\"")
	conns_before := http102_count(&peer.log, "\"event\":\"conn\"")
	bare := http102_client(t, http102_config(nil, offered[:], 3 * time.Second), {})

	if bare == nil {
		return
	}

	defer free(bare)
	defer http_client_close(bare)
	bare_response, bare_error := http_client_exchange(bare, {method = .GET, url = echo_url})
	response_destroy(&bare_response)
	testing.expect_value(t, bare_error.kind, .TLS_Failed)
	testing.expect_value(t, http_client_dials(bare), 0)
	testing.expect_value(t, http102_count(&peer.log, "\"event\":\"request\""), requests_before)
	testing.expect_value(t, http102_count(&peer.log, "\"event\":\"conn\""), conns_before)

	wrong := http102_roots(t, "async/tests/connection/testdata/client/wrong-root.pem")

	if wrong == nil {
		return
	}

	defer free(wrong)
	defer tls.root_pool_destroy(wrong)
	rejected := http102_client(t, http102_config(wrong.roots[:wrong.count], offered[:], 3 * time.Second), {})

	if rejected == nil {
		return
	}

	defer free(rejected)
	defer http_client_close(rejected)
	rejected_response, rejected_error := http_client_exchange(rejected, {method = .GET, url = echo_url})
	response_destroy(&rejected_response)
	testing.expect_value(t, rejected_error.kind, .TLS_Failed)
	testing.expect_value(t, rejected_error.write_effect, .Not_Sent)
	testing.expect_value(t, http_client_dials(rejected), 1)
	testing.expect_value(t, http102_count(&peer.log, "\"event\":\"request\""), requests_before)
}

@(test)
http2_peer_http1_selection_uses_http1_client :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 90 * time.Second)
	peer := http102_start(t, "http1")

	if peer == nil {
		return
	}

	defer free(peer)
	defer http102_stop(peer)
	pool := http102_roots(t, "async/tests/connection/testdata/peer/credentials/root.pem")

	if pool == nil {
		return
	}

	defer free(pool)
	defer tls.root_pool_destroy(pool)
	offered := [?]string{"http/1.1", "h2"}
	buf: [96]u8
	url := http102_url(buf[:], peer.port, "/plain")
	cfg := http102_config(pool.roots[:pool.count], offered[:], 8 * time.Second)
	once, once_error := execute({method = .GET, url = url}, cfg)
	testing.expect_value(t, once_error.kind, .None)
	testing.expect_value(t, once.status, 200)
	testing.expect(t, string(once.body) == "/plain")
	response_destroy(&once)
	client := http102_client(t, cfg, {})

	if client == nil {
		return
	}

	defer free(client)
	defer http_client_close(client)
	response, error := http_client_exchange(client, {method = .GET, url = url})
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, string(response.body) == "/plain")
	response_destroy(&response)
	testing.expect_value(t, http_client_dials(client), 1)
}

@(test)
http2_missing_alpn_stays_on_http1 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 90 * time.Second)
	peer := http102_start(t, "http1-noalpn")

	if peer == nil {
		return
	}

	defer free(peer)
	defer http102_stop(peer)
	pool := http102_roots(t, "async/tests/connection/testdata/peer/credentials/root.pem")

	if pool == nil {
		return
	}

	defer free(pool)
	defer tls.root_pool_destroy(pool)
	buf: [96]u8
	url := http102_url(buf[:], peer.port, "/plain")
	cfg := http102_config(pool.roots[:pool.count], nil, 8 * time.Second)
	response, error := execute({method = .GET, url = url}, cfg)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect(t, string(response.body) == "/plain")
	response_destroy(&response)
}

@(test)
http2_goaway_does_not_send_the_request :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 90 * time.Second)
	peer := http102_start(t, "goaway")

	if peer == nil {
		return
	}

	defer free(peer)
	defer http102_stop(peer)
	pool := http102_roots(t, "async/tests/connection/testdata/peer/credentials/root.pem")

	if pool == nil {
		return
	}

	defer free(pool)
	defer tls.root_pool_destroy(pool)
	offered := [?]string{"h2"}
	buf: [96]u8
	url := http102_url(buf[:], peer.port, "/echo")
	client := http102_client(t, http102_config(pool.roots[:pool.count], offered[:], 5 * time.Second), {})

	if client == nil {
		return
	}

	defer free(client)
	defer http_client_close(client)
	response, error := http_client_exchange(client, {method = .GET, url = url})
	response_destroy(&response)
	testing.expect_value(t, error.kind, .IO_Failed)
	testing.expect_value(t, error.phase, .Protocol)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, http_client_dials(client), 1)
	headers, ok := http102_wait_int(&peer.log, "\"headers\":", 5 * time.Second)
	testing.expect(t, ok)
	testing.expect_value(t, headers, 0)
}

http102_call :: proc(call: ^Http102_Call) {
	call.response, call.error = http_client_exchange(call.client, {method = .GET, url = call.url})
}

http102_config :: proc(roots: []^x509.Certificate, alpn: []string, timeout: time.Duration) -> Config {
	return {tls = {root_cas = roots, alpn_protocols = alpn}, timeout = timeout}
}

http102_client :: proc(t: ^testing.T, config: Config, limits: HTTP_Origin_Limits) -> ^HTTP_Client {
	client := new(HTTP_Client)
	error := http_client_init(client, config, limits, context.allocator)
	testing.expect_value(t, error.kind, .None)

	if error.kind != .None {
		http_client_close(client)
		free(client)
		return nil
	}

	return client
}

http102_roots :: proc(t: ^testing.T, path: string) -> ^tls.Root_Pool {
	pool := new(tls.Root_Pool)
	load_error := tls.root_pool_load_file(pool, path)
	testing.expect_value(t, load_error.kind, .None)

	if load_error.kind != .None {
		free(pool)
		return nil
	}

	return pool
}

http102_url :: proc(dst: []u8, port: int, path: string) -> string {
	n := copy(dst, "https://localhost:")
	port_text := strconv.write_int(dst[n:], i64(port), 10)
	n += len(port_text)
	n += copy(dst[n:], path)

	return string(dst[:n])
}

http102_body_is :: proc(body: []u8, n: int, value: u8) -> bool {
	if len(body) != n {
		return false
	}

	for octet in body {
		if octet != value {
			return false
		}
	}

	return true
}

http102_build :: proc(t: ^testing.T) -> bool {
	process, start_error := os.process_start(
		{
			command = {http102_go(), "build", "-o", "/tmp/okami-102-peer", "."},
			working_dir = "surf/tests/http102",
			stderr = os.stderr,
		},
	)
	testing.expect(t, start_error == nil)

	if start_error != nil {
		return false
	}

	state, wait_error := os.process_wait(process)
	testing.expect(t, wait_error == nil && state.exit_code == 0)

	return wait_error == nil && state.exit_code == 0
}

http102_go :: proc() -> string {
	if os.exists("/opt/homebrew/bin/go") {
		return "/opt/homebrew/bin/go"
	}

	return "/opt/homebrew/Cellar/go/1.26.2/bin/go"
}

http102_start :: proc(t: ^testing.T, mode: string) -> ^Http102_Peer {
	peer := new(Http102_Peer)
	read_end, write_end, pipe_error := os.pipe()
	testing.expect(t, pipe_error == nil)

	if pipe_error != nil {
		free(peer)
		return nil
	}

	if !http102_build(t) {
		os.close(read_end)
		os.close(write_end)
		free(peer)
		return nil
	}

	process, start_error := os.process_start(
		{
			command = {"/tmp/okami-102-peer", "-mode", mode},
			working_dir = "surf/tests/http102",
			stdout = write_end,
			stderr = os.stderr,
		},
	)
	os.close(write_end)
	testing.expect(t, start_error == nil)

	if start_error != nil {
		os.close(read_end)
		free(peer)
		return nil
	}

	peer.process = process
	peer.up = true
	peer.log.file = read_end
	peer.worker = thread.create_and_start_with_poly_data(&peer.log, http102_read_log)
	testing.expect(t, peer.worker != nil)

	if peer.worker == nil {
		http102_stop(peer)
		free(peer)
		return nil
	}

	port, ok := http102_wait_int(&peer.log, "\"port\":", 30 * time.Second)
	testing.expect(t, ok)

	if !ok || port <= 0 || port > 65535 {
		http102_stop(peer)
		free(peer)
		return nil
	}

	peer.port = port

	return peer
}

http102_stop :: proc(peer: ^Http102_Peer) {
	if peer == nil || !peer.up {
		return
	}

	_ = os.process_kill(peer.process)
	_, _ = os.process_wait(peer.process)
	peer.up = false

	if peer.worker != nil {
		thread.join(peer.worker)
		thread.destroy(peer.worker)
		peer.worker = nil
	}

	if peer.log.file != nil {
		os.close(peer.log.file)
		peer.log.file = nil
	}
}

http102_read_log :: proc(log: ^Http102_Log) {
	buf: [512]u8

	for {
		got, err := os.read(log.file, buf[:])

		if got > 0 {
			sync.lock(&log.mu)

			for octet in buf[:got] {
				if log.n < len(log.text) {
					log.text[log.n] = octet
					log.n += 1
				}
			}

			sync.unlock(&log.mu)
		}

		if err != nil || got == 0 {
			return
		}
	}
}

http102_count :: proc(log: ^Http102_Log, needle: string) -> int {
	sync.lock(&log.mu)
	defer sync.unlock(&log.mu)
	text := string(log.text[:log.n])
	count := 0
	from := 0

	for from < len(text) {
		at := strings.index(text[from:], needle)

		if at < 0 {
			break
		}

		count += 1
		from += at + len(needle)
	}

	return count
}

http102_wait_int :: proc(log: ^Http102_Log, key: string, budget: time.Duration) -> (int, bool) {
	deadline := time.time_add(time.now(), budget)

	for time.diff(time.now(), deadline) > 0 {
		value, ok := http102_find_int(log, key)

		if ok {
			return value, true
		}

		time.sleep(20 * time.Millisecond)
	}

	return http102_find_int(log, key)
}

http102_find_int :: proc(log: ^Http102_Log, key: string) -> (int, bool) {
	sync.lock(&log.mu)
	defer sync.unlock(&log.mu)
	text := string(log.text[:log.n])
	at := strings.last_index(text, key)

	if at < 0 {
		return 0, false
	}

	rest := text[at + len(key):]
	i := 0

	for i < len(rest) && (rest[i] == ' ' || rest[i] == '"') {
		i += 1
	}

	end := i

	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end += 1
	}

	if end == i {
		return 0, false
	}

	return strconv.parse_int(rest[i:end])
}
