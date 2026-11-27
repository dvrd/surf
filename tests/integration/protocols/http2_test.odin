package tests

import "core:testing"
import "core:time"
import "shared:surf"

CONN_EVENT :: "\"event\":\"conn\""
REQUEST_EVENT :: "\"event\":\"request\""

h2_client :: proc(t: ^testing.T, c: ^surf.Client, roots: ^surf.Trust_Roots, timeout: time.Duration, limit := 0) -> bool {
	config := surf.Config {
		tls           = {roots = roots},
		timeout       = timeout,
		max_body_size = limit,
	}

	return testing.expect_value(t, surf.client_start(c, {http = config}).kind, .None)
}

h2_wait :: proc(c: ^surf.Client, handles: []surf.Request_Handle, errors: []surf.HTTP_Error, limit: time.Duration) -> bool {
	pending := len(handles)
	started := time.tick_now()

	for pending > 0 && time.tick_since(started) < limit {
		completion, done := surf.client_poll(c)

		if !done {
			time.sleep(2 * time.Millisecond)
			continue
		}

		for handle, i in handles {
			if handle == completion.request {
				errors[i] = completion.error
				pending -= 1
			}
		}
	}

	return pending == 0
}

body_is :: proc(body: []u8, n: int, value: u8) -> bool {
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

// ALPN picks h2; requests on one Client share one connection, including two
// in flight at once, a stream the server resets, and a failed body limit.
@(test)
http2_alpn_multiplexes_requests_on_one_connection :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	peer := peer_start(t, "h2")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	roots := peer_roots(t, "tests/support/credentials/root.pem")

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	once, once_error := surf.execute({method = .GET, url = peer_url(peer, "/echo")}, {tls = {roots = roots}, timeout = 8 * time.Second})
	testing.expect_value(t, once_error.kind, .None)
	testing.expect_value(t, once.status, 200)
	testing.expect_value(t, string(once.body), "/echo")
	surf.response_destroy(&once)
	testing.expect(t, peer_wait_count(peer, "\"alpn\":\"h2\"", 1, 5 * time.Second))
	c: surf.Client

	if !h2_client(t, &c, roots, 8 * time.Second) {
		return
	}
	defer surf.client_destroy(&c)

	conns := peer_count(peer, CONN_EVENT)
	echo, echo_submitted := surf.client_submit(&c, {method = .GET, url = peer_url(peer, "/echo")})
	blob, blob_submitted := surf.client_submit(&c, {method = .GET, url = peer_url(peer, "/blob?n=70000")})
	testing.expect_value(t, echo_submitted.kind, .None)
	testing.expect_value(t, blob_submitted.kind, .None)
	handles := [2]surf.Request_Handle{echo, blob}
	errors: [2]surf.HTTP_Error

	if !testing.expect(t, h2_wait(&c, handles[:], errors[:], 10 * time.Second), "both requests complete") {
		return
	}

	testing.expect_value(t, errors[0].kind, .None)
	testing.expect_value(t, errors[1].kind, .None)
	first, second: surf.Response
	testing.expect_value(t, surf.client_take(&c, echo, &first).kind, .None)
	testing.expect_value(t, surf.client_take(&c, blob, &second).kind, .None)
	testing.expect_value(t, string(first.body), "/echo")
	testing.expect(t, body_is(second.body, 70000, 'a'))
	surf.response_destroy(&first)
	surf.response_destroy(&second)
	_ = surf.client_release(&c, echo)
	_ = surf.client_release(&c, blob)
	again, again_error := surf.client_execute(&c, {method = .GET, url = peer_url(peer, "/again")})
	testing.expect_value(t, again_error.kind, .None)
	testing.expect_value(t, string(again.body), "/again")
	surf.response_destroy(&again)
	resets := peer_count(peer, "\"path\":\"/reset\"")
	reset, reset_error := surf.client_execute(&c, {method = .GET, url = peer_url(peer, "/reset")})
	surf.response_destroy(&reset)
	testing.expect(t, reset_error.kind != .None)
	testing.expect_value(t, reset_error.write_effect, .Unknown)
	testing.expect_value(t, peer_count(peer, "\"path\":\"/reset\"") - resets, 1)
	after, after_error := surf.client_execute(&c, {method = .GET, url = peer_url(peer, "/after-reset")})
	testing.expect_value(t, after_error.kind, .None)
	testing.expect_value(t, string(after.body), "/after-reset")
	surf.response_destroy(&after)
	testing.expect(t, peer_wait_count(peer, CONN_EVENT, conns + 1, 5 * time.Second))
	testing.expect_value(t, peer_count(peer, CONN_EVENT) - conns, 1)
}

@(test)
http2_deadline_cancellation_and_body_limit_keep_their_phases :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	peer := peer_start(t, "h2")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	roots := peer_roots(t, "tests/support/credentials/root.pem")

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	stall: surf.Client

	if !h2_client(t, &stall, roots, 1500 * time.Millisecond) {
		return
	}

	started := time.tick_now()
	stalled, stall_error := surf.client_execute(&stall, {method = .GET, url = peer_url(peer, "/stall")})
	elapsed := time.tick_since(started)
	surf.response_destroy(&stalled)
	testing.expect_value(t, stall_error.kind, .Deadline_Failed)
	testing.expect_value(t, stall_error.phase, .Deadline)
	testing.expect_value(t, stall_error.write_effect, .Unknown)
	testing.expect(t, elapsed < 4 * time.Second)
	_ = surf.client_destroy(&stall)
	canceller: surf.Client

	if !h2_client(t, &canceller, roots, 8 * time.Second) {
		return
	}
	defer surf.client_destroy(&canceller)

	seen := peer_count(peer, "\"path\":\"/cancel\"")
	handle, submitted := surf.client_submit(&canceller, {method = .GET, url = peer_url(peer, "/cancel")})

	if !testing.expect_value(t, submitted.kind, .None) {
		return
	}

	testing.expect(t, peer_wait_count(peer, "\"path\":\"/cancel\"", seen + 1, 5 * time.Second))
	cancel_started := time.tick_now()
	testing.expect_value(t, surf.client_cancel(&canceller, handle).kind, .None)
	handles := [1]surf.Request_Handle{handle}
	errors: [1]surf.HTTP_Error
	testing.expect(t, h2_wait(&canceller, handles[:], errors[:], 5 * time.Second))
	testing.expect_value(t, errors[0].phase, .Cancellation)
	testing.expect_value(t, errors[0].write_effect, .Unknown)
	testing.expect(t, time.tick_since(cancel_started) < 4 * time.Second)
	_ = surf.client_release(&canceller, handle)
	capped: surf.Client

	if !h2_client(t, &capped, roots, 8 * time.Second, 64) {
		return
	}
	defer surf.client_destroy(&capped)

	big, big_error := surf.client_execute(&capped, {method = .GET, url = peer_url(peer, "/blob?n=2000")})
	testing.expect_value(t, big_error.kind, .Body_Oversized)
	testing.expect_value(t, big_error.phase, .Body_Limit)
	testing.expect_value(t, len(big.body), 0)
	surf.response_destroy(&big)
}

// A certificate the roots do not trust fails the handshake: no request
// reaches the peer.
@(test)
http2_untrusted_certificate_is_refused_before_any_request :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	peer := peer_start(t, "h2")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	wrong := peer_roots(t, "tests/support/credentials/wrong-root.pem")

	if wrong == nil {
		return
	}
	defer peer_roots_free(wrong)

	for roots in ([]^surf.Trust_Roots{wrong, nil}) {
		response, error := surf.execute(
			{method = .GET, url = peer_url(peer, "/echo")},
			{tls = {roots = roots}, timeout = 3 * time.Second},
		)
		surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .TLS_Failed)
		testing.expect_value(t, error.phase, .TLS)
		testing.expect_value(t, error.write_effect, .Not_Sent)
		testing.expect(t, error.tls_error != nil)
	}

	testing.expect_value(t, peer_count(peer, REQUEST_EVENT), 0)
	testing.expect_value(t, peer_count(peer, CONN_EVENT), 0)
}

@(test)
http2_peer_selecting_http1_is_spoken_over_http1 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	peer := peer_start(t, "http1")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	roots := peer_roots(t, "tests/support/credentials/root.pem")

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	once, once_error := surf.execute({method = .GET, url = peer_url(peer, "/plain")}, {tls = {roots = roots}, timeout = 8 * time.Second})
	testing.expect_value(t, once_error.kind, .None)
	testing.expect_value(t, once.status, 200)
	testing.expect_value(t, string(once.body), "/plain")
	surf.response_destroy(&once)
	c: surf.Client

	if !h2_client(t, &c, roots, 8 * time.Second) {
		return
	}
	defer surf.client_destroy(&c)

	testing.expect(t, peer_wait_count(peer, CONN_EVENT, 1, 5 * time.Second))
	conns := peer_count(peer, CONN_EVENT)

	for _ in 0 ..< 2 {
		response, error := surf.client_execute(&c, {method = .GET, url = peer_url(peer, "/plain")})
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, string(response.body), "/plain")
		surf.response_destroy(&response)
	}

	testing.expect(t, peer_wait_count(peer, CONN_EVENT, conns + 1, 5 * time.Second))
	testing.expect_value(t, peer_count(peer, CONN_EVENT) - conns, 1)
	testing.expect(t, peer_wait_count(peer, "\"alpn\":\"http/1.1\"", 2, 5 * time.Second))
}

@(test)
http2_missing_alpn_stays_on_http1 :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	peer := peer_start(t, "http1-noalpn")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	roots := peer_roots(t, "tests/support/credentials/root.pem")

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	response, error := surf.execute({method = .GET, url = peer_url(peer, "/plain")}, {tls = {roots = roots}, timeout = 8 * time.Second})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "/plain")
	surf.response_destroy(&response)
	testing.expect(t, peer_wait_count(peer, "\"alpn\":\"\"", 1, 5 * time.Second))
}

// GOAWAY with last-stream 0 right after the preface: the server says it
// processed nothing, so the request is reported as not sent. The client may
// already have sent its HEADERS before the GOAWAY arrived, but never again.
@(test)
http2_goaway_does_not_send_the_request :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	peer := peer_start(t, "goaway")

	if peer == nil {
		return
	}
	defer peer_stop(peer)

	roots := peer_roots(t, "tests/support/credentials/root.pem")

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	c: surf.Client

	if !h2_client(t, &c, roots, 5 * time.Second) {
		return
	}
	defer surf.client_destroy(&c)

	response, error := surf.client_execute(&c, {method = .GET, url = peer_url(peer, "/echo")})
	surf.response_destroy(&response)
	testing.expectf(t, error.kind != .None, "%v", error)
	testing.expectf(t, error.write_effect == .Not_Sent, "%v", error)
	headers, ok := peer_wait_int(peer, "\"headers\":", 5 * time.Second)
	testing.expect(t, ok)
	testing.expect(t, headers <= 1)
	testing.expect_value(t, peer_count(peer, CONN_EVENT), 1)
}
