package tests

import "../../support/site"
import "core:testing"
import "core:time"
import "shared:surf"

h3_roots :: proc(t: ^testing.T) -> ^surf.Trust_Roots {
	return peer_roots(t, "tests/support/http3/localhost.pem")
}

@(test)
http3_cleartext_is_refused :: proc(t: ^testing.T) {
	response, error := surf.execute(
		{method = .GET, url = "http://127.0.0.1:9/saba"},
		{http3 = true, allow_http = true, timeout = 2 * time.Second},
	)
	surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Insecure_URL)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
http3_get_reaches_an_http3_peer :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	roots := h3_roots(t)

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	s := new(site.Site)
	defer free(s)

	if !testing.expect(t, site.start(s, {.HTTP1, .H2, .H3})) {
		return
	}
	defer site.stop(s)

	response, error := surf.execute(
		{method = .GET, url = site.url(s, "/protocol")},
		{http3 = true, tls = {roots = roots}, timeout = 8 * time.Second},
	)
	defer surf.response_destroy(&response)
	testing.expectf(t, error.kind == .None, "%v", error)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "HTTP/3")
	testing.expect_value(t, site.requests(s, .H3), 1)
	testing.expect_value(t, site.requests(s, .HTTP1) + site.requests(s, .H2), 0)
}

// Nothing answers HTTP/3 at the port, but TCP does. A GET falls back to TCP
// once; a POST is never sent again over TCP.
@(test)
http3_get_falls_back_to_tcp_once_and_post_is_not_replayed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	roots := h3_roots(t)

	if roots == nil {
		return
	}
	defer peer_roots_free(roots)

	s := new(site.Site)
	defer free(s)

	if !testing.expect(t, site.start(s, {.HTTP1, .H2})) {
		return
	}
	defer site.stop(s)

	config := surf.Config {
		http3 = true,
		tls = {roots = roots},
		timeout = 5 * time.Second,
	}
	response, error := surf.execute({method = .GET, url = site.url(s, "/protocol")}, config)
	testing.expectf(t, error.kind == .None, "%v", error)
	testing.expect_value(t, response.status, 200)
	testing.expect(t, string(response.body) == "HTTP/2" || string(response.body) == "HTTP/1.1")
	surf.response_destroy(&response)
	tcp := site.requests(s, .HTTP1) + site.requests(s, .H2)
	testing.expect_value(t, tcp, 1)
	posted, post_error := surf.execute(
		{method = .POST, url = site.url(s, "/echo"), body = transmute([]u8)string("once")},
		config,
	)
	surf.response_destroy(&posted)
	testing.expect(t, post_error.kind != .None)
	testing.expect(t, post_error.write_effect != .Response_Received)
	testing.expect_value(t, site.requests(s, .HTTP1) + site.requests(s, .H2), tcp)
}
