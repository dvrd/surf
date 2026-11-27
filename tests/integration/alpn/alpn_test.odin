package tests

import "../../support/loopback"
import "../../support/site"
import "core:fmt"
import "core:io"
import "core:strings"
import "core:testing"
import "core:time"
import "shared:async"
import "shared:surf"

// Local stand-in so this suite does not share the upload suite's package.
Upload_Producer :: struct {
	bytes:         []u8,
	reads, closes: int,
}

upload_producer :: proc(
	data: rawptr,
	mode: io.Stream_Mode,
	dst: []u8,
	_: i64,
	_: io.Seek_From,
) -> (
	i64,
	io.Error,
) {
	state := cast(^Upload_Producer)data
	#partial switch mode {
	case .Query:
		return io.query_utility({.Read, .Close})
	case .Close:
		state.closes += 1
		return 0, {}
	case .Read:
		state.reads += 1
		n := copy(dst, state.bytes)
		state.bytes = state.bytes[n:]
		if n == 0 {
			return 0, .EOF
		}

		return i64(n), {}
	}

	return 0, .Unsupported
}

alpn_roots :: proc(t: ^testing.T, roots: ^surf.Trust_Roots) -> bool {
	return testing.expect_value(t, surf.trust_roots_load_file(roots, "tests/support/http3/localhost.pem"), surf.Trust_Roots_Error.None)
}

// Over TLS the client offers h2 and http/1.1 and speaks whichever the server
// selected.
@(test)
alpn_tls_speaks_the_protocol_the_server_selects :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	roots: surf.Trust_Roots
	defer surf.trust_roots_destroy(&roots)

	if !alpn_roots(t, &roots) {
		return
	}

	for sample in ([]struct {
			protocols: bit_set[async.Protocol],
			expected:  string,
		} {
			{{.HTTP1}, "HTTP/1.1"},
			{{.H2}, "HTTP/2"},
			{{.HTTP1, .H2}, "HTTP/2"},
		}) {
		s := new(site.Site)
		defer free(s)

		if !testing.expect(t, site.start(s, sample.protocols)) {
			return
		}

		response, error := surf.execute(
			{method = .GET, url = site.url(s, "/protocol")},
			{tls = {roots = &roots}, timeout = 5 * time.Second},
		)
		testing.expectf(t, error.kind == .None, "%v: %v", sample.protocols, error)
		testing.expect_value(t, response.status, 200)
		testing.expect_value(t, string(response.body), sample.expected)
		surf.response_destroy(&response)
		site.stop(s)
	}
}

// Cleartext is HTTP/1.1 from the first byte: no h2c upgrade and no prior
// knowledge preface.
@(test)
alpn_cleartext_is_http1 :: proc(t: ^testing.T) {
	peer := loopback.Server {
		answer = {wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
	}

	if !testing.expect(t, loopback.server_start(&peer)) {
		return
	}
	defer loopback.server_stop(&peer)

	response, error := surf.execute(
		{method = .GET, url = fmt.tprintf("http://127.0.0.1:%d/plain", peer.port)},
		{allow_http = true, timeout = 3 * time.Second},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	request := loopback.server_last(&peer, context.temp_allocator)
	testing.expect(t, strings.has_prefix(request, "GET /plain HTTP/1.1\r\n"))
	_, upgrade := loopback.header_value(request, "Upgrade")
	_, settings := loopback.header_value(request, "HTTP2-Settings")
	testing.expect(t, !upgrade && !settings)
}

@(test)
alpn_http3_over_cleartext_is_refused_before_reading_upload_source :: proc(t: ^testing.T) {
	producer := Upload_Producer {
		bytes = {1},
	}

	response, error := surf.execute_upload(
		{method = .POST, url = "http://127.0.0.1:1/"},
		{stream = {procedure = upload_producer, data = &producer}, content_length = 1},
		{allow_http = true, http3 = true},
	)
	surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Insecure_URL)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, producer.reads, 0)
	testing.expect_value(t, producer.closes, 0)
}
