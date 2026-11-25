package surf

import http "shared:async/http"
import "core:testing"

@(test)
buffered_h2_preserves_application_headers_and_empty_conventions :: proc(t: ^testing.T) {
	storage: [8]http.Header
	fields, error := buffered_http_h2_headers(
		{
			"Authorization: Bearer fixture",
			"Cookie: session=fixture",
			"Content-Type: application/json",
			"X-Review: first",
			"X-Review: second",
			"X-Suppressed:",
			"X-Empty;",
		},
		storage[:],
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, len(fields), 6)

	if len(fields) != 6 {
		return
	}

	testing.expect_value(t, fields[0], http.Header{"Authorization", "Bearer fixture"})
	testing.expect_value(t, fields[1], http.Header{"Cookie", "session=fixture"})
	testing.expect_value(t, fields[2], http.Header{"Content-Type", "application/json"})
	testing.expect_value(t, fields[3], http.Header{"X-Review", "first"})
	testing.expect_value(t, fields[4], http.Header{"X-Review", "second"})
	testing.expect_value(t, fields[5], http.Header{"X-Empty", ""})
}

@(test)
buffered_h2_header_rejection_is_bounded_and_pre_send :: proc(t: ^testing.T) {
	storage: [1]http.Header

	for lines in ([][]string{{"Bad Name: value"}, {"X: value\r\nInjected: yes"}, {"X: one", "Y: two"}}) {
		fields, error := buffered_http_h2_headers(lines, storage[:])
		testing.expect(t, error.kind == .Invalid_Header || error.kind == .Header_Limit)
		testing.expect_value(t, error.write_effect, .Not_Sent)
		testing.expect_value(t, len(fields), 0)
	}
}

@(test)
buffered_h2_public_wire_preserves_authentication_headers :: proc(t: ^testing.T) {
	peer := http102_start(t, "h2")

	if peer == nil {
		return
	}

	defer free(peer)
	defer http102_stop(peer)
	url_buf: [96]u8
	url := http102_url(url_buf[:], peer.port, "/buffered-headers")
	data, result := buffered_http_execute(
		"POST",
		url,
		transmute([]u8)string("body-review"),
		{
			"Authorization: Bearer fixture",
			"Cookie: session=fixture",
			"Content-Type: application/json",
			"X-Review: first",
			"X-Review: second",
		},
		"tests/testdata/credentials/root.pem",
		timeout_ms = 5000,
	)
	testing.expect_value(t, result.error.kind, .None)
	testing.expect(t, result.transport_ok && result.status == 200)
	testing.expect_value(
		t,
		string(data),
		"HTTP/2.0|POST|Bearer fixture|session=fixture|application/json|first,second|body-review",
	)
}
