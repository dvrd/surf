package surf

import "core:strings"
import "core:testing"
import http "shared:async/http"

@(test)
buffered_http1_rejects_caller_framing :: proc(t: ^testing.T) {
	parsed, parse_error := http.url_parse("https://example.com/upload")
	testing.expect_value(t, parse_error.kind, .None)

	body := [4]u8{1, 2, 3, 4}
	dst: [1024]u8

	rejected := []string {
		"Transfer-Encoding: chunked",
		"Content-Length: 0",
		"Content-Length: 4",
		"Connection: keep-alive",
	}

	for line in rejected {
		headers := []string{line}
		n, error := buffered_http_encode(dst[:], "POST", parsed, body[:], headers[:], nil, 0)

		testing.expect_value(t, n, 0)
		testing.expect_value(t, error.kind, .Reserved_Header)
		testing.expect_value(t, error.phase, .Configuration)
		testing.expect_value(t, error.write_effect, .Not_Sent)
	}

	headers := []string{"X-Test: ok"}
	n, error := buffered_http_encode(dst[:], "POST", parsed, body[:], headers[:], nil, 0)
	testing.expect_value(t, error.kind, .None)
	encoded := string(dst[:n])

	testing.expect(t, strings.contains(encoded, "Content-Length: 4\r\n"))
	testing.expect(t, strings.contains(encoded, "Connection: close\r\n"))
	testing.expect(t, strings.contains(encoded, "X-Test: ok\r\n"))
	testing.expect(t, strings.count(encoded, "X-Test") == 1)

	host_headers := []string{"Host: bucket.example"}
	n, error = buffered_http_encode(dst[:], "POST", parsed, body[:], host_headers[:], nil, 0)
	testing.expect_value(t, error.kind, .None)
	encoded = string(dst[:n])

	testing.expect(t, strings.contains(encoded, "Host: bucket.example\r\n"))
	testing.expect(t, strings.count(encoded, "Host:") == 1)
}
