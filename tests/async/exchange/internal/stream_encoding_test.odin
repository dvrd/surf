package surf_exchange

import channel "../stream"
import h1 "../../../http/v1"
import "core:testing"

@(test)
stream_content_coding_uses_http_whitespace :: proc(t: ^testing.T) {
	for wire in ([]string {
			"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Encoding: \u00a0gzip\u00a0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Encoding: \u2003gzip\r\n\r\n",
		}) {
		head, _, parse := h1.response_header_decode(transmute([]u8)wire)
		testing.expect_value(t, parse.kind, .None)
		cell := channel.Channel {
			options = {decoding = .Gzip},
		}
		x := Stream_Exchange {
			channel = &cell,
		}
		x.base._head = head
		x.base._response.headers = head.headers[:head.header_count]
		error := stream_encoding(&x)
		testing.expect_value(t, error.kind, .Unsupported_Content_Encoding)
		testing.expect(t, !x.decoded)
	}

	cell := channel.Channel {
		options = {decoding = .Gzip, max_encoded_bytes = 100, max_decoded_bytes = 100},
	}

	x := Stream_Exchange {
		channel = &cell,
	}

	x.base._head.framing = .Length
	x.base._response.headers = {{"Content-Encoding", "\tGZip \t"}}
	testing.expect_value(t, stream_encoding(&x).kind, .None)
	testing.expect(t, x.decoded)
}
