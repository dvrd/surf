package tests

import "../../support/loopback"
import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"
import "shared:surf"

// The peer never closes and never sends more than the wire: a client that
// waited for a body it should not read would run into the 3s deadline.
framing_fetch :: proc(
	t: ^testing.T,
	method: surf.Method,
	wire: string,
	limit: int,
) -> (
	response: surf.Response,
	error: surf.HTTP_Error,
	request: string,
	elapsed: time.Duration,
) {
	peer := loopback.Server {
		answer = {wire = wire},
	}

	if !testing.expect(t, loopback.server_start(&peer)) {
		return
	}
	defer loopback.server_stop(&peer)

	url := fmt.tprintf("http://127.0.0.1:%d/", peer.port)
	started := time.tick_now()
	response, error = surf.execute(
		{method = method, url = url},
		{allow_http = true, max_body_size = limit, timeout = 3 * time.Second},
	)
	elapsed = time.tick_since(started)
	request = loopback.server_last(&peer, context.temp_allocator)

	return
}

@(test)
head_never_waits_for_representation_body :: proc(t: ^testing.T) {
	for wire in ([]string {
			"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n",
		}) {
		response, error, request, elapsed := framing_fetch(t, .HEAD, wire, 8)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, response.status, 200)
		testing.expect_value(t, len(response.body), 0)
		testing.expect(t, elapsed < 2 * time.Second)
		testing.expect(t, strings.has_prefix(request, "HEAD / HTTP/1.1\r\n"))
	}
}

@(test)
status_without_body_and_ordinary_body_frame_by_status_and_length :: proc(t: ^testing.T) {
	for sample in ([]struct {
			wire:   string,
			status: int,
			body:   string,
		} {
			{"HTTP/1.1 204 No Content\r\n\r\n", 204, ""},
			{"HTTP/1.1 304 Not Modified\r\nContent-Length: 999999999999\r\n\r\n", 304, ""},
			{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", 200, "body"},
		}) {
		response, error, request, elapsed := framing_fetch(t, .GET, sample.wire, 8)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, response.status, sample.status)
		testing.expect_value(t, string(response.body), sample.body)
		testing.expect(t, elapsed < 2 * time.Second)
		testing.expect(t, strings.has_prefix(request, "GET / HTTP/1.1\r\n"))
	}
}

// Larger than one task turn reads (CLIENT_BODY_STEP_LIMIT reads of
// CLIENT_READ_BYTES): the client must resume by itself and deliver every byte.
@(test)
buffered_body_larger_than_one_turn_arrives_whole :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	size :: 3 * surf.CLIENT_BODY_STEP_LIMIT * surf.CLIENT_READ_BYTES + 12345
	wire: strings.Builder
	strings.builder_init(&wire)
	defer strings.builder_destroy(&wire)
	fmt.sbprintf(&wire, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)

	for index in 0 ..< size {
		strings.write_byte(&wire, u8(index * 31 + index >> 9))
	}

	response, error, _, _ := framing_fetch(t, .GET, strings.to_string(wire), size)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)

	if !testing.expect_value(t, len(response.body), size) {
		return
	}

	intact := true

	for value, index in response.body {
		if value != u8(index * 31 + index >> 9) {
			intact = false
			break
		}
	}

	testing.expect(t, intact)
}
