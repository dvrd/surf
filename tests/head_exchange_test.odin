package tests

import surf ".."
import http "../../http"
import "core:net"
import "core:strings"
import "core:testing"

Fixture :: struct {
	wire: string,
	at: int,
	reads_after_headers: int,
	written: [32768]u8,
	written_count: int,
}
read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	fixture := cast(^Fixture)data
	if fixture.at == len(fixture.wire) {
		fixture.reads_after_headers += 1
		return 0, {kind = .Peer_Closed}
	}
	n := copy(dst, fixture.wire[fixture.at:])
	fixture.at += n
	return n, {}
}
write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	fixture := cast(^Fixture)data
	n := copy(fixture.written[fixture.written_count:], src)
	fixture.written_count += n
	return n, {}
}
close :: proc(data: rawptr) -> net.Connection_Error {return {}}

@(test)
head_exchange_never_waits_for_representation_body :: proc(t: ^testing.T) {
	for wire in ([]string{
		"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\n",
	}) {
		fixture := Fixture{wire = wire}
		stream := net.Connection{data = &fixture, read = read, write = write, close = close}
		response, error := surf.exchange(stream, {method = .HEAD, url = "https://example.com/"}, 8)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, response.status, 200)
		testing.expect_value(t, len(response.body), 0)
		testing.expect_value(t, fixture.reads_after_headers, 0)
		testing.expect(t, strings.has_prefix(string(fixture.written[:fixture.written_count]), "HEAD / HTTP/1.1\r\n"))
	}
}

@(test)
status_without_body_and_ordinary_body_use_actual_exchange :: proc(t: ^testing.T) {
	for sample in ([]struct{wire: string, status: int, body: string}{
		{"HTTP/1.1 204 No Content\r\n\r\n", 204, ""},
		{"HTTP/1.1 304 Not Modified\r\nContent-Length: 999999999999\r\n\r\n", 304, ""},
		{"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", 200, "body"},
	}) {
		fixture := Fixture{wire = sample.wire}
		stream := net.Connection{data = &fixture, read = read, write = write, close = close}
		response, error := surf.exchange(stream, {method = .GET, url = "https://example.com/"}, 8)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, response.status, sample.status)
		testing.expect_value(t, string(response.body), sample.body)
		testing.expect_value(t, fixture.reads_after_headers, 0)
	}
}
