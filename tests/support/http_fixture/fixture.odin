package http_fixture

import "core:net"

// Shared stand-in for a public HTTP exchange. The integration suites that
// drive surf.exchange through a net.Connection use this one connection.
Fixture :: struct {
	wire:                string,
	at:                  int,
	reads_after_headers: int,
	written:             [32768]u8,
	written_count:       int,
}

read :: proc(data: rawptr, dst: []u8) -> (int, net.Network_Error) {
	fixture := cast(^Fixture)data

	if fixture.at == len(fixture.wire) {
		fixture.reads_after_headers += 1
		return 0, net.Connection_Error.Peer_Closed
	}

	n := copy(dst, fixture.wire[fixture.at:])
	fixture.at += n

	return n, nil
}

write :: proc(data: rawptr, src: []u8) -> (int, net.Network_Error) {
	fixture := cast(^Fixture)data
	n := copy(fixture.written[fixture.written_count:], src)
	fixture.written_count += n

	return n, nil
}

close :: proc(data: rawptr) -> net.Network_Error {
	return nil
}
