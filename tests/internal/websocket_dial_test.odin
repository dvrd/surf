package surf

import "core:net"
import "core:testing"
import "core:time"

@(test)
websocket_dial_returns_within_handshake_timeout :: proc(t: ^testing.T) {
	conn := new(WebSocket_Conn)
	defer free(conn)

	servers := [1]net.Endpoint {
		{address = net.IP4_Address{203, 0, 113, 1}, port = 53},
	}
	started := time.now()
	error := websocket_dial(
		conn,
		"blackhole.invalid",
		9,
		{handshake_timeout = 300 * time.Millisecond},
		{},
		{resolver = {name_servers = servers[:]}},
	)
	elapsed := time.diff(started, time.now())

	testing.expect(t, error.kind != .None)
	testing.expect(t, elapsed < 2 * time.Second)
	testing.expect(t, conn.phase != .Open)
}

@(test)
websocket_dial_network_returns_the_transport_error :: proc(t: ^testing.T) {
	conn: WebSocket_Conn
	resolve_error := net.Network_Error(net.Resolve_Error.Unable_To_Resolve)
	dialed := websocket_dial_network(&conn, resolve_error)

	testing.expect_value(t, dialed.kind, .Network_Failed)
	testing.expect(t, dialed.tls == nil)
	testing.expect(t, dialed.transport == resolve_error)
	testing.expect(t, conn.last_error.stream.transport == resolve_error)

	timeout := net.Network_Error(net.Dial_Error.Timeout)
	timed := websocket_dial_network(&conn, timeout)

	testing.expect_value(t, timed.kind, .Network_Failed)
	testing.expect(t, timed.tls == nil)
	testing.expect(t, timed.transport == timeout)
	testing.expect(t, conn.last_error.stream.transport == timeout)
}
