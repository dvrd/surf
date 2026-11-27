package tests

import "../../support/loopback"
import "core:bytes"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "shared:async/tls"

// The test TLS server checked against async's blocking client, an independent
// TLS 1.3 implementation. The gates trust this server to speak correct TLS
// while it writes records by hand, so its handshake, record layer, KeyUpdate
// and close_notify are pinned here.

CREDENTIALS :: "tests/support/credentials"
PEER_TIMEOUT :: 5 * time.Second
ECHO_BYTES :: 40_000

// The server's identity is package state in loopback: one test at a time.
identity_lock: sync.Mutex

Script :: enum {
	Handshake,
	Echo,
	Key_Update,
	Close_Notify,
}

// One TLS connection served on its own thread. The test reads every field
// after peer_stop has joined that thread.
Peer :: struct {
	mode:       loopback.Mode,
	script:     Script,
	listener:   net.TCP_Socket,
	port:       int,
	worker:     ^thread.Thread,
	accepted:   bool,
	conn:       loopback.Conn,
	handshaken: bool,
	served:     bool,
	received:   [dynamic]u8,
}

peer_start :: proc(peer: ^Peer) -> bool {
	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		return false
	}

	endpoint, bound_error := net.bound_endpoint(listener)
	if bound_error != nil {
		net.close(listener)
		return false
	}

	peer.listener = listener
	peer.port = endpoint.port
	peer.worker = thread.create_and_start_with_poly_data(peer, peer_serve)

	if peer.worker == nil {
		net.close(listener)
		return false
	}

	return true
}

peer_stop :: proc(peer: ^Peer) {
	if peer.worker == nil {
		return
	}

	// accept(2) is not woken by a close from another thread on every platform.
	if !sync.atomic_load(&peer.accepted) {
		if wake, e := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = peer.port}); e == nil {
			net.close(wake)
		}
	}

	thread.join(peer.worker)
	thread.destroy(peer.worker)
	peer.worker = nil
	net.close(peer.listener)
}

peer_destroy :: proc(peer: ^Peer) {
	peer_stop(peer)
	delete(peer.received)
	loopback.conn_wipe(&peer.conn)
	free(peer)
}

peer_serve :: proc(peer: ^Peer) {
	socket, _, accept_error := net.accept_tcp(peer.listener)
	sync.atomic_store(&peer.accepted, true)

	if accept_error != nil {
		return
	}
	defer net.close(socket)

	conn := &peer.conn
	conn.fd = socket
	loopback.set_recv_timeout(socket, PEER_TIMEOUT)
	peer.handshaken = loopback.handshake(conn, peer.mode)

	if !peer.handshaken {
		return
	}

	loopback.set_recv_timeout(socket, PEER_TIMEOUT)

	switch peer.script {
	case .Handshake:
		peer.served = true
	case .Echo:
		peer.served = peer_read(peer, ECHO_BYTES) && loopback.tls_write(conn, peer.received[:])
	case .Key_Update:
		peer.served = loopback.server_key_update(conn) && loopback.tls_write(conn, transmute([]u8)string("rotated")) && peer_read(peer, len("ack"))
	case .Close_Notify:
		notify := [2]u8{1, 0}
		peer.served = loopback.tls_write(conn, transmute([]u8)string("bye")) && loopback.seal(conn, 21, notify[:])
	}

	// Read until the client closes, so nothing it sent is left unread and the
	// close is a FIN, not a reset that could drop what the client has not read.
	scratch: [1024]u8

	for {
		if _, status := loopback.tls_read(conn, scratch[:]); status != .Ok {
			break
		}
	}
}

peer_read :: proc(peer: ^Peer, count: int) -> bool {
	scratch: [16 * 1024]u8

	for len(peer.received) < count {
		n, status := loopback.tls_read(&peer.conn, scratch[:min(len(scratch), count - len(peer.received))])

		if status != .Ok {
			return false
		}

		append(&peer.received, ..scratch[:n])
	}

	return true
}

roots_load :: proc(t: ^testing.T, path: string) -> ^tls.Root_Pool {
	pool := new(tls.Root_Pool)

	if error := tls.root_pool_load_file(pool, path); !testing.expectf(t, error == nil, "roots %s: %v", path, error) {
		free(pool)
		return nil
	}

	return pool
}

roots_destroy :: proc(pool: ^tls.Root_Pool) {
	tls.root_pool_destroy(pool)
	free(pool)
}

client_dial :: proc(client: ^tls.Conn, peer: ^Peer, roots: ^tls.Root_Pool, alpn: []string) -> tls.Error {
	return tls.dial(
		client,
		"127.0.0.1",
		peer.port,
		{
			server_name = "localhost",
			root_cas = roots.roots[:roots.count],
			alpn_protocols = alpn,
			handshake_timeout = PEER_TIMEOUT,
			no_system_roots = true,
		},
	)
}

client_read :: proc(client: ^tls.Conn, dst: []u8) -> tls.Error {
	at := 0

	for at < len(dst) {
		n, error := tls.read(client, dst[at:])

		if error != nil {
			return error
		}

		at += n
	}

	return nil
}

// Starts a peer with the fixture identity and the client trusting its root.
setup :: proc(t: ^testing.T, mode: loopback.Mode, script: Script) -> (peer: ^Peer, roots: ^tls.Root_Pool, ok: bool) {
	if !testing.expect(t, loopback.load_identity(CREDENTIALS), "load the fixture identity") {
		return
	}

	roots = roots_load(t, CREDENTIALS + "/root.pem")

	if roots == nil {
		return
	}

	peer = new(Peer)
	peer.mode = mode
	peer.script = script

	if !testing.expect(t, peer_start(peer), "start the peer") {
		free(peer)
		roots_destroy(roots)
		return nil, nil, false
	}

	return peer, roots, true
}

@(test)
loopback_tls_negotiates_the_protocol_of_each_mode :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	samples := []struct {
		mode:     loopback.Mode,
		offers:   []string,
		expected: string,
	} {
		{.H2, {"h2", "http/1.1"}, "h2"},
		{.GoAway, {"h2", "http/1.1"}, "h2"},
		{.HTTP1, {"h2", "http/1.1"}, "http/1.1"},
		{.HTTP1_NoALPN, {"h2", "http/1.1"}, ""},
		// A client that offers nothing gets no ALPN in any mode.
		{.H2, nil, ""},
	}

	for sample in samples {
		peer, roots, ok := setup(t, sample.mode, .Handshake)

		if !ok {
			return
		}

		client: tls.Conn
		error := client_dial(&client, peer, roots, sample.offers)
		negotiated := strings.clone(tls.connection_state(&client).negotiated_protocol, context.temp_allocator)

		if error == nil {
			_ = tls.conn_close(&client)
		}

		peer_stop(peer)
		testing.expectf(t, error == nil, "%v: dial: %v", sample.mode, error)
		testing.expectf(t, peer.handshaken, "%v: server handshake: %s", sample.mode, peer.conn.reason)
		testing.expect_value(t, negotiated, sample.expected)
		testing.expect_value(t, string(peer.conn.alpn[:peer.conn.alpn_n]), sample.expected)
		testing.expect_value(t, string(peer.conn.sni[:peer.conn.sni_n]), "localhost")
		peer_destroy(peer)
		roots_destroy(roots)
	}
}

// A mode with a protocol refuses a client that offers ALPN without it.
@(test)
loopback_tls_refuses_an_offer_without_the_mode_protocol :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	peer, roots, ok := setup(t, .H2, .Handshake)

	if !ok {
		return
	}
	defer roots_destroy(roots)
	defer peer_destroy(peer)

	client: tls.Conn
	error := client_dial(&client, peer, roots, {"http/1.1"})

	if error == nil {
		_ = tls.conn_close(&client)
	}

	peer_stop(peer)
	testing.expect(t, error != nil, "the client handshake fails")
	testing.expect(t, !peer.handshaken)
	testing.expect_value(t, peer.conn.reason, "alpn")
}

// The client verifies the chain: a client trusting another root refuses the
// server's certificate, and the server never sees a Finished.
@(test)
loopback_tls_certificate_is_verified_against_the_root :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	peer, roots, ok := setup(t, .HTTP1, .Handshake)

	if !ok {
		return
	}
	defer roots_destroy(roots)
	defer peer_destroy(peer)

	wrong := roots_load(t, CREDENTIALS + "/wrong-root.pem")

	if wrong == nil {
		return
	}
	defer roots_destroy(wrong)

	client: tls.Conn
	error := client_dial(&client, peer, wrong, {"http/1.1"})

	if error == nil {
		_ = tls.conn_close(&client)
	}

	peer_stop(peer)
	testing.expect(t, error != nil, "the client refuses the certificate")
	testing.expect(t, !peer.handshaken)
	testing.expect_value(t, peer.conn.reason, "client finished")
}

// Data larger than one record crosses both ways, split into full records.
@(test)
loopback_tls_application_data_crosses_records :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	peer, roots, ok := setup(t, .HTTP1, .Echo)

	if !ok {
		return
	}
	defer roots_destroy(roots)
	defer peer_destroy(peer)

	sent := make([]u8, ECHO_BYTES)
	defer delete(sent)

	for i in 0 ..< len(sent) {
		sent[i] = u8(i * 7 + i / 251)
	}

	echoed := make([]u8, ECHO_BYTES)
	defer delete(echoed)

	client: tls.Conn
	error := client_dial(&client, peer, roots, {"http/1.1"})

	if !testing.expectf(t, error == nil, "dial: %v", error) {
		return
	}

	written, write_error := tls.write(&client, sent)
	read_error := client_read(&client, echoed)
	_ = tls.conn_close(&client)
	peer_stop(peer)
	testing.expectf(t, write_error == nil, "write: %v", write_error)
	testing.expect_value(t, written, ECHO_BYTES)
	testing.expectf(t, read_error == nil, "read: %v", read_error)
	testing.expect(t, peer.served, "the server read and echoed every byte")
	testing.expect(t, bytes.equal(peer.received[:], sent), "the server received what was sent")
	testing.expect(t, bytes.equal(echoed, sent), "the client received the echo")
	// 40000 bytes at 16383 a record.
	testing.expect_value(t, peer.conn.app_records, 3)
}

// The server's KeyUpdate asks for one back. The client reads the data sealed
// under the server's new key, and its own KeyUpdate precedes its reply.
@(test)
loopback_tls_key_update_rotates_both_directions :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	peer, roots, ok := setup(t, .HTTP1, .Key_Update)

	if !ok {
		return
	}
	defer roots_destroy(roots)
	defer peer_destroy(peer)

	client: tls.Conn
	error := client_dial(&client, peer, roots, {"http/1.1"})

	if !testing.expectf(t, error == nil, "dial: %v", error) {
		return
	}

	rotated: [len("rotated")]u8
	read_error := client_read(&client, rotated[:])
	_, write_error := tls.write(&client, transmute([]u8)string("ack"))
	_ = tls.conn_close(&client)
	peer_stop(peer)
	testing.expectf(t, read_error == nil, "read: %v", read_error)
	testing.expect_value(t, string(rotated[:]), "rotated")
	testing.expectf(t, write_error == nil, "write: %v", write_error)
	testing.expect(t, peer.served, "the server read the reply under the client's new key")
	testing.expect_value(t, string(peer.received[:]), "ack")
	testing.expect_value(t, peer.conn.updates, 1)
	testing.expect_value(t, peer.conn.client_updates, 1)
	testing.expect_value(t, peer.conn.manual_n, 1)
}

// A sealed close_notify alert ends the client's reads cleanly.
@(test)
loopback_tls_close_notify_ends_the_stream :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	peer, roots, ok := setup(t, .HTTP1, .Close_Notify)

	if !ok {
		return
	}
	defer roots_destroy(roots)
	defer peer_destroy(peer)

	client: tls.Conn
	error := client_dial(&client, peer, roots, {"http/1.1"})

	if !testing.expectf(t, error == nil, "dial: %v", error) {
		return
	}

	bye: [len("bye")]u8
	read_error := client_read(&client, bye[:])
	extra: [16]u8
	_, end_error := tls.read(&client, extra[:])
	_ = tls.conn_close(&client)
	peer_stop(peer)
	testing.expectf(t, read_error == nil, "read: %v", read_error)
	testing.expect_value(t, string(bye[:]), "bye")
	testing.expectf(t, end_error == tls.Protocol_Error.Close_Notify, "end of stream: %v", end_error)
	testing.expect(t, peer.served)
}

// A minted P-256 identity replaces the Ed25519 fixture: the server signs with
// ECDSA and the client verifies against the minted root.
@(test)
loopback_tls_minted_p256_identity_verifies :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	sync.guard(&identity_lock)
	defer loopback.identity_clear()

	directory, temp_error := os.temp_directory(context.allocator)

	if !testing.expectf(t, temp_error == nil, "temp directory: %v", temp_error) {
		return
	}
	defer delete(directory)

	path := strings.concatenate({directory, "/surf-loopback-p256.pem"})
	defer delete(path)
	defer os.remove(path)

	ip := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{ip[:]}
	names := [1]string{"localhost"}

	if !testing.expect(t, loopback.mint_p256(path, "localhost", names[:], ips[:]), "mint the identity") {
		return
	}

	roots := roots_load(t, path)

	if roots == nil {
		return
	}
	defer roots_destroy(roots)

	peer := new(Peer)
	peer.mode = .H2

	if !testing.expect(t, peer_start(peer), "start the peer") {
		free(peer)
		return
	}
	defer peer_destroy(peer)

	client: tls.Conn
	error := client_dial(&client, peer, roots, {"h2"})

	if error == nil {
		_ = tls.conn_close(&client)
	}

	peer_stop(peer)
	testing.expectf(t, error == nil, "dial: %v", error)
	testing.expectf(t, peer.handshaken, "server handshake: %s", peer.conn.reason)
}
