package surf

import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "shared:async"

WS_PEER_OK :: 1
WS_PEER_ACCEPT :: 2
WS_PEER_REQUEST :: 3
WS_PEER_KEY :: 4
WS_PEER_TEXT :: 5
WS_PEER_FRAGMENT :: 6
WS_PEER_PONG :: 7
WS_PEER_CLOSE :: 8
WS_PEER_IO :: 9

WS_OP_TEXT :: 0x1
WS_OP_CONTINUATION :: 0x0
WS_OP_CLOSE :: 0x8
WS_OP_PING :: 0x9
WS_OP_PONG :: 0xa

WS_TLS_PEER :: "/tmp/surf-websocket-peer"

Ws_Peer_Mode :: enum {
	Echo,
	Queue,
	Bad_Accept,
	Unauthorized,
	Bad_UTF8,
	Masked,
	Too_Big,
	Slow,
	Cancel,
	// Sends two messages once go is set.
	Wakes,
	// The first fragment of a message, then nothing but Pongs.
	Stall_Message,
	// The first bytes of a frame, then nothing.
	Stall_Frame,
	// No message; answers Pings.
	Idle,
}

Ws_Peer :: struct {
	listener:      net.TCP_Socket,
	mode:          Ws_Peer_Mode,
	status:        int,
	accepted:      int,
	text:          [128]u8,
	text_n:        int,
	texts:         int,
	continuations: int,
	pongs:         int,
	pings:         int,
	closes:        int,
	go:            int,
}

// The session ends through its operations: a failed open, or a read that
// ended with the session once no close is outstanding.
Ws_Test :: struct {
	client:                                              Client,
	handle:                                              WebSocket_Handle,
	ready:                                               int,
	peer:                                                Ws_Peer,
	open:                                                WebSocket_Op,
	read:                                                WebSocket_Op,
	write_a:                                             WebSocket_Op,
	write_b:                                             WebSocket_Op,
	close:                                               WebSocket_Op,
	protocols:                                           [1]string,
	src:                                                 [32]u8,
	dst:                                                 [128]u8,
	payload6:                                            [6]u8,
	payload1:                                            [1]u8,
	subprotocol:                                         [16]u8,
	subprotocol_n:                                       int,
	write_text:                                          string,
	expect_read:                                         string,
	open_error, read_error, write_error, close_error:    WebSocket_Error,
	write_errors:                                        [2]WebSocket_Error,
	write_ns:                                            [2]int,
	reject_bytes, reject_count, reject_utf8, reject_size: Client_Error_Kind,
	cancel_close:                                        Client_Error_Kind,
	src_n, read_n, write_n, saw_open, saw_write:         int,
	saw_close, write_count, done:                        int,
	read_ok, write_ok, read_is_text, close_once, clean:  bool,
	read_ended, close_pending:                           bool,
	client_up, listener_up:                              bool,
	worker:                                              ^thread.Thread,
	policy_host:                                         [32]u8,
	policy_host_n:                                       int,
	policy_endpoint:                                     net.Endpoint,
	policy_calls:                                        int,
}

@(test)
websocket_open_rejects_bad_requests_synchronously :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	c: Client
	capacities := DEFAULT_CAPACITIES
	capacities.websockets = 1
	start_error := client_start(&c, {capacities = capacities}, rt.heap_allocator())
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return
	}
	defer client_destroy(&c)

	listener, listen_error := net.listen_tcp({net.IP4_Loopback, 0})
	testing.expect(t, listen_error == nil)
	if listen_error != nil {
		return
	}
	defer net.close(listener)

	endpoint, _ := net.bound_endpoint(listener)
	url := fmt.tprintf("wss://127.0.0.1:%d/ws", endpoint.port)
	done: int
	op := WebSocket_Op {
		callback  = ws_count_callback,
		user_data = &done,
	}

	_, nil_op := client_websocket_open(&c, url, {}, nil)
	testing.expect_value(t, nil_op.kind, .Invalid_State)
	no_callback: WebSocket_Op
	_, missing := client_websocket_open(&c, url, {}, &no_callback)
	testing.expect_value(t, missing.kind, .Invalid_State)
	_, scheme := client_websocket_open(&c, "https://127.0.0.1/", {}, &op)
	testing.expect_value(t, scheme.kind, .Invalid_Config)
	testing.expect_value(t, scheme.http.kind, .Invalid_URL)
	_, insecure := client_websocket_open(&c, "ws://127.0.0.1:9/", {}, &op)
	testing.expect_value(t, insecure.kind, .Invalid_Config)
	testing.expect_value(t, insecure.http.kind, .Insecure_URL)
	_, empty := client_websocket_open(&c, "wss:///ws", {}, &op)
	testing.expect_value(t, empty.kind, .Invalid_Config)
	_, negative := client_websocket_open(&c, url, {max_message_size = -1}, &op)
	testing.expect_value(t, negative.kind, .Invalid_Config)
	_, timeout := client_websocket_open(&c, url, {message_timeout = -time.Second}, &op)
	testing.expect_value(t, timeout.kind, .Invalid_Config)
	_, ping := client_websocket_open(&c, url, {ping_interval = -2}, &op)
	testing.expect_value(t, ping.kind, .Invalid_Config)
	testing.expect(t, !op._pending)

	stale := WebSocket_Handle{}
	read_op := WebSocket_Op {
		callback  = ws_count_callback,
		user_data = &done,
	}
	buffer: [8]u8
	testing.expect_value(t, client_websocket_read(&c, stale, &read_op, buffer[:]).kind, .Invalid_Handle)

	// The listener never accepts, so the upgrade stays in flight.
	handle, opened := client_websocket_open(&c, url, {ping_interval = async.WS_PING_OFF}, &op)
	testing.expect_value(t, opened.kind, .None)
	if opened.kind != .None {
		return
	}

	_, full := client_websocket_open(&c, url, {}, &read_op)
	testing.expect_value(t, full.kind, .Capacity)
	testing.expect_value(t, client_websocket_read(&c, handle, &read_op, buffer[:]).kind, .Invalid_State)
	testing.expect_value(t, client_websocket_write(&c, handle, &read_op, .Text, buffer[:1]).kind, .Invalid_State)
	testing.expect_value(t, client_websocket_close(&c, handle, &read_op).kind, .Invalid_State)
	testing.expect_value(t, client_websocket_close(&c, handle, &read_op, 1005).kind, .Invalid_Config)
	long_reason := strings.repeat("r", 124, context.temp_allocator)
	testing.expect_value(t, client_websocket_close(&c, handle, &read_op, 1000, long_reason).kind, .Invalid_Config)
	bad := [1]u8{0xff}
	testing.expect_value(t, client_websocket_write(&c, handle, &read_op, .Text, bad[:]).kind, .Invalid_Config)
	testing.expect_value(t, client_websocket_read(&c, handle, &op, buffer[:]).kind, .Invalid_State)
	testing.expect_value(t, client_websocket_cancel(&c, handle, &read_op).kind, .Invalid_State)
	testing.expect_value(t, client_websocket_cancel(&c, handle, &op).kind, .None)

	if !ws_until(t, &done, 1, 5 * time.Second, "the cancelled open") {
		return
	}

	testing.expect_value(t, op.kind, WebSocket_Op_Kind.Open)
	testing.expect_value(t, op.error.error.kind, async.Error_Kind.Cancelled)
	testing.expect_value(t, client_websocket_read(&c, handle, &read_op, buffer[:]).kind, .Closed)
	testing.expect_value(t, client_websocket_release(&c, handle).kind, .None)
	testing.expect_value(t, client_websocket_release(&c, handle).kind, .Invalid_Handle)
	testing.expect_value(t, client_websocket_read(&c, handle, &read_op, buffer[:]).kind, .Invalid_Handle)
}

ws_count_callback :: proc(op: ^WebSocket_Op) {
	counter := cast(^int)op.user_data
	intrinsics.atomic_add(counter, 1)
}

@(test)
websocket_fragments_ping_and_echo :: proc(t: ^testing.T) {
	ws_run(t, .Echo)
}

@(test)
websocket_bounds_queue_and_message :: proc(t: ^testing.T) {
	ws_run(t, .Queue)
}

@(test)
websocket_upgrade_authentication_rejected :: proc(t: ^testing.T) {
	ws_run(t, .Bad_Accept)
	if testing.failed(t) {
		return
	}

	ws_run(t, .Unauthorized)
}

@(test)
websocket_invalid_utf8_and_masked_server_frame :: proc(t: ^testing.T) {
	ws_run(t, .Bad_UTF8)
	if testing.failed(t) {
		return
	}

	ws_run(t, .Masked)
}

@(test)
websocket_message_too_big :: proc(t: ^testing.T) {
	ws_run(t, .Too_Big)
}

@(test)
websocket_slow_peer_times_out :: proc(t: ^testing.T) {
	ws_run(t, .Slow)
}

@(test)
websocket_cancel_during_upgrade :: proc(t: ^testing.T) {
	ws_run(t, .Cancel)
}

@(test)
websocket_dials_localhost_from_the_hosts_file :: proc(t: ^testing.T) {
	ws_run(t, .Echo, true)
}

@(test)
websocket_tls_loopback_by_address_and_by_name :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 90 * time.Second)
	if !ws_build(t) {
		return
	}

	read_end, write_end, pipe_error := os.pipe()
	testing.expect(t, pipe_error == nil)
	if pipe_error != nil {
		return
	}

	defer os.close(read_end)
	process, start_error := os.process_start(
		{
			command = {WS_TLS_PEER},
			working_dir = "tests/support/websocket",
			stdout = write_end,
			stderr = os.stderr,
		},
	)
	os.close(write_end)
	testing.expect(t, start_error == nil)
	if start_error != nil {
		return
	}

	defer {
		_, wait_error := os.process_wait(process, 0)

		if wait_error != nil {
			_ = os.process_kill(process)
			_, _ = os.process_wait(process)
		}
	}

	port, port_ok := ws_read_port(read_end)
	testing.expect(t, port_ok)
	if !port_ok {
		return
	}

	pool := new(async.Root_Pool)
	defer free(pool)
	defer async.root_pool_destroy(pool)
	load_error := async.root_pool_load_file(pool, "tests/support/credentials/root.pem")
	testing.expect(t, load_error == nil)
	if load_error != nil {
		return
	}

	// The peer serves, in order: echo by address, a wrong host, echo by name
	// and the platform roots.
	ws_tls_echo(t, fmt.tprintf("wss://127.0.0.1:%d/ws", port), pool, false)
	if testing.failed(t) {
		return
	}

	ws_tls_wrong_host(t, port, pool)
	if testing.failed(t) {
		return
	}

	ws_tls_echo(t, fmt.tprintf("wss://LocalHost:%d/ws", port), pool, true)
	if testing.failed(t) {
		return
	}

	ws_tls_platform_roots(t, port)
}

// named dials localhost by name through the hosts file.
ws_run :: proc(t: ^testing.T, mode: Ws_Peer_Mode, named := false) {
	testing.set_fail_timeout(t, 20 * time.Second)
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	listener, listen_error := net.listen_tcp({net.IP4_Loopback, 0})
	testing.expect(t, listen_error == nil)
	if listen_error != nil {
		return
	}

	h.peer.listener = listener
	h.listener_up = true
	endpoint, bound_error := net.bound_endpoint(listener)
	testing.expect_value(t, bound_error, .None)
	if bound_error != .None {
		return
	}

	h.peer.mode = mode
	h.worker = thread.create_and_start_with_poly_data(&h.peer, ws_peer_serve)
	testing.expect(t, h.worker != nil)
	if h.worker == nil {
		return
	}

	config := Config {
		allow_http = true,
	}
	url := fmt.tprintf("ws://127.0.0.1:%d/ws", endpoint.port)
	if named {
		url = fmt.tprintf("ws://localhost:%d/ws", endpoint.port)
		config.address_policy = ws_named_policy
		config.address_policy_data = h
	}

	if !ws_client_start(t, h, config, url, ws_case_options(h, mode)) {
		return
	}

	if mode == .Cancel && !ws_cancel_when_accepted(t, h) {
		return
	}

	if !ws_until(t, &h.done, 1, 8 * time.Second, "the websocket session") {
		return
	}

	ws_test_stop(h)
	ws_expect_case(t, h, mode)
	if named {
		v4, ok := h.policy_endpoint.address.(net.IP4_Address)
		testing.expect_value(t, h.policy_calls, 1)
		testing.expect_value(t, string(h.policy_host[:h.policy_host_n]), "localhost")
		testing.expect(t, ok && v4 == net.IP4_Loopback)
		testing.expect_value(t, h.policy_endpoint.port, endpoint.port)
	}
}

ws_named_policy :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	h := cast(^Ws_Test)user
	h.policy_calls += 1
	h.policy_host_n = copy(h.policy_host[:], host)
	if len(addresses) > 0 {
		h.policy_endpoint = addresses[0]
	}

	return true
}

ws_case_options :: proc(h: ^Ws_Test, mode: Ws_Peer_Mode) -> WebSocket_Options {
	h.protocols[0] = "chat"
	options := WebSocket_Options {
		subprotocols      = h.protocols[:],
		handshake_timeout = 5 * time.Second,
		idle_timeout      = 5 * time.Second,
		write_timeout     = 5 * time.Second,
		close_timeout     = time.Second,
	}

	switch mode {
	case .Echo:
		options.max_frame_payload = 5
		h.write_text = "hello-from-client"
		h.expect_read = "hello-from-server"
	case .Queue:
		options.max_message_size = 16
		options.max_queued_bytes = 8
	case .Too_Big:
		options.max_message_size = 16
	case .Slow:
		options.handshake_timeout = time.Second
	case .Bad_Accept, .Unauthorized, .Bad_UTF8, .Masked, .Cancel, .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}

	return options
}

ws_client_start :: proc(t: ^testing.T, h: ^Ws_Test, config: Config, url: string, options: WebSocket_Options) -> bool {
	start_error := client_start(&h.client, {http = config}, rt.heap_allocator())
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return false
	}

	h.client_up = true
	h.open.callback = ws_on_open
	h.open.user_data = h
	handle, open_error := client_websocket_open(&h.client, url, options, &h.open)
	testing.expect_value(t, open_error.kind, .None)
	if open_error.kind != .None {
		return false
	}

	h.handle = handle
	intrinsics.atomic_store_explicit(&h.ready, 1, .Release)

	return true
}

// Callbacks may run before client_websocket_open has returned the handle.
ws_handle :: proc(h: ^Ws_Test) -> WebSocket_Handle {
	for intrinsics.atomic_load_explicit(&h.ready, .Acquire) == 0 {
		thread.yield()
	}

	return h.handle
}

// The peer accepted, so the upgrade request is in flight or waiting for its answer.
ws_cancel_when_accepted :: proc(t: ^testing.T, h: ^Ws_Test) -> bool {
	start := time.tick_now()

	for intrinsics.atomic_load_explicit(&h.peer.accepted, .Acquire) == 0 {
		if time.tick_since(start) > 3 * time.Second {
			testing.expect(t, false, "peer never accepted")
			return false
		}

		thread.yield()
	}

	time.sleep(50 * time.Millisecond)
	cancel_error := client_websocket_cancel(&h.client, h.handle, &h.open)
	testing.expect_value(t, cancel_error.kind, .None)

	return cancel_error.kind == .None
}

ws_until :: proc(t: ^testing.T, flag: ^int, value: int, limit: time.Duration, what: string) -> bool {
	start := time.tick_now()

	for intrinsics.atomic_load_explicit(flag, .Acquire) < value {
		if time.tick_since(start) > limit {
			testing.expectf(t, false, "timed out waiting for %s", what)
			return false
		}

		time.sleep(time.Millisecond)
	}

	return true
}

// Releases the session and destroys the client, so every callback has run.
ws_test_stop :: proc(h: ^Ws_Test) {
	if h.client_up {
		if intrinsics.atomic_load_explicit(&h.ready, .Acquire) != 0 {
			_ = client_websocket_release(&h.client, h.handle)
		}

		_ = client_destroy(&h.client)
		h.client_up = false
	}

	if h.listener_up {
		net.close(h.peer.listener)
		h.listener_up = false
	}

	if h.worker != nil {
		thread.destroy(h.worker)
		h.worker = nil
	}
}

ws_expect_case :: proc(t: ^testing.T, h: ^Ws_Test, mode: Ws_Peer_Mode) {
	testing.expect_value(t, h.saw_open, 1)

	switch mode {
	case .Echo:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect(t, ws_bytes_equal(h.peer.text[:h.peer.text_n], "hello-from-client"))
		testing.expect(t, h.peer.continuations >= 1 && h.peer.pongs >= 1 && h.peer.closes >= 1)
		testing.expect(t, h.read_ok && h.read_is_text && h.write_ok)
		testing.expect_value(t, h.write_n, len("hello-from-client"))
		testing.expect(t, h.clean && h.saw_close == 1)
		testing.expect_value(t, h.close_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.cancel_close, Client_Error_Kind.Invalid_State)
		testing.expect_value(t, string(h.subprotocol[:h.subprotocol_n]), "chat")
	case .Queue:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.reject_bytes, Client_Error_Kind.Capacity)
		testing.expect_value(t, h.reject_count, Client_Error_Kind.Capacity)
		testing.expect_value(t, h.reject_utf8, Client_Error_Kind.Invalid_Config)
		testing.expect_value(t, h.reject_size, Client_Error_Kind.Invalid_Config)
		testing.expect_value(t, h.write_count, 2)
		testing.expect_value(t, h.write_errors[0].error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.write_errors[1].error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.write_ns[0], 6)
		testing.expect_value(t, h.write_ns[1], 1)
		testing.expect_value(t, h.peer.texts, 2)
		testing.expect_value(t, h.read_error.error.kind, async.Error_Kind.Closed)
		testing.expect_value(t, h.read_error.close.peer_code, 1000)
		testing.expect(t, h.clean)
		testing.expect_value(t, h.close_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, string(h.subprotocol[:h.subprotocol_n]), "chat")
	case .Bad_Accept:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect(t, h.open_error.error.kind != .None)
		testing.expect_value(t, h.open_error.upgrade.upgrade, .Invalid_Accept)
		testing.expect(t, !h.clean)
	case .Unauthorized:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.Refused)
		testing.expect_value(t, h.open_error.upgrade.upgrade, .Invalid_Status)
		testing.expect_value(t, h.open_error.upgrade.status, 401)
		testing.expect(t, !h.clean)
	case .Bad_UTF8:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.read_error.error.kind, async.Error_Kind.Network_Error)
		testing.expect_value(t, h.read_error.close.reason, async.WS_Close_Reason.Invalid_Data)
		testing.expect_value(t, h.read_error.close.code, 1007)
		testing.expect(t, !h.clean)
	case .Masked:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.read_error.error.kind, async.Error_Kind.Network_Error)
		testing.expect_value(t, h.read_error.close.frame, .Unexpected_Masking)
		testing.expect(t, !h.clean)
	case .Too_Big:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, h.read_error.error.kind, async.Error_Kind.Capacity)
		testing.expect_value(t, h.read_error.close.code, 1009)
		testing.expect(t, !h.clean)
	case .Slow:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.Timeout)
		testing.expect(t, !h.clean)
	case .Cancel:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.Cancelled)
		testing.expect(t, !h.clean)
	case .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}
}

// url is wss:// at the TLS peer; named checks that the hosts file gave
// 127.0.0.1 for its host.
ws_tls_echo :: proc(t: ^testing.T, url: string, roots: ^async.Root_Pool, named: bool) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Echo
	h.protocols[0] = "chat"
	h.write_text = "hello-tls"
	h.expect_read = "hello-tls"
	config := Config {
		tls = {roots = roots},
	}
	if named {
		config.address_policy = ws_named_policy
		config.address_policy_data = h
	}

	options := WebSocket_Options {
		subprotocols      = h.protocols[:],
		max_frame_payload = 4,
		handshake_timeout = 5 * time.Second,
		idle_timeout      = 5 * time.Second,
		write_timeout     = 5 * time.Second,
		close_timeout     = 2 * time.Second,
	}

	if !ws_client_start(t, h, config, url, options) {
		return
	}

	if !ws_until(t, &h.done, 1, 10 * time.Second, "the TLS session") {
		return
	}

	ws_test_stop(h)
	testing.expect_value(t, h.saw_open, 1)
	testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.None)
	testing.expect(t, h.read_ok && h.read_is_text && h.write_ok && h.clean)
	testing.expect_value(t, string(h.subprotocol[:h.subprotocol_n]), "chat")
	testing.expect_value(t, h.close_error.error.kind, async.Error_Kind.None)
	if named {
		v4, ok := h.policy_endpoint.address.(net.IP4_Address)
		testing.expect_value(t, string(h.policy_host[:h.policy_host_n]), "LocalHost")
		testing.expect(t, ok && v4 == net.IP4_Loopback)
	}
}

// Without roots the session verifies against the platform's roots, which do
// not hold the test root.
ws_tls_platform_roots :: proc(t: ^testing.T, port: int) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Bad_Accept
	options := WebSocket_Options {
		handshake_timeout = 5 * time.Second,
		close_timeout     = time.Second,
	}

	if !ws_client_start(t, h, {}, fmt.tprintf("wss://localhost:%d/ws", port), options) {
		return
	}

	if !ws_until(t, &h.done, 1, 10 * time.Second, "the platform-roots session") {
		return
	}

	ws_test_stop(h)
	testing.expect_value(t, h.saw_open, 1)
	testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.Network_Error)
	testing.expect(t, h.open_error.upgrade.tls != nil)
	testing.expect(t, h.read_n == 0 && !h.clean)
}

// wrong.example resolves to the peer through a stub name server; its
// certificate names only localhost and 127.0.0.1.
ws_tls_wrong_host :: proc(t: ^testing.T, port: int, roots: ^async.Root_Pool) {
	dns := new(Ws_Dns)
	defer free(dns)
	dns.answer = true
	server, dns_worker, dns_ok := ws_dns_start(t, dns)
	if !dns_ok {
		return
	}

	defer ws_dns_stop(dns, dns_worker)
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Bad_Accept
	servers := [1]net.Endpoint{server}
	config := Config {
		tls = {roots = roots},
		resolver = {name_servers = servers[:]},
	}
	options := WebSocket_Options {
		handshake_timeout = 5 * time.Second,
		close_timeout     = time.Second,
	}

	if !ws_client_start(t, h, config, fmt.tprintf("wss://wrong.example:%d/ws", port), options) {
		return
	}

	if !ws_until(t, &h.done, 1, 10 * time.Second, "the wrong-host session") {
		return
	}

	ws_test_stop(h)
	testing.expect_value(t, h.saw_open, 1)
	testing.expect_value(t, h.open_error.error.kind, async.Error_Kind.Network_Error)
	testing.expect(t, h.open_error.upgrade.tls != nil)
	testing.expect(t, h.read_n == 0 && !h.clean)
}

ws_on_open :: proc(op: ^WebSocket_Op) {
	h := cast(^Ws_Test)op.user_data
	h.open_error = op.error
	h.saw_open = 1
	if op.error.error.kind != .None {
		intrinsics.atomic_store_explicit(&h.done, 1, .Release)
		return
	}

	handle := ws_handle(h)
	name, _ := client_websocket_subprotocol(&h.client, handle, h.subprotocol[:])
	h.subprotocol_n = len(name)

	switch h.peer.mode {
	case .Echo:
		h.src_n = copy(h.src[:], h.write_text)
		h.write_a.callback = ws_on_write
		h.write_a.user_data = h
		_ = client_websocket_write(&h.client, handle, &h.write_a, .Text, h.src[:h.src_n])
		ws_submit_read(h)
	case .Queue:
		ws_queue_probe(h)
	case .Bad_UTF8, .Masked, .Too_Big:
		ws_submit_read(h)
	case .Bad_Accept, .Unauthorized, .Slow, .Cancel, .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}
}

ws_submit_read :: proc(h: ^Ws_Test) {
	h.read.callback = ws_on_read
	h.read.user_data = h
	_ = client_websocket_read(&h.client, ws_handle(h), &h.read, h.dst[:])
}

// Runs on the client's task, so nothing queued here is handed to the session
// before the last write is checked.
ws_queue_probe :: proc(h: ^Ws_Test) {
	handle := ws_handle(h)
	for i in 0 ..< len(h.payload6) {
		h.payload6[i] = 'a'
	}

	h.payload1[0] = 'b'
	h.write_a.callback = ws_on_write
	h.write_a.user_data = h
	h.write_b.callback = ws_on_write
	h.write_b.user_data = h
	first := client_websocket_write(&h.client, handle, &h.write_a, .Text, h.payload6[:])
	h.reject_bytes = client_websocket_write(&h.client, handle, &h.write_b, .Text, h.payload6[:4]).kind
	second := client_websocket_write(&h.client, handle, &h.write_b, .Text, h.payload1[:])
	extra := WebSocket_Op {
		callback  = ws_on_write,
		user_data = h,
	}
	// Every write below is refused, and a refused operation is never queued.
	h.reject_count = client_websocket_write(&h.client, handle, &extra, .Text, h.payload6[:2]).kind
	bad := [1]u8{0xff}
	h.reject_utf8 = client_websocket_write(&h.client, handle, &extra, .Text, bad[:]).kind
	big: [20]u8
	h.reject_size = client_websocket_write(&h.client, handle, &extra, .Text, big[:]).kind

	if first.kind != .None || second.kind != .None {
		h.reject_bytes = first.kind if first.kind != .None else second.kind
	}

	ws_submit_read(h)
	ws_submit_close(h)
}

// A failed read is how the session ended; a successful one is followed by the
// next read, which waits for that end.
ws_on_read :: proc(op: ^WebSocket_Op) {
	h := cast(^Ws_Test)op.user_data

	if op.error.error.kind != .None {
		h.read_error = op.error
		h.read_ended = true
		h.clean = h.clean || op.error.close.clean
		ws_check_done(h)
		return
	}

	h.read_n = op.n
	if !h.read_ok && h.expect_read != "" {
		h.read_ok = ws_bytes_equal(h.dst[:op.n], h.expect_read)
		h.read_is_text = op.message == .Text
	}

	ws_submit_read(h)
	if h.read_ok && h.write_ok {
		ws_submit_close(h)
	}
}

ws_on_write :: proc(op: ^WebSocket_Op) {
	h := cast(^Ws_Test)op.user_data

	if h.peer.mode == .Queue {
		if h.write_count < len(h.write_errors) {
			h.write_errors[h.write_count] = op.error
			h.write_ns[h.write_count] = op.n
			h.write_count += 1
		}

		return
	}

	h.write_error = op.error
	h.write_n = op.n
	h.saw_write = 1
	h.write_ok = op.error.error.kind == .None && op.n == h.src_n
	if h.read_ok && h.write_ok {
		ws_submit_close(h)
	}
}

ws_on_close :: proc(op: ^WebSocket_Op) {
	h := cast(^Ws_Test)op.user_data
	h.close_error = op.error
	h.clean = h.clean || op.error.close.clean
	h.saw_close = 1
	h.close_pending = false
	ws_check_done(h)
}

ws_check_done :: proc(h: ^Ws_Test) {
	if h.read_ended && !h.close_pending {
		intrinsics.atomic_store_explicit(&h.done, 1, .Release)
	}
}

ws_submit_close :: proc(h: ^Ws_Test) {
	if h.close_once {
		return
	}

	h.close_once = true
	h.close.callback = ws_on_close
	h.close.user_data = h
	handle := ws_handle(h)
	if client_websocket_close(&h.client, handle, &h.close, 1000, "bye").kind == .None {
		h.close_pending = true
		h.cancel_close = client_websocket_cancel(&h.client, handle, &h.close).kind
	}
}

ws_bytes_equal :: proc(buf: []u8, text: string) -> bool {
	return string(buf) == text
}

ws_peer_serve :: proc(peer: ^Ws_Peer) {
	defer if peer.status == 0 {
		peer.status = WS_PEER_IO
	}

	sock, _, accept_error := net.accept_tcp(peer.listener)

	if accept_error != .None {
		peer.status = WS_PEER_ACCEPT
		return
	}

	defer net.close(sock)
	intrinsics.atomic_store_explicit(&peer.accepted, 1, .Release)
	_ = net.set_option(sock, .TCP_Nodelay, true)
	_ = net.set_option(sock, .Receive_Timeout, 4 * time.Second)
	_ = net.set_option(sock, .Send_Timeout, 4 * time.Second)

	if peer.mode == .Slow || peer.mode == .Cancel {
		ws_peer_hold(sock)
		peer.status = WS_PEER_OK
		return
	}

	request: [2048]u8
	request_n, request_ok := ws_peer_request(sock, request[:])

	if !request_ok {
		peer.status = WS_PEER_REQUEST
		return
	}

	header := string(request[:request_n])
	key := ws_peer_key(header)

	if key == "" {
		peer.status = WS_PEER_KEY
		return
	}

	response: [512]u8
	response_n := 0

	switch peer.mode {
	case .Bad_Accept:
		response_n = ws_peer_101(response[:], "AAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	case .Unauthorized:
		response_n = copy(response[:], "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	case .Echo, .Queue, .Bad_UTF8, .Masked, .Too_Big, .Wakes, .Stall_Message, .Stall_Frame, .Idle:
		protocol := "chat" if strings.index(header, "Sec-WebSocket-Protocol: chat") >= 0 else ""
		accept: [64]u8
		response_n = ws_peer_101(response[:], ws_peer_accept(key, accept[:]), protocol)
	case .Slow, .Cancel:
	}

	if !ws_peer_send_slow(sock, response[:response_n]) {
		peer.status = WS_PEER_IO
		return
	}

	frames: [256]u8
	frame_n := 0

	switch peer.mode {
	case .Echo:
		frame_n = ws_peer_echo_frames(frames[:])
	case .Bad_UTF8:
		frame_n = ws_peer_put(frames[:], 0, true, WS_OP_TEXT, []u8{0xff}, {})
	case .Masked:
		frame_n = ws_peer_put(frames[:], 0, true, WS_OP_TEXT, []u8{'x'}, {9, 8, 7, 6})
	case .Too_Big:
		big: [40]u8
		for &b in big {
			b = 'q'
		}

		frame_n = ws_peer_put(frames[:], 0, true, WS_OP_TEXT, big[:], {})
	case .Stall_Message:
		frame_n = ws_peer_put(frames[:], 0, false, WS_OP_TEXT, transmute([]u8)string("par"), {})
	case .Stall_Frame:
		// The header promises ten bytes; three follow.
		frame_n = ws_peer_put(frames[:], 0, true, WS_OP_TEXT, transmute([]u8)string("0123456789"), {}) - 7
	case .Queue, .Bad_Accept, .Unauthorized, .Slow, .Cancel, .Wakes, .Idle:
	}

	if frame_n > 0 {
		time.sleep(50 * time.Millisecond)

		if !ws_peer_send_slow(sock, frames[:frame_n]) {
			peer.status = WS_PEER_IO
			return
		}
	}

	switch peer.mode {
	case .Echo:
		ws_peer_frames(sock, peer, true)
	case .Queue, .Stall_Message, .Idle:
		ws_peer_frames(sock, peer, false)
	case .Wakes:
		ws_peer_wakes(sock, peer)
	case .Bad_Accept, .Unauthorized, .Bad_UTF8, .Masked, .Too_Big, .Stall_Frame:
		ws_peer_hold(sock)
		peer.status = WS_PEER_OK
	case .Slow, .Cancel:
	}
}

// Waits for go, then sends a fragmented message and a whole one.
ws_peer_wakes :: proc(sock: net.TCP_Socket, peer: ^Ws_Peer) {
	start := time.tick_now()

	for intrinsics.atomic_load_explicit(&peer.go, .Acquire) == 0 {
		if time.tick_since(start) > 10 * time.Second {
			peer.status = WS_PEER_IO
			return
		}

		time.sleep(time.Millisecond)
	}

	frames: [64]u8
	at := ws_peer_put(frames[:], 0, false, WS_OP_TEXT, transmute([]u8)string("fir"), {})
	at = ws_peer_put(frames[:], at, true, WS_OP_CONTINUATION, transmute([]u8)string("st"), {})
	at = ws_peer_put(frames[:], at, true, WS_OP_TEXT, transmute([]u8)string("second"), {})

	if !ws_peer_send_slow(sock, frames[:at]) {
		peer.status = WS_PEER_IO
		return
	}

	ws_peer_frames(sock, peer, false)
}

ws_peer_hold :: proc(sock: net.TCP_Socket) {
	scratch: [64]u8

	for {
		got, err := net.recv_tcp(sock, scratch[:])
		if err != .None || got == 0 {
			return
		}
	}
}

ws_peer_request :: proc(sock: net.TCP_Socket, dst: []u8) -> (int, bool) {
	n := 0

	for n < len(dst) {
		if n >= 4 && string(dst[n - 4:n]) == "\r\n\r\n" {
			return n, true
		}

		got, err := net.recv_tcp(sock, dst[n:])
		if err != .None || got == 0 {
			return n, false
		}

		n += got
	}

	return n, false
}

ws_peer_key :: proc(header: string) -> string {
	needle := "Sec-WebSocket-Key: "
	at := strings.index(header, needle)
	if at < 0 {
		return ""
	}

	rest := header[at + len(needle):]
	end := strings.index(rest, "\r\n")
	if end <= 0 {
		return ""
	}

	return rest[:end]
}

ws_peer_accept :: proc(key: string, dst: []u8) -> string {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]u8)key)
	sha1.update(&ctx, transmute([]u8)string("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	digest: [sha1.DIGEST_SIZE]u8
	sha1.final(&ctx, digest[:])
	encoded, _ := base64.encode(digest[:], allocator = context.temp_allocator)

	return string(dst[:copy(dst, encoded)])
}

ws_peer_101 :: proc(dst: []u8, accept, protocol: string) -> int {
	wrote := copy(dst, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	wrote += copy(dst[wrote:], accept)
	wrote += copy(dst[wrote:], "\r\n")

	if protocol != "" {
		wrote += copy(dst[wrote:], "Sec-WebSocket-Protocol: ")
		wrote += copy(dst[wrote:], protocol)
		wrote += copy(dst[wrote:], "\r\n")
	}

	wrote += copy(dst[wrote:], "\r\n")

	return wrote
}

ws_peer_echo_frames :: proc(dst: []u8) -> int {
	at := ws_peer_put(dst, 0, true, WS_OP_PING, []u8{'z'}, {})
	text := "hello-from-server"
	offset := 0

	for offset < len(text) {
		step := min(5, len(text) - offset)
		fin := offset + step == len(text)
		opcode: u8 = WS_OP_TEXT if offset == 0 else WS_OP_CONTINUATION
		at = ws_peer_put(dst, at, fin, opcode, transmute([]u8)text[offset:offset + step], {})
		offset += step
	}

	return at
}

// Payloads stay below 126 bytes, so the length fits the second byte.
ws_peer_put :: proc(dst: []u8, at: int, fin: bool, opcode: u8, payload: []u8, mask: [4]u8) -> int {
	at := at
	mask := mask
	dst[at] = opcode | (0x80 if fin else 0)
	dst[at + 1] = u8(len(payload))
	at += 2

	if mask != {} {
		dst[at - 1] |= 0x80
		at += copy(dst[at:], mask[:])
	}

	for b, i in payload {
		dst[at + i] = b ~ mask[i % 4]
	}

	return at + len(payload)
}

ws_peer_send_slow :: proc(sock: net.TCP_Socket, data: []u8) -> bool {
	for b in data {
		one := [1]u8{b}
		sent, err := net.send_tcp(sock, one[:])
		if err != .None || sent != 1 {
			return false
		}

		time.sleep(time.Millisecond)
	}

	return true
}

ws_peer_frames :: proc(sock: net.TCP_Socket, peer: ^Ws_Peer, want_text: bool) {
	buf: [2048]u8
	n := 0

	for peer.closes == 0 {
		for n >= 2 {
			length := int(buf[1] & 0x7f)
			consumed := 2
			if length == 126 {
				if n < 4 {
					break
				}

				length = int(buf[2]) << 8 | int(buf[3])
				consumed = 4
			}

			if buf[1] & 0x80 == 0 || length == 127 {
				peer.status = WS_PEER_IO
				return
			}

			total := consumed + 4 + length
			if total > len(buf) {
				peer.status = WS_PEER_IO
				return
			}

			if n < total {
				break
			}

			mask := buf[consumed:consumed + 4]
			payload := buf[consumed + 4:total]
			for &b, i in payload {
				b ~= mask[i % 4]
			}

			if !ws_peer_take(sock, peer, buf[0] & 0x0f, payload) {
				return
			}

			remain := n - total
			copy(buf[:remain], buf[total:n])
			n = remain
		}

		if peer.closes > 0 {
			break
		}

		got, err := net.recv_tcp(sock, buf[n:])

		if err != .None || got == 0 {
			peer.status = WS_PEER_IO
			return
		}

		n += got
	}

	if want_text {
		if !ws_bytes_equal(peer.text[:peer.text_n], "hello-from-client") {
			peer.status = WS_PEER_TEXT
			return
		}

		if peer.continuations < 1 {
			peer.status = WS_PEER_FRAGMENT
			return
		}

		if peer.pongs < 1 {
			peer.status = WS_PEER_PONG
			return
		}
	}

	peer.status = WS_PEER_OK
}

ws_peer_take :: proc(sock: net.TCP_Socket, peer: ^Ws_Peer, opcode: u8, payload: []u8) -> bool {
	switch opcode {
	case WS_OP_TEXT:
		peer.texts += 1
		peer.text_n = copy(peer.text[:], payload)
	case WS_OP_CONTINUATION:
		peer.continuations += 1

		if peer.text_n + len(payload) > len(peer.text) {
			peer.status = WS_PEER_IO
			return false
		}

		peer.text_n += copy(peer.text[peer.text_n:], payload)
	case WS_OP_PONG:
		peer.pongs += 1
	case WS_OP_PING:
		intrinsics.atomic_add(&peer.pings, 1)
		frame: [128]u8
		n := ws_peer_put(frame[:], 0, true, WS_OP_PONG, payload, {})
		sent, send_error := net.send_tcp(sock, frame[:n])

		if send_error != .None || sent != n {
			peer.status = WS_PEER_IO
			return false
		}
	case WS_OP_CLOSE:
		peer.closes += 1
		frame: [4]u8
		n := ws_peer_put(frame[:], 0, true, WS_OP_CLOSE, []u8{0x03, 0xe8}, {})
		sent, send_error := net.send_tcp(sock, frame[:n])

		if send_error != .None || sent != n {
			peer.status = WS_PEER_IO
			return false
		}
	}

	return true
}

ws_build_mu: sync.Mutex
ws_built: bool

ws_compiler :: proc() -> string {
	value, found := os.lookup_env("ODIN", context.temp_allocator)
	if !found || value == "" {
		return "odin"
	}

	return value
}

ws_build :: proc(t: ^testing.T) -> bool {
	sync.lock(&ws_build_mu)
	defer sync.unlock(&ws_build_mu)
	if ws_built && os.exists(WS_TLS_PEER) {
		return true
	}

	process, start_error := os.process_start(
		{
			command = {ws_compiler(), "build", ".", "-out:" + WS_TLS_PEER},
			working_dir = "tests/support/websocket",
			stderr = os.stderr,
		},
	)
	testing.expect(t, start_error == nil)
	if start_error != nil {
		return false
	}

	state, wait_error := os.process_wait(process)
	testing.expect(t, wait_error == nil && state.exit_code == 0)
	ws_built = wait_error == nil && state.exit_code == 0

	return ws_built
}

ws_read_port :: proc(file: ^os.File) -> (int, bool) {
	buf: [128]u8
	n := 0

	for n < len(buf) {
		got, err := os.read(file, buf[n:])

		if got > 0 {
			n += got
			text := string(buf[:n])
			nl := strings.index_byte(text, '\n')

			if nl >= 0 {
				value, ok := strconv.parse_int(text[:nl], 10)
				return value, ok && value > 0 && value <= 65535
			}
		}

		if err != nil || got == 0 {
			return 0, false
		}
	}

	return 0, false
}

Ws_Dns :: struct {
	socket:  net.UDP_Socket,
	queries: int,
	stop:    int,
	// Answer every A question with 127.0.0.1; otherwise NXDOMAIN.
	answer:  bool,
}

ws_dns_start :: proc(t: ^testing.T, dns: ^Ws_Dns) -> (server: net.Endpoint, worker: ^thread.Thread, ok: bool) {
	socket, socket_error := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	testing.expect(t, socket_error == nil)
	if socket_error != nil {
		return
	}

	dns.socket = socket
	_ = net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond)
	bound, bound_error := net.bound_endpoint(socket)
	testing.expect(t, bound_error == nil)
	if bound_error != nil {
		net.close(socket)
		return
	}

	worker = thread.create_and_start_with_poly_data(dns, ws_dns_serve)
	testing.expect(t, worker != nil)
	if worker == nil {
		net.close(socket)
		return
	}

	return bound, worker, true
}

ws_dns_stop :: proc(dns: ^Ws_Dns, worker: ^thread.Thread) {
	intrinsics.atomic_store_explicit(&dns.stop, 1, .Release)
	thread.destroy(worker)
	net.close(dns.socket)
}

ws_dns_serve :: proc(dns: ^Ws_Dns) {
	buf: [512]u8

	for intrinsics.atomic_load_explicit(&dns.stop, .Acquire) == 0 {
		n, from, err := net.recv_udp(dns.socket, buf[:])
		if err != nil || n < 12 {
			continue
		}

		intrinsics.atomic_add(&dns.queries, 1)

		if !dns.answer {
			buf[2] |= 0x80
			buf[3] = 0x83
			_, _ = net.send_udp(dns.socket, buf[:n], from)
			continue
		}

		// The question ends after its name, type and class.
		at := 12
		for at < n && buf[at] != 0 {
			at += int(buf[at]) + 1
		}

		at += 5
		if at > n {
			continue
		}

		a_question := buf[at - 4] == 0 && buf[at - 3] == 1
		buf[2] = 0x80 | (buf[2] & 0x01)
		buf[3] = 0x80
		buf[6], buf[7] = 0, 1 if a_question else 0
		buf[8], buf[9], buf[10], buf[11] = 0, 0, 0, 0

		if a_question {
			record := [16]u8{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1}
			at += copy(buf[at:], record[:])
		}

		_, _ = net.send_udp(dns.socket, buf[:at], from)
	}
}

Ws_Policy_Harness :: struct {
	client:    Client,
	handle:    WebSocket_Handle,
	open:      WebSocket_Op,
	error:     WebSocket_Error,
	done:      int,
	calls:     int,
	host:      [32]u8,
	host_n:    int,
	endpoint:  net.Endpoint,
	allow:     bool,
	listener:  net.TCP_Socket,
	accepts:   int,
	mu:        sync.Mutex,
	servers:   [1]net.Endpoint,
	client_up: bool,
}

ws_policy_open :: proc(op: ^WebSocket_Op) {
	harness := cast(^Ws_Policy_Harness)op.user_data
	harness.error = op.error
	intrinsics.atomic_store_explicit(&harness.done, 1, .Release)
}

ws_policy_decide :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	harness := cast(^Ws_Policy_Harness)user
	harness.calls += 1
	harness.host_n = copy(harness.host[:], host)

	if len(addresses) == 1 {
		harness.endpoint = addresses[0]
	}

	return harness.allow
}

ws_policy_accept :: proc(harness: ^Ws_Policy_Harness) {
	for {
		client, _, err := net.accept_tcp(harness.listener)

		if err != nil {
			return
		}

		sync.lock(&harness.mu)
		harness.accepts += 1
		sync.unlock(&harness.mu)
		net.close(client)
	}
}

ws_policy_loopback :: proc(harness: ^Ws_Policy_Harness) -> bool {
	ip, ok := harness.endpoint.address.(net.IP4_Address)

	return ok && ip == net.IP4_Loopback
}

ws_policy_accepts :: proc(harness: ^Ws_Policy_Harness) -> int {
	sync.lock(&harness.mu)
	defer sync.unlock(&harness.mu)

	return harness.accepts
}

ws_policy_finish :: proc(harness: ^Ws_Policy_Harness, worker: ^thread.Thread) {
	if harness.client_up {
		_ = client_websocket_release(&harness.client, harness.handle)
		_ = client_destroy(&harness.client)
	}

	net.close(harness.listener)

	if worker != nil {
		thread.destroy(worker)
	}
}

// Opens ws://host at the listener's port, resolving host only through server.
ws_policy_run :: proc(
	t: ^testing.T,
	allow: bool,
	host: string,
	server: net.Endpoint,
) -> (
	harness: ^Ws_Policy_Harness,
	worker: ^thread.Thread,
	ok: bool,
) {
	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, listen_error == nil)

	if listen_error != nil {
		return nil, nil, false
	}

	endpoint, bound_error := net.bound_endpoint(listener)
	testing.expect_value(t, bound_error, .None)

	if bound_error != .None {
		net.close(listener)
		return nil, nil, false
	}

	harness = new(Ws_Policy_Harness)
	harness.listener = listener
	harness.allow = allow
	harness.servers[0] = server
	worker = thread.create_and_start_with_poly_data(harness, ws_policy_accept)
	testing.expect(t, worker != nil)

	if worker == nil {
		net.close(listener)
		free(harness)
		return nil, nil, false
	}

	config := Config {
		allow_http          = true,
		resolver            = {name_servers = harness.servers[:]},
		address_policy      = ws_policy_decide,
		address_policy_data = harness,
	}
	start_error := client_start(&harness.client, {http = config}, rt.heap_allocator())
	testing.expect_value(t, start_error.kind, .None)

	if start_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.client_up = true
	harness.open.callback = ws_policy_open
	harness.open.user_data = harness
	url := fmt.tprintf("ws://%s:%d/", host, endpoint.port)
	handle, open_error := client_websocket_open(&harness.client, url, {handshake_timeout = 2 * time.Second}, &harness.open)
	testing.expect_value(t, open_error.kind, .None)

	if open_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.handle = handle

	return harness, worker, true
}

ws_policy_case :: proc(t: ^testing.T, allow: bool, answer: bool, host: string) -> (harness: ^Ws_Policy_Harness, dns: ^Ws_Dns) {
	dns = new(Ws_Dns)
	dns.answer = answer
	server, dns_worker, dns_ok := ws_dns_start(t, dns)
	if !dns_ok {
		free(dns)
		return nil, nil
	}

	worker: ^thread.Thread
	ok: bool
	harness, worker, ok = ws_policy_run(t, allow, host, server)
	if ok {
		ws_until(t, &harness.done, 1, 8 * time.Second, "the open")
		ws_policy_finish(harness, worker)
	}

	ws_dns_stop(dns, dns_worker)
	if !ok {
		free(dns)
		return nil, nil
	}

	return harness, dns
}

@(test)
websocket_rejects_the_endpoint_before_connect :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	harness, dns := ws_policy_case(t, false, true, "ws.example")
	if harness == nil {
		return
	}

	defer free(harness)
	defer free(dns)
	testing.expect_value(t, harness.error.error.kind, async.Error_Kind.Refused)
	testing.expect_value(t, harness.error.upgrade.status, 0)
	testing.expect_value(t, harness.calls, 1)
	testing.expect_value(t, string(harness.host[:harness.host_n]), "ws.example")
	testing.expect(t, ws_policy_loopback(harness))
	testing.expect(t, harness.endpoint.port > 0)
	testing.expect_value(t, ws_policy_accepts(harness), 0)
}

@(test)
websocket_connects_to_the_endpoint_the_policy_checked :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	harness, dns := ws_policy_case(t, true, true, "ws.example")
	if harness == nil {
		return
	}

	defer free(harness)
	defer free(dns)
	testing.expect(t, harness.error.error.kind != .Refused)
	testing.expect(t, harness.error.error.kind != .None)
	testing.expect_value(t, harness.calls, 1)
	testing.expect_value(t, string(harness.host[:harness.host_n]), "ws.example")
	testing.expect(t, ws_policy_loopback(harness))
	testing.expect(t, harness.endpoint.port > 0)
	testing.expect_value(t, ws_policy_accepts(harness), 1)
}

@(test)
websocket_unresolvable_name_fails_before_connect :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	harness, dns := ws_policy_case(t, true, false, "nowhere.invalid")
	if harness == nil {
		return
	}

	defer free(harness)
	defer free(dns)
	_, resolving := harness.error.error.network_cause.(net.Resolve_Error)
	testing.expect_value(t, harness.error.error.kind, async.Error_Kind.Network_Error)
	testing.expect(t, resolving)
	testing.expect_value(t, harness.calls, 0)
	testing.expect_value(t, ws_policy_accepts(harness), 0)
	testing.expect(t, intrinsics.atomic_load(&dns.queries) > 0)
}

Ws_Owa_Conn :: struct {
	handle:      WebSocket_Handle,
	ready:       int,
	peer:        Ws_Peer,
	worker:      ^thread.Thread,
	owner:       ^Ws_Owa,
	open:        WebSocket_Op,
	read:        WebSocket_Op,
	close:       WebSocket_Op,
	dst:         [64]u8,
	messages:    [2][16]u8,
	message_ns:  [2]int,
	open_error:  WebSocket_Error,
	read_error:  WebSocket_Error,
	close_error: WebSocket_Error,
	// Reads the owner submits, one at a time.
	want:        int,
	upgraded:    int,
	reading:     int,
	reads:       int,
	failed:      int,
	closing:     int,
	done:        int,
	clean:       bool,
	listener_up: bool,
}

// The caller's own task on the client's runtime. It submits the reads and is
// otherwise woken for nothing.
Ws_Owa :: struct {
	rt:        async.Runtime,
	task:      async.Task,
	wake:      async.Signal,
	client:    Client,
	conns:     [3]Ws_Owa_Conn,
	count:     int,
	resumes:   int,
	stop:      int,
	task_done: int,
	rt_up:     bool,
	signal_up: bool,
	client_up: bool,
}

ws_owa_resume :: proc(data: rawptr) -> async.Resume_Result {
	owa := cast(^Ws_Owa)data
	intrinsics.atomic_add(&owa.resumes, 1)
	if intrinsics.atomic_load_explicit(&owa.stop, .Acquire) != 0 {
		return .Done
	}

	for &conn in owa.conns[:owa.count] {
		ws_owa_submit(owa, &conn)
	}

	return .Waiting
}

ws_owa_task_done :: proc(data: rawptr) {
	owa := cast(^Ws_Owa)data
	intrinsics.atomic_store_explicit(&owa.task_done, 1, .Release)
}

ws_owa_submit :: proc(owa: ^Ws_Owa, conn: ^Ws_Owa_Conn) {
	if intrinsics.atomic_load_explicit(&conn.ready, .Acquire) == 0 ||
	   intrinsics.atomic_load_explicit(&conn.upgraded, .Acquire) == 0 ||
	   intrinsics.atomic_load_explicit(&conn.reading, .Acquire) != 0 ||
	   intrinsics.atomic_load_explicit(&conn.failed, .Acquire) != 0 ||
	   intrinsics.atomic_load_explicit(&conn.reads, .Acquire) >= conn.want ||
	   conn.open_error.error.kind != .None {
		return
	}

	intrinsics.atomic_store_explicit(&conn.reading, 1, .Release)
	conn.read.callback = ws_owa_on_read
	conn.read.user_data = conn
	error := client_websocket_read(&owa.client, conn.handle, &conn.read, conn.dst[:])
	if error.kind != .None {
		intrinsics.atomic_store_explicit(&conn.failed, 1, .Release)
		intrinsics.atomic_store_explicit(&conn.reading, 0, .Release)
	}
}

ws_owa_on_open :: proc(op: ^WebSocket_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	conn.open_error = op.error
	intrinsics.atomic_store_explicit(&conn.upgraded, 1, .Release)
	_ = async.signal_wake(conn.owner.wake)
}

ws_owa_on_read :: proc(op: ^WebSocket_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	reads := intrinsics.atomic_load_explicit(&conn.reads, .Acquire)

	if op.error.error.kind == .None && reads < len(conn.messages) {
		conn.message_ns[reads] = copy(conn.messages[reads][:], conn.dst[:op.n])
		intrinsics.atomic_store_explicit(&conn.reads, reads + 1, .Release)
	} else {
		conn.read_error = op.error
		intrinsics.atomic_store_explicit(&conn.failed, 1, .Release)

		// Without a close, the failed read is how the session ended.
		if intrinsics.atomic_load_explicit(&conn.closing, .Acquire) == 0 {
			intrinsics.atomic_store_explicit(&conn.done, 1, .Release)
		}
	}

	intrinsics.atomic_store_explicit(&conn.reading, 0, .Release)
	_ = async.signal_wake(conn.owner.wake)
}

ws_owa_on_close :: proc(op: ^WebSocket_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	conn.close_error = op.error
	conn.clean = op.error.close.clean
	intrinsics.atomic_store_explicit(&conn.done, 1, .Release)
}

ws_owa_start :: proc(t: ^testing.T, owa: ^Ws_Owa) -> bool {
	init_error := async.init(&owa.rt, {workers = 2, task_capacity = 8, io_capacity = 32})
	testing.expect_value(t, init_error.kind, .None)
	if init_error.kind != .None {
		return false
	}

	owa.rt_up = true
	owa.task = {
		data    = owa,
		resume  = ws_owa_resume,
		on_done = ws_owa_task_done,
	}

	wake, created := async.signal_create(&owa.rt, &owa.task)
	testing.expect(t, created)
	if !created {
		return false
	}

	owa.wake = wake
	owa.signal_up = true
	spawn_error := async.spawn(&owa.rt, &owa.task)
	testing.expect_value(t, spawn_error.kind, .None)
	if spawn_error.kind != .None {
		return false
	}

	client_error := client_init(&owa.client, &owa.rt, {http = {allow_http = true}}, rt.heap_allocator())
	testing.expect_value(t, client_error.kind, .None)
	owa.client_up = client_error.kind == .None

	return owa.client_up
}

ws_owa_connect :: proc(t: ^testing.T, owa: ^Ws_Owa, mode: Ws_Peer_Mode, want: int, options: WebSocket_Options) -> bool {
	conn := &owa.conns[owa.count]
	owa.count += 1
	conn.owner = owa
	conn.want = want
	conn.peer.mode = mode
	listener, listen_error := net.listen_tcp({net.IP4_Loopback, 0})
	testing.expect(t, listen_error == nil)
	if listen_error != nil {
		return false
	}

	conn.peer.listener = listener
	conn.listener_up = true
	endpoint, bound_error := net.bound_endpoint(listener)
	testing.expect_value(t, bound_error, .None)
	if bound_error != .None {
		return false
	}

	conn.worker = thread.create_and_start_with_poly_data(&conn.peer, ws_peer_serve)
	testing.expect(t, conn.worker != nil)
	if conn.worker == nil {
		return false
	}

	conn.open.callback = ws_owa_on_open
	conn.open.user_data = conn
	url := fmt.tprintf("ws://127.0.0.1:%d/ws", endpoint.port)
	handle, open_error := client_websocket_open(&owa.client, url, options, &conn.open)
	testing.expect_value(t, open_error.kind, .None)
	if open_error.kind != .None {
		return false
	}

	conn.handle = handle
	intrinsics.atomic_store_explicit(&conn.ready, 1, .Release)
	_ = async.signal_wake(owa.wake)

	return true
}

ws_owa_close :: proc(t: ^testing.T, owa: ^Ws_Owa, conn: ^Ws_Owa_Conn) -> bool {
	conn.close.callback = ws_owa_on_close
	conn.close.user_data = conn
	intrinsics.atomic_store_explicit(&conn.closing, 1, .Release)
	error := client_websocket_close(&owa.client, conn.handle, &conn.close, 1000, "bye")
	testing.expect_value(t, error.kind, .None)

	return error.kind == .None && ws_until(t, &conn.done, 1, 5 * time.Second, "close")
}

ws_owa_stop :: proc(owa: ^Ws_Owa) {
	for &conn in owa.conns[:owa.count] {
		intrinsics.atomic_store_explicit(&conn.peer.go, 1, .Release)
	}

	if owa.signal_up {
		intrinsics.atomic_store_explicit(&owa.stop, 1, .Release)
		_ = async.signal_wake(owa.wake)
		start := time.tick_now()
		for intrinsics.atomic_load_explicit(&owa.task_done, .Acquire) == 0 && time.tick_since(start) < 2 * time.Second {
			time.sleep(time.Millisecond)
		}

		async.signal_detach(owa.wake)
		async.signal_release(&owa.wake)
		owa.signal_up = false
	}

	if owa.client_up {
		for &conn in owa.conns[:owa.count] {
			if intrinsics.atomic_load_explicit(&conn.ready, .Acquire) != 0 {
				_ = client_websocket_release(&owa.client, conn.handle)
			}
		}

		_ = client_close(&owa.client)
		start := time.tick_now()
		for !client_quiescent(&owa.client) && time.tick_since(start) < 5 * time.Second {
			time.sleep(time.Millisecond)
		}

		_ = client_destroy(&owa.client)
		owa.client_up = false
	}

	if owa.rt_up {
		_ = async.destroy(&owa.rt)
		owa.rt_up = false
	}

	for &conn in owa.conns[:owa.count] {
		if conn.listener_up {
			net.close(conn.peer.listener)
			conn.listener_up = false
		}

		if conn.worker != nil {
			thread.destroy(conn.worker)
			conn.worker = nil
		}
	}
}

ws_owa_options :: proc() -> WebSocket_Options {
	return {handshake_timeout = 5 * time.Second, close_timeout = 500 * time.Millisecond}
}

// The read stays pending while the caller's task is woken for other reasons,
// then completes with each whole message in order.
@(test)
websocket_read_survives_unrelated_wakes :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	owa := new(Ws_Owa)
	defer free(owa)
	defer ws_owa_stop(owa)
	if !ws_owa_start(t, owa) || !ws_owa_connect(t, owa, .Wakes, 2, ws_owa_options()) {
		return
	}

	start_error := async.start(&owa.rt)
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return
	}

	conn := &owa.conns[0]
	if !ws_until(t, &conn.reading, 1, 5 * time.Second, "the read") {
		return
	}

	for _ in 0 ..< 5 {
		before := intrinsics.atomic_load(&owa.resumes)
		_ = async.signal_wake(owa.wake)
		if !ws_until(t, &owa.resumes, before + 1, 2 * time.Second, "a wake") {
			return
		}

		time.sleep(20 * time.Millisecond)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reading), 1)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reads), 0)
		testing.expect_value(t, intrinsics.atomic_load(&conn.failed), 0)
	}

	intrinsics.atomic_store_explicit(&conn.peer.go, 1, .Release)
	if !ws_until(t, &conn.reads, 2, 5 * time.Second, "both messages") {
		return
	}

	testing.expect_value(t, string(conn.messages[0][:conn.message_ns[0]]), "first")
	testing.expect_value(t, string(conn.messages[1][:conn.message_ns[1]]), "second")
	testing.expect_value(t, conn.read_error.error.kind, async.Error_Kind.None)
	if !ws_owa_close(t, owa, conn) {
		return
	}

	testing.expect_value(t, conn.close_error.error.kind, async.Error_Kind.None)
	testing.expect(t, conn.clean)
	ws_owa_stop(owa)
	testing.expect_value(t, conn.peer.status, WS_PEER_OK)
}

// One configuration: a stalled message or frame ends its session, an idle
// session whose peer answers Pings outlives every one of those bounds.
@(test)
websocket_stalled_message_times_out_and_idle_session_stays_open :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	owa := new(Ws_Owa)
	defer free(owa)
	defer ws_owa_stop(owa)
	options := ws_owa_options()
	options.idle_timeout = time.Second
	options.ping_interval = 250 * time.Millisecond
	options.frame_timeout = 400 * time.Millisecond
	options.message_timeout = 400 * time.Millisecond
	if !ws_owa_start(t, owa) ||
	   !ws_owa_connect(t, owa, .Stall_Message, 1, options) ||
	   !ws_owa_connect(t, owa, .Stall_Frame, 1, options) ||
	   !ws_owa_connect(t, owa, .Idle, 1, options) {
		return
	}

	start_error := async.start(&owa.rt)
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return
	}

	idle := &owa.conns[2]
	if !ws_until(t, &idle.reading, 1, 5 * time.Second, "the idle read") {
		return
	}

	opened := time.tick_now()
	for i in 0 ..< 2 {
		conn := &owa.conns[i]
		if !ws_until(t, &conn.failed, 1, 5 * time.Second, "the stalled read") {
			return
		}

		testing.expect_value(t, conn.open_error.error.kind, async.Error_Kind.None)
		testing.expect_value(t, conn.read_error.error.kind, async.Error_Kind.Timeout)
		testing.expect_value(t, conn.read_error.close.code, 1001)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reads), 0)
		testing.expect_value(t, intrinsics.atomic_load(&conn.done), 1)
	}

	for time.tick_since(opened) < 2 * time.Second {
		time.sleep(10 * time.Millisecond)
	}

	testing.expect_value(t, intrinsics.atomic_load(&idle.reading), 1)
	testing.expect_value(t, intrinsics.atomic_load(&idle.failed), 0)
	testing.expect_value(t, intrinsics.atomic_load(&idle.done), 0)
	testing.expect(t, intrinsics.atomic_load(&idle.peer.pings) >= 2)
	if !ws_owa_close(t, owa, idle) {
		return
	}

	testing.expect_value(t, idle.read_error.error.kind, async.Error_Kind.Closed)
	testing.expect_value(t, idle.close_error.error.kind, async.Error_Kind.None)
	testing.expect(t, idle.clean)
}
