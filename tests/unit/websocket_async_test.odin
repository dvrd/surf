package surf

import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/legacy/sha1"
import "core:encoding/base64"
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

Ws_Test :: struct {
	session:                                                    WebSocket_Async,
	rt:                                                         async.Runtime,
	peer:                                                       Ws_Peer,
	upgrade:                                                    WebSocket_Async_Op,
	read:                                                       WebSocket_Async_Op,
	write_a:                                                    WebSocket_Async_Op,
	write_b:                                                    WebSocket_Async_Op,
	close:                                                      WebSocket_Async_Op,
	protocols:                                                  [1]string,
	src:                                                        [32]u8,
	dst:                                                        [128]u8,
	payload6:                                                   [6]u8,
	payload1:                                                   [1]u8,
	write_text:                                                 string,
	expect_read:                                                string,
	upgrade_error, read_error, write_error, close_error:        WebSocket_Async_Error,
	write_errors:                                               [2]WebSocket_Async_Error,
	write_ns:                                                   [2]int,
	reject_bytes, reject_count, reject_utf8, reject_size:       WebSocket_Async_Error_Kind,
	read_opcode:                                                async.WS_Message_Kind,
	src_n, read_n, write_n, saw_upgrade, saw_read, saw_write:   int,
	saw_close, write_count, done:                               int,
	read_ok, write_ok, read_is_text, close_once, clean:         bool,
	phase:                                                      WebSocket_Async_Phase,
	rt_up, listener_up:                                         bool,
	worker:                                                     ^thread.Thread,
	policy_host:                                                string,
	policy_endpoint:                                            net.Endpoint,
	policy_calls:                                               int,
}

@(test)
websocket_async_bind_rejects_bad_config_and_ignores_close_cancel :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)
	marker := 1
	session := new(WebSocket_Async)
	defer free(session)
	session.user = &marker
	session.route.address[0] = 0xAB
	rt_value: async.Runtime
	testing.expect_value(t, websocket_async_bind(nil, &rt_value, {}).kind, .Invalid_Config)
	testing.expect_value(t, websocket_async_bind(session, nil, {}).kind, .Invalid_Config)
	bad := WebSocket_Async_Config {
		endpoint = {address = net.IP4_Loopback, port = 9},
		host     = "127.0.0.1",
	}

	bad.max_message_size = -1
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_message_size = 0
	bad.max_frame_payload = async.WS_MAX_MESSAGE_BYTES + 1
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_frame_payload = 0
	bad.max_fragments = 65537
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_fragments = 0
	bad.handshake_timeout = -time.Second
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.handshake_timeout = 0
	bad.target = "ws"
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.target = ""
	pool: async.Root_Pool
	bad.roots = &pool
	bad.host = "[::1]:443"
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.roots = nil
	bad.host = ""
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.host = "127.0.0.1"
	bad.idle_timeout = 25 * time.Hour
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.idle_timeout = 0
	bad.message_timeout = -time.Second
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.message_timeout = 0
	bad.ping_interval = 25 * time.Hour
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.ping_interval = 0
	bad.endpoint = {}
	bad.port = 65536
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.port = 0
	bad.host = ":80"
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	testing.expect(t, session.user == &marker && session.route.address[0] == 0xAB && !session.bound)
	good := WebSocket_Async_Config {
		endpoint = {address = net.IP4_Loopback, port = 9},
		host     = "127.0.0.1",
	}

	testing.expect_value(t, websocket_async_bind(session, &rt_value, good).kind, .None)
	testing.expect(t, session.bound && session.user == &marker)
	testing.expect_value(t, string(session.route.address[:session.route.address_n]), "127.0.0.1")
	testing.expect_value(t, websocket_async_bind(session, &rt_value, good).kind, .Invalid_Config)
	op: WebSocket_Async_Op
	op.callback = ws_on_upgrade
	op.user_data = session
	testing.expect_value(t, websocket_async_write(session, &op, .Text, []u8{'a'}).kind, .Invalid_State)
	testing.expect_value(t, websocket_async_read(session, &op, nil).kind, .Invalid_State)
	testing.expect_value(t, websocket_async_close(session, &op).kind, .Invalid_State)
	pending := WebSocket_Async_Op {
		pending = true,
		kind    = .Close,
	}

	testing.expect_value(t, websocket_async_cancel(session, &pending).kind, .Invalid_State)
	testing.expect(t, pending.pending)
}

@(test)
websocket_async_fragments_ping_and_echo :: proc(t: ^testing.T) {
	ws_run(t, .Echo)
}

@(test)
websocket_async_bounds_queue_and_message :: proc(t: ^testing.T) {
	ws_run(t, .Queue)
}

@(test)
websocket_async_upgrade_authentication_rejected :: proc(t: ^testing.T) {
	ws_run(t, .Bad_Accept)
	if testing.failed(t) {
		return
	}

	ws_run(t, .Unauthorized)
}

@(test)
websocket_async_invalid_utf8_and_masked_server_frame :: proc(t: ^testing.T) {
	ws_run(t, .Bad_UTF8)
	if testing.failed(t) {
		return
	}

	ws_run(t, .Masked)
}

@(test)
websocket_async_message_too_big :: proc(t: ^testing.T) {
	ws_run(t, .Too_Big)
}

@(test)
websocket_async_slow_peer_times_out :: proc(t: ^testing.T) {
	ws_run(t, .Slow)
}

@(test)
websocket_async_cancel_during_upgrade :: proc(t: ^testing.T) {
	ws_run(t, .Cancel)
}

@(test)
websocket_async_dials_localhost_from_the_hosts_file :: proc(t: ^testing.T) {
	ws_run(t, .Echo, true)
}

@(test)
websocket_async_tls_loopback_by_endpoint_and_by_name :: proc(t: ^testing.T) {
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

	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = port,
	}

	ws_tls_echo(t, endpoint, pool)
	if testing.failed(t) {
		return
	}

	ws_tls_wrong_host(t, endpoint, pool)
	if testing.failed(t) {
		return
	}

	ws_tls_named(t, port, pool)
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

	cfg := ws_case_config(h, endpoint, mode)
	if named {
		cfg.endpoint = {}
		cfg.host = "localhost"
		cfg.port = endpoint.port
		cfg.address_policy = ws_named_policy
		cfg.address_policy_data = h
	}

	if !ws_client_start(t, h, cfg) {
		return
	}

	if mode == .Cancel && !ws_cancel_when_accepted(t, h) {
		return
	}

	if !ws_wait(t, h, 8 * time.Second) {
		return
	}

	ws_test_stop(h)
	ws_expect_case(t, h, mode)
	if named {
		v4, ok := h.policy_endpoint.address.(net.IP4_Address)
		testing.expect_value(t, h.policy_calls, 1)
		testing.expect_value(t, h.policy_host, "localhost")
		testing.expect(t, ok && v4 == net.IP4_Loopback)
		testing.expect_value(t, h.policy_endpoint.port, endpoint.port)
	}
}

ws_named_policy :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	h := cast(^Ws_Test)user
	h.policy_calls += 1
	h.policy_host = host
	if len(addresses) > 0 {
		h.policy_endpoint = addresses[0]
	}

	return true
}

ws_case_config :: proc(h: ^Ws_Test, endpoint: net.Endpoint, mode: Ws_Peer_Mode) -> WebSocket_Async_Config {
	h.protocols[0] = "chat"
	cfg := WebSocket_Async_Config {
		endpoint          = endpoint,
		host              = "127.0.0.1",
		target            = "/ws",
		subprotocols      = h.protocols[:],
		handshake_timeout = 5 * time.Second,
		idle_timeout      = 5 * time.Second,
		write_timeout     = 5 * time.Second,
		close_timeout     = time.Second,
	}

	switch mode {
	case .Echo:
		cfg.max_frame_payload = 5
		h.write_text = "hello-from-client"
		h.expect_read = "hello-from-server"
	case .Queue:
		cfg.max_message_size = 16
		cfg.max_queued_bytes = 8
	case .Too_Big:
		cfg.max_message_size = 16
	case .Slow:
		cfg.handshake_timeout = time.Second
	case .Bad_Accept, .Unauthorized, .Bad_UTF8, .Masked, .Cancel, .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}

	return cfg
}

ws_client_start :: proc(t: ^testing.T, h: ^Ws_Test, cfg: WebSocket_Async_Config) -> bool {
	init_error := async.init(&h.rt, {workers = 1, task_capacity = 4, io_capacity = 16})
	testing.expect_value(t, init_error.kind, .None)
	if init_error.kind != .None {
		return false
	}

	h.rt_up = true
	h.session.user = h
	saved := context.allocator
	context.allocator = rt.heap_allocator()
	bind_error := websocket_async_bind(&h.session, &h.rt, cfg, ws_on_done)
	context.allocator = saved
	testing.expect_value(t, bind_error.kind, .None)
	if bind_error.kind != .None {
		return false
	}

	h.upgrade.callback = ws_on_upgrade
	h.upgrade.user_data = h
	submit_error := websocket_async_upgrade(&h.session, &h.upgrade)
	testing.expect_value(t, submit_error.kind, .None)
	if submit_error.kind != .None {
		return false
	}

	spawn_error := async.spawn(&h.rt, &h.session.task)
	testing.expect_value(t, spawn_error.kind, .None)
	if spawn_error.kind != .None {
		return false
	}

	start_error := async.start(&h.rt)
	testing.expect_value(t, start_error.kind, .None)

	return start_error.kind == .None
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
	cancel_error := websocket_async_cancel(&h.session, &h.upgrade)
	testing.expect_value(t, cancel_error.kind, .None)

	return cancel_error.kind == .None
}

ws_wait :: proc(t: ^testing.T, h: ^Ws_Test, limit: time.Duration) -> bool {
	start := time.tick_now()

	for intrinsics.atomic_load_explicit(&h.done, .Acquire) == 0 {
		if time.tick_since(start) > limit {
			testing.expect(t, false, "websocket session did not finish")
			return false
		}

		thread.yield()
	}

	return true
}

ws_test_stop :: proc(h: ^Ws_Test) {
	if h.listener_up {
		net.close(h.peer.listener)
		h.listener_up = false
	}

	if h.rt_up {
		_ = async.destroy(&h.rt)
		h.rt_up = false
	}

	if h.worker != nil {
		thread.destroy(h.worker)
		h.worker = nil
	}
}

ws_expect_terminal :: proc(t: ^testing.T, h: ^Ws_Test) {
	testing.expect_value(t, h.phase, .Ended)
	testing.expect_value(t, h.saw_upgrade, 1)
}

ws_expect_case :: proc(t: ^testing.T, h: ^Ws_Test, mode: Ws_Peer_Mode) {
	ws_expect_terminal(t, h)

	switch mode {
	case .Echo:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect(t, ws_bytes_equal(h.peer.text[:h.peer.text_n], "hello-from-client"))
		testing.expect(t, h.peer.continuations >= 1 && h.peer.pongs >= 1 && h.peer.closes >= 1)
		testing.expect(t, h.read_ok && h.read_is_text && h.write_ok)
		testing.expect_value(t, h.write_n, len("hello-from-client"))
		testing.expect(t, h.clean && h.saw_close == 1 && h.close_error.kind == .None)
		testing.expect(t, websocket_async_subprotocol(&h.session) == "chat")
	case .Queue:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.reject_bytes, .Queue_Full)
		testing.expect_value(t, h.reject_count, .Queue_Full)
		testing.expect_value(t, h.reject_utf8, .Invalid_UTF8)
		testing.expect_value(t, h.reject_size, .Message_Oversized)
		testing.expect_value(t, h.write_count, 2)
		testing.expect_value(t, h.write_errors[0].kind, .None)
		testing.expect_value(t, h.write_errors[1].kind, .None)
		testing.expect_value(t, h.write_ns[0], 6)
		testing.expect_value(t, h.write_ns[1], 1)
		testing.expect_value(t, h.peer.texts, 2)
		testing.expect_value(t, h.read_error.kind, .Closed)
		testing.expect_value(t, h.read_error.close.peer_code, 1000)
		testing.expect(t, h.clean && h.close_error.kind == .None)
		testing.expect(t, websocket_async_subprotocol(&h.session) == "chat")
	case .Bad_Accept:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Upgrade_Failed)
		testing.expect_value(t, h.upgrade_error.close.upgrade, .Invalid_Accept)
		testing.expect(t, !h.clean)
	case .Unauthorized:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Upgrade_Failed)
		testing.expect_value(t, h.upgrade_error.close.upgrade, .Invalid_Status)
		testing.expect_value(t, h.upgrade_error.close.status, 401)
		testing.expect(t, !h.clean)
	case .Bad_UTF8:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .None)
		testing.expect_value(t, h.read_error.kind, .Invalid_UTF8)
		testing.expect_value(t, h.read_error.close.code, 1007)
		testing.expect(t, !h.clean)
	case .Masked:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .None)
		testing.expect_value(t, h.read_error.kind, .Protocol_Failed)
		testing.expect_value(t, h.read_error.close.frame, .Unexpected_Masking)
		testing.expect(t, !h.clean)
	case .Too_Big:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .None)
		testing.expect_value(t, h.read_error.kind, .Message_Oversized)
		testing.expect_value(t, h.read_error.close.code, 1009)
		testing.expect(t, !h.clean)
	case .Slow:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Timeout)
		testing.expect(t, !h.clean)
	case .Cancel:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Cancelled)
		testing.expect(t, !h.clean)
	case .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}
}

ws_tls_echo :: proc(t: ^testing.T, endpoint: net.Endpoint, roots: ^async.Root_Pool) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Echo
	h.protocols[0] = "chat"
	h.write_text = "hello-tls"
	h.expect_read = "hello-tls"
	cfg := WebSocket_Async_Config {
		endpoint          = endpoint,
		host              = "localhost",
		target            = "/ws",
		server_name       = "localhost",
		subprotocols      = h.protocols[:],
		roots             = roots,
		max_frame_payload = 4,
		handshake_timeout = 5 * time.Second,
		idle_timeout      = 5 * time.Second,
		write_timeout     = 5 * time.Second,
		close_timeout     = 2 * time.Second,
	}

	ws_tls_echo_run(t, h, cfg)
}

// secure with explicit roots, dialing localhost by name.
ws_tls_named :: proc(t: ^testing.T, port: int, roots: ^async.Root_Pool) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Echo
	h.protocols[0] = "chat"
	h.write_text = "hello-name"
	h.expect_read = "hello-name"
	cfg := WebSocket_Async_Config {
		host              = "LocalHost",
		port              = port,
		target            = "/ws",
		subprotocols      = h.protocols[:],
		secure            = true,
		roots             = roots,
		handshake_timeout = 5 * time.Second,
		close_timeout     = 2 * time.Second,
	}

	ws_tls_echo_run(t, h, cfg)
	testing.expect_value(t, string(h.session.route.address[:h.session.route.address_n]), "127.0.0.1")
}

ws_tls_echo_run :: proc(t: ^testing.T, h: ^Ws_Test, cfg: WebSocket_Async_Config) {
	if !ws_client_start(t, h, cfg) {
		return
	}

	if !ws_wait(t, h, 10 * time.Second) {
		return
	}

	ws_test_stop(h)
	ws_expect_terminal(t, h)
	testing.expect_value(t, h.upgrade_error.kind, .None)
	testing.expect(t, h.read_ok && h.read_is_text && h.write_ok && h.clean)
	testing.expect(t, websocket_async_subprotocol(&h.session) == "chat")
	testing.expect_value(t, h.close_error.kind, .None)
}

// secure without roots verifies against the platform's roots, which do not
// hold the test root.
ws_tls_platform_roots :: proc(t: ^testing.T, port: int) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Bad_Accept
	cfg := WebSocket_Async_Config {
		host              = "localhost",
		port              = port,
		target            = "/ws",
		secure            = true,
		handshake_timeout = 5 * time.Second,
		close_timeout     = time.Second,
	}

	if !ws_client_start(t, h, cfg) {
		return
	}

	if !ws_wait(t, h, 10 * time.Second) {
		return
	}

	ws_test_stop(h)
	ws_expect_terminal(t, h)
	testing.expect_value(t, h.upgrade_error.kind, .TLS_Failed)
	testing.expect(t, h.upgrade_error.tls_error != nil)
	testing.expect(t, h.saw_read == 0 && !h.clean)
}

ws_tls_wrong_host :: proc(t: ^testing.T, endpoint: net.Endpoint, roots: ^async.Root_Pool) {
	h := new(Ws_Test)
	defer free(h)
	defer ws_test_stop(h)
	h.peer.mode = .Bad_Accept
	cfg := WebSocket_Async_Config {
		endpoint          = endpoint,
		host              = "localhost",
		target            = "/ws",
		server_name       = "wrong.example",
		roots             = roots,
		handshake_timeout = 5 * time.Second,
		close_timeout     = time.Second,
	}

	if !ws_client_start(t, h, cfg) {
		return
	}

	if !ws_wait(t, h, 10 * time.Second) {
		return
	}

	ws_test_stop(h)
	ws_expect_terminal(t, h)
	testing.expect_value(t, h.upgrade_error.kind, .TLS_Failed)
	testing.expect(t, h.upgrade_error.tls_error != nil)
	testing.expect(t, h.saw_read == 0 && !h.clean)
}

ws_on_done :: proc(data: rawptr) {
	session := cast(^WebSocket_Async)data
	h := cast(^Ws_Test)session.user
	h.clean = session.ended.clean
	h.phase = session.phase
	intrinsics.atomic_store_explicit(&h.done, 1, .Release)
}

ws_on_upgrade :: proc(op: ^WebSocket_Async_Op) {
	h := cast(^Ws_Test)op.user_data
	h.upgrade_error = op.error
	h.saw_upgrade = 1
	if op.error.kind != .None {
		return
	}

	switch h.peer.mode {
	case .Echo:
		h.src_n = copy(h.src[:], h.write_text)
		h.write_a.callback = ws_on_write
		h.write_a.user_data = h
		_ = websocket_async_write(&h.session, &h.write_a, .Text, h.src[:h.src_n])
		h.read.callback = ws_on_read
		h.read.user_data = h
		_ = websocket_async_read(&h.session, &h.read, h.dst[:])
	case .Queue:
		ws_queue_probe(h)
	case .Bad_UTF8, .Masked, .Too_Big:
		h.read.callback = ws_on_read
		h.read.user_data = h
		_ = websocket_async_read(&h.session, &h.read, h.dst[:])
	case .Bad_Accept, .Unauthorized, .Slow, .Cancel, .Wakes, .Stall_Message, .Stall_Frame, .Idle:
	}
}

// Runs on the session task, so nothing queued here is handed to the session
// before the last write is checked.
ws_queue_probe :: proc(h: ^Ws_Test) {
	for i in 0 ..< len(h.payload6) {
		h.payload6[i] = 'a'
	}

	h.payload1[0] = 'b'
	h.write_a.callback = ws_on_write
	h.write_a.user_data = h
	h.write_b.callback = ws_on_write
	h.write_b.user_data = h
	first := websocket_async_write(&h.session, &h.write_a, .Text, h.payload6[:])
	h.reject_bytes = websocket_async_write(&h.session, &h.write_b, .Text, h.payload6[:4]).kind
	second := websocket_async_write(&h.session, &h.write_b, .Text, h.payload1[:])
	extra: WebSocket_Async_Op
	extra.callback = ws_on_write
	extra.user_data = h
	// Every write below is rejected, and a rejected operation is never queued: the stack operation ends here.
	rejected := (^WebSocket_Async_Op)(rawptr(&extra))
	h.reject_count = websocket_async_write(&h.session, rejected, .Text, h.payload6[:2]).kind
	bad := [1]u8{0xff}
	h.reject_utf8 = websocket_async_write(&h.session, rejected, .Text, bad[:]).kind
	big: [20]u8
	h.reject_size = websocket_async_write(&h.session, rejected, .Text, big[:]).kind

	if first.kind != .None || second.kind != .None {
		h.reject_bytes = first.kind if first.kind != .None else second.kind
	}

	h.read.callback = ws_on_read
	h.read.user_data = h
	_ = websocket_async_read(&h.session, &h.read, h.dst[:])
	ws_submit_close(h)
}

ws_on_read :: proc(op: ^WebSocket_Async_Op) {
	h := cast(^Ws_Test)op.user_data
	h.read_error = op.error
	h.read_n = op.n
	h.read_opcode = op.opcode
	h.saw_read = 1

	if h.peer.mode == .Echo && op.error.kind == .None {
		h.read_ok = ws_bytes_equal(h.dst[:op.n], h.expect_read)
		h.read_is_text = op.opcode == .Text
	}

	if h.read_ok && h.write_ok {
		ws_submit_close(h)
	}
}

ws_on_write :: proc(op: ^WebSocket_Async_Op) {
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
	h.write_ok = op.error.kind == .None && op.n == h.src_n
	if h.read_ok && h.write_ok {
		ws_submit_close(h)
	}
}

ws_on_close :: proc(op: ^WebSocket_Async_Op) {
	h := cast(^Ws_Test)op.user_data
	h.close_error = op.error
	h.saw_close = 1
}

ws_submit_close :: proc(h: ^Ws_Test) {
	if h.close_once {
		return
	}

	h.close_once = true
	h.close.callback = ws_on_close
	h.close.user_data = h
	_ = websocket_async_close(&h.session, &h.close, 1000, "bye")
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

Ws_Policy_Harness :: struct {
	session:  WebSocket_Async,
	runtime:  async.Runtime,
	upgrade:  WebSocket_Async_Op,
	error:    WebSocket_Async_Error,
	done:     int,
	calls:    int,
	host:     string,
	endpoint: net.Endpoint,
	allow:    bool,
	listener: net.TCP_Socket,
	accepts:  int,
	mu:       sync.Mutex,
	started:  bool,
}

ws_policy_done :: proc(data: rawptr) {
	session := cast(^WebSocket_Async)data
	harness := cast(^Ws_Policy_Harness)session.user
	intrinsics.atomic_store_explicit(&harness.done, 1, .Release)
}

ws_policy_upgrade :: proc(op: ^WebSocket_Async_Op) {
	harness := cast(^Ws_Policy_Harness)op.user_data
	harness.error = op.error
}

ws_policy_decide :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	harness := cast(^Ws_Policy_Harness)user
	harness.calls += 1
	harness.host = host

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
	if harness.started {
		async.shutdown(&harness.runtime)
		_ = async.join(&harness.runtime)
	}

	_ = async.destroy(&harness.runtime)
	net.close(harness.listener)

	if worker != nil {
		thread.destroy(worker)
	}
}

// With name_servers, the session dials nowhere.invalid at the listener's port
// and asks only those servers.
ws_policy_run :: proc(
	t: ^testing.T,
	allow: bool,
	name_servers: []net.Endpoint = nil,
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
	worker = thread.create_and_start_with_poly_data(harness, ws_policy_accept)
	testing.expect(t, worker != nil)

	if worker == nil {
		net.close(listener)
		free(harness)
		return nil, nil, false
	}

	init_error := async.init(&harness.runtime, {workers = 1, task_capacity = 4, io_capacity = 16})
	testing.expect_value(t, init_error.kind, .None)

	if init_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.session.user = harness
	config := WebSocket_Async_Config {
		endpoint            = endpoint,
		host                = "ws.example",
		handshake_timeout   = 2 * time.Second,
		address_policy      = ws_policy_decide,
		address_policy_data = harness,
	}

	if name_servers != nil {
		config.endpoint = {}
		config.host = "nowhere.invalid"
		config.port = endpoint.port
		config.resolver.name_servers = name_servers
	}

	bind_error := websocket_async_bind(&harness.session, &harness.runtime, config, ws_policy_done)
	testing.expect_value(t, bind_error.kind, .None)

	if bind_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.upgrade.callback = ws_policy_upgrade
	harness.upgrade.user_data = harness
	submit_error := websocket_async_upgrade(&harness.session, &harness.upgrade)
	testing.expect_value(t, submit_error.kind, .None)

	if submit_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	spawn_error := async.spawn(&harness.runtime, &harness.session.task)
	testing.expect_value(t, spawn_error.kind, .None)

	if spawn_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	start_error := async.start(&harness.runtime)
	testing.expect_value(t, start_error.kind, .None)

	if start_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.started = true

	return harness, worker, true
}

ws_policy_wait :: proc(t: ^testing.T, harness: ^Ws_Policy_Harness) {
	deadline := time.tick_now()

	for intrinsics.atomic_load_explicit(&harness.done, .Acquire) == 0 {
		if time.tick_since(deadline) > 8 * time.Second {
			testing.expect(t, false)
			return
		}

		time.sleep(time.Millisecond)
	}
}

@(test)
websocket_async_rejects_the_endpoint_before_connect :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	harness, worker, ok := ws_policy_run(t, false)

	if !ok {
		return
	}

	defer {
		ws_policy_finish(harness, worker)
		free(harness)
	}

	ws_policy_wait(t, harness)
	testing.expect_value(t, harness.error.kind, .Address_Rejected)
	testing.expect_value(t, harness.calls, 1)
	testing.expect_value(t, harness.host, "ws.example")
	testing.expect(t, ws_policy_loopback(harness))
	testing.expect(t, harness.endpoint.port > 0)
	testing.expect_value(t, ws_policy_accepts(harness), 0)
}

@(test)
websocket_async_connects_to_the_endpoint_the_policy_checked :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	harness, worker, ok := ws_policy_run(t, true)

	if !ok {
		return
	}

	defer {
		ws_policy_finish(harness, worker)
		free(harness)
	}

	ws_policy_wait(t, harness)
	testing.expect(t, harness.error.kind != .Address_Rejected)
	testing.expect(t, harness.error.kind != .None)
	testing.expect_value(t, harness.calls, 1)
	testing.expect_value(t, harness.host, "ws.example")
	testing.expect(t, ws_policy_loopback(harness))
	testing.expect(t, harness.endpoint.port > 0)
	testing.expect_value(t, ws_policy_accepts(harness), 1)
}

Ws_Dns :: struct {
	socket:  net.UDP_Socket,
	queries: int,
	stop:    int,
}

// Answers every query with NXDOMAIN.
ws_dns_serve :: proc(dns: ^Ws_Dns) {
	buf: [512]u8

	for intrinsics.atomic_load_explicit(&dns.stop, .Acquire) == 0 {
		n, from, err := net.recv_udp(dns.socket, buf[:])
		if err != nil || n < 12 {
			continue
		}

		intrinsics.atomic_add(&dns.queries, 1)
		buf[2] |= 0x80
		buf[3] = 0x83
		_, _ = net.send_udp(dns.socket, buf[:n], from)
	}
}

@(test)
websocket_async_unresolvable_name_fails_before_connect :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns := new(Ws_Dns)
	defer free(dns)
	socket, socket_error := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	testing.expect(t, socket_error == nil)
	if socket_error != nil {
		return
	}

	dns.socket = socket
	defer net.close(socket)
	_ = net.set_option(socket, .Receive_Timeout, 50 * time.Millisecond)
	server, bound_error := net.bound_endpoint(socket)
	testing.expect(t, bound_error == nil)
	if bound_error != nil {
		return
	}

	dns_worker := thread.create_and_start_with_poly_data(dns, ws_dns_serve)
	testing.expect(t, dns_worker != nil)
	if dns_worker == nil {
		return
	}

	defer {
		intrinsics.atomic_store_explicit(&dns.stop, 1, .Release)
		thread.destroy(dns_worker)
	}

	servers := [1]net.Endpoint{server}
	harness, worker, ok := ws_policy_run(t, true, servers[:])
	if !ok {
		return
	}

	defer {
		ws_policy_finish(harness, worker)
		free(harness)
	}

	ws_policy_wait(t, harness)
	testing.expect_value(t, harness.error.kind, .Resolve_Failed)
	testing.expect_value(t, harness.calls, 0)
	testing.expect_value(t, ws_policy_accepts(harness), 0)
	testing.expect(t, intrinsics.atomic_load(&dns.queries) > 0)
}

Ws_Owa_Conn :: struct {
	session:       WebSocket_Async,
	peer:          Ws_Peer,
	worker:        ^thread.Thread,
	owner:         ^Ws_Owa,
	upgrade:       WebSocket_Async_Op,
	read:          WebSocket_Async_Op,
	close:         WebSocket_Async_Op,
	dst:           [64]u8,
	messages:      [2][16]u8,
	message_ns:    [2]int,
	upgrade_error: WebSocket_Async_Error,
	read_error:    WebSocket_Async_Error,
	close_error:   WebSocket_Async_Error,
	// Reads the owner submits, one at a time.
	want:          int,
	upgraded:      int,
	reading:       int,
	reads:         int,
	failed:        int,
	closed:        int,
	done:          int,
	clean:         bool,
	listener_up:   bool,
}

// The caller's own task on the session's runtime. It submits the reads and is
// otherwise woken for nothing.
Ws_Owa :: struct {
	rt:        async.Runtime,
	task:      async.Task,
	wake:      async.Signal,
	conns:     [3]Ws_Owa_Conn,
	count:     int,
	resumes:   int,
	stop:      int,
	task_done: int,
	rt_up:     bool,
	signal_up: bool,
}

ws_owa_resume :: proc(data: rawptr) -> async.Resume_Result {
	owa := cast(^Ws_Owa)data
	intrinsics.atomic_add(&owa.resumes, 1)
	if intrinsics.atomic_load_explicit(&owa.stop, .Acquire) != 0 {
		return .Done
	}

	for &conn in owa.conns[:owa.count] {
		ws_owa_submit(&conn)
	}

	return .Waiting
}

ws_owa_task_done :: proc(data: rawptr) {
	owa := cast(^Ws_Owa)data
	intrinsics.atomic_store_explicit(&owa.task_done, 1, .Release)
}

ws_owa_submit :: proc(conn: ^Ws_Owa_Conn) {
	if intrinsics.atomic_load_explicit(&conn.upgraded, .Acquire) == 0 ||
	   intrinsics.atomic_load_explicit(&conn.reading, .Acquire) != 0 ||
	   intrinsics.atomic_load_explicit(&conn.failed, .Acquire) != 0 ||
	   intrinsics.atomic_load_explicit(&conn.reads, .Acquire) >= conn.want ||
	   conn.upgrade_error.kind != .None {
		return
	}

	intrinsics.atomic_store_explicit(&conn.reading, 1, .Release)
	conn.read.callback = ws_owa_on_read
	conn.read.user_data = conn
	error := websocket_async_read(&conn.session, &conn.read, conn.dst[:])
	if error.kind != .None {
		conn.read_error = error
		intrinsics.atomic_store_explicit(&conn.failed, 1, .Release)
		intrinsics.atomic_store_explicit(&conn.reading, 0, .Release)
	}
}

ws_owa_on_upgrade :: proc(op: ^WebSocket_Async_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	conn.upgrade_error = op.error
	intrinsics.atomic_store_explicit(&conn.upgraded, 1, .Release)
	_ = async.signal_wake(conn.owner.wake)
}

ws_owa_on_read :: proc(op: ^WebSocket_Async_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	reads := intrinsics.atomic_load_explicit(&conn.reads, .Acquire)

	if op.error.kind == .None && reads < len(conn.messages) {
		conn.message_ns[reads] = copy(conn.messages[reads][:], conn.dst[:op.n])
		intrinsics.atomic_store_explicit(&conn.reads, reads + 1, .Release)
	} else {
		conn.read_error = op.error
		intrinsics.atomic_store_explicit(&conn.failed, 1, .Release)
	}

	intrinsics.atomic_store_explicit(&conn.reading, 0, .Release)
	_ = async.signal_wake(conn.owner.wake)
}

ws_owa_on_close :: proc(op: ^WebSocket_Async_Op) {
	conn := cast(^Ws_Owa_Conn)op.user_data
	conn.close_error = op.error
	intrinsics.atomic_store_explicit(&conn.closed, 1, .Release)
}

ws_owa_on_done :: proc(data: rawptr) {
	session := cast(^WebSocket_Async)data
	conn := cast(^Ws_Owa_Conn)session.user
	conn.clean = session.ended.clean
	intrinsics.atomic_store_explicit(&conn.done, 1, .Release)
}

ws_owa_until :: proc(t: ^testing.T, flag: ^int, value: int, limit: time.Duration, what: string) -> bool {
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

	return spawn_error.kind == .None
}

ws_owa_connect :: proc(
	t: ^testing.T,
	owa: ^Ws_Owa,
	mode: Ws_Peer_Mode,
	want: int,
	config: WebSocket_Async_Config,
) -> bool {
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

	cfg := config
	cfg.endpoint = endpoint
	conn.session.user = conn
	saved := context.allocator
	context.allocator = rt.heap_allocator()
	bind_error := websocket_async_bind(&conn.session, &owa.rt, cfg, ws_owa_on_done)
	context.allocator = saved
	testing.expect_value(t, bind_error.kind, .None)
	if bind_error.kind != .None {
		return false
	}

	conn.upgrade.callback = ws_owa_on_upgrade
	conn.upgrade.user_data = conn
	submit_error := websocket_async_upgrade(&conn.session, &conn.upgrade)
	testing.expect_value(t, submit_error.kind, .None)
	if submit_error.kind != .None {
		return false
	}

	spawn_error := async.spawn(&owa.rt, &conn.session.task)
	testing.expect_value(t, spawn_error.kind, .None)

	return spawn_error.kind == .None
}

ws_owa_close :: proc(t: ^testing.T, conn: ^Ws_Owa_Conn) -> bool {
	conn.close.callback = ws_owa_on_close
	conn.close.user_data = conn
	error := websocket_async_close(&conn.session, &conn.close, 1000, "bye")
	testing.expect_value(t, error.kind, .None)

	return error.kind == .None && ws_owa_until(t, &conn.done, 1, 5 * time.Second, "close")
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

ws_owa_config :: proc() -> WebSocket_Async_Config {
	return {
		host = "127.0.0.1",
		target = "/ws",
		handshake_timeout = 5 * time.Second,
		close_timeout = 500 * time.Millisecond,
	}
}

// The read stays pending while the caller's task is woken for other reasons,
// then completes with each whole message in order.
@(test)
websocket_async_read_survives_unrelated_wakes :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	owa := new(Ws_Owa)
	defer free(owa)
	defer ws_owa_stop(owa)
	if !ws_owa_start(t, owa) || !ws_owa_connect(t, owa, .Wakes, 2, ws_owa_config()) {
		return
	}

	start_error := async.start(&owa.rt)
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return
	}

	conn := &owa.conns[0]
	if !ws_owa_until(t, &conn.reading, 1, 5 * time.Second, "the read") {
		return
	}

	for _ in 0 ..< 5 {
		before := intrinsics.atomic_load(&owa.resumes)
		_ = async.signal_wake(owa.wake)
		if !ws_owa_until(t, &owa.resumes, before + 1, 2 * time.Second, "a wake") {
			return
		}

		time.sleep(20 * time.Millisecond)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reading), 1)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reads), 0)
		testing.expect_value(t, intrinsics.atomic_load(&conn.failed), 0)
	}

	intrinsics.atomic_store_explicit(&conn.peer.go, 1, .Release)
	if !ws_owa_until(t, &conn.reads, 2, 5 * time.Second, "both messages") {
		return
	}

	testing.expect_value(t, string(conn.messages[0][:conn.message_ns[0]]), "first")
	testing.expect_value(t, string(conn.messages[1][:conn.message_ns[1]]), "second")
	testing.expect_value(t, conn.read_error.kind, .None)
	if !ws_owa_close(t, conn) {
		return
	}

	testing.expect_value(t, conn.close_error.kind, .None)
	testing.expect(t, conn.clean)
	ws_owa_stop(owa)
	testing.expect_value(t, conn.peer.status, WS_PEER_OK)
}

// One configuration: a stalled message or frame ends its session, an idle
// session whose peer answers Pings outlives every one of those bounds.
@(test)
websocket_async_stalled_message_times_out_and_idle_session_stays_open :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	owa := new(Ws_Owa)
	defer free(owa)
	defer ws_owa_stop(owa)
	config := ws_owa_config()
	config.idle_timeout = time.Second
	config.ping_interval = 250 * time.Millisecond
	config.frame_timeout = 400 * time.Millisecond
	config.message_timeout = 400 * time.Millisecond
	if !ws_owa_start(t, owa) ||
	   !ws_owa_connect(t, owa, .Stall_Message, 1, config) ||
	   !ws_owa_connect(t, owa, .Stall_Frame, 1, config) ||
	   !ws_owa_connect(t, owa, .Idle, 1, config) {
		return
	}

	start_error := async.start(&owa.rt)
	testing.expect_value(t, start_error.kind, .None)
	if start_error.kind != .None {
		return
	}

	idle := &owa.conns[2]
	if !ws_owa_until(t, &idle.reading, 1, 5 * time.Second, "the idle read") {
		return
	}

	opened := time.tick_now()
	for i in 0 ..< 2 {
		conn := &owa.conns[i]
		if !ws_owa_until(t, &conn.failed, 1, 5 * time.Second, "the stalled read") {
			return
		}

		testing.expect_value(t, conn.upgrade_error.kind, .None)
		testing.expect_value(t, conn.read_error.kind, .Timeout)
		testing.expect_value(t, conn.read_error.close.code, 1001)
		testing.expect_value(t, intrinsics.atomic_load(&conn.reads), 0)
	}

	for time.tick_since(opened) < 2 * time.Second {
		time.sleep(10 * time.Millisecond)
	}

	testing.expect_value(t, intrinsics.atomic_load(&idle.reading), 1)
	testing.expect_value(t, intrinsics.atomic_load(&idle.failed), 0)
	testing.expect_value(t, intrinsics.atomic_load(&idle.done), 0)
	testing.expect(t, intrinsics.atomic_load(&idle.peer.pings) >= 2)
	if !ws_owa_close(t, idle) {
		return
	}

	testing.expect_value(t, idle.read_error.kind, .Closed)
	testing.expect_value(t, idle.close_error.kind, .None)
	testing.expect(t, idle.clean)
	for i in 0 ..< 2 {
		ws_owa_until(t, &owa.conns[i].done, 1, 5 * time.Second, "the stalled session")
	}
}
