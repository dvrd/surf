package surf

import websocket "shared:websocket"
import runtime_async "shared:async"

import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/tls"
import x509 "core:crypto/x509"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"

// Loopback coverage for the async WebSocket client. Peers are owned sockets on
// 127.0.0.1. TLS uses the existing test certificate and does not claim HTTP/2 or QUIC.

WS_PEER_OK :: 1
WS_PEER_ACCEPT :: 2
WS_PEER_REQUEST :: 3
WS_PEER_KEY :: 4
WS_PEER_TEXT :: 5
WS_PEER_FRAGMENT :: 6
WS_PEER_PONG :: 7
WS_PEER_CLOSE :: 8
WS_PEER_IO :: 9

Ws_Peer_Mode :: enum {
	Echo,
	Queue,
	Bad_Accept,
	Unauthorized,
	Bad_UTF8,
	Masked,
	Slow,
	Cancel,
}

Ws_Peer :: struct {
	listener:      net.TCP_Socket,
	mode:          Ws_Peer_Mode,
	status:        int,
	text:          [128]u8,
	text_n:        int,
	continuations: int,
	pongs:         int,
	closes:        int,
}

Ws_Test :: struct {
	session:                                                                                WebSocket_Async,
	rt:                                                                                     runtime_async.Runtime,
	peer:                                                                                   Ws_Peer,
	upgrade:                                                                                WebSocket_Async_Op,
	read:                                                                                   WebSocket_Async_Op,
	write_a:                                                                                WebSocket_Async_Op,
	write_b:                                                                                WebSocket_Async_Op,
	close:                                                                                  WebSocket_Async_Op,
	protocols:                                                                              [1]string,
	src:                                                                                    [32]u8,
	dst:                                                                                    [128]u8,
	payload6:                                                                               [6]u8,
	payload1:                                                                               [1]u8,
	write_text:                                                                             string,
	expect_read:                                                                            string,
	upgrade_error, read_error, write_error, close_error:                                    WebSocket_Async_Error,
	write_errors:                                                                           [2]WebSocket_Async_Error,
	reject_bytes, reject_count, reject_utf8, reject_size:                                   WebSocket_Async_Error_Kind,
	read_opcode:                                                                            websocket.Opcode,
	src_n, read_n, write_n, saw_upgrade, saw_read, saw_write, saw_close, write_count, done: int,
	read_ok, write_ok, read_is_text, close_once, released, clean:                           bool,
	phase:                                                                                  WebSocket_Async_Phase,
	rt_up, listener_up:                                                                     bool,
	worker:                                                                                 ^thread.Thread,
}

@(test)
websocket_async_bind_rejects_bad_config_and_ignores_close_cancel :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)
	marker := 1
	session := new(WebSocket_Async)
	defer free(session)
	session.user = &marker
	session.request_buf[0] = 0xAB
	rt_value: runtime_async.Runtime
	testing.expect_value(t, websocket_async_bind(nil, &rt_value, {}).kind, .Invalid_Config)
	testing.expect_value(t, websocket_async_bind(session, nil, {}).kind, .Invalid_Config)
	bad := WebSocket_Async_Config {
		endpoint = {address = net.IP4_Loopback, port = 9},
		host = "127.0.0.1",
	}

	bad.max_message_size = -1
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_message_size = 0
	bad.max_frame_payload = WebSocket_Async_MAX_FRAME_PAYLOAD + 1
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_frame_payload = 0
	bad.max_queued_messages = WebSocket_Async_QUEUE_CAP + 1
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.max_queued_messages = 0
	bad.handshake_timeout = -time.Second
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	bad.handshake_timeout = 0
	bad.host = ""
	testing.expect_value(t, websocket_async_bind(session, &rt_value, bad).kind, .Invalid_Config)
	testing.expect(t, session.user == &marker && session.request_buf[0] == 0xAB && !session.bound)
	good := WebSocket_Async_Config {
		endpoint = {address = net.IP4_Loopback, port = 9},
		host = "127.0.0.1",
	}

	testing.expect_value(t, websocket_async_bind(session, &rt_value, good).kind, .None)
	testing.expect(t, session.bound && session.user == &marker && session.request_buf[0] == 0)
	testing.expect_value(t, websocket_async_bind(session, &rt_value, good).kind, .Invalid_Config)
	op: WebSocket_Async_Op
	op.callback = ws_on_upgrade
	op.user_data = session
	testing.expect_value(t, websocket_async_write(session, &op, .Text, []u8{'a'}).kind, .Invalid_State)
	pending := WebSocket_Async_Op {
		pending = true,
		kind    = .Close,
	}

	testing.expect_value(t, websocket_async_cancel(session, &pending).kind, .Invalid_State)
	testing.expect(t, pending.pending)
}

@(test)
websocket_async_partial_frames_both_directions :: proc(t: ^testing.T) {
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
websocket_async_slow_peer_times_out :: proc(t: ^testing.T) {
	ws_run(t, .Slow)
}

@(test)
websocket_async_cancel_while_upgrade_read_is_armed :: proc(t: ^testing.T) {
	ws_run(t, .Cancel)
}

@(test)
websocket_async_tls_loopback_echo_and_hostname_mismatch :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 90 * time.Second)
	go_bin := ws_go_bin()
	read_end, write_end, pipe_error := os.pipe()
	testing.expect(t, pipe_error == nil)
	if pipe_error != nil {
		return
	}
	defer os.close(read_end)
	process, start_error := os.process_start(
		{
			command = {go_bin, "run", "."},
			working_dir = "tests/websocket105",
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
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	load_error := tls.root_pool_load_file(pool, "tests/testdata/credentials/root.pem")
	testing.expect(t, load_error.kind == .None)
	if load_error.kind != .None {
		return
	}
	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = port,
	}

	ws_tls_echo(t, endpoint, pool.roots[:pool.count])
	if testing.failed(t) {
		return
	}
	ws_tls_wrong_host(t, endpoint, pool.roots[:pool.count])
}

ws_run :: proc(t: ^testing.T, mode: Ws_Peer_Mode) {
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
	if !ws_client_start(t, h, cfg) {
		return
	}
	if mode == .Cancel && !ws_cancel_when_armed(t, h) {
		return
	}
	limit := 8 * time.Second
	if mode == .Slow {
		limit = 5 * time.Second
	}
	if !ws_wait(t, h, limit) {
		return
	}
	ws_test_stop(h)
	ws_expect_case(t, h, mode)
}

ws_case_config :: proc(h: ^Ws_Test, endpoint: net.Endpoint, mode: Ws_Peer_Mode) -> WebSocket_Async_Config {
	h.protocols[0] = "chat"
	cfg := WebSocket_Async_Config {
		endpoint          = endpoint,
		host              = "127.0.0.1",
		target            = "/ws",
		subprotocols      = h.protocols[:],
		handshake_timeout = 5 * time.Second,
		io_timeout        = 5 * time.Second,
		close_timeout     = 2 * time.Second,
	}

	switch mode {
	case .Echo:
		cfg.max_frame_payload = 5
		h.write_text = "hello-from-client"
		h.expect_read = "hello-from-server"
	case .Queue:
		cfg.max_message_size = 16
		cfg.max_queued_messages = 2
		cfg.max_queued_bytes = 8
	case .Slow:
		cfg.handshake_timeout = time.Second
	case .Bad_Accept, .Unauthorized, .Bad_UTF8, .Masked, .Cancel:
	}

	return cfg
}

ws_client_start :: proc(t: ^testing.T, h: ^Ws_Test, cfg: WebSocket_Async_Config) -> bool {
	init_error := runtime_async.init(&h.rt, {workers = 1, task_capacity = 4, io_capacity = 16})
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
	spawn_error := runtime_async.spawn(&h.rt, &h.session.task)
	testing.expect_value(t, spawn_error.kind, .None)
	if spawn_error.kind != .None {
		return false
	}
	start_error := runtime_async.start(&h.rt)
	testing.expect_value(t, start_error.kind, .None)

	return start_error.kind == .None
}

ws_cancel_when_armed :: proc(t: ^testing.T, h: ^Ws_Test) -> bool {
	start := time.tick_now()

	for intrinsics.atomic_load_explicit(&h.session.upgrade_read_armed, .Acquire) == 0 {
		if time.tick_since(start) > 3 * time.Second {
			testing.expect(t, false, "upgrade read was not armed")
			return false
		}

		thread.yield()
	}

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
		destroy_error := runtime_async.destroy(&h.rt)
		h.rt_up = false
		_ = destroy_error
	}

	if h.worker != nil {
		thread.destroy(h.worker)
		h.worker = nil
	}
}

ws_expect_terminal :: proc(t: ^testing.T, h: ^Ws_Test) {
	testing.expect(t, h.released)
	testing.expect_value(t, h.phase, .Terminal)
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
		testing.expect_value(t, h.write_errors[0].kind, .Closed)
		testing.expect_value(t, h.write_errors[1].kind, .Closed)
		testing.expect_value(t, h.read_error.kind, .EOF)
		testing.expect_value(t, h.read_error.close_code, 1000)
		testing.expect(t, h.clean && h.close_error.kind == .None)
		testing.expect(t, websocket_async_subprotocol(&h.session) == "chat")
	case .Bad_Accept:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Upgrade_Failed)
		testing.expect_value(t, h.upgrade_error.upgrade, .Invalid_Accept)
		testing.expect(t, !h.clean)
	case .Unauthorized:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Upgrade_Failed)
		testing.expect_value(t, h.upgrade_error.upgrade, .Invalid_Status)
		testing.expect(t, !h.clean)
	case .Bad_UTF8:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .None)
		testing.expect_value(t, h.read_error.kind, .Invalid_UTF8)
		testing.expect(t, !h.clean)
	case .Masked:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .None)
		testing.expect_value(t, h.read_error.kind, .Invalid_Frame)
		testing.expect_value(t, h.read_error.frame, .Unexpected_Masking)
		testing.expect(t, !h.clean)
	case .Slow:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Timeout)
		testing.expect(t, !h.clean)
	case .Cancel:
		testing.expect_value(t, h.peer.status, WS_PEER_OK)
		testing.expect_value(t, h.upgrade_error.kind, .Cancelled)
		testing.expect(t, !h.clean && intrinsics.atomic_load(&h.session.upgrade_read_armed) > 0)
	}
}

ws_tls_echo :: proc(t: ^testing.T, endpoint: net.Endpoint, roots: []^x509.Certificate) {
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
		io_timeout        = 5 * time.Second,
		close_timeout     = 2 * time.Second,
	}

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

ws_tls_wrong_host :: proc(t: ^testing.T, endpoint: net.Endpoint, roots: []^x509.Certificate) {
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
		io_timeout        = 5 * time.Second,
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
	testing.expect_value(t, h.upgrade_error.tls_kind, .Authentication_Failed)
	testing.expect_value(t, h.upgrade_error.x509_error, .Hostname_Mismatch)
	testing.expect(t, h.saw_read == 0 && !h.clean)
}

ws_on_done :: proc(data: rawptr) {
	session := cast(^WebSocket_Async)data
	h := cast(^Ws_Test)session.user
	h.released = session.released
	h.clean = session.clean
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
		h.src_n = copy(h.src[:], transmute([]u8)h.write_text)
		h.write_a.callback = ws_on_write
		h.write_a.user_data = h
		_ = websocket_async_write(&h.session, &h.write_a, .Text, h.src[:h.src_n])
		h.read.callback = ws_on_read
		h.read.user_data = h
		_ = websocket_async_read(&h.session, &h.read, h.dst[:])
	case .Queue:
		ws_queue_probe(h)
	case .Bad_UTF8, .Masked:
		h.read.callback = ws_on_read
		h.read.user_data = h
		_ = websocket_async_read(&h.session, &h.read, h.dst[:])
	case .Bad_Accept, .Unauthorized, .Slow, .Cancel:
	}
}

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
	h.reject_count = websocket_async_write(&h.session, rejected, .Text, h.payload1[:]).kind
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
	if len(buf) != len(text) {
		return false
	}
	raw := transmute([]u8)text

	for b, i in buf {
		if b != raw[i] {
			return false
		}
	}

	return true
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

	header := transmute(string)request[:request_n]
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
		response_n = copy(
			response[:],
			transmute([]u8)string("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
		)
	case .Echo, .Queue, .Bad_UTF8, .Masked:
		{
			protocol := "chat" if strings.index(header, "Sec-WebSocket-Protocol: chat") >= 0 else ""
			accepted := websocket.upgrade_accept_encoded(key)
			response_n = ws_peer_101(response[:], transmute(string)accepted[:], protocol)
		}
	case .Slow, .Cancel:
	}

	if response_n < 0 || !ws_peer_send_slow(sock, response[:response_n]) {
		peer.status = WS_PEER_IO
		return
	}

	frames: [256]u8
	frame_n := 0

	switch peer.mode {
	case .Echo:
		frame_n = ws_peer_echo_frames(frames[:])
	case .Bad_UTF8:
		frame_n = ws_peer_put(frames[:], 0, true, .Text, []u8{0xff}, {})
	case .Masked:
		frame_n = ws_peer_put(frames[:], 0, true, .Text, []u8{'x'}, {9, 8, 7, 6})
	case .Queue, .Bad_Accept, .Unauthorized, .Slow, .Cancel:
	}

	if frame_n < 0 {
		peer.status = WS_PEER_IO
		return
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
	case .Queue:
		ws_peer_frames(sock, peer, false)
	case .Bad_Accept, .Unauthorized, .Bad_UTF8, .Masked:
		ws_peer_hold(sock)
		peer.status = WS_PEER_OK
	case .Slow, .Cancel:
	}
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
		if n >= 4 && dst[n - 4] == '\r' && dst[n - 3] == '\n' && dst[n - 2] == '\r' && dst[n - 1] == '\n' {
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

ws_peer_101 :: proc(dst: []u8, accept, protocol: string) -> int {
	wrote := copy(
		dst,
		transmute([]u8)string(
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
		),
	)
	wrote += copy(dst[wrote:], transmute([]u8)accept)
	wrote += copy(dst[wrote:], transmute([]u8)string("\r\n"))

	if protocol != "" {
		wrote += copy(dst[wrote:], transmute([]u8)string("Sec-WebSocket-Protocol: "))
		wrote += copy(dst[wrote:], transmute([]u8)protocol)
		wrote += copy(dst[wrote:], transmute([]u8)string("\r\n"))
	}

	wrote += copy(dst[wrote:], transmute([]u8)string("\r\n"))

	return wrote
}

ws_peer_echo_frames :: proc(dst: []u8) -> int {
	at := ws_peer_put(dst, 0, true, .Ping, []u8{'z'}, {})
	if at < 0 {
		return at
	}
	text := "hello-from-server"
	offset := 0

	for offset < len(text) {
		step := min(5, len(text) - offset)
		fin := offset + step == len(text)
		opcode := websocket.Opcode.Text if offset == 0 else .Continuation
		chunk := transmute([]u8)text[offset:offset + step]
		at = ws_peer_put(dst, at, fin, opcode, chunk, {})
		if at < 0 {
			return at
		}
		offset += step
	}

	return at
}

ws_peer_put :: proc(dst: []u8, at: int, fin: bool, opcode: websocket.Opcode, payload: []u8, mask: [4]u8) -> int {
	if at < 0 || at > len(dst) {
		return -1
	}
	masked := mask != {}
	n, err := websocket.frame_encode(dst[at:], fin, opcode, payload, mask, masked)
	if err != .None {
		return -1
	}

	return at + n
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
		for {
			if n < 2 {
				break
			}
			header, consumed, frame_error := websocket.frame_header_decode(buf[:n], true)
			if frame_error == .Header_Incomplete {
				break
			}

			if frame_error != .None {
				peer.status = WS_PEER_IO
				return
			}

			total := consumed + int(header.payload_length)

			if total < consumed || total > len(buf) {
				peer.status = WS_PEER_IO
				return
			}

			if n < total {
				break
			}
			payload := buf[consumed:total]
			websocket.mask_payload(payload, header.masking_key)
			if !ws_peer_take(sock, peer, header, payload) {
				return
			}
			remain := n - total
			copy(buf[:remain], buf[total:n])
			n = remain
		}

		if peer.closes > 0 {
			break
		}

		if n == len(buf) {
			peer.status = WS_PEER_IO
			return
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

	if peer.closes < 1 {
		peer.status = WS_PEER_CLOSE
		return
	}

	peer.status = WS_PEER_OK
}

ws_peer_take :: proc(sock: net.TCP_Socket, peer: ^Ws_Peer, header: websocket.Frame_Header, payload: []u8) -> bool {
	switch header.opcode {
	case .Text:
		if peer.text_n != 0 || len(payload) > len(peer.text) {
			peer.status = WS_PEER_IO
			return false
		}

		peer.text_n = copy(peer.text[:], payload)
	case .Continuation:
		peer.continuations += 1

		if peer.text_n + len(payload) > len(peer.text) {
			peer.status = WS_PEER_IO
			return false
		}

		peer.text_n += copy(peer.text[peer.text_n:], payload)
	case .Pong:
		peer.pongs += 1
	case .Ping, .Binary:
	case .Close:
		peer.closes += 1
		body := [2]u8{0x03, 0xe8}
		frame: [16]u8
		n, err := websocket.frame_encode(frame[:], true, .Close, body[:], {}, false)

		if err != .None {
			peer.status = WS_PEER_IO
			return false
		}

		sent, send_error := net.send_tcp(sock, frame[:n])

		if send_error != .None || sent != n {
			peer.status = WS_PEER_IO
			return false
		}
	}

	return true
}

ws_go_bin :: proc() -> string {
	if os.exists("/opt/homebrew/bin/go") {
		return "/opt/homebrew/bin/go"
	}

	return "/opt/homebrew/Cellar/go/1.26.2/bin/go"
}

ws_read_port :: proc(file: ^os.File) -> (int, bool) {
	buf: [128]u8
	n := 0

	for n < len(buf) {
		got, err := os.read(file, buf[n:])

		if got > 0 {
			n += got
			text := transmute(string)buf[:n]
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
