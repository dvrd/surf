package surf

import runtime_async "shared:async"
import "base:intrinsics"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

Ws_Policy_Harness :: struct {
	session:  WebSocket_Async,
	runtime:  runtime_async.Runtime,
	upgrade:  WebSocket_Async_Op,
	error:    WebSocket_Async_Error,
	done:     int,
	calls:    int,
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

ws_policy_decide :: proc(_: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	harness := cast(^Ws_Policy_Harness)user
	harness.calls += 1

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
	switch ip in harness.endpoint.address {
	case net.IP4_Address:
		return ip == net.IP4_Loopback
	case net.IP6_Address:
		return false
	}

	return false
}

ws_policy_accepts :: proc(harness: ^Ws_Policy_Harness) -> int {
	sync.lock(&harness.mu)
	defer sync.unlock(&harness.mu)

	return harness.accepts
}

ws_policy_finish :: proc(harness: ^Ws_Policy_Harness, worker: ^thread.Thread) {
	if harness.started {
		runtime_async.shutdown(&harness.runtime)
		_ = runtime_async.join(&harness.runtime)
	}

	_ = runtime_async.destroy(&harness.runtime)
	net.close(harness.listener)

	if worker != nil {
		thread.destroy(worker)
	}
}

ws_policy_run :: proc(t: ^testing.T, allow: bool) -> (harness: ^Ws_Policy_Harness, worker: ^thread.Thread, ok: bool) {
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

	init_error := runtime_async.init(&harness.runtime, {workers = 1, task_capacity = 4, io_capacity = 16})
	testing.expect_value(t, init_error.kind, .None)

	if init_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	harness.session.user = harness
	bind_error := websocket_async_bind(
		&harness.session,
		&harness.runtime,
		{
			endpoint = endpoint,
			host = "127.0.0.1",
			handshake_timeout = 2 * time.Second,
			address_policy = ws_policy_decide,
			address_policy_data = harness,
		},
		ws_policy_done,
	)
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

	spawn_error := runtime_async.spawn(&harness.runtime, &harness.session.task)
	testing.expect_value(t, spawn_error.kind, .None)

	if spawn_error.kind != .None {
		ws_policy_finish(harness, worker)
		free(harness)
		return nil, nil, false
	}

	start_error := runtime_async.start(&harness.runtime)
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
	testing.expect_value(t, harness.calls, 1)
	testing.expect(t, ws_policy_loopback(harness))
	testing.expect(t, harness.endpoint.port > 0)
	testing.expect_value(t, ws_policy_accepts(harness), 1)
}
