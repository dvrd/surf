package surf

import websocket "../websocket"
import runtime_async "../async"
import adapter "../async/connection"

import "base:intrinsics"
import "core:crypto"
import "core:crypto/tls"
import "core:net"
import "core:time"

websocket_async_resume :: proc(data: rawptr) -> runtime_async.Resume_Result {
	session := cast(^WebSocket_Async)data
	session.running = true
	if session.phase == .Terminal do return .Done
	if !session.connected {
		result := websocket_async_connect(session)
		if !session.connected do return result
		return .Yield
	}
	drive_result := runtime_async.Resume_Result.Waiting
	if session.executor_ready {
		drive_result = adapter.drive(&session.loop)
	}
	if websocket_async_pump(session) do return .Yield
	if session.phase == .Terminal do return .Done
	return drive_result
}

websocket_async_on_cancel :: proc(data: rawptr) -> runtime_async.Resume_Result {
	session := cast(^WebSocket_Async)data
	session.running = true
	session.task_cancelled = true
	if !session.ops_finished {
		websocket_async_fail_ops(session, {kind = .Cancelled})
		session.ops_finished = true
	}
	if !session.executor_ready {
		websocket_async_release(session)
		session.phase = .Terminal
		return .Done
	}
	adapter.abort(&session.loop)
	if !session.close_started do websocket_async_begin_transport_close(session)
	result := adapter.drive(&session.loop)
	if session.close_state == .Done || adapter.quiescent(&session.loop) {
		websocket_async_release(session)
		session.phase = .Terminal
		return .Done
	}
	if result == .Done do return .Yield
	return result
}

@(private)
websocket_async_connect :: proc(session: ^WebSocket_Async) -> runtime_async.Resume_Result {
	if websocket_async_cancelled(session.upgrade_op) || session.task_cancelled {
		websocket_async_finish_early(session, {kind = .Cancelled})
		return .Done
	}
	if !session.connect_started {
		session.connect_deadline = runtime_async.deadline_after(session.runtime, session.config.handshake_timeout)
		pending, error := runtime_async.begin_connect(session.runtime, &session.task, session.config.endpoint, session.connect_deadline)
		if error.kind != .None {
			websocket_async_finish_early(session, websocket_async_runtime_error(error))
			return .Done
		}
		session.connecting = pending
		session.connect_started = true
		session.phase = .Connecting
	}
	socket, error := runtime_async.finish_connect(session.connecting, session.connect_deadline)
	if error.kind == .Pending do return .Waiting
	if error.kind != .None {
		websocket_async_finish_early(session, websocket_async_runtime_error(error))
		return .Done
	}
	if wrap_error := websocket_async_wrap(session, socket); wrap_error.kind != .None {
		websocket_async_fail(session, wrap_error)
		if !session.close_started do websocket_async_begin_transport_close(session)
	}
	session.connected = true
	return .Yield
}

@(private)
websocket_async_wrap :: proc(session: ^WebSocket_Async, socket: runtime_async.Socket) -> WebSocket_Async_Error {
	if error := adapter.init_executor(&session.loop, session.runtime, &session.task, {}); error.kind != .None {
		return websocket_async_runtime_error(error)
	}
	session.executor_ready = true
	if error := adapter.init_transport(&session.transport, &session.loop, socket); error.kind != .None {
		return websocket_async_runtime_error(error)
	}
	session.net_read = {callback = websocket_async_read_done, user_data = session}
	session.net_write = {callback = websocket_async_write_done, user_data = session}
	session.net_close = {callback = websocket_async_close_done, user_data = session}
	if !session.secure {
		session.phase = .Upgrade
		return {}
	}
	name := session.config.server_name
	if name == "" do name = websocket_async_name(session.config.host)
	if error := tls.async_client(&session.secure_conn, adapter.stream(&session.transport), adapter.executor(&session.loop), {
		server_name = name, root_cas = session.config.roots, handshake_timeout = session.config.handshake_timeout,
	}, session.allocator); error != .None {
		return {kind = .TLS_Failed}
	}
	session.tls_ready = true
	deadline := runtime_async.deadline_after(session.runtime, session.config.handshake_timeout)
	if error := adapter.set_request_budget(&session.loop, deadline); error.kind != .None {
		return websocket_async_runtime_error(error)
	}
	session.hs = {callback = websocket_async_handshake_done, user_data = session}
	wall := time.time_add(time.now(), session.config.handshake_timeout)
	if error := tls.async_handshake(&session.secure_conn, &session.hs, wall); error.kind != .None {
		return {kind = .TLS_Failed, transport = error}
	}
	session.phase = .Securing
	return {}
}

@(private)
websocket_async_handshake_done :: proc(op: ^tls.Async_Handshake_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.handshake_error = op.result
	session.handshake_transport = op.err
	session.handshake_ready = true
}

@(private)
websocket_async_read_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.inbox_at = 0
	session.inbox_len = op.result.count
	session.read_error = op.result.err
	session.read_state = .Done
}

@(private)
websocket_async_write_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.wire_len = op.result.count
	session.write_error = op.result.err
	session.write_state = .Done
}

@(private)
websocket_async_close_done :: proc(op: ^net.Async_Operation) {
	session := cast(^WebSocket_Async)op.user_data
	session.read_error = op.result.err
	session.close_state = .Done
}

@(private)
websocket_async_pump :: proc(session: ^WebSocket_Async) -> bool {
	progressed := false
	for _ in 0 ..< 32 {
		if !websocket_async_step(session) do break
		progressed = true
		if session.phase == .Terminal do break
	}
	return progressed
}

@(private)
websocket_async_step :: proc(session: ^WebSocket_Async) -> bool {
	if session.phase == .Terminal do return false
	if session.close_state == .Done && session.phase != .Terminal {
		if !session.ops_finished {
			if session.phase != .Failed && session.failure.kind == .None && session.close_op != nil {
				session.clean = session.close_sent && session.peer_closed
				op := session.close_op
				session.close_op = nil
				session.ops_finished = true
				websocket_async_complete(op, {})
			} else {
				error := session.failure
				if error.kind == .None do error.kind = .IO_Failed
				websocket_async_fail_ops(session, error)
				session.ops_finished = true
			}
		}
		websocket_async_release(session)
		session.phase = .Terminal
		return true
	}
	if session.phase == .Failed {
		if !session.ops_finished {
			websocket_async_fail_ops(session, session.failure)
			session.ops_finished = true
			if !session.close_started do websocket_async_begin_transport_close(session)
			return true
		}
		return false
	}
	if session.task_cancelled || websocket_async_cancelled(session.upgrade_op) {
		websocket_async_fail(session, {kind = .Cancelled})
		return true
	}
	if session.write_state == .Done {
		websocket_async_finish_write(session)
		return true
	}
	#partial switch session.phase {
	case .Securing:
		return websocket_async_secure_step(session)
	case .Upgrade:
		return websocket_async_upgrade_step(session)
	case .Open, .Closing:
		return websocket_async_open_step(session)
	}
	return false
}

@(private)
websocket_async_secure_step :: proc(session: ^WebSocket_Async) -> bool {
	if !session.handshake_ready do return false
	if session.handshake_transport.kind != .None || session.handshake_error.kind != .None {
		websocket_async_fail(session, {
			kind = .TLS_Failed,
			transport = session.handshake_transport,
			tls_kind = session.handshake_error.kind,
			x509_error = session.handshake_error.authentication.x509,
		})
		return true
	}
	if budget := adapter.budget_error(&session.loop); budget.kind != .None {
		websocket_async_fail(session, websocket_async_net_error(budget))
		return true
	}
	if !tls.async_connection_state(&session.secure_conn).handshake_complete {
		websocket_async_fail(session, {kind = .TLS_Failed, tls_kind = .Invalid_State})
		return true
	}
	idle := tls.async_idle_state(&session.secure_conn)
	// Busy still has a handshake callback or socket op. Buffered is residual
	// handshake state after success; application reads drain it.
	if idle == .Busy do return true
	if idle != .Ready && idle != .Buffered {
		websocket_async_fail(session, {kind = .TLS_Failed})
		return true
	}
	cleared := adapter.set_request_budget(&session.loop, {})
	if cleared.kind == .Task_Busy do return true
	if cleared.kind != .None {
		websocket_async_fail(session, websocket_async_runtime_error(cleared))
		return true
	}
	session.phase = .Upgrade
	return true
}

@(private)
websocket_async_upgrade_step :: proc(session: ^WebSocket_Async) -> bool {
	if session.upgrade_op == nil do return false
	if !session.request_sent {
		if session.write_state != .Idle do return false
		when !crypto.HAS_RAND_BYTES {
			websocket_async_fail(session, {kind = .Entropy_Unavailable})
			return true
		}
		crypto.rand_bytes(session.upgrade_key[:])
		size, encode_error := websocket.upgrade_request_encode(session.request_buf[:], {
			host = session.config.host,
			target = session.config.target,
			origin = session.config.origin,
			subprotocols = session.config.subprotocols,
		}, session.upgrade_key)
		if encode_error != .None {
			websocket_async_fail(session, {kind = .Upgrade_Failed, upgrade = encode_error})
			return true
		}
		session.request_len = size
		session.write_deadline = time.time_add(time.now(), session.config.handshake_timeout)
		if !websocket_async_arm_write(session, session.request_buf[:size], .Request) do return true
		return true
	}
	if session.upgrade_len > 0 || session.inbox_at < session.inbox_len || session.read_state == .Done {
		if !websocket_async_take_upgrade(session) do return session.phase == .Failed
		response, consumed, validate_error := websocket.upgrade_response_validate(
			session.upgrade_buf[:session.upgrade_len], session.upgrade_key, session.config.subprotocols,
		)
		if validate_error == .Header_Incomplete {
			if session.upgrade_len == len(session.upgrade_buf) {
				websocket_async_fail(session, {kind = .Upgrade_Failed, upgrade = .Header_Oversized})
				return true
			}
			return websocket_async_arm_upgrade_read(session)
		}
		if validate_error != .None {
			websocket_async_fail(session, {kind = .Upgrade_Failed, upgrade = validate_error})
			return true
		}
		if budget := adapter.budget_error(&session.loop); budget.kind != .None && session.secure {
			websocket_async_fail(session, websocket_async_net_error(budget))
			return true
		}
		copy(session.selected_protocol[:], transmute([]u8)response.subprotocol)
		session.selected_protocol_size = len(response.subprotocol)
		tail := session.upgrade_len - consumed
		copy(session.inbox[:], session.upgrade_buf[consumed:session.upgrade_len])
		session.inbox_at = 0
		session.inbox_len = tail
		session.upgrade_open = true
		session.phase = .Open
		op := session.upgrade_op
		session.upgrade_op = nil
		websocket_async_complete(op, {})
		return true
	}
	return websocket_async_arm_upgrade_read(session)
}

@(private)
websocket_async_take_upgrade :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state == .Done {
		error := session.read_error
		got := session.inbox_len
		session.read_state = .Idle
		if got == 0 {
			if error.kind == .None do error.kind = .No_Progress
			websocket_async_fail(session, websocket_async_upgrade_io(error))
			return false
		}
	}
	room := len(session.upgrade_buf) - session.upgrade_len
	available := session.inbox_len - session.inbox_at
	if available <= 0 do return session.upgrade_len > 0
	n := copy(session.upgrade_buf[session.upgrade_len:], session.inbox[session.inbox_at:session.inbox_len])
	if n > room do n = room
	session.upgrade_len += n
	session.inbox_at += n
	return true
}

@(private)
websocket_async_arm_upgrade_read :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state == .Pending do return false
	if session.inbox_at < session.inbox_len do return true
	session.read_deadline = time.time_add(time.now(), session.config.handshake_timeout)
	if websocket_async_arm_read(session) {
		intrinsics.atomic_add(&session.upgrade_read_armed, 1)
		return true
	}
	return session.phase == .Failed
}

@(private)
websocket_async_open_step :: proc(session: ^WebSocket_Async) -> bool {
	if websocket_async_cancelled(session.read_op) {
		if session.read_state == .Pending {
			if !session.read_cancel_sent {
				_ = net.async_cancel(websocket_async_stream(session), &session.net_read)
				session.read_cancel_sent = true
				return true
			}
		} else {
			session.read_cancel_sent = false
			op := session.read_op
			session.read_op = nil
			mid := session.header_have > 0 || session.payload_have > 0 || session.message.fragmented || len(session.message.message) > 0
			websocket_async_complete(op, {kind = .Cancelled})
			if mid do websocket_async_fail(session, {kind = .Cancelled})
			return true
		}
	}
	if session.read_state == .Done {
		session.read_cancel_sent = false
		if session.read_error.kind == .Cancelled || (session.read_error.kind == .None && session.inbox_len == 0) {
			empty := session.read_error.kind == .None && session.inbox_len == 0
			session.read_state = .Idle
			if empty {
				websocket_async_fail(session, {kind = .IO_Failed, transport = {kind = .No_Progress}})
				return true
			}
			op := session.read_op
			session.read_op = nil
			websocket_async_complete(op, {kind = .Cancelled})
			return true
		}
		terminal_read := session.phase == .Closing && (session.read_error.kind == .Peer_Closed || session.read_error.kind == .Closed || session.read_error.kind == .Cancelled)
		if session.read_error.kind != .None && session.inbox_len == 0 && !terminal_read {
			websocket_async_fail(session, websocket_async_net_error(session.read_error))
			session.read_state = .Idle
			return true
		}
		session.read_state = .Idle
		if terminal_read && !session.close_started {
			websocket_async_begin_transport_close(session)
			return true
		}
	}
	if session.phase == .Closing && session.close_deadline != (time.Time{}) && time.diff(time.now(), session.close_deadline) <= 0 && !session.close_started {
		websocket_async_fail(session, {kind = .Timeout})
		return true
	}
	if session.close_sent && session.peer_closed && !session.close_started {
		session.clean = session.failure.kind == .None
		websocket_async_begin_transport_close(session)
		return true
	}
	if websocket_async_parse(session) do return true
	if session.phase == .Failed do return true
	if websocket_async_send_next(session) do return true
	// Closing still reads so a peer close or control frame is observed. Application
	// data stays buffered until a caller read is submitted.
	closing_read := session.phase == .Closing && !session.peer_closed && !session.close_started
	if (session.read_op != nil || closing_read) && session.read_state == .Idle && session.inbox_at >= session.inbox_len && !session.message.message_ready {
		if closing_read && session.close_deadline != (time.Time{}) {
			if session.read_op == nil || time.diff(session.read_deadline, session.close_deadline) < 0 {
				session.read_deadline = session.close_deadline
			}
		}
		if !websocket_async_arm_read(session) do return session.phase == .Failed
		return true
	}
	return false
}

@(private)
websocket_async_parse :: proc(session: ^WebSocket_Async) -> bool {
	progressed := false
	for {
		if session.message.message_ready && session.read_op != nil {
			websocket_async_deliver(session)
			return true
		}
		if session.message.message_ready do return progressed
		if session.payload_need > 0 {
			if !websocket_async_fill_payload(session) do return progressed
			progressed = true
			continue
		}
		if session.header_have < 2 {
			if !websocket_async_pull_header(session, 2) do return progressed
			progressed = true
		}
		need := websocket_async_header_need(session)
		if session.header_have < need {
			if !websocket_async_pull_header(session, need) do return progressed
			progressed = true
		}
		header, _, frame_error := websocket.frame_header_decode(session.header_raw[:session.header_have], false)
		if frame_error != .None {
			websocket_async_fail(session, {kind = .Invalid_Frame, frame = frame_error})
			return true
		}
		session.header = header
		session.header_have = 0
		if header.opcode == .Continuation || header.opcode == .Text || header.opcode == .Binary {
			session.controls = 0
			_, prepare_error := websocket.message_prepare(&session.message, header, session.config.max_message_size, session.allocator)
			if prepare_error.kind != .None {
				websocket_async_fail(session, websocket_async_message_error(prepare_error))
				return true
			}
			session.fragments += 1
			if session.fragments > session.config.max_fragments {
				websocket_async_fail(session, {kind = .Message_Oversized})
				return true
			}
			session.payload_need = int(header.payload_length)
			session.payload_have = 0
			if session.payload_need == 0 {
				if finish_error := websocket.message_finish(&session.message, header.fin); finish_error.kind != .None {
					websocket_async_fail(session, websocket_async_message_error(finish_error))
					return true
				}
			}
			progressed = true
			continue
		}
		session.controls += 1
		if session.controls > WebSocket_Async_MAX_CONTROL_WITHOUT_MESSAGE {
			websocket_async_fail(session, {kind = .Protocol_Failed})
			return true
		}
		session.payload_need = int(header.payload_length)
		session.payload_have = 0
		progressed = true
		if session.payload_need == 0 {
			if !websocket_async_finish_control(session, session.control_in[:0]) do return true
		}
	}
}

@(private)
websocket_async_fill_payload :: proc(session: ^WebSocket_Async) -> bool {
	if session.inbox_at >= session.inbox_len do return false
	if websocket_async_control_opcode(session.header.opcode) {
		dst := session.control_in[session.payload_have:session.payload_need]
		n := copy(dst, session.inbox[session.inbox_at:session.inbox_len])
		session.inbox_at += n
		session.payload_have += n
		if session.payload_have < session.payload_need do return false
		session.payload_need = 0
		return websocket_async_finish_control(session, session.control_in[:session.payload_have])
	}
	base := len(session.message.message) - int(session.header.payload_length)
	if base < 0 {
		websocket_async_fail(session, {kind = .Protocol_Failed})
		return false
	}
	dst := session.message.message[base + session.payload_have:]
	n := copy(dst, session.inbox[session.inbox_at:session.inbox_len])
	session.inbox_at += n
	session.payload_have += n
	if session.payload_have < int(session.header.payload_length) do return false
	session.payload_need = 0
	if finish_error := websocket.message_finish(&session.message, session.header.fin); finish_error.kind != .None {
		websocket_async_fail(session, websocket_async_message_error(finish_error))
		return false
	}
	return true
}

@(private)
websocket_async_finish_control :: proc(session: ^WebSocket_Async, body: []u8) -> bool {
	session.payload_need = 0
	#partial switch session.header.opcode {
	case .Ping:
		if session.control_pending {
			websocket_async_fail(session, {kind = .Protocol_Failed})
			return false
		}
		copy(session.control_out[:], body)
		session.control_len = len(body)
		session.control_pending = true
		session.control_is_close = false
	case .Pong:
	case .Close:
		if frame_error := websocket.close_payload_validate(body); frame_error != .None {
			code: u16 = 1002
			if frame_error == .Invalid_UTF8 do code = 1007
			websocket_async_fail(session, {kind = .Invalid_Frame, frame = frame_error, close_code = code})
			return false
		}
		copy(session.peer_close_body[:], body)
		session.peer_close_len = len(body)
		session.peer_closed = true
		code: u16 = 1005
		if len(body) >= 2 do code = u16(body[0]) << 8 | u16(body[1])
		kind := WebSocket_Async_Error_Kind.EOF
		if code != 1000 && code != 1001 && code != 1005 do kind = .Peer_Close
		if !session.local_close && !session.close_sent {
			copy(session.close_body[:], body)
			session.close_len = len(body)
			session.echo_close = true
		}
		if session.read_op != nil {
			op := session.read_op
			session.read_op = nil
			websocket_async_complete(op, {kind = kind, close_code = code})
		}
	case:
		websocket_async_fail(session, {kind = .Invalid_Frame})
		return false
	}
	return true
}

@(private)
websocket_async_deliver :: proc(session: ^WebSocket_Async) {
	op := session.read_op
	session.read_op = nil
	opcode, n, error := websocket.message_deliver(&session.message, op.buffer)
	session.fragments = 0
	if error.kind != .None {
		result := websocket_async_message_error(error)
		result.n = n
		if error.kind == .Destination_Undersized {
			session.fragments = 1
		}
		websocket_async_complete(op, result)
		return
	}
	op.opcode = opcode
	websocket_async_complete(op, {n = n})
}

@(private)
websocket_async_control_opcode :: proc(opcode: websocket.Opcode) -> bool {
	#partial switch opcode {
	case .Close, .Ping, .Pong:
		return true
	}
	return false
}

@(private)
websocket_async_pull_header :: proc(session: ^WebSocket_Async, need: int) -> bool {
	for session.header_have < need && session.inbox_at < session.inbox_len {
		session.header_raw[session.header_have] = session.inbox[session.inbox_at]
		session.header_have += 1
		session.inbox_at += 1
	}
	return session.header_have >= need
}

@(private)
websocket_async_header_need :: proc(session: ^WebSocket_Async) -> int {
	if session.header_have < 2 do return 2
	need := 2
	length := session.header_raw[1] & 0x7f
	if length == 126 do need = 4
	if length == 127 do need = 10
	if session.header_raw[1] & 0x80 != 0 do need += 4
	return need
}

@(private)
websocket_async_send_next :: proc(session: ^WebSocket_Async) -> bool {
	if session.write_state != .Idle || session.phase == .Failed do return false
	if session.control_pending {
		if session.close_sent && !session.control_is_close {
			session.control_pending = false
			session.control_len = 0
		} else {
			opcode := websocket.Opcode.Pong
			if session.control_is_close do opcode = .Close
			return websocket_async_arm_frame(session, opcode, session.control_out[:session.control_len], true, .Control)
		}
	}
	if (session.local_close || session.echo_close) && !session.close_sent {
		return websocket_async_arm_frame(session, .Close, session.close_body[:session.close_len], true, .Control)
	}
	if session.phase != .Open || session.queue_count == 0 do return false
	op := session.queue[session.queue_head]
	remain := op.buffer[session.write_offset:]
	chunk := len(remain)
	if chunk > session.config.max_frame_payload do chunk = session.config.max_frame_payload
	fin := session.write_offset + chunk == len(op.buffer)
	opcode := op.opcode if session.write_offset == 0 else websocket.Opcode.Continuation
	session.fragment_len = chunk
	return websocket_async_arm_frame(session, opcode, remain[:chunk], fin, .Frame)
}

@(private)
websocket_async_arm_frame :: proc(
	session: ^WebSocket_Async,
	opcode: websocket.Opcode,
	payload: []u8,
	fin: bool,
	writer: WebSocket_Async_Writer,
) -> bool {
	when !crypto.HAS_RAND_BYTES {
		websocket_async_fail(session, {kind = .Entropy_Unavailable})
		return true
	}
	mask: [4]u8
	crypto.rand_bytes(mask[:])
	size, frame_error := websocket.frame_encode(session.wire[:], fin, opcode, payload, mask, true)
	if frame_error != .None {
		websocket_async_fail(session, {kind = .Invalid_Frame, frame = frame_error})
		return true
	}
	session.write_deadline = time.time_add(time.now(), session.config.io_timeout)
	if writer == .Control && opcode == .Close {
		session.control_is_close = true
		session.control_pending = true
		session.control_len = len(payload)
	}
	return websocket_async_arm_write(session, session.wire[:size], writer)
}

@(private)
websocket_async_finish_write :: proc(session: ^WebSocket_Async) {
	writer := session.writer
	error := session.write_error
	count := session.wire_len
	session.write_state = .Idle
	session.writer = .None
	session.write_error = {}
	if error.kind != .None {
		if error.kind == .Cancelled {
			websocket_async_fail(session, {kind = .Cancelled, transport = error, n = count})
			return
		}
		websocket_async_fail(session, websocket_async_net_error(error))
		return
	}
	#partial switch writer {
	case .Request:
		session.request_sent = true
	case .Frame:
		session.write_offset += session.fragment_len
		session.fragment_len = 0
		op := session.queue[session.queue_head]
		if session.write_offset == len(op.buffer) {
			session.write_offset = 0
			websocket_async_dequeue(session)
			op.n = len(op.buffer)
			websocket_async_complete(op, {n = len(op.buffer)})
		}
	case .Control:
		sent_close := session.control_is_close
		session.control_pending = false
		session.control_is_close = false
		session.control_len = 0
		if sent_close {
			session.close_sent = true
			if session.phase == .Open do session.phase = .Closing
			session.close_deadline = time.time_add(time.now(), session.config.close_timeout)
			websocket_async_discard_queue(session)
			if session.peer_closed do websocket_async_begin_transport_close(session)
		}
	}
}

@(private)
websocket_async_dequeue :: proc(session: ^WebSocket_Async) {
	if session.queue_count == 0 do return
	op := session.queue[session.queue_head]
	session.queue[session.queue_head] = nil
	session.queue_head = (session.queue_head + 1) % session.config.max_queued_messages
	session.queue_count -= 1
	session.queue_bytes -= len(op.buffer)
}

@(private)
websocket_async_discard_queue :: proc(session: ^WebSocket_Async) {
	for session.queue_count > 0 {
		op := session.queue[session.queue_head]
		websocket_async_dequeue(session)
		websocket_async_complete(op, {kind = .Closed})
	}
	session.write_offset = 0
	session.fragment_len = 0
}

@(private)
websocket_async_arm_read :: proc(session: ^WebSocket_Async) -> bool {
	if session.read_state != .Idle || session.phase == .Failed || session.phase == .Terminal do return false
	error := net.async_read(websocket_async_stream(session), &session.net_read, session.inbox[:], session.read_deadline)
	if error.kind != .None {
		websocket_async_fail(session, websocket_async_net_error(error))
		return false
	}
	session.read_state = .Pending
	session.inbox_at = 0
	session.inbox_len = 0
	return true
}

@(private)
websocket_async_arm_write :: proc(
	session: ^WebSocket_Async, src: []u8, writer: WebSocket_Async_Writer,
) -> bool {
	if session.write_state != .Idle do return false
	error := net.async_write(websocket_async_stream(session), &session.net_write, src, session.write_deadline)
	if error.kind != .None {
		websocket_async_fail(session, websocket_async_net_error(error))
		return false
	}
	session.write_state = .Pending
	session.writer = writer
	return true
}

@(private)
websocket_async_stream :: proc(session: ^WebSocket_Async) -> net.Async_Connection {
	if session.tls_ready do return tls.async_connection(&session.secure_conn)
	return adapter.stream(&session.transport)
}

@(private)
websocket_async_finish_early :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	websocket_async_fail(session, error)
	if !session.ops_finished {
		websocket_async_fail_ops(session, session.failure)
		session.ops_finished = true
	}
	websocket_async_release(session)
	session.phase = .Terminal
}

@(private)
websocket_async_fail :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	if session.phase == .Failed || session.phase == .Terminal do return
	session.failure = error
	session.phase = .Failed
}

@(private)
websocket_async_fail_ops :: proc(session: ^WebSocket_Async, error: WebSocket_Async_Error) {
	upgrade := session.upgrade_op
	read := session.read_op
	close := session.close_op
	session.upgrade_op = nil
	session.read_op = nil
	session.close_op = nil
	pending: [WebSocket_Async_QUEUE_CAP]^WebSocket_Async_Op
	count := session.queue_count
	for i in 0 ..< count {
		pending[i] = session.queue[(session.queue_head + i) % session.config.max_queued_messages]
	}
	session.queue_count = 0
	session.queue_bytes = 0
	session.queue_head = 0
	websocket_async_complete(upgrade, error)
	websocket_async_complete(read, error)
	for i in 0 ..< count {
		websocket_async_complete(pending[i], error)
	}
	websocket_async_complete(close, error)
}

@(private)
websocket_async_begin_transport_close :: proc(session: ^WebSocket_Async) {
	if session.close_started do return
	if !session.executor_ready {
		session.close_state = .Done
		return
	}
	session.close_started = true
	error := net.async_close(websocket_async_stream(session), &session.net_close)
	if error.kind != .None {
		session.close_state = .Done
	}
}

@(private)
websocket_async_release :: proc(session: ^WebSocket_Async) {
	if session.released do return
	session.released = true
	websocket.message_release(&session.message)
}

@(private)
websocket_async_runtime_error :: proc(error: runtime_async.Error) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.IO_Failed
	if error.kind == .Timeout do kind = .Timeout
	if error.kind == .Cancelled || error.kind == .Stopping do kind = .Cancelled
	if error.kind == .Invalid_Config || error.kind == .Wrong_Task do kind = .Invalid_Config
	transport := net.Connection_Error{}
	if kind == .Timeout do transport.kind = .Timeout
	if kind == .Cancelled do transport.kind = .Cancelled
	return {kind = kind, transport = transport}
}

@(private)
websocket_async_net_error :: proc(error: net.Connection_Error) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.IO_Failed
	if error.kind == .Timeout do kind = .Timeout
	if error.kind == .Cancelled do kind = .Cancelled
	if error.kind == .Peer_Closed do kind = .EOF
	if error.kind == .Protocol_Failed do kind = .Protocol_Failed
	return {kind = kind, transport = error}
}

@(private)
websocket_async_upgrade_io :: proc(error: net.Connection_Error) -> WebSocket_Async_Error {
	mapped := websocket_async_net_error(error)
	if mapped.kind == .IO_Failed || mapped.kind == .EOF do mapped.kind = .Upgrade_Failed
	return mapped
}
