package surf

// Websocket sessions on a Client: RFC 6455 over HTTP/1.1, for ws:// and wss://
// URLs, run by async's websocket facade on the client's task. A session shares
// the client's Config: TLS roots and credentials, the resolver and hosts file,
// the address policy and allow_http for ws://.
//
// Every client_websocket_ call may come from any thread. It only queues the
// operation and wakes the task. Each operation completes once, through its
// callback, on the client's task and outside the client's lock, so a callback
// may start the next operation. Client_Config.notify is woken as well.

import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "core:unicode/utf8"
import "shared:async"

WEBSOCKET_DEFAULT_HANDSHAKE_TIMEOUT :: 10 * time.Second

WebSocket_Handle :: struct {
	owner_id:   u64,
	slot:       u32,
	generation: u64,
}

// Copied by client_websocket_open. A zero limit or timeout selects async's
// default (async.WS_DEFAULT_*); async refuses one above its maximum, and the
// open then fails with .Invalid_Config.
WebSocket_Options :: struct {
	// Sent as Origin when not "".
	origin:            string,
	// Offered in preference order.
	subprotocols:      []string,
	// More request fields; none may repeat the handshake's own.
	headers:           []async.Http_Header,
	// One whole message, one received frame, the bytes queued for writing and
	// the fragments of one message.
	max_message_size:  int,
	max_frame_payload: int,
	max_queued_bytes:  int,
	max_fragments:     int,
	// DNS, the connect, the TLS handshake and the upgrade together. Zero is
	// WEBSOCKET_DEFAULT_HANDSHAKE_TIMEOUT.
	handshake_timeout: time.Duration,
	// Without any received byte, Pongs included. A peer that answers the Pings
	// sent every ping_interval keeps an idle session open.
	idle_timeout:      time.Duration,
	// One received frame from its first byte.
	frame_timeout:     time.Duration,
	// One fragmented message from its first fragment.
	message_timeout:   time.Duration,
	// One written frame without progress.
	write_timeout:     time.Duration,
	// The peer's Close after ours, and each step of the teardown.
	close_timeout:     time.Duration,
	// Zero is idle_timeout / 2; async.WS_PING_OFF sends none.
	ping_interval:     time.Duration,
}

WebSocket_Op_Kind :: enum {
	Open,
	Read,
	Write,
	Close,
}

// Follows async's error model: error.kind says what to do, the rest says why.
// .Cancelled: the operation was cancelled or the session released.
// .Capacity: a read whose message did not fit its buffer (the message is
// consumed; op.n holds its size). .Refused: the server refused the upgrade
// (upgrade.status) or the address policy refused every address
// (upgrade.status zero). .Closed: the session or the client closed.
WebSocket_Error :: struct {
	error:   async.Error,
	// A failed open: the answer's status, the handshake field that was wrong,
	// the exchange's HTTP failure and the TLS failure.
	upgrade: async.WS_Failure,
	// How the session ended, once it did.
	close:   async.WS_Close,
}

// Caller-owned. Borrowed, with its buffer, from the call that starts it until
// its callback runs; do not copy or reuse it before then.
WebSocket_Op :: struct {
	callback:  proc(op: ^WebSocket_Op),
	user_data: rawptr,
	kind:      WebSocket_Op_Kind,
	// Read: the kind that arrived. Write: the kind sent.
	message:   async.WS_Message_Kind,
	// Read: the destination. Write: the payload.
	buffer:    []u8,
	// Read: the message's size, also when it did not fit. Write: bytes queued.
	n:         int,
	error:     WebSocket_Error,
	_code:     u16,
	_pending:  bool,
	_cancel:   bool,
	_next:     ^WebSocket_Op,
}

@(private)
WebSocket_Phase :: enum {
	Free,
	Queued,
	Upgrading,
	Open,
	Draining,
	Ended,
}

@(private)
WebSocket_Slot :: struct {
	s:              ^Client_State,
	generation:     u64,
	phase:          WebSocket_Phase,
	released:       bool,
	// The URL, the origin, the subprotocols and the header strings.
	storage:        []u8,
	url:            async.Http_URL,
	origin:         string,
	subprotocols:   []string,
	headers:        []async.Http_Header,
	session:        async.WS_Config,
	handshake:      time.Duration,
	max_message:    int,
	max_queued:     int,
	dial_host:      [64]u8,
	sni:            [256]u8,
	stream:         async.Stream,
	dial:           async.WS_Dial,
	ws:             async.WS_Session,
	open_op:        ^WebSocket_Op,
	read_op:        ^WebSocket_Op,
	close_op:       ^WebSocket_Op,
	write_head:     ^WebSocket_Op,
	write_tail:     ^WebSocket_Op,
	queued:         int,
	close_reason:   [123]u8,
	close_reason_n: int,
	close_sent:     bool,
	protocol:       [255]u8,
	protocol_n:     int,
}

// Starts a session for a ws:// or wss:// URL; op completes once the upgrade
// finished. The handle stays valid until client_websocket_release, also after
// the session ended.
client_websocket_open :: proc(
	c: ^Client,
	url: string,
	options: WebSocket_Options,
	op: ^WebSocket_Op,
) -> (
	WebSocket_Handle,
	Client_Error,
) {
	s, error := client_state(c)
	if error.kind != .None {
		return {}, error
	}

	if op == nil || op.callback == nil || op._pending {
		return {}, {kind = .Invalid_State}
	}

	if !websocket_options_valid(options) {
		return {}, {kind = .Invalid_Config}
	}

	http_url, secure, scheme_ok := websocket_http_url(url)
	if !scheme_ok {
		return {}, {kind = .Invalid_Config, http = {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent}}
	}

	if !secure && !s.config.allow_http {
		return {}, {kind = .Invalid_Config, http = {kind = .Insecure_URL, phase = .Configuration, write_effect = .Not_Sent}}
	}

	prepared: WebSocket_Slot
	if fill := websocket_fill(s, &prepared, http_url, secure, options); fill.kind != .None {
		websocket_free(s, &prepared)
		return {}, fill
	}

	sync.lock(&s.mu)
	if s.closing {
		sync.unlock(&s.mu)
		websocket_free(s, &prepared)
		return {}, {kind = .Closed}
	}

	index := -1
	for &slot, i in s.websockets {
		if slot.phase == .Free {
			index = i
			break
		}
	}

	if index < 0 {
		sync.unlock(&s.mu)
		websocket_free(s, &prepared)
		return {}, {kind = .Capacity}
	}

	slot := &s.websockets[index]
	prepared.generation = slot.generation
	prepared.s = s
	prepared.phase = .Queued
	slot^ = prepared
	websocket_op_start(op, .Open)
	slot.open_op = op
	handle := WebSocket_Handle {
		owner_id   = s.id,
		slot       = u32(index),
		generation = slot.generation,
	}
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return handle, {}
}

// Completes with one whole message copied into dst. One read at a time.
client_websocket_read :: proc(c: ^Client, h: WebSocket_Handle, op: ^WebSocket_Op, dst: []u8) -> Client_Error {
	s, slot, error := websocket_lock(c, h, op)
	if error.kind != .None {
		return error
	}

	if slot.phase != .Open || slot.read_op != nil {
		sync.unlock(&s.mu)
		return {kind = .Invalid_State}
	}

	websocket_op_start(op, .Read)
	op.buffer = dst
	slot.read_op = op
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// Completes once the session copied src into its output queue, not when it
// reached the peer. Writes go out in the order they were started.
client_websocket_write :: proc(
	c: ^Client,
	h: WebSocket_Handle,
	op: ^WebSocket_Op,
	kind: async.WS_Message_Kind,
	src: []u8,
) -> Client_Error {
	if kind == .Text && !utf8.valid_string(string(src)) {
		return {kind = .Invalid_Config}
	}

	s, slot, error := websocket_lock(c, h, op)
	if error.kind != .None {
		return error
	}

	if len(src) > slot.max_message {
		sync.unlock(&s.mu)
		return {kind = .Invalid_Config}
	}

	if slot.phase != .Open || slot.close_op != nil || slot.close_sent {
		sync.unlock(&s.mu)
		return {kind = .Invalid_State}
	}

	if len(src) > slot.max_queued - slot.queued {
		sync.unlock(&s.mu)
		return {kind = .Capacity}
	}

	websocket_op_start(op, .Write)
	op.message = kind
	op.buffer = src

	if slot.write_tail == nil {
		slot.write_head = op
	} else {
		slot.write_tail._next = op
	}

	slot.write_tail = op
	slot.queued += len(src)
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// Queued writes go out first, then a Close with code, which must be one an
// endpoint may send, and reason, at most 123 bytes of UTF-8 (copied). op
// completes once the session ended; cleanly when both Close frames were
// exchanged.
client_websocket_close :: proc(
	c: ^Client,
	h: WebSocket_Handle,
	op: ^WebSocket_Op,
	code: u16 = 1000,
	reason: string = "",
) -> Client_Error {
	switch code {
	case 1000 ..= 1003, 1007 ..= 1014, 3000 ..= 4999:
	case:
		return {kind = .Invalid_Config}
	}

	if len(reason) > 123 || !utf8.valid_string(reason) {
		return {kind = .Invalid_Config}
	}

	s, slot, error := websocket_lock(c, h, op)
	if error.kind != .None {
		return error
	}

	if slot.phase != .Open || slot.close_op != nil || slot.close_sent {
		sync.unlock(&s.mu)
		return {kind = .Invalid_State}
	}

	websocket_op_start(op, .Close)
	op._code = code
	slot.close_reason_n = copy(slot.close_reason[:], reason)
	slot.close_op = op
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// Cancels a pending open, read or write; it completes with .Cancelled.
// Cancelling the open ends the session. A close cannot be cancelled.
client_websocket_cancel :: proc(c: ^Client, h: WebSocket_Handle, op: ^WebSocket_Op) -> Client_Error {
	s, error := client_state(c)
	if error.kind != .None {
		return error
	}

	if op == nil {
		return {kind = .Invalid_State}
	}

	sync.lock(&s.mu)
	slot := websocket_slot(s, h)
	if slot == nil {
		sync.unlock(&s.mu)
		return {kind = .Invalid_Handle}
	}

	if !websocket_owns(slot, op) {
		sync.unlock(&s.mu)
		return {kind = .Invalid_State}
	}

	op._cancel = true
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// Ends the session if it is still open, without a Close handshake, and frees
// it. Pending operations complete with .Cancelled; the handle is invalid at
// once.
client_websocket_release :: proc(c: ^Client, h: WebSocket_Handle) -> Client_Error {
	s, error := client_state(c)
	if error.kind != .None {
		return error
	}

	sync.lock(&s.mu)
	slot := websocket_slot(s, h)
	if slot == nil {
		sync.unlock(&s.mu)
		return {kind = .Invalid_Handle}
	}

	slot.released = true
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// The subprotocol the server selected, copied into buffer: "" before the
// upgrade or for none.
client_websocket_subprotocol :: proc(c: ^Client, h: WebSocket_Handle, buffer: []u8) -> (string, Client_Error) {
	s, error := client_state(c)
	if error.kind != .None {
		return "", error
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)
	slot := websocket_slot(s, h)
	if slot == nil {
		return "", {kind = .Invalid_Handle}
	}

	if len(buffer) < slot.protocol_n {
		return "", {kind = .Capacity}
	}

	return string(buffer[:copy(buffer, slot.protocol[:slot.protocol_n])]), {}
}

// ---- opening ----

@(private)
websocket_options_valid :: proc(o: WebSocket_Options) -> bool {
	return(
		o.max_message_size >= 0 &&
		o.max_frame_payload >= 0 &&
		o.max_queued_bytes >= 0 &&
		o.max_fragments >= 0 &&
		o.handshake_timeout >= 0 &&
		o.idle_timeout >= 0 &&
		o.frame_timeout >= 0 &&
		o.message_timeout >= 0 &&
		o.write_timeout >= 0 &&
		o.close_timeout >= 0 &&
		(o.ping_interval >= 0 || o.ping_interval == async.WS_PING_OFF) \
	)
}

// The http:// or https:// URL async's parser reads for a ws:// or wss:// one.
@(private)
websocket_http_url :: proc(url: string) -> (rest: string, secure: bool, ok: bool) {
	if len(url) > 6 && strings.equal_fold(url[:6], "wss://") {
		return url[6:], true, true
	}

	if len(url) > 5 && strings.equal_fold(url[:5], "ws://") {
		return url[5:], false, true
	}

	return "", false, false
}

// Copies what the dial reads later into slot's own storage.
@(private)
websocket_fill :: proc(
	s: ^Client_State,
	slot: ^WebSocket_Slot,
	rest: string,
	secure: bool,
	options: WebSocket_Options,
) -> Client_Error {
	scheme := "https://" if secure else "http://"
	size := len(scheme) + len(rest) + len(options.origin)

	for p in options.subprotocols {
		size += len(p)
	}

	for h in options.headers {
		size += len(h.name) + len(h.value)
	}

	storage, allocation := make([]u8, size, s.allocator)
	if allocation != nil || len(storage) != size {
		return {kind = .Allocation_Failed}
	}
	slot.storage = storage

	subprotocols, sub_error := make([]string, len(options.subprotocols), s.allocator)
	if sub_error != nil {
		return {kind = .Allocation_Failed}
	}
	slot.subprotocols = subprotocols

	headers, header_error := make([]async.Http_Header, len(options.headers), s.allocator)
	if header_error != nil {
		return {kind = .Allocation_Failed}
	}
	slot.headers = headers

	at := 0
	take :: proc(storage: []u8, at: ^int, text: string) -> string {
		n := copy(storage[at^:], text)
		result := string(storage[at^:][:n])
		at^ += n
		return result
	}

	at += copy(storage, scheme)
	at += copy(storage[at:], rest)
	parsed, parse_error := async.http_url_parse(string(storage[:at]))
	if parse_error.kind != .None {
		return {kind = .Invalid_Config, http = {kind = parse_error.kind, phase = .Configuration, write_effect = .Not_Sent}}
	}

	if len(parsed.host) > len(slot.sni) {
		return {kind = .Invalid_Config, http = {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent}}
	}

	slot.url = parsed
	slot.origin = take(storage, &at, options.origin)

	for p, i in options.subprotocols {
		slot.subprotocols[i] = take(storage, &at, p)
	}

	for h, i in options.headers {
		slot.headers[i].name = take(storage, &at, h.name)
		slot.headers[i].value = take(storage, &at, h.value)
	}

	slot.max_message = options.max_message_size if options.max_message_size > 0 else async.WS_DEFAULT_MESSAGE_BYTES
	slot.max_queued = options.max_queued_bytes if options.max_queued_bytes > 0 else async.WS_DEFAULT_OUTPUT_BYTES
	slot.handshake = options.handshake_timeout if options.handshake_timeout > 0 else WEBSOCKET_DEFAULT_HANDSHAKE_TIMEOUT
	slot.session = {
		max_frame_bytes   = options.max_frame_payload,
		max_message_bytes = options.max_message_size,
		max_output_bytes  = options.max_queued_bytes,
		max_fragments     = options.max_fragments,
		idle_timeout      = options.idle_timeout,
		frame_timeout     = options.frame_timeout,
		message_timeout   = options.message_timeout,
		write_timeout     = options.write_timeout,
		close_timeout     = options.close_timeout,
		ping_interval     = options.ping_interval,
		allocator         = s.allocator,
	}

	return {}
}

// ---- the task ----

// Steps every session; returns whether any made progress and how many are
// still live.
@(private)
websockets_resume :: proc(s: ^Client_State) -> (yield: bool, live: int) {
	for &slot in s.websockets {
		if slot.phase == .Free {
			continue
		}

		if websocket_step(s, &slot) {
			yield = true
		}

		if slot.phase == .Ended && slot.released {
			websocket_free(s, &slot)
		}

		if slot.phase != .Free && slot.phase != .Ended {
			live += 1
		}
	}

	return
}

// From the client's on_cancel: ends every session at once. True once all
// ended.
@(private)
websockets_cancel :: proc(s: ^Client_State) -> bool {
	done := true

	for &slot in s.websockets {
		switch slot.phase {
		case .Free, .Ended:
		case .Queued:
			websocket_end(s, &slot, {error = {kind = .Cancelled}})
		case .Upgrading:
			websocket_dial_abort(s, &slot, {error = {kind = .Cancelled}})
			_ = websocket_drain(&slot)
		case .Open:
			if async.ws_session_cancel(&slot.ws) == .Done {
				websocket_finish(s, &slot)
				_ = websocket_drain(&slot)
			}
		case .Draining:
			_ = websocket_drain(&slot)
		}

		if slot.phase != .Free && slot.phase != .Ended {
			done = false
		}
	}

	return done
}

@(private)
websocket_step :: proc(s: ^Client_State, slot: ^WebSocket_Slot) -> bool {
	switch slot.phase {
	case .Free, .Ended:
		return false
	case .Queued:
		if slot.released || slot.open_op._cancel {
			websocket_end(s, slot, {error = {kind = .Cancelled}})
			return true
		}

		if s.closing {
			websocket_end(s, slot, {error = {kind = .Closed}})
			return true
		}

		return websocket_dial(s, slot)
	case .Upgrading:
		if slot.released || slot.open_op._cancel {
			websocket_dial_abort(s, slot, {error = {kind = .Cancelled}})
			return websocket_drain(slot)
		}

		if s.closing {
			websocket_dial_abort(s, slot, {error = {kind = .Closed}})
			return websocket_drain(slot)
		}

		return websocket_upgrading(s, slot)
	case .Open:
		if slot.released {
			if async.ws_session_cancel(&slot.ws) != .Done {
				return false
			}

			websocket_finish(s, slot)
			return websocket_drain(slot)
		}

		if s.closing && !slot.close_sent {
			slot.close_sent = true
			_ = async.ws_close(&slot.ws, 1001, "")
		}

		return websocket_open(s, slot)
	case .Draining:
		return websocket_drain(slot)
	}

	return false
}

@(private)
websocket_dial :: proc(s: ^Client_State, slot: ^WebSocket_Slot) -> bool {
	host := slot.url.host
	dial := async.Dial_Config {
		host     = host,
		port     = slot.url.port,
		deadline = async.deadline_after(s.runtime, slot.handshake),
		stream   = {allocator = s.allocator},
	}

	if address, found := client_hosts_address(s, host, slot.url.port); found {
		builder := strings.builder_from_bytes(slot.dial_host[:])
		dial.host = net.address_to_string(address, &builder)
	} else if net.parse_address(host) == nil {
		dial.nameservers = client_name_servers(s)
		if len(dial.nameservers) == 0 {
			unresolved := async.Error {
				kind          = .Network_Error,
				network_cause = net.Resolve_Error.Unable_To_Resolve,
			}
			websocket_end(s, slot, {error = unresolved})
			return true
		}
	}

	if s.config.address_policy != nil {
		dial.address_policy = websocket_policy
		dial.policy_user = slot
	}

	if slot.url.secure {
		roots := client_roots(s)
		if roots == nil {
			refused := WebSocket_Error {
				error = {kind = .Invalid_Config},
				upgrade = {tls = async.TLS_General_Error.Invalid_Trust_Roots},
			}
			websocket_end(s, slot, refused)
			return true
		}

		for i in 0 ..< len(host) {
			c := host[i]
			slot.sni[i] = c + 32 if c >= 'A' && c <= 'Z' else c
		}

		dial.tls = async.Dial_TLS {
			server_name        = string(slot.sni[:len(host)]),
			roots              = roots,
			client_credentials = s.config.tls.client_credentials,
			session_cache      = s.config.tls.session_cache,
		}
	}

	error := async.ws_dial_begin(
		&slot.dial,
		&s.task,
		&slot.stream,
		{
			dial = dial,
			options = {
				authority = slot.url.authority,
				path = slot.url.target,
				origin = slot.origin,
				subprotocols = slot.subprotocols,
				headers = slot.headers,
			},
			exchange = {deadline = dial.deadline, allocator = s.allocator},
			session = slot.session,
		},
	)

	if error.kind != .None {
		failure := async.ws_dial_failure(&slot.dial)
		async.ws_dial_destroy(&slot.dial)
		async.stream_destroy(&slot.stream)
		websocket_end(s, slot, {error = error, upgrade = failure})
		return true
	}

	slot.phase = .Upgrading
	_ = websocket_upgrading(s, slot)

	return true
}

// The caller's policy sees the URL's host, also when the hosts file gave the
// address that is dialed.
@(private)
websocket_policy :: proc(_: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	slot := cast(^WebSocket_Slot)user
	config := slot.s.config

	return len(addresses) > 0 && config.address_policy(slot.url.host, addresses, config.address_policy_data)
}

@(private)
websocket_upgrading :: proc(s: ^Client_State, slot: ^WebSocket_Slot) -> bool {
	error := async.ws_dial_finish(&slot.dial, &slot.ws)
	if error.kind == .Pending {
		wait := async.ws_dial_wait(&slot.dial)
		if wait.kind == .Pending {
			return false
		}

		if wait.kind == .None {
			return true
		}

		error = wait
	}

	if error.kind != .None {
		websocket_dial_abort(s, slot, {error = error, upgrade = async.ws_dial_failure(&slot.dial)})
		return websocket_drain(slot)
	}

	async.ws_dial_destroy(&slot.dial)
	slot.protocol_n = copy(slot.protocol[:], async.ws_session_protocol(&slot.ws))
	slot.phase = .Open
	websocket_complete(s, slot.open_op, {})
	slot.open_op = nil
	_ = websocket_open(s, slot)

	return true
}

// Ends a dial that has begun: its operations complete with failure and the
// Stream is torn down (websocket_drain).
@(private)
websocket_dial_abort :: proc(s: ^Client_State, slot: ^WebSocket_Slot, failure: WebSocket_Error) {
	async.ws_dial_destroy(&slot.dial)
	async.stream_abort(&slot.stream)
	websocket_fail_ops(s, slot, failure, failure)
	slot.phase = .Draining
}

@(private)
websocket_open :: proc(s: ^Client_State, slot: ^WebSocket_Slot) -> bool {
	progressed := websocket_pump(s, slot)

	switch async.ws_session_resume(&slot.ws) {
	case .Done:
		websocket_finish(s, slot)
		_ = websocket_drain(slot)
		return true
	case .Yield:
		progressed = true
	case .Waiting:
	}

	if websocket_pump(s, slot) {
		progressed = true
	}

	return progressed
}

// Hands the session what the pending operations ask for.
@(private)
websocket_pump :: proc(s: ^Client_State, slot: ^WebSocket_Slot) -> bool {
	progressed := false

	if read := slot.read_op; read != nil {
		message: async.WS_Message

		if read._cancel {
			slot.read_op = nil
			websocket_complete(s, read, {error = {kind = .Cancelled}})
			progressed = true
		} else if async.ws_message_next(&slot.ws, &message).kind == .None {
			slot.read_op = nil
			read.message = message.kind
			read.n = len(message.payload)
			result: WebSocket_Error

			if len(message.payload) > len(read.buffer) {
				result.error.kind = .Capacity
			} else {
				copy(read.buffer, message.payload)
			}

			websocket_complete(s, read, result)
			progressed = true
		}
	}

	for slot.write_head != nil {
		write := slot.write_head
		result: WebSocket_Error

		if write._cancel {
			result.error.kind = .Cancelled
		} else {
			sent := async.ws_message_send(&slot.ws, write.message, write.buffer)
			if sent.kind == .Pending {
				break
			}

			if sent.kind == .None {
				write.n = len(write.buffer)
			} else {
				result.error = sent
			}
		}

		slot.write_head = write._next
		if slot.write_head == nil {
			slot.write_tail = nil
		}

		slot.queued -= len(write.buffer)
		websocket_complete(s, write, result)
		progressed = true
	}

	if close := slot.close_op; close != nil && !slot.close_sent {
		slot.close_sent = true
		reason := string(slot.close_reason[:slot.close_reason_n])

		if error := async.ws_close(&slot.ws, close._code, reason); error.kind != .None {
			slot.close_op = nil
			websocket_complete(s, close, {error = error})
		}

		progressed = true
	}

	return progressed
}

// The session ended: every pending operation completes with how it ended. A
// close completes cleanly after our Close or after the peer's answered it.
@(private)
websocket_finish :: proc(s: ^Client_State, slot: ^WebSocket_Slot) {
	closed, _ := async.ws_session_closed(&slot.ws)
	async.ws_session_destroy(&slot.ws)
	ended := WebSocket_Error {
		error = websocket_end_error(closed),
		close = closed,
	}
	result := ended

	if closed.reason == .Local_Close || closed.reason == .Peer_Close && slot.close_sent {
		result = {
			close = closed,
		}
	}

	websocket_fail_ops(s, slot, ended, result)
	slot.phase = .Draining
}

// As async reports the end of a session (ws_message_next once it ended).
@(private)
websocket_end_error :: proc(close: async.WS_Close) -> async.Error {
	if close.error.kind != .None {
		return close.error
	}

	#partial switch close.reason {
	case .Peer_Close:
		return {kind = .Peer_Closed}
	case .Refused:
		return {kind = .Refused}
	case .Protocol_Error, .Invalid_Data:
		return {kind = .Network_Error, network_cause = net.Connection_Error.Protocol_Failed}
	case .Too_Big:
		return {kind = .Capacity}
	case .Timeout:
		return {kind = .Timeout}
	case .Cancelled:
		return {kind = .Cancelled}
	}

	return {kind = .Closed}
}

// Waits for the Stream's teardown, then destroys it.
@(private)
websocket_drain :: proc(slot: ^WebSocket_Slot) -> bool {
	_ = async.stream_drive(&slot.stream)

	if async.stream_quiescent(&slot.stream) {
		async.stream_destroy(&slot.stream)
		slot.phase = .Ended
		return true
	}

	return async.stream_wait(&slot.stream, false, false, {}).kind != .Pending
}

// Ends a session that never reached its Stream.
@(private)
websocket_end :: proc(s: ^Client_State, slot: ^WebSocket_Slot, failure: WebSocket_Error) {
	websocket_fail_ops(s, slot, failure, failure)
	slot.phase = .Ended
}

@(private)
websocket_fail_ops :: proc(s: ^Client_State, slot: ^WebSocket_Slot, error: WebSocket_Error, closed: WebSocket_Error) {
	cancelled := error
	if slot.released {
		cancelled = {
			error = {kind = .Cancelled},
			close = error.close,
		}
	}

	websocket_complete(s, slot.open_op, cancelled)
	websocket_complete(s, slot.read_op, cancelled)

	for write := slot.write_head; write != nil; {
		next := write._next
		websocket_complete(s, write, cancelled)
		write = next
	}

	websocket_complete(s, slot.close_op, closed)
	slot.open_op, slot.read_op, slot.close_op = nil, nil, nil
	slot.write_head, slot.write_tail = nil, nil
	slot.queued = 0
}

// Queues op's callback; websocket_callbacks runs it once mu is released.
@(private)
websocket_complete :: proc(s: ^Client_State, op: ^WebSocket_Op, error: WebSocket_Error) {
	if op == nil {
		return
	}

	op.error = error
	op._next = nil

	if s.ws_done_tail == nil {
		s.ws_done = op
	} else {
		s.ws_done_tail._next = op
	}

	s.ws_done_tail = op
	s.notify_pending = true
}

@(private)
websocket_callbacks :: proc(s: ^Client_State) {
	for {
		sync.lock(&s.mu)
		op := s.ws_done
		if op == nil {
			sync.unlock(&s.mu)
			return
		}

		s.ws_done = op._next
		if s.ws_done == nil {
			s.ws_done_tail = nil
		}

		op._next = nil
		op._pending = false
		sync.unlock(&s.mu)
		op.callback(op)
	}
}

// Releases what a live session still holds, from the client's on_done or its
// destroy.
@(private)
websocket_teardown :: proc(slot: ^WebSocket_Slot) {
	switch slot.phase {
	case .Free, .Queued, .Ended:
	case .Upgrading:
		async.ws_dial_destroy(&slot.dial)
		async.stream_destroy(&slot.stream)
	case .Open:
		async.ws_session_destroy(&slot.ws)
		async.stream_destroy(&slot.stream)
	case .Draining:
		async.stream_destroy(&slot.stream)
	}

	if slot.phase != .Free {
		slot.phase = .Ended
	}
}

@(private)
websocket_free :: proc(s: ^Client_State, slot: ^WebSocket_Slot) {
	delete(slot.storage, s.allocator)
	delete(slot.subprotocols, s.allocator)
	delete(slot.headers, s.allocator)
	generation := slot.generation + 1
	slot^ = {}
	slot.generation = generation
}

// ---- handles and operations ----

@(private)
websocket_slot :: proc(s: ^Client_State, h: WebSocket_Handle) -> ^WebSocket_Slot {
	if h.owner_id != s.id || int(h.slot) >= len(s.websockets) {
		return nil
	}

	slot := &s.websockets[h.slot]
	if slot.phase == .Free || slot.released || slot.generation != h.generation {
		return nil
	}

	return slot
}

// Locks the client for an operation on h. Ended sessions report .Closed.
@(private)
websocket_lock :: proc(
	c: ^Client,
	h: WebSocket_Handle,
	op: ^WebSocket_Op,
) -> (
	^Client_State,
	^WebSocket_Slot,
	Client_Error,
) {
	s, error := client_state(c)
	if error.kind != .None {
		return nil, nil, error
	}

	if op == nil || op.callback == nil || op._pending {
		return nil, nil, {kind = .Invalid_State}
	}

	sync.lock(&s.mu)
	slot := websocket_slot(s, h)
	if slot == nil {
		sync.unlock(&s.mu)
		return nil, nil, {kind = .Invalid_Handle}
	}

	if slot.phase == .Draining || slot.phase == .Ended {
		sync.unlock(&s.mu)
		return nil, nil, {kind = .Closed}
	}

	return s, slot, {}
}

@(private)
websocket_owns :: proc(slot: ^WebSocket_Slot, op: ^WebSocket_Op) -> bool {
	if op == slot.open_op || op == slot.read_op {
		return true
	}

	for write := slot.write_head; write != nil; write = write._next {
		if write == op {
			return true
		}
	}

	return false
}

@(private)
websocket_op_start :: proc(op: ^WebSocket_Op, kind: WebSocket_Op_Kind) {
	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = kind,
		_pending  = true,
	}
}
