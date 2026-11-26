package surf

import "base:intrinsics"
import rt "base:runtime"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"
import "core:unicode/utf8"
import "shared:async"

// Asynchronous RFC 6455 client over HTTP/1.1, and over TLS when secure or roots
// are set, built on async's websocket facade. One task drives the session and runs
// every callback. Upgrade, read, write, close and cancel may be requested from
// any thread; they only queue the operation and wake the task. Caller-owned
// read and write buffers stay borrowed until that operation's callback.

// The longest timeout or ping interval: async's own limit, which it does not
// export.
WEBSOCKET_ASYNC_MAX_TIMEOUT :: 24 * time.Hour

WebSocket_Async_Kind :: enum {
	Upgrade,
	Read,
	Write,
	Close,
}

WebSocket_Async_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Cancelled,
	Timeout,
	Queue_Full,
	Busy,
	Upgrade_Failed,
	TLS_Failed,
	IO_Failed,
	Protocol_Failed,
	Closed,
	EOF,
	Peer_Close,
	Message_Oversized,
	Invalid_UTF8,
	Invalid_Frame,
	Allocation_Failed,
	Destination_Undersized,
	Address_Rejected,
	// The host name is in no hosts file entry and DNS gave no address, or
	// there was no name server to ask.
	Resolve_Failed,
}

WebSocket_Async_Error :: struct {
	kind:      WebSocket_Async_Error_Kind,
	// How the session ended. A refused upgrade sets status and upgrade, a
	// failed dial or exchange sets error.
	close:     async.WS_Close,
	tls_error: async.TLS_Error,
}

// Stable until callback. Do not copy or reuse while pending.
WebSocket_Async_Op :: struct {
	callback:    proc(op: ^WebSocket_Async_Op),
	user_data:   rawptr,
	kind:        WebSocket_Async_Kind,
	opcode:      async.WS_Message_Kind,
	buffer:      []u8,
	close_code:  u16,
	pending:     bool,
	cancel_flag: int,
	// Bytes read or queued. A read whose message did not fit holds its size.
	n:           int,
	error:       WebSocket_Async_Error,
	next:        ^WebSocket_Async_Op,
}

// Borrowed host, target, origin, subprotocols, headers, server_name, roots and
// resolver must outlive the session. A zero limit or timeout selects async's
// default.
WebSocket_Async_Config :: struct {
	// A numeric endpoint is dialed as is. Without an address, host's name is
	// dialed at port: from the hosts file when it lists the name (IPv4 first),
	// else through DNS. Bind reads the resolver files, so call it off the
	// runtime's workers.
	endpoint:            net.Endpoint,
	// The Host header, also with a port. Without server_name it gives SNI.
	host:                string,
	// Zero is 443 with TLS and 80 without. Unused with an endpoint address.
	port:                int,
	target:              string,
	origin:              string,
	server_name:         string,
	subprotocols:        []string,
	headers:             []async.Http_Header,
	// TLS verified against roots, or against the platform's roots when roots
	// is nil; the session task loads those as the upgrade starts. Set roots
	// alone also selects TLS.
	secure:              bool,
	roots:               ^async.Root_Pool,
	// Empty name_servers reads the system resolver configuration. Explicit
	// name servers skip the hosts file.
	resolver:            net.Resolver_Options,
	max_message_size:    int,
	max_frame_payload:   int,
	max_queued_bytes:    int,
	max_fragments:       int,
	// Bounds DNS, the connect, the TLS handshake and the upgrade together.
	// Zero is 10 s.
	handshake_timeout:   time.Duration,
	// Without any received byte, Pongs included (60 s). It cannot be turned
	// off; the most is WEBSOCKET_ASYNC_MAX_TIMEOUT. A peer that answers the
	// Pings sent every ping_interval keeps an idle session open.
	idle_timeout:        time.Duration,
	// One received frame from its first byte (5 s).
	frame_timeout:       time.Duration,
	// One fragmented message from its first fragment (30 s).
	message_timeout:     time.Duration,
	// One written frame without progress (5 s).
	write_timeout:       time.Duration,
	// The peer's Close after ours, and each step of the teardown (1 s).
	close_timeout:       time.Duration,
	// Zero is idle_timeout / 2; negative sends no Ping.
	ping_interval:       time.Duration,
	// Nil allows every address. Called with the host name and the addresses
	// about to be dialed, before connect.
	address_policy:      Address_Policy,
	address_policy_data: rawptr,
}

// Where the session dials, settled at bind.
WebSocket_Async_Route :: struct {
	// The host name in lowercase, without port or brackets.
	name:      [256]u8,
	name_n:    int,
	// The address dialed. Empty dials name through DNS.
	address:   [64]u8,
	address_n: int,
	port:      int,
	servers:   [net.MAX_RESOLVER_SNAPSHOT_NAME_SERVERS]net.Endpoint,
	servers_n: int,
}

// Caller-owned, stable address, not copied. user is untouched by bind and is
// available to the on_done procedure. Free the session only after on_done.
WebSocket_Async :: struct {
	user:           rawptr,
	runtime:        ^async.Runtime,
	task:           async.Task,
	config:         WebSocket_Async_Config,
	on_done:        proc(_: rawptr),
	allocator:      mem.Allocator,
	stream:         async.Stream,
	dial:           async.WS_Dial,
	ws:             async.WS_Session,
	ended:          async.WS_Close,
	wake:           async.Signal,
	mu:             sync.Mutex,
	phase:          WebSocket_Async_Phase,
	upgrade_op:     ^WebSocket_Async_Op,
	read_op:        ^WebSocket_Async_Op,
	close_op:       ^WebSocket_Async_Op,
	write_head:     ^WebSocket_Async_Op,
	write_tail:     ^WebSocket_Async_Op,
	queued_bytes:   int,
	route:          WebSocket_Async_Route,
	platform_roots: ^async.Root_Pool,
	protocol:       [255]u8,
	protocol_n:     int,
	close_reason:   [123]u8,
	close_reason_n: int,
	bound:          bool,
	refused:        bool,
	close_sent:     bool,
}

WebSocket_Async_Phase :: enum {
	Bound,
	Upgrading,
	Open,
	Closing,
	Draining,
	Ended,
}

websocket_async_limits :: proc(
	config: WebSocket_Async_Config,
) -> (
	WebSocket_Async_Config,
	WebSocket_Async_Error,
) {
	settings := config
	if settings.max_message_size == 0 {
		settings.max_message_size = async.WS_DEFAULT_MESSAGE_BYTES
	}

	if settings.max_queued_bytes == 0 {
		settings.max_queued_bytes = async.WS_DEFAULT_MESSAGE_BYTES
	}

	if settings.handshake_timeout == 0 {
		settings.handshake_timeout = 10 * time.Second
	}

	secure := settings.secure || settings.roots != nil
	if settings.endpoint.address == nil && settings.port == 0 {
		settings.port = 443 if secure else 80
	}

	numeric := settings.endpoint.address != nil
	if settings.host == "" ||
	   numeric && (settings.endpoint.port <= 0 || settings.endpoint.port > 65535) ||
	   !numeric && (settings.port <= 0 || settings.port > 65535 || websocket_async_host(settings.host) == "") ||
	   settings.target != "" && settings.target[0] != '/' ||
	   settings.max_message_size < 0 ||
	   settings.max_message_size > async.WS_MAX_MESSAGE_BYTES ||
	   settings.max_frame_payload < 0 ||
	   settings.max_frame_payload > async.WS_MAX_MESSAGE_BYTES ||
	   settings.max_queued_bytes < 0 ||
	   settings.max_queued_bytes > async.WS_MAX_MESSAGE_BYTES ||
	   settings.max_fragments < 0 ||
	   settings.max_fragments > 65536 ||
	   settings.handshake_timeout < 0 ||
	   settings.ping_interval > WEBSOCKET_ASYNC_MAX_TIMEOUT ||
	   secure && settings.server_name == "" && websocket_async_name(settings.host) == "" {
		return {}, {kind = .Invalid_Config}
	}

	for timeout in ([5]time.Duration {
			settings.idle_timeout,
			settings.frame_timeout,
			settings.message_timeout,
			settings.write_timeout,
			settings.close_timeout,
		}) {
		if timeout < 0 || timeout > WEBSOCKET_ASYNC_MAX_TIMEOUT {
			return {}, {kind = .Invalid_Config}
		}
	}

	return settings, {}
}

// The host name of a Host value: brackets and port removed.
websocket_async_host :: proc(host: string) -> string {
	if len(host) > 0 && host[0] == '[' {
		closing := strings.index_byte(host, ']')
		if closing < 0 {
			return ""
		}

		return host[1:closing]
	}

	colon := strings.index_byte(host, ':')
	if colon < 0 {
		return host
	}

	return host[:colon]
}

// Reads the hosts file and the resolver configuration, so it runs on the
// caller's thread and not on a worker.
websocket_async_route :: proc(
	config: WebSocket_Async_Config,
	allocator: mem.Allocator,
) -> (
	route: WebSocket_Async_Route,
	error: WebSocket_Async_Error,
) {
	host := websocket_async_host(config.host)
	if len(host) > len(route.name) {
		return {}, {kind = .Invalid_Config}
	}

	route.name_n = copy(route.name[:], host)
	for &b in route.name[:route.name_n] {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
	}

	name := string(route.name[:route.name_n])
	address := config.endpoint.address
	route.port = config.endpoint.port
	if address == nil {
		route.port = config.port
		address = net.parse_address(name)
	}

	if address == nil {
		address = websocket_async_hosts_entry(config, name, &route, allocator)
	}

	if address != nil {
		builder := strings.builder_from_bytes(route.address[:])
		route.address_n = len(net.address_to_string(address, &builder))
		return route, {}
	}

	if route.servers_n == 0 {
		return {}, {kind = .Resolve_Failed}
	}

	return route, {}
}

// The address the hosts file gives name, IPv4 first. Otherwise nil, and the
// route keeps the name servers to ask.
websocket_async_hosts_entry :: proc(
	config: WebSocket_Async_Config,
	name: string,
	route: ^WebSocket_Async_Route,
	allocator: mem.Allocator,
) -> net.Address {
	resolver: net.Resolver_Snapshot
	options := net.Resolver_Snapshot_Options {
		name_servers = config.resolver.name_servers,
		limits       = net.DEFAULT_RESOLVER_SNAPSHOT_LIMITS,
	}

	if net.resolver_snapshot_prepare(&resolver, options, allocator) != nil {
		return nil
	}
	defer net.resolver_snapshot_destroy(&resolver)

	endpoints: [DNS_HOSTS_ENTRIES]net.Endpoint
	count, found, lookup := net.resolver_snapshot_lookup(&resolver, name, endpoints[:], route.port)
	if found && lookup == nil && count > 0 {
		chosen := endpoints[0]
		for endpoint in endpoints[:count] {
			if _, v4 := endpoint.address.(net.IP4_Address); v4 {
				chosen = endpoint
				break
			}
		}

		return chosen.address
	}

	servers, _ := net.resolver_snapshot_name_servers(&resolver)
	route.servers_n = copy(route.servers[:], servers)

	return nil
}

websocket_async_name :: proc(host: string) -> string {
	if len(host) == 0 || host[0] == '[' {
		return ""
	}

	colon := strings.index_byte(host, ':')
	if colon < 0 {
		return host
	}

	return host[:colon]
}

// Installs resume, on_cancel and on_done. The caller registers or spawns the
// task. on_done may be nil. A rejected bind leaves the session unchanged.
websocket_async_bind :: proc(
	session: ^WebSocket_Async,
	runtime: ^async.Runtime,
	config: WebSocket_Async_Config,
	on_done: proc(_: rawptr) = nil,
) -> WebSocket_Async_Error {
	if session == nil || runtime == nil || session.bound {
		return {kind = .Invalid_Config}
	}

	settings, limit_error := websocket_async_limits(config)
	if limit_error.kind != .None {
		return limit_error
	}

	allocator := context.allocator
	if allocator.procedure == nil {
		allocator = rt.heap_allocator()
	}

	route, route_error := websocket_async_route(settings, allocator)
	if route_error.kind != .None {
		return route_error
	}

	user := session.user
	session^ = {
		user = user,
	}
	session.runtime = runtime
	session.config = settings
	session.on_done = on_done
	session.allocator = allocator
	session.route = route

	session.task = {
		data      = session,
		resume    = websocket_async_resume,
		on_cancel = websocket_async_on_cancel,
		on_done   = websocket_async_done,
	}
	session.bound = true

	return {}
}

websocket_async_upgrade :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	sync.lock(&session.mu)
	defer sync.unlock(&session.mu)
	if session.upgrade_op != nil || session.phase != .Bound && session.phase != .Upgrading {
		return {kind = .Invalid_State}
	}

	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Upgrade,
		pending   = true,
	}
	session.upgrade_op = op

	return {}
}

// Completes with one whole message copied into dst.
websocket_async_read :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	dst: []u8,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	sync.lock(&session.mu)
	if session.phase != .Open || session.read_op != nil {
		busy := session.read_op != nil
		sync.unlock(&session.mu)
		return {kind = .Busy if busy else .Invalid_State}
	}

	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Read,
		buffer    = dst,
		pending   = true,
	}
	session.read_op = op
	sync.unlock(&session.mu)
	websocket_async_wake(session)

	return {}
}

// Completes once the session has copied src into its output queue.
websocket_async_write :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	opcode: async.WS_Message_Kind,
	src: []u8,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	if len(src) > session.config.max_message_size {
		return {kind = .Message_Oversized}
	}

	if opcode == .Text && !utf8.valid_string(string(src)) {
		return {kind = .Invalid_UTF8}
	}

	sync.lock(&session.mu)
	if session.phase != .Open {
		sync.unlock(&session.mu)
		return {kind = .Invalid_State}
	}

	if len(src) > session.config.max_queued_bytes - session.queued_bytes {
		sync.unlock(&session.mu)
		return {kind = .Queue_Full}
	}

	op^ = {
		callback  = op.callback,
		user_data = op.user_data,
		kind      = .Write,
		opcode    = opcode,
		buffer    = src,
		pending   = true,
	}
	if session.write_tail == nil {
		session.write_head = op
	} else {
		session.write_tail.next = op
	}

	session.write_tail = op
	session.queued_bytes += len(src)
	sync.unlock(&session.mu)
	websocket_async_wake(session)

	return {}
}

// reason is copied before return. code must be one an endpoint may send.
// Queued writes go out first; the operation completes once the session closed.
websocket_async_close :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	code: u16 = 1000,
	reason: string = "",
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil || op.callback == nil || op.pending {
		return {kind = .Invalid_State}
	}

	switch code {
	case 1000 ..= 1003, 1007 ..= 1014, 3000 ..= 4999:
	case:
		return {kind = .Invalid_Frame}
	}

	if len(reason) > len(session.close_reason) || !utf8.valid_string(reason) {
		return {kind = .Invalid_Frame}
	}

	sync.lock(&session.mu)
	if session.phase != .Open || session.close_op != nil {
		sync.unlock(&session.mu)
		return {kind = .Invalid_State}
	}

	session.close_reason_n = copy(session.close_reason[:], reason)
	op^ = {
		callback   = op.callback,
		user_data  = op.user_data,
		kind       = .Close,
		close_code = code,
		pending    = true,
	}
	session.close_op = op
	session.phase = .Closing
	sync.unlock(&session.mu)
	websocket_async_wake(session)

	return {}
}

// Safe from another thread. The operation stays borrowed until its callback.
// Close cannot be cancelled. Cancelling the upgrade ends the session.
websocket_async_cancel :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
) -> WebSocket_Async_Error {
	if session == nil || !session.bound || op == nil {
		return {kind = .Invalid_State}
	}

	sync.lock(&session.mu)
	if !op.pending || op.kind == .Close {
		sync.unlock(&session.mu)
		return {kind = .Invalid_State}
	}

	intrinsics.atomic_store(&op.cancel_flag, 1)
	sync.unlock(&session.mu)
	websocket_async_wake(session)

	return {}
}

// The subprotocol the server selected, "" before the upgrade or for none.
websocket_async_subprotocol :: proc(session: ^WebSocket_Async) -> string {
	if session == nil {
		return ""
	}

	return string(session.protocol[:session.protocol_n])
}

websocket_async_wake :: proc(session: ^WebSocket_Async) {
	sync.lock(&session.mu)
	defer sync.unlock(&session.mu)
	_ = async.signal_wake(session.wake)
}

websocket_async_cancelled :: proc(op: ^WebSocket_Async_Op) -> bool {
	return op != nil && intrinsics.atomic_load(&op.cancel_flag) != 0
}

websocket_async_complete :: proc(
	session: ^WebSocket_Async,
	op: ^WebSocket_Async_Op,
	error: WebSocket_Async_Error,
) {
	if op == nil {
		return
	}

	op.error = error
	op.next = nil
	sync.lock(&session.mu)
	op.pending = false
	sync.unlock(&session.mu)
	op.callback(op)
}

// Takes every pending operation and moves the session to phase, then completes
// them with error. A pending close completes with closed instead.
websocket_async_fail_ops :: proc(
	session: ^WebSocket_Async,
	phase: WebSocket_Async_Phase,
	error: WebSocket_Async_Error,
	closed: WebSocket_Async_Error,
) {
	sync.lock(&session.mu)
	upgrade := session.upgrade_op
	read := session.read_op
	close := session.close_op
	writes := session.write_head
	session.upgrade_op = nil
	session.read_op = nil
	session.close_op = nil
	session.write_head = nil
	session.write_tail = nil
	session.queued_bytes = 0
	session.phase = phase
	sync.unlock(&session.mu)
	websocket_async_complete(session, upgrade, error)
	websocket_async_complete(session, read, error)
	for writes != nil {
		next := writes.next
		websocket_async_complete(session, writes, error)
		writes = next
	}

	websocket_async_complete(session, close, closed)
}

websocket_async_resume :: proc(data: rawptr) -> async.Resume_Result {
	session := cast(^WebSocket_Async)data

	switch session.phase {
	case .Bound:
		return websocket_async_start(session)
	case .Upgrading:
		return websocket_async_upgrading(session)
	case .Open, .Closing:
		return websocket_async_open(session)
	case .Draining:
		return websocket_async_drain(session)
	case .Ended:
	}

	return .Done
}

websocket_async_on_cancel :: proc(data: rawptr) -> async.Resume_Result {
	session := cast(^WebSocket_Async)data
	cancelled := WebSocket_Async_Error {
		kind = .Cancelled,
	}

	switch session.phase {
	case .Bound:
		websocket_async_fail_ops(session, .Ended, cancelled, cancelled)
	case .Upgrading:
		async.ws_dial_destroy(&session.dial)
		async.stream_abort(&session.stream)
		websocket_async_fail_ops(session, .Draining, cancelled, cancelled)
		return websocket_async_drain(session)
	case .Open, .Closing:
		result := async.ws_session_cancel(&session.ws)
		if result != .Done {
			return result
		}

		return websocket_async_finish(session)
	case .Draining:
		return websocket_async_drain(session)
	case .Ended:
	}

	return .Done
}

websocket_async_done :: proc(data: rawptr) {
	session := cast(^WebSocket_Async)data
	async.stream_destroy(&session.stream)
	if session.platform_roots != nil {
		async.root_pool_destroy(session.platform_roots)
		free(session.platform_roots, session.allocator)
		session.platform_roots = nil
	}

	sync.lock(&session.mu)
	async.signal_detach(session.wake)
	async.signal_release(&session.wake)
	sync.unlock(&session.mu)

	if session.on_done != nil {
		session.on_done(session)
	}
}

websocket_async_on_close :: proc(_: ^async.WS_Session, close: ^async.WS_Close, user: rawptr) {
	session := cast(^WebSocket_Async)user
	session.ended = close^
}

// The refusal is reported to the caller as Address_Rejected; the dial itself
// only sees Invalid_Config. The caller's policy sees the host name, also when
// an address literal is dialed.
websocket_async_policy :: proc(_: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	session := cast(^WebSocket_Async)user
	config := session.config
	name := string(session.route.name[:session.route.name_n])
	allowed := config.address_policy(name, addresses, config.address_policy_data)

	if !allowed {
		session.refused = true
	}

	return allowed
}

websocket_async_start :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	wake, created := async.signal_create(session.runtime, &session.task)
	sync.lock(&session.mu)
	session.wake = wake
	session.phase = .Upgrading
	sync.unlock(&session.mu)

	if !created {
		failure := WebSocket_Async_Error {
			kind = .Allocation_Failed,
		}

		websocket_async_fail_ops(session, .Ended, failure, failure)
		return .Done
	}

	if websocket_async_cancelled(session.upgrade_op) {
		cancelled := WebSocket_Async_Error {
			kind = .Cancelled,
		}

		websocket_async_fail_ops(session, .Ended, cancelled, cancelled)
		return .Done
	}

	config := session.config
	route := &session.route
	name := string(route.name[:route.name_n])
	dial := async.Dial_Config {
		host     = name,
		port     = route.port,
		deadline = async.deadline_after(session.runtime, config.handshake_timeout),
		stream   = {allocator = session.allocator},
	}

	if route.address_n > 0 {
		dial.host = string(route.address[:route.address_n])
	} else {
		dial.nameservers = route.servers[:route.servers_n]
	}

	if config.address_policy != nil {
		dial.address_policy = websocket_async_policy
		dial.policy_user = session
	}

	if config.secure || config.roots != nil {
		server_name := config.server_name
		if server_name == "" {
			server_name = name
		}

		roots := config.roots
		if roots == nil {
			roots = websocket_async_platform_roots(session)
		}

		if roots == nil {
			failure := WebSocket_Async_Error {
				kind = .TLS_Failed,
			}

			websocket_async_fail_ops(session, .Ended, failure, failure)
			return .Done
		}

		dial.tls = async.Dial_TLS {
			server_name = server_name,
			roots       = roots,
		}
	}

	error := async.ws_dial_begin(
		&session.dial,
		&session.task,
		&session.stream,
		{
			dial = dial,
			options = {
				authority = config.host,
				path = config.target,
				origin = config.origin,
				subprotocols = config.subprotocols,
				headers = config.headers,
			},
			exchange = {deadline = dial.deadline, allocator = session.allocator},
			session = {
				max_frame_bytes = config.max_frame_payload,
				max_message_bytes = config.max_message_size,
				max_output_bytes = config.max_queued_bytes,
				max_fragments = config.max_fragments,
				idle_timeout = config.idle_timeout,
				frame_timeout = config.frame_timeout,
				message_timeout = config.message_timeout,
				write_timeout = config.write_timeout,
				close_timeout = config.close_timeout,
				ping_interval = config.ping_interval,
				events = {on_close = websocket_async_on_close, user = session},
				allocator = session.allocator,
			},
		},
	)

	if error.kind != .None {
		failure := websocket_async_dial_error(session, error, async.ws_dial_failure(&session.dial))
		websocket_async_fail_ops(session, .Ended, failure, failure)
		return .Done
	}

	return websocket_async_upgrading(session)
}

// The stream dial hands nil roots to the TLS client as no roots at all, which
// refuses every handshake, so the session loads the platform's roots itself.
// Freed in websocket_async_done.
websocket_async_platform_roots :: proc(session: ^WebSocket_Async) -> ^async.Root_Pool {
	context.allocator = session.allocator
	pool, allocation := new(async.Root_Pool, session.allocator)
	if allocation != nil {
		return nil
	}

	session.platform_roots = pool
	if async.root_pool_load_system(pool) != nil {
		return nil
	}

	return pool
}

websocket_async_upgrading :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	if websocket_async_cancelled(session.upgrade_op) {
		cancelled := WebSocket_Async_Error {
			kind = .Cancelled,
		}

		async.ws_dial_destroy(&session.dial)
		async.stream_abort(&session.stream)
		websocket_async_fail_ops(session, .Draining, cancelled, cancelled)
		return websocket_async_drain(session)
	}

	error := async.ws_dial_finish(&session.dial, &session.ws)
	if error.kind == .Pending {
		wait := async.ws_dial_wait(&session.dial)
		if wait.kind == .Pending {
			return .Waiting
		}

		if wait.kind == .None {
			return .Yield
		}

		error = wait
	}

	dialed := async.ws_dial_failure(&session.dial)
	async.ws_dial_destroy(&session.dial)

	if error.kind != .None {
		failure := websocket_async_dial_error(session, error, dialed)

		async.stream_abort(&session.stream)
		websocket_async_fail_ops(session, .Draining, failure, failure)
		return websocket_async_drain(session)
	}

	session.protocol_n = copy(session.protocol[:], async.ws_session_protocol(&session.ws))
	sync.lock(&session.mu)
	session.phase = .Open
	op := session.upgrade_op
	session.upgrade_op = nil
	sync.unlock(&session.mu)
	websocket_async_complete(session, op, {})

	return websocket_async_open(session)
}

websocket_async_dial_error :: proc(
	session: ^WebSocket_Async,
	error: async.Error,
	dialed: async.WS_Failure,
) -> WebSocket_Async_Error {
	failure := WebSocket_Async_Error {
		kind = .IO_Failed,
		close = {status = dialed.status, upgrade = dialed.upgrade, error = error},
		tls_error = dialed.tls,
	}

	#partial switch error.kind {
	case .Timeout:
		failure.kind = .Timeout
	case .Cancelled, .Stopping:
		failure.kind = .Cancelled
	case .Invalid_Config:
		failure.kind = .TLS_Failed if dialed.tls != nil else .Invalid_Config
	case .Allocation_Failed:
		failure.kind = .Allocation_Failed
	case .Refused:
		failure.kind = .Upgrade_Failed
	case:
		cause, resolving := error.network_cause.(net.Resolve_Error)
		if dialed.status != 0 || dialed.upgrade != .None {
			failure.kind = .Upgrade_Failed
		} else if failure.tls_error != nil {
			failure.kind = .TLS_Failed
		} else if resolving && cause == .Unable_To_Resolve {
			failure.kind = .Resolve_Failed
		}
	}

	if session.refused {
		failure.kind = .Address_Rejected
	}

	return failure
}

websocket_async_open :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	websocket_async_pump(session)
	result := async.ws_session_resume(&session.ws)

	if result == .Done {
		return websocket_async_finish(session)
	}

	if websocket_async_pump(session) {
		return .Yield
	}

	return result
}

// Hands the session what the pending operations ask for. Only this task
// removes an operation, so a pointer read under the lock stays pending.
websocket_async_pump :: proc(session: ^WebSocket_Async) -> bool {
	progressed := false

	sync.lock(&session.mu)
	read := session.read_op
	sync.unlock(&session.mu)

	if read != nil && websocket_async_cancelled(read) {
		websocket_async_take_read(session)
		websocket_async_complete(session, read, {kind = .Cancelled})
		progressed = true
	} else if read != nil {
		message: async.WS_Message
		if async.ws_message_next(&session.ws, &message).kind == .None {
			websocket_async_take_read(session)
			read.opcode = message.kind
			read.n = len(message.payload)
			error := WebSocket_Async_Error{}
			if len(message.payload) > len(read.buffer) {
				error.kind = .Destination_Undersized
			} else {
				copy(read.buffer, message.payload)
			}

			websocket_async_complete(session, read, error)
			progressed = true
		}
	}

	for {
		sync.lock(&session.mu)
		write := session.write_head
		sync.unlock(&session.mu)

		if write == nil {
			break
		}

		error := WebSocket_Async_Error{}
		if websocket_async_cancelled(write) {
			error.kind = .Cancelled
		} else {
			sent := async.ws_message_send(&session.ws, write.opcode, write.buffer)
			#partial switch sent.kind {
			case .None:
				write.n = len(write.buffer)
			case .Pending:
				return progressed
			case .Capacity:
				error.kind = .Message_Oversized
			case .Invalid_Config:
				error.kind = .Invalid_UTF8
			case .Closed:
				error.kind = .Closed
			case .Allocation_Failed:
				error.kind = .Allocation_Failed
			case:
				error.kind = .Invalid_State
			}
		}

		sync.lock(&session.mu)
		session.write_head = write.next
		if session.write_head == nil {
			session.write_tail = nil
		}

		session.queued_bytes -= len(write.buffer)
		sync.unlock(&session.mu)
		websocket_async_complete(session, write, error)
		progressed = true
	}

	sync.lock(&session.mu)
	close := session.close_op
	sync.unlock(&session.mu)

	if close != nil && !session.close_sent {
		session.close_sent = true
		reason := string(session.close_reason[:session.close_reason_n])
		if async.ws_close(&session.ws, close.close_code, reason).kind != .None {
			sync.lock(&session.mu)
			session.close_op = nil
			sync.unlock(&session.mu)
			websocket_async_complete(session, close, {kind = .Invalid_Frame})
		}

		progressed = true
	}

	return progressed
}

websocket_async_take_read :: proc(session: ^WebSocket_Async) {
	sync.lock(&session.mu)
	session.read_op = nil
	sync.unlock(&session.mu)
}

// The session ended and its Stream is quiescent.
websocket_async_finish :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	ended := session.ended
	async.ws_session_destroy(&session.ws)
	error := websocket_async_close_error(ended)
	closed := error
	if ended.reason == .Local_Close || ended.reason == .Peer_Close && session.close_sent {
		closed = {
			close = ended,
		}
	}

	websocket_async_fail_ops(session, .Ended, error, closed)

	return .Done
}

websocket_async_close_error :: proc(close: async.WS_Close) -> WebSocket_Async_Error {
	kind := WebSocket_Async_Error_Kind.IO_Failed

	switch close.reason {
	case .Local_Close:
		kind = .Closed
	case .Peer_Close:
		kind = .Peer_Close
	case .Protocol_Error:
		kind = .Protocol_Failed
	case .Invalid_Data:
		kind = .Invalid_UTF8
	case .Too_Big:
		kind = .Message_Oversized
	case .Timeout:
		kind = .Timeout
	case .Refused:
		kind = .Upgrade_Failed
	case .Cancelled:
		kind = .Cancelled
	case .Transport:
		if close.error.kind == .Peer_Closed {
			kind = .EOF
		}
	case .None:
	}

	return {kind = kind, close = close}
}

websocket_async_drain :: proc(session: ^WebSocket_Async) -> async.Resume_Result {
	_ = async.stream_drive(&session.stream)

	if async.stream_quiescent(&session.stream) {
		sync.lock(&session.mu)
		session.phase = .Ended
		sync.unlock(&session.mu)
		return .Done
	}

	if async.stream_wait(&session.stream, false, false, {}).kind == .Pending {
		return .Waiting
	}

	return .Yield
}
