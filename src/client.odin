package surf

// One HTTP client for every origin a program talks to, over HTTP/1.1, HTTP/2
// and HTTP/3, and its websocket sessions (websocket.odin). shared:async's Client moves the bytes for each origin; surf adds
// what sits above an origin: redirects, limits, the address policy, Alt-Svc,
// budgets and the HTTP_Error a caller sees.
//
// A Client runs as one task. Three ways to run it:
//
// - client_init: on a runtime the caller owns. Every client_ call may come from
//   any thread or task; client_close, then client_quiescent, then
//   client_destroy.
// - client_start: on a runtime of its own with one worker thread.
//   client_destroy closes it and joins that thread.
// - execute: a runtime on the calling thread for one request, torn down before
//   it returns.
//
// The blocking calls (client_execute, client_execute_upload) wait on the
// calling thread. They refuse to run on the client's own task.

import "core:mem"
import "core:net"
import "core:sync"
import "core:time"
import "shared:async"

CLIENT_DEFAULT_REQUESTS :: 32
CLIENT_DEFAULT_ORIGINS :: 16
CLIENT_DEFAULT_CONNECTIONS :: async.CLIENT_DEFAULT_CONNECTIONS
CLIENT_DEFAULT_UPLOAD_CHUNKS :: 4
CLIENT_DEFAULT_RESPONSE_CHUNKS :: 8
CLIENT_DEFAULT_WEBSOCKETS :: 8
CLIENT_DEFAULT_IDLE_TIMEOUT :: 30 * time.Second
CLIENT_MAX_REQUESTS :: 4096
CLIENT_MAX_ORIGINS :: 1024
CLIENT_MAX_CHUNKS :: 64
CLIENT_MAX_WEBSOCKETS :: 256
DNS_MAX_NAME_SERVERS :: 8
// Hosts-file addresses considered for one name.
DNS_HOSTS_ENTRIES :: 8

// Bounds a graceful close of an origin's connections.
CLIENT_CLOSE_TIMEOUT :: 2 * time.Second
CLIENT_READ_BYTES :: 16 << 10

Request_Handle :: struct {
	owner_id:   u64,
	slot:       u32,
	generation: u64,
}

Capacities :: struct {
	// Requests submitted and not yet released.
	requests:               int,
	// Origins with open connections at once.
	origins:                int,
	// TCP connections one origin keeps.
	connections_per_origin: int,
	// Upload chunks queued per request before client_upload_submit reports
	// backpressure.
	upload_chunks:          int,
	// Response chunks queued per stream before the client stops reading.
	response_chunks:        int,
	// Websocket sessions opened and not yet released. Zero is
	// CLIENT_DEFAULT_WEBSOCKETS.
	websockets:             int,
}

DEFAULT_CAPACITIES :: Capacities {
	requests               = CLIENT_DEFAULT_REQUESTS,
	origins                = CLIENT_DEFAULT_ORIGINS,
	connections_per_origin = CLIENT_DEFAULT_CONNECTIONS,
	upload_chunks          = CLIENT_DEFAULT_UPLOAD_CHUNKS,
	response_chunks        = CLIENT_DEFAULT_RESPONSE_CHUNKS,
	websockets             = CLIENT_DEFAULT_WEBSOCKETS,
}

Client_Config :: struct {
	http:         Config,
	capacities:   Maybe(Capacities),
	// Closes an origin's connections once it has had no request for this long.
	// Zero is 30 s.
	idle_timeout: time.Duration,
	// Woken from the client's task whenever a completion, a stream event or a
	// websocket operation is ready. The client retains its own reference.
	notify:       async.Signal,
}

Client_Error_Kind :: enum {
	None,
	Invalid_Config,
	Invalid_State,
	Capacity,
	Closed,
	Invalid_Handle,
	Pending,
	Allocation_Failed,
	Would_Deadlock,
	Request_Error,
	Error,
}

// kind .Error: the runtime refused; the causes it gave follow.
Client_Error :: struct {
	kind:        Client_Error_Kind,
	http:        HTTP_Error,
	network:     net.Network_Error,
	allocation:  mem.Allocator_Error,
	system_code: i32,
}

Request_Stage :: enum {
	Queued,
	Connecting,
	Writing,
	Reading,
	Redirecting,
	Completed,
}

Completion :: struct {
	request: Request_Handle,
	error:   HTTP_Error,
}

// Never copy or move a Client between its init and its destroy.
Client :: struct {
	_self:  ^Client,
	_state: ^Client_State,
}

Client_State :: struct {
	mu:             sync.Mutex,
	id:             u64,
	config:         Config,
	capacities:     Capacities,
	idle_timeout:   time.Duration,
	runtime:        ^async.Runtime,
	own_runtime:    bool,
	task:           async.Task,
	wake:           async.Signal,
	notify:         async.Signal,
	allocator:      mem.Allocator,
	// Responses are built with this allocator. It is allocator unless execute
	// builds them for its caller.
	response_alloc: mem.Allocator,
	slots:          []Slot,
	// Submitted requests the task has not picked up, oldest first.
	pending:        [dynamic]u32,
	// Completed requests client_poll has not reported, oldest first.
	completions:    [dynamic]u32,
	websockets:     []WebSocket_Slot,
	// Completed websocket operations whose callbacks have not run, oldest
	// first. Callbacks run on the task once mu is released.
	ws_done:        ^WebSocket_Op,
	ws_done_tail:   ^WebSocket_Op,
	// Task only below, apart from the flags read under mu.
	origins:        [dynamic]^Origin,
	resolver:       net.Resolver_Snapshot,
	resolver_ready: bool,
	h3_pool:        ^async.H3_Pool,
	// The platform roots, loaded on the first HTTPS origin when Config.tls has
	// none: async's dial does not load them for nil roots yet.
	system_roots:   ^async.Root_Pool,
	own_h3:         bool,
	read_buffer:    [CLIENT_READ_BYTES]u8,
	// One request, then the task closes and shuts the runtime down.
	once:           bool,
	closing:        bool,
	cancelled:      bool,
	finished:       bool,
	finished_sema:  sync.Sema,
	notify_pending: bool,
}

client_id_next: u64

client_init :: proc(
	c: ^Client,
	runtime: ^async.Runtime,
	config: Client_Config,
	allocator := context.allocator,
) -> Client_Error {
	if c == nil || c._self != nil || runtime == nil || allocator.procedure == nil {
		return {kind = .Invalid_Config}
	}

	if error := config_validate(config.http); error.kind != .None {
		return {kind = .Invalid_Config, http = error}
	}

	caps := config.capacities.? or_else DEFAULT_CAPACITIES
	if caps.websockets == 0 {
		caps.websockets = CLIENT_DEFAULT_WEBSOCKETS
	}

	if caps.requests <= 0 ||
	   caps.requests > CLIENT_MAX_REQUESTS ||
	   caps.origins <= 0 ||
	   caps.origins > CLIENT_MAX_ORIGINS ||
	   caps.connections_per_origin <= 0 ||
	   caps.upload_chunks <= 0 ||
	   caps.upload_chunks > CLIENT_MAX_CHUNKS ||
	   caps.response_chunks <= 0 ||
	   caps.response_chunks > CLIENT_MAX_CHUNKS ||
	   caps.websockets < 0 ||
	   caps.websockets > CLIENT_MAX_WEBSOCKETS ||
	   config.idle_timeout < 0 {
		return {kind = .Invalid_Config}
	}

	s, allocation := new(Client_State, allocator)
	if allocation != nil {
		return {kind = .Allocation_Failed}
	}

	s.id = sync.atomic_add(&client_id_next, 1) + 1
	s.config = config.http
	s.capacities = caps
	s.idle_timeout =
		config.idle_timeout if config.idle_timeout > 0 else CLIENT_DEFAULT_IDLE_TIMEOUT
	s.runtime = runtime
	s.allocator = allocator
	s.response_alloc = allocator
	s.pending.allocator = allocator
	s.completions.allocator = allocator
	s.origins.allocator = allocator

	if error := client_state_alloc(s); error.kind != .None {
		client_state_free(s)
		return error
	}

	if error := client_resolver_prepare(s); error.kind != .None {
		client_state_free(s)
		return error
	}

	if config.notify != {} {
		retained, ok := async.signal_retain(config.notify)
		if !ok {
			client_state_free(s)
			return {kind = .Invalid_Config}
		}
		s.notify = retained
	}

	s.task = {
		data      = s,
		resume    = client_task_resume,
		on_cancel = client_task_cancel,
		on_done   = client_task_done,
	}

	wake, created := async.signal_create(runtime, &s.task)
	if !created {
		client_state_free(s)
		return {kind = .Allocation_Failed}
	}
	s.wake = wake

	c._self, c._state = c, s

	if error := async.spawn(runtime, &s.task); error.kind != .None {
		c._self, c._state = nil, nil
		client_state_free(s)
		return client_runtime_error(error)
	}

	return {}
}

// Starts the client on a runtime of its own, with one worker thread.
client_start :: proc(
	c: ^Client,
	config: Client_Config,
	allocator := context.allocator,
) -> Client_Error {
	if c == nil || c._self != nil {
		return {kind = .Invalid_Config}
	}

	r, allocation := new(async.Runtime, allocator)
	if allocation != nil {
		return {kind = .Allocation_Failed}
	}

	if error := async.init(r, {workers = 1, task_capacity = 64, io_capacity = 1024});
	   error.kind != .None {
		free(r, allocator)
		return client_runtime_error(error)
	}

	if error := client_init(c, r, config, allocator); error.kind != .None {
		_ = async.destroy(r)
		free(r, allocator)
		return error
	}

	c._state.own_runtime = true

	if error := async.start(r); error.kind != .None {
		s := c._state
		c._self, c._state = nil, nil
		_ = async.destroy(r)
		client_state_free(s)
		free(r, allocator)
		return client_runtime_error(error)
	}

	return {}
}

// New requests get .Closed. Requests in flight finish; then the client closes
// its connections and its task ends (client_quiescent).
client_close :: proc(c: ^Client) -> Client_Error {
	s, error := client_state(c)
	if error.kind != .None {
		return error
	}

	sync.lock(&s.mu)
	s.closing = true
	sync.unlock(&s.mu)
	async.signal_wake(s.wake)

	return {}
}

// The client's task has ended: nothing is in flight and every connection is
// closed. Completed requests can still be taken.
client_quiescent :: proc(c: ^Client) -> bool {
	s, error := client_state(c)
	if error.kind != .None {
		return false
	}

	sync.lock(&s.mu)
	defer sync.unlock(&s.mu)

	return s.finished
}

// With client_start: closes the client, waits for its requests and joins its
// thread. With client_init: .Pending until client_quiescent; close first.
// Responses not yet taken are freed.
client_destroy :: proc(c: ^Client) -> Client_Error {
	s, error := client_state(c)
	if error.kind != .None {
		return error
	}

	if s.own_runtime {
		if async.is_current_task(&s.task) {
			return {kind = .Would_Deadlock}
		}

		_ = client_close(c)
		sync.sema_wait(&s.finished_sema)
		r := s.runtime
		async.shutdown(r)
		_ = async.join(r)
		_ = async.destroy(r)
		allocator := s.allocator
		c._self, c._state = nil, nil
		client_state_free(s)
		free(r, allocator)
		return {}
	}

	sync.lock(&s.mu)
	finished := s.finished
	sync.unlock(&s.mu)

	if !finished {
		return {kind = .Pending}
	}

	c._self, c._state = nil, nil
	client_state_free(s)

	return {}
}

client_state :: proc(c: ^Client) -> (^Client_State, Client_Error) {
	if c == nil || c._self != c || c._state == nil {
		return nil, {kind = .Invalid_State}
	}

	return c._state, {}
}

client_state_alloc :: proc(s: ^Client_State) -> Client_Error {
	slots, error := make([]Slot, s.capacities.requests, s.allocator)
	if error != nil {
		return {kind = .Allocation_Failed}
	}
	s.slots = slots

	websockets, ws_error := make([]WebSocket_Slot, s.capacities.websockets, s.allocator)
	if ws_error != nil {
		return {kind = .Allocation_Failed}
	}
	s.websockets = websockets

	if e := reserve(&s.pending, s.capacities.requests); e != nil {
		return {kind = .Allocation_Failed}
	}

	if e := reserve(&s.completions, s.capacities.requests); e != nil {
		return {kind = .Allocation_Failed}
	}

	if e := reserve(&s.origins, s.capacities.origins); e != nil {
		return {kind = .Allocation_Failed}
	}

	return {}
}

client_resolver_prepare :: proc(s: ^Client_State) -> Client_Error {
	if error := net.resolver_snapshot_prepare(
		&s.resolver,
		{
			name_servers = s.config.resolver.name_servers,
			limits = net.DEFAULT_RESOLVER_SNAPSHOT_LIMITS,
		},
		s.allocator,
	); error != nil {
		// No resolver configuration: IP literals still work.
		return {}
	}

	s.resolver_ready = true

	return {}
}

client_state_free :: proc(s: ^Client_State) {
	if s == nil {
		return
	}

	for &slot in s.slots {
		slot_clear(s, &slot)
	}

	for o in s.origins {
		origin_free(s, o)
	}

	for &slot in s.websockets {
		websocket_teardown(&slot)
		websocket_free(s, &slot)
	}

	if s.own_h3 && s.h3_pool != nil {
		async.h3_pool_destroy(s.h3_pool)
		free(s.h3_pool, s.allocator)
	}

	if s.resolver_ready {
		net.resolver_snapshot_destroy(&s.resolver)
	}

	if s.system_roots != nil {
		async.root_pool_destroy(s.system_roots)
		free(s.system_roots, s.allocator)
	}

	async.signal_release(&s.wake)
	async.signal_release(&s.notify)
	delete(s.slots, s.allocator)
	delete(s.websockets, s.allocator)
	delete(s.pending)
	delete(s.completions)
	delete(s.origins)
	free(s, s.allocator)
}

// ---- the task ----

client_task_resume :: proc(data: rawptr) -> async.Resume_Result {
	s := cast(^Client_State)data

	sync.lock(&s.mu)

	for index in s.pending {
		slot := &s.slots[index]
		if slot.phase == .Pending {
			slot.phase = .Active
		}
	}
	clear(&s.pending)

	result := async.Resume_Result.Waiting
	active := 0

	for &slot in s.slots {
		if slot.phase != .Active {
			continue
		}

		if request_step(s, &slot) {
			result = .Yield
		}

		if slot.phase == .Active {
			active += 1
		}
	}

	if s.once && active == 0 {
		s.closing = true
	}

	ws_yield, ws_live := websockets_resume(s)
	if ws_yield {
		result = .Yield
	}

	if origins_resume(s, active) {
		result = .Yield
	}

	done := s.closing && active == 0 && ws_live == 0 && len(s.pending) == 0 && len(s.origins) == 0
	notify := s.notify_pending
	s.notify_pending = false
	sync.unlock(&s.mu)

	websocket_callbacks(s)

	if notify {
		async.signal_wake(s.notify)
	}

	return .Done if done else result
}

client_task_cancel :: proc(data: rawptr) -> async.Resume_Result {
	s := cast(^Client_State)data

	sync.lock(&s.mu)
	s.closing, s.cancelled = true, true

	for index in s.pending {
		slot := &s.slots[index]
		if slot.phase == .Pending {
			slot.phase = .Active
		}
	}
	clear(&s.pending)

	for &slot in s.slots {
		if slot.phase == .Active {
			request_fail(
				s,
				&slot,
				{
					kind = .IO_Failed,
					phase = .Cancellation,
					transport = net.Connection_Error.Cancelled,
				},
			)
		}
	}

	done := websockets_cancel(s)

	for o in s.origins {
		if !o.done && async.client_cancel(&o.client) == .Done {
			o.done = true
		}
		done = done && o.done
	}

	notify := s.notify_pending
	s.notify_pending = false
	sync.unlock(&s.mu)

	websocket_callbacks(s)

	if notify {
		async.signal_wake(s.notify)
	}

	return .Done if done else .Yield
}

client_task_done :: proc(data: rawptr) {
	s := cast(^Client_State)data

	sync.lock(&s.mu)

	for o in s.origins {
		async.client_destroy(&o.client)
	}

	for o in s.origins {
		origin_free(s, o)
	}
	clear(&s.origins)

	for &slot in s.websockets {
		websocket_teardown(&slot)
	}

	once := s.once
	s.finished = true
	sync.unlock(&s.mu)

	async.signal_detach(s.wake)
	sync.sema_post(&s.finished_sema)
	async.signal_wake(s.notify)

	if once {
		async.shutdown(s.runtime)
	}
}

client_runtime_error :: proc(error: async.Error) -> Client_Error {
	return {
		kind = .Error,
		network = error.network_cause,
		allocation = error.allocation_cause,
		system_code = error.system_code,
	}
}
