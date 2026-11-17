package surf

import http "../http"
import h2 "../http/v2"
import hpack "../http/v2/hpack"
import http1 "../http/v1"
import "base:intrinsics"
import tls_api "core:crypto/tls"
import "core:io"
import "core:mem"
import owned "core:mem/owned"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:time"
import credential_store "core:crypto/tls/credentials/store"

// An origin identity uses one live connection. Identity/trust rotation may keep
// older WebSocket connections alive while new requests use a fresh bounded lane.
// Keep immutable Config roots/ALPN/resolver borrows alive through close. Do not
// copy or concurrently mutate a client.
HTTP_ORIGIN_SLOTS :: 4
HTTP_STREAM_SLOTS :: 8

HTTP_Origin_Limits :: struct {
	// Zero selects 8. This is the origin's concurrent stream cap, not a peer promise.
	max_streams: int,
	// Zero uses Config.max_body_size. A positive value also caps response bytes.
	max_bytes:   int,
}

HTTP_Result :: struct {
	response: Response,
	error:    HTTP_Error,
}

HTTP_Client :: struct {
	config:        Config,
	limits:        HTTP_Origin_Limits,
	allocator:     mem.Allocator,
	lanes:         [HTTP_ORIGIN_SLOTS]HTTP_Lane,
	http3_tunnels: [4]^HTTP3_Tunnel,
	dials:         int,
	cancel:        int,
	mu:            sync.Mutex,
	socket:        net.TCP_Socket,
	_self:         ^HTTP_Client,
}

@(private)
HTTP_Lane :: struct {
	live, reusable, booted, ready, dead, goaway, engine_up: bool,
	secure:                                                 bool,
	port:                                                   int,
	host:                                                   string,
	protocol:                                               enum {
		None,
		HTTP1,
		HTTP2,
	},
	tls:                                                    ^tls_api.Conn,
	engine:                                                 h2.Connection,
	allocator:                                              mem.Allocator,
	max_streams, byte_limit:                                int,
	read_buf:                                               [1 << 14]u8,
	tunnels:                                                [HTTP_STREAM_SLOTS]^HTTP2_Tunnel,
	closed_tunnels:                                         [HTTP_STREAM_SLOTS]h2.Stream_Handle,
	retired_requests:                                       [HTTP_RETIRED_REQUEST_SLOTS]h2.Stream_Handle,
	identity:                                               HTTP_Client_Identity,
}

@(private)
H2_Job :: struct {
	request:                                                      http.Request,
	upload:                                                       ^Upload_Source,
	response:                                                     Response,
	error:                                                        HTTP_Error,
	handle:                                                       h2.Stream_Handle,
	names:                                                        [2048]u8,
	names_n:                                                      int,
	length_text:                                                  [32]u8,
	fields:                                                       [32]hpack.Field,
	field_n:                                                      int,
	body:                                                         []u8,
	body_at:                                                      int,
	upload_left:                                                  i64,
	chunk:                                                        owned.Chunk,
	opened, on_wire, sent, ended, failed, want_reset, reset_sent: bool,
	status, informational:                                        int,
}

http_client_init :: proc(
	c: ^HTTP_Client,
	config: Config,
	limits: HTTP_Origin_Limits,
	allocator: mem.Allocator,
) -> HTTP_Error {
	if c == nil || c._self != nil || allocator.procedure == nil {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	if limits.max_streams < 0 || limits.max_streams > 32 || limits.max_bytes < 0 {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	if error := config_validate(config); error.kind != .None {
		return error
	}
	c._self = c
	c.config = config
	c.limits = limits
	if c.limits.max_streams == 0 {
		c.limits.max_streams = 8
	}
	c.allocator = allocator
	return {}
}

http_client_close :: proc(c: ^HTTP_Client) {
	if c == nil || c._self != c {
		return
	}

	for &tunnel in c.http3_tunnels {
		if tunnel != nil {
			_ = h3_tunnel_abort(tunnel)
			tunnel = nil
		}
	}

	for &lane in c.lanes {
		http_lane_close(c, &lane)
	}

	c._self = nil
	c^ = {}
}

http_client_dials :: proc(c: ^HTTP_Client) -> int {
	if c == nil || c._self != c {
		return 0
	}

	return c.dials
}

// Unblocks the in-flight exchange. A failed write is not replayed.
http_client_cancel :: proc(c: ^HTTP_Client) {
	if c == nil || c._self != c {
		return
	}

	intrinsics.atomic_store(&c.cancel, 1)
	sync.lock(&c.mu)
	socket := c.socket
	sync.unlock(&c.mu)

	if socket != {} {
		_ = net.shutdown(socket, .Both)
	}
}

http_client_exchange :: proc(
	c: ^HTTP_Client,
	request: http.Request,
	allocator := context.allocator,
) -> (
	Response,
	HTTP_Error,
) {
	requests: [1]http.Request
	results: [1]HTTP_Result
	requests[0] = request
	error := http_client_multiplex(c, requests[:], results[:], allocator)
	if results[0].error.kind != .None {
		response_destroy(&results[0].response)
		return {}, results[0].error
	}
	if error.kind != .None {
		return {}, error
	}
	return results[0].response, {}
}

// Every request must share one origin. Per-result errors do not replay a request.
http_client_multiplex :: proc(
	c: ^HTTP_Client,
	requests: []http.Request,
	results: []HTTP_Result,
	allocator := context.allocator,
) -> HTTP_Error {
	if c == nil ||
	   c._self != c ||
	   len(requests) < 1 ||
	   len(requests) > HTTP_STREAM_SLOTS ||
	   len(results) != len(requests) {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}
	intrinsics.atomic_store(&c.cancel, 0)
	for &result in results {
		result = {}
	}
	if c.config.http3 {
		if len(requests) != 1 {
			return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
		}

		config := c.config
		config._http3_cancel = http_client_h3_cancelled
		config._http3_cancel_data = c
		results[0].response, results[0].error = execute(requests[0], config, allocator)
		return results[0].error
	}
	parsed: [HTTP_STREAM_SLOTS]http.URL
	for request, i in requests {
		url, error := http.url_parse(request.url)

		if error.kind != .None {
			return {kind = error.kind, phase = .Configuration, write_effect = .Not_Sent}
		}

		if i > 0 &&
		   (url.secure != parsed[0].secure ||
				   url.port != parsed[0].port ||
				   !strings.equal_fold(url.host, parsed[0].host)) {
			return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
		}

		scratch: [http.MAX_HEADER_SIZE]u8

		if _, validation := http1.request_encode(scratch[:], request); validation.kind != .None {
			invalid := http_protocol_error(validation)
			invalid.phase = .Configuration
			invalid.write_effect = .Not_Sent
			return invalid
		}

		parsed[i] = url
	}
	if !parsed[0].secure {
		if len(requests) != 1 {
			return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
		}

		deadline := time.time_add(time.now(), effective_timeout(c.config))
		results[0].response, results[0].error = execute_tcp(parsed[0], requests[0], c.config, deadline, allocator, nil)
		return results[0].error
	}
	deadline := time.time_add(time.now(), effective_timeout(c.config))
	lane, reused, lane_error := http_lane_prepare(c, parsed[0], deadline)
	if lane_error.kind != .None {
		for &result in results {
			result.error = lane_error
		}

		return lane_error
	}
	if deadline_error := tls_api.set_deadline(lane.tls, deadline); deadline_error.kind != .None {
		http_lane_close(c, lane)
		error := HTTP_Error {
			kind         = .Deadline_Failed,
			phase        = .Deadline,
			write_effect = .Not_Sent,
			transport    = deadline_error,
		}

		for &result in results {
			result.error = error
		}

		return error
	}
	if lane.protocol != .HTTP2 {
		if len(requests) != 1 {
			error := HTTP_Error {
				kind         = .IO_Failed,
				phase        = .Protocol,
				write_effect = .Not_Sent,
			}

			http_lane_close(c, lane)

			for &result in results {
				result.error = error
			}

			return error
		}

		results[0].response, results[0].error = http_lane_http1(c, lane, requests[0], nil, allocator, deadline)
		return results[0].error
	}
	if !reused {
		if error := h2_boot(lane, deadline, &c.cancel); error.kind != .None {
			http_lane_close(c, lane)

			for &result in results {
				result.error = error
			}

			return error
		}
	}
	jobs: [HTTP_STREAM_SLOTS]H2_Job
	for request, i in requests {
		jobs[i].request = request
		jobs[i].body = request.body
	}
	drive_error := h2_drive(lane, jobs[:len(requests)], deadline, &c.cancel)
	for job, i in jobs[:len(requests)] {
		results[i].response = job.response
		results[i].error = job.error
	}
	if lane.dead || lane.goaway || !lane.reusable {
		http_lane_close(c, lane)
	}
	return drive_error
}

@(private)
http_body_limit :: proc(config: Config, limits: HTTP_Origin_Limits) -> int {
	limit := config.max_body_size

	if limit <= 0 {
		limit = http.DEFAULT_MAX_BODY_SIZE
	}

	if limits.max_bytes > 0 && limits.max_bytes < limit {
		limit = limits.max_bytes
	}

	return limit
}

@(private)
http_arm_socket :: proc(c: ^HTTP_Client, socket: net.TCP_Socket) {
	if c == nil {
		return
	}

	sync.lock(&c.mu)
	c.socket = socket
	sync.unlock(&c.mu)
}

@(private)
http_disarm_socket :: proc(c: ^HTTP_Client, socket: net.TCP_Socket) {
	if c == nil {
		return
	}

	sync.lock(&c.mu)

	if c.socket == socket {
		c.socket = {}
	}

	sync.unlock(&c.mu)
}

@(private)
http_tls_connect :: proc(
	url: http.URL,
	config: Config,
	total_deadline: time.Time,
	allocator: mem.Allocator,
	dials: ^int,
) -> (
	^tls_api.Conn,
	HTTP_Error,
) {
	connection, allocation_err := new(tls_api.Conn, allocator)
	if allocation_err != nil || connection == nil {
		if allocation_err == nil {
			allocation_err = .Out_Of_Memory
		}

		return nil, {
			kind = .Allocation_Failed,
			phase = .Configuration,
			write_effect = .Not_Sent,
			allocation = allocation_err,
		}
	}
	settings := config.tls
	settings.server_name = url.host
	if validation := tls_api.config_validate(settings); validation != .None {
		free(connection, allocator)
		return nil, http_error_classify(
			{kind = .TLS_Failed, tls_dial = {kind = .Invalid_Config, config = validation}},
			.Configuration,
			.Not_Sent,
		)
	}
	setup_deadline := connection_setup_deadline(config, total_deadline)
	socket, setup_error := bounded_socket(url, config, setup_deadline)
	if setup_error.kind != .None {
		free(connection, allocator)
		return nil, setup_error
	}
	if dials != nil {
		dials^ += 1
	}
	if time.diff(time.now(), setup_deadline) <= 0 {
		net.close(socket)
		free(connection, allocator)
		return nil, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
	}
	underlying := net.tcp_connection(&connection.tcp)
	if client_error := tls_api.client(connection, underlying, settings); client_error != .None {
		net.close(socket)
		free(connection, allocator)
		return nil, http_error_classify(
			{kind = .TLS_Failed, tls_dial = {kind = .Invalid_Config, config = client_error}},
			.Configuration,
			.Not_Sent,
		)
	}
	connection.tcp = {
		socket = socket,
	}
	if handshake_error := tls_api.handshake_until(connection, setup_deadline); handshake_error.kind != .None {
		tls_api.abort(connection)
		free(connection, allocator)
		return nil, http_error_classify(
			{kind = .TLS_Failed, tls_dial = {kind = .Handshake_Failed, handshake = handshake_error}},
			.TLS,
			.Not_Sent,
		)
	}
	return connection, {}
}

@(private)
http_lane_prepare :: proc(
	c: ^HTTP_Client,
	url: http.URL,
	deadline: time.Time,
) -> (
	lane: ^HTTP_Lane,
	reused: bool,
	error: HTTP_Error,
) {
	identity, identity_error := http_identity_acquire(c.config.tls)
	if identity_error.kind != .None {
		return nil, false, identity_error
	}
	defer http_identity_release(&identity)
	for &candidate in c.lanes {
		if candidate.tls == nil {
			continue
		}

		if candidate.secure != url.secure ||
		   candidate.port != url.port ||
		   !strings.equal_fold(candidate.host, url.host) {
			continue
		}

		matches :=
			candidate.identity.store == identity.store &&
			candidate.identity.generation == identity.generation &&
			http_tls_config_equal(candidate.tls.config, c.config.tls)
		if matches &&
		   candidate.protocol == .HTTP2 &&
		   candidate.reusable &&
		   candidate.booted &&
		   !candidate.dead &&
		   !candidate.goaway {
			http_arm_socket(c, candidate.tls.tcp.socket)
			return &candidate, true, {}
		}

		// Identity/trust rotation affects new streams. An admitted WebSocket
		// keeps its pinned identity and transport until explicitly retired.
		if !matches && http_lane_has_tunnels(&candidate) && !candidate.dead && !candidate.goaway {
			continue
		}

		http_lane_close(c, &candidate)
	}
	for &candidate in c.lanes {
		if candidate.tls != nil {
			continue
		}

		lane = &candidate
		break
	}
	if lane == nil {
		return nil, false, {kind = .Invalid_Config, phase = .Admission, write_effect = .Not_Sent}
	}
	lane.identity = identity
	identity = {}
	settings := c.config
	if lane.identity.store != nil {
		settings.tls.client_credential_lease = &lane.identity.lease
	}
	connection, dial_error := http_tls_connect(url, settings, deadline, c.allocator, &c.dials)
	if dial_error.kind != .None {
		http_identity_release(&lane.identity)
		return nil, false, dial_error
	}
	host, allocation := make([]u8, len(url.host), c.allocator)
	if allocation != nil {
		tls_api.abort(connection)
		free(connection, c.allocator)
		http_identity_release(&lane.identity)
		return nil, false, {
			kind = .Allocation_Failed,
			phase = .Admission,
			write_effect = .Not_Sent,
			allocation = allocation,
		}
	}
	copy(host, url.host)
	lane.host = string(host)
	lane.port = url.port
	lane.secure = url.secure
	lane.tls = connection
	lane.allocator = c.allocator
	lane.max_streams = c.limits.max_streams
	lane.byte_limit = http_body_limit(c.config, c.limits)
	http_arm_socket(c, connection.tcp.socket)
	selected := tls_api.connection_state(connection).negotiated_protocol
	if selected == "h2" {
		lane.protocol = .HTTP2

		if open_error := h2_engine_open(lane); open_error.kind != .None {
			http_lane_close(c, lane)
			return nil, false, open_error
		}

		lane.reusable = true
		return lane, false, {}
	}
	if selected != "" && selected != "http/1.1" {
		http_lane_close(c, lane)
		return nil, false, {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
	}
	lane.protocol = .HTTP1
	lane.reusable = false
	return lane, false, {}
}

@(private)
http_lane_close :: proc(c: ^HTTP_Client, lane: ^HTTP_Lane) {
	if lane == nil || lane.tls == nil && !lane.engine_up && len(lane.host) == 0 && lane.identity.store == nil {
		return
	}

	if lane.tls != nil {
		http_disarm_socket(c, lane.tls.tcp.socket)
	}

	h2_engine_close(lane)
	allocator := lane.allocator

	if lane.tls != nil {
		tls_api.abort(lane.tls)
		free(lane.tls, allocator)
	}

	if len(lane.host) > 0 && allocator.procedure != nil {
		delete(lane.host, allocator)
	}

	http_identity_release(&lane.identity)
	lane^ = {}
}

@(private)
http_lane_http1 :: proc(
	c: ^HTTP_Client,
	lane: ^HTTP_Lane,
	request: http.Request,
	upload: ^Upload_Source,
	allocator: mem.Allocator,
	deadline: time.Time,
) -> (
	Response,
	HTTP_Error,
) {
	if deadline_error := tls_api.set_deadline(lane.tls, deadline); deadline_error.kind != .None {
		http_lane_close(c, lane)
		return {}, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent, transport = deadline_error}
	}
	response, err := exchange_tls(lane.tls, request, upload, c.config.max_body_size, allocator, deadline)
	http_lane_close(c, lane)
	return response, err
}

@(private)
h2_exchange_once :: proc(
	connection: ^tls_api.Conn,
	request: http.Request,
	upload: ^Upload_Source,
	config: Config,
	deadline: time.Time,
	allocator: mem.Allocator,
	cancel: ^int,
) -> (
	Response,
	HTTP_Error,
) {
	lane := HTTP_Lane {
		protocol    = .HTTP2,
		tls         = connection,
		allocator   = allocator,
		max_streams = 1,
		byte_limit  = http_body_limit(config, {}),
		reusable    = true,
	}
	if error := h2_engine_open(&lane); error.kind != .None {
		return {}, error
	}
	defer h2_engine_close(&lane)
	if error := h2_boot(&lane, deadline, cancel); error.kind != .None {
		return {}, error
	}
	jobs: [1]H2_Job
	jobs[0].request = request
	jobs[0].upload = upload
	if upload != nil {
		jobs[0].upload_left = upload.content_length
	} else {
		jobs[0].body = request.body
	}
	drive_error := h2_drive(&lane, jobs[:], deadline, cancel)
	if jobs[0].error.kind != .None {
		return {}, jobs[0].error
	}
	if drive_error.kind != .None {
		return {}, drive_error
	}
	return jobs[0].response, {}
}

@(private)
h2_engine_open :: proc(lane: ^HTTP_Lane) -> HTTP_Error {
	if lane.engine_up || lane.max_streams < 1 {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	limits := h2.DEFAULT_LIMITS
	limits.streams = lane.max_streams
	limits.reserved_streams = 0
	limits.work_per_feed = 8192
	limits.retained_body_bytes = 256 * 1024
	limits.events = 32
	capacity := max(lane.max_streams, 4)
	error := h2.connection_init(
		&lane.engine,
		{role = .Client, limits = limits, initial_stream_capacity = capacity},
		{header_sections = 4, enable_push = false, max_stream_capacity = capacity},
		lane.allocator,
	)

	if error.kind != .None {
		return h2_map_error(error, .Not_Sent, 0)
	}

	lane.engine_up = true

	return {}
}

@(private)
h2_engine_close :: proc(lane: ^HTTP_Lane) {
	if lane == nil || !lane.engine_up {
		return
	}

	for stream in lane.tunnels {
		if stream != nil {
			h2_tunnel_detach(stream)
		}
	}

	for {
		event, ok := h2.connection_poll(&lane.engine)

		if !ok {
			break
		}

		_ = h2.connection_event_release(&lane.engine, event.token)
	}

	for {
		view, ok := h2.connection_output_front(&lane.engine)

		if !ok {
			break
		}

		_ = h2.connection_output_release(&lane.engine, view.token)
	}

	_ = h2.connection_destroy(&lane.engine)
	lane.engine_up = false
}

@(private)
h2_cancelled :: proc(flag: ^int) -> bool {
	return flag != nil && intrinsics.atomic_load(flag) != 0
}

@(private)
h2_effect :: proc(job: ^H2_Job) -> HTTP_Write_Effect {
	if job.status > 0 {
		return .Response_Received
	}

	if job.on_wire {
		return .Unknown
	}

	return .Not_Sent
}

@(private)
h2_fail :: proc(job: ^H2_Job, error: HTTP_Error) {
	if job == nil || job.failed {
		return
	}

	job.failed = true
	job.ended = true
	classified := error
	classified.write_effect = h2_effect(job)

	if classified.status == 0 {
		classified.status = job.status
	}

	job.error = classified
	response_destroy(&job.response)
	owned.destroy(&job.chunk)
}

@(private)
h2_map_error :: proc(error: h2.Error, effect: HTTP_Write_Effect, status: int) -> HTTP_Error {
	if error.kind == .None {
		return {}
	}

	kind := http.Error_Kind.IO_Failed
	phase := HTTP_Phase.Protocol
	#partial switch error.kind {
	case .Allocation_Failed:
		kind = .Allocation_Failed
		phase = .Admission
	case .Budget_Rejected, .Closed, .Limit_Exceeded:
		phase = .Admission
	case .Invalid_Config, .Invalid_Input, .Invalid_State:
		kind = .Invalid_Header
		phase = .Protocol
	}

	return {kind = kind, phase = phase, write_effect = effect, status = status, allocation = error.allocation}
}

@(private)
h2_tls_error :: proc(io_error: tls_api.IO_Error, effect: HTTP_Write_Effect, status: int) -> HTTP_Error {
	kind := http.Error_Kind.IO_Failed
	phase := HTTP_Phase.Read

	if io_error.transport.kind == .Timeout {
		kind = .Deadline_Failed
		phase = .Deadline
	} else if io_error.kind == .Transport_Write_Failed {
		phase = .Write
	}

	return {
		kind = kind,
		phase = phase,
		write_effect = effect,
		status = status,
		tls_io = io_error,
		transport = io_error.transport,
	}
}

@(private)
h2_boot :: proc(lane: ^HTTP_Lane, deadline: time.Time, cancel: ^int) -> HTTP_Error {
	empty: [0]H2_Job

	for _ in 0 ..< 64 {
		if h2_cancelled(cancel) {
			return {
				kind = .IO_Failed,
				phase = .Cancellation,
				write_effect = .Not_Sent,
				transport = {kind = .Cancelled},
			}
		}

		if time.diff(time.now(), deadline) <= 0 {
			return {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
		}

		_, service_error := h2_service(lane, empty[:])

		if service_error.kind != .None {
			return service_error
		}

		_, write_error := h2_write_all(lane, empty[:])

		if write_error.kind != .None {
			return write_error
		}

		if lane.goaway || lane.dead {
			lane.reusable = false
			return {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
		}

		if lane.ready {
			_, service_error = h2_service(lane, empty[:])

			if service_error.kind != .None {
				return service_error
			}

			_, write_error = h2_write_all(lane, empty[:])

			if write_error.kind != .None {
				return write_error
			}

			if lane.goaway || lane.dead {
				lane.reusable = false
				return {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
			}

			lane.booted = true
			return {}
		}

		n, read_error := h2_read(lane)

		if read_error.kind != .None {
			return read_error
		}

		if feed_error := h2_feed(lane, empty[:], lane.read_buf[:n]); feed_error.kind != .None {
			return feed_error
		}
	}

	lane.reusable = false

	return {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
}

@(private)
h2_drive :: proc(lane: ^HTTP_Lane, jobs: []H2_Job, deadline: time.Time, cancel: ^int) -> HTTP_Error {
	defer h2_finish(lane, jobs)

	for _ in 0 ..< 100000 {
		if h2_cancelled(cancel) {
			h2_reset_open(lane, jobs)
			_, _ = h2_write_all(lane, jobs)
			error := HTTP_Error {
				kind = .IO_Failed,
				phase = .Cancellation,
				transport = {kind = .Cancelled},
			}

			h2_fail_open(jobs, error)
			lane.reusable = false
			return error
		}

		if time.diff(time.now(), deadline) <= 0 {
			error := HTTP_Error {
				kind  = .Deadline_Failed,
				phase = .Deadline,
			}

			h2_fail_open(jobs, error)
			lane.dead = true
			lane.reusable = false
			return error
		}

		h2_submit(lane, jobs)
		progress, service_error := h2_service(lane, jobs)

		if service_error.kind != .None {
			h2_fail_open(jobs, service_error)
			return service_error
		}

		wrote, write_error := h2_write_all(lane, jobs)

		if write_error.kind != .None {
			h2_fail_open(jobs, write_error)
			return write_error
		}

		if h2_settled(jobs) {
			return {}
		}

		if lane.dead || lane.goaway && h2_no_progress(jobs) {
			error := HTTP_Error {
				kind  = .IO_Failed,
				phase = .Protocol,
			}

			h2_fail_open(jobs, error)
			return error
		}

		if progress || wrote {
			continue
		}

		n, read_error := h2_read(lane)

		if read_error.kind != .None {
			if h2_cancelled(cancel) {
				read_error = {
					kind = .IO_Failed,
					phase = .Cancellation,
					transport = {kind = .Cancelled},
				}
			}

			h2_fail_open(jobs, read_error)
			lane.dead = true
			lane.reusable = false
			return read_error
		}

		if feed_error := h2_feed(lane, jobs, lane.read_buf[:n]); feed_error.kind != .None {
			h2_fail_open(jobs, feed_error)
			return feed_error
		}
	}

	error := HTTP_Error {
		kind  = .IO_Failed,
		phase = .Protocol,
	}

	h2_fail_open(jobs, error)
	lane.dead = true

	return error
}

@(private)
h2_settled :: proc(jobs: []H2_Job) -> bool {
	for &job in jobs {
		if !(job.failed || job.ended && job.sent) {
			return false
		}
	}

	return true
}

@(private)
h2_no_progress :: proc(jobs: []H2_Job) -> bool {
	for &job in jobs {
		if job.opened && !job.failed && !job.ended {
			return false
		}
	}

	return true
}

@(private)
h2_fail_open :: proc(jobs: []H2_Job, error: HTTP_Error) {
	for &job in jobs {
		if job.ended && job.sent && job.error.kind == .None {
			continue
		}

		h2_fail(&job, error)
	}
}

@(private)
h2_active :: proc(jobs: []H2_Job) -> int {
	count := 0

	for &job in jobs {
		if job.opened && !job.ended && !job.failed {
			count += 1
		}
	}

	return count
}

@(private)
h2_submit :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) {
	if lane.dead || !lane.engine_up {
		return
	}

	for &job in jobs {
		if job.failed || job.sent || job.ended {
			continue
		}

		if !job.opened {
			if h2_active(jobs) >= lane.max_streams {
				h2_fail(&job, {kind = .IO_Failed, phase = .Admission})
				continue
			}

			if open_error := h2_open(lane, &job); open_error.kind == .Limit_Exceeded {
				if h2_active(jobs) >= lane.max_streams {
					h2_fail(&job, {kind = .IO_Failed, phase = .Admission})
				}

				continue
			} else if open_error.kind != .None {
				h2_fail(&job, h2_map_error(open_error, .Not_Sent, 0))

				if open_error.kind == .Closed {
					lane.dead = true
					lane.reusable = false
				}

				continue
			}
		}

		if job.opened && !job.sent && !job.failed {
			h2_send_body(lane, &job)
		}
	}
}

@(private)
h2_open :: proc(lane: ^HTTP_Lane, job: ^H2_Job) -> h2.Error {
	if error := h2_fields(job); error.kind != .None {
		return error
	}

	end_stream := len(job.body) == 0 && job.upload_left == 0
	handle, error := h2.connection_open(&lane.engine, job.fields[:job.field_n], end_stream)

	if error.kind != .None {
		return error
	}

	job.handle = handle
	job.opened = true

	if end_stream {
		job.sent = true
	}

	return {}
}

@(private)
h2_fields :: proc(job: ^H2_Job) -> h2.Error {
	url, error := http.url_parse(job.request.url)

	if error.kind != .None {
		return {kind = .Invalid_Input}
	}

	method := http.method_text(job.request.method)

	if method == "" || !url.secure {
		return {kind = .Invalid_Input}
	}

	path := url.target if len(url.target) > 0 else "/"

	if path[0] != '/' {
		return {kind = .Invalid_Input}
	}

	job.field_n = 0
	job.names_n = 0
	if !h2_field(job, ":method", method) ||
	   !h2_field(job, ":scheme", "https") ||
	   !h2_field(job, ":authority", url.authority) ||
	   !h2_field(job, ":path", path) {
		return {kind = .Limit_Exceeded}
	}

	length := i64(len(job.body))

	if job.upload != nil {
		length = job.upload.content_length
	}

	if length > 0 {
		if !h2_field(job, "content-length", strconv.write_int(job.length_text[:], length, 10)) {
			return {kind = .Invalid_Input}
		}
	}

	for header in job.request.headers {
		name := header.name

		if len(name) == 0 {
			return {kind = .Invalid_Input}
		}

		if strings.equal_fold(name, "host") || strings.equal_fold(name, "content-length") {
			continue
		}

		if h2_name_forbidden(name) {
			return {kind = .Invalid_Input}
		}

		if !h2_field(job, name, header.value) {
			return {kind = .Limit_Exceeded}
		}
	}

	return {}
}

@(private)
h2_field :: proc(job: ^H2_Job, name, value: string) -> bool {
	if job.field_n >= len(job.fields) || len(name) == 0 {
		return false
	}

	stored := name

	if name[0] != ':' {
		stored = field_name_lower(job.names[:], &job.names_n, name) or_return
	}

	job.fields[job.field_n] = {
		name  = stored,
		value = value,
	}

	job.field_n += 1

	return true
}

@(private)
is_upper :: proc(c: u8) -> bool {
	return c >= 'A' && c <= 'Z'
}

// HTTP/2 and HTTP/3 field names are lowercase on the wire. Appends the folded
// name to storage and returns that copy; false when it does not fit.
@(private)
field_name_lower :: proc(storage: []u8, used: ^int, name: string) -> (string, bool) {
	if len(name) > len(storage) - used^ {
		return "", false
	}

	start := used^

	for i in 0 ..< len(name) {
		c := name[i]

		if is_upper(c) {
			c += 32
		}

		storage[start + i] = c
	}

	used^ += len(name)

	return string(storage[start:used^]), true
}

@(private)
h2_send_body :: proc(lane: ^HTTP_Lane, job: ^H2_Job) {
	if job.chunk.allocator.procedure != nil || len(job.chunk.storage) > 0 {
		end_stream := job.body_at >= len(job.body) && job.upload_left == 0
		error := h2.connection_send_data(&lane.engine, job.handle, &job.chunk, end_stream)

		if error.kind == .Limit_Exceeded {
			return
		}

		if error.kind != .None {
			owned.destroy(&job.chunk)
			h2_fail(job, h2_map_error(error, h2_effect(job), job.status))
			job.want_reset = true
			return
		}

		if end_stream {
			job.sent = true
		}

		return
	}

	if job.body_at < len(job.body) {
		amount := min(16384, len(job.body) - job.body_at)
		chunk, error := owned.allocate(amount, lane.allocator)

		if error.kind != .None {
			h2_fail(job, {kind = .Allocation_Failed, phase = .Admission, allocation = error.allocation})
			return
		}

		copy(chunk.data, job.body[job.body_at:][:amount])
		job.body_at += amount
		job.chunk = chunk
		h2_send_body(lane, job)
		return
	}

	if job.upload_left > 0 {
		amount := min(16384, int(job.upload_left))
		chunk, error := owned.allocate(amount, lane.allocator)

		if error.kind != .None {
			h2_fail(job, {kind = .Allocation_Failed, phase = .Admission, allocation = error.allocation})
			return
		}

		filled := 0

		for filled < amount {
			got, read_error := io.read(job.upload.stream, chunk.data[filled:])

			if got > 0 {
				filled += got
			}

			if read_error != nil && read_error != io.Error.EOF || got == 0 {
				owned.destroy(&chunk)
				fail := HTTP_Error {
					kind      = .IO_Failed,
					phase     = .Read,
					source_io = read_error,
				}

				h2_fail(job, fail)
				lane.reusable = false
				return
			}
		}

		job.upload_left -= i64(amount)
		job.chunk = chunk
		h2_send_body(lane, job)
	}
}

@(private)
h2_service :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) -> (bool, HTTP_Error) {
	h2_tunnel_reap(lane)
	progress := h2_retired_requests_reap(lane)

	if !lane.engine_up {
		return false, {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
	}

	for _ in 0 ..< 16 {
		events, poll_error := h2_poll(lane, jobs)

		if poll_error.kind != .None {
			lane.dead = true
			lane.reusable = false
			return progress, poll_error
		}

		if events {
			progress = true
		}

		flushed := h2.connection_flush(&lane.engine)
		lived := h2.connection_lifecycle(&lane.engine)
		fed := h2.connection_feed(&lane.engine, nil)
		progress = h2_retired_requests_reap(lane) || progress

		if flushed.error.kind != .None || lived.error.kind != .None || fed.error.kind != .None {
			lane.dead = true
			lane.reusable = false
			error :=
				flushed.error if \
					flushed.error.kind != .None else \
					lived.error if lived.error.kind != .None else fed.error
			return progress, h2_map_error(error, .Unknown, 0)
		}

		reason :=
			fed.reason if \
				fed.status == .Backpressure else \
				lived.reason if lived.status == .Backpressure else flushed.reason
		waiting := fed.status == .Backpressure || lived.status == .Backpressure || flushed.status == .Backpressure

		if waiting && reason == .Events {
			continue
		}

		if fed.status == .Yield || lived.status == .Yield || flushed.status == .Yield {
			continue
		}

		break
	}

	return progress, {}
}

@(private)
h2_poll :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) -> (bool, HTTP_Error) {
	saw := false

	for {
		event, ok := h2.connection_poll(&lane.engine)

		if !ok {
			break
		}

		saw = true
		handled, taken, error := h2_tunnel_event(lane, event)

		if !handled {
			error = h2_apply(lane, jobs, event)
		}

		release_error: h2.Error

		if !taken {
			release_error = h2.connection_event_release(&lane.engine, event.token)
		}

		if error.kind != .None {
			return true, error
		}

		if release_error.kind != .None {
			return true, h2_map_error(release_error, .Unknown, 0)
		}

		for &job in jobs {
			if job.want_reset && !job.reset_sent && job.opened {
				reset_error := h2.connection_reset(&lane.engine, job.handle, .Cancel)
				job.reset_sent = reset_error.kind == .None || reset_error.kind == .Closed
				job.want_reset = false
			}
		}
	}

	return saw, {}
}

@(private)
h2_apply :: proc(lane: ^HTTP_Lane, jobs: []H2_Job, event: h2.Event_View) -> HTTP_Error {
	if h2_retired_request_event(lane, event) {
		return {}
	}

	switch value in event.payload {
	case h2.Ready_Event:
		lane.ready = true
	case h2.Peer_Settings_Event, h2.Ping_Ack_Event:
	case h2.Goaway_Event:
		lane.goaway = true
		lane.reusable = false

		for &job in jobs {
			if !job.opened || job.failed || job.ended {
				continue
			}

			if job.handle.stream_id > value.last_stream_id {
				h2_fail(&job, {kind = .IO_Failed, phase = .Protocol})
			}
		}
	case h2.Terminal_Event:
		lane.dead = true
		lane.reusable = false
		return h2_map_error(value.error, .Unknown, 0)
	case h2.Headers_Event:
		job := h2_find(jobs, value.stream)

		if job == nil {
			lane.dead = true
			return {kind = .IO_Failed, phase = .Protocol, write_effect = .Unknown}
		}

		if value.kind == .Trailers {
			if value.end_stream {
				job.ended = true
			}

			break
		}

		if value.summary.status < 200 {
			job.informational += 1

			if job.informational > 7 {
				h2_fail(job, {kind = .Too_Many_Informational, phase = .Protocol})
				job.want_reset = true
			}

			break
		}

		if job.status != 0 {
			h2_fail(job, {kind = .Invalid_Status, phase = .Protocol})
			job.want_reset = true
			break
		}

		job.status = int(value.summary.status)

		if copy_error := h2_copy_headers(job, value.summary.fields, lane.allocator); copy_error.kind != .None {
			h2_fail(job, copy_error)
			job.want_reset = true
			break
		}

		if length, present := value.summary.content_length.?; present && length > u64(lane.byte_limit) {
			h2_fail(job, {kind = .Body_Oversized, phase = .Body_Limit, status = job.status})
			job.want_reset = true
			break
		}

		if value.end_stream {
			job.ended = true
		}
	case h2.Data_Event:
		job := h2_find(jobs, value.stream)

		if job == nil {
			lane.dead = true
			return {kind = .IO_Failed, phase = .Protocol, write_effect = .Unknown}
		}

		if job.failed {
			break
		}

		method := http.method_text(job.request.method)

		if len(value.data) > 0 && !http.response_body_allowed(job.status, method) {
			h2_fail(job, {kind = .Conflicting_Framing, phase = .Protocol, status = job.status})
			job.want_reset = true
			break
		}

		if len(job.response.body_storage) + len(value.data) > lane.byte_limit {
			h2_fail(job, {kind = .Body_Oversized, phase = .Body_Limit, status = job.status})
			job.want_reset = true
			break
		}

		if len(value.data) > 0 {
			if _, allocation := append(&job.response.body_storage, ..value.data); allocation != nil {
				h2_fail(
					job,
					{kind = .Allocation_Failed, phase = .Admission, allocation = allocation, status = job.status},
				)
				job.want_reset = true
				break
			}
		}

		if value.end_stream {
			job.ended = true
		}
	case h2.Stream_End_Event:
		if job := h2_find(jobs, value.stream); job != nil {
			job.ended = true
		}
	case h2.Reset_Event:
		if job := h2_find(jobs, value.stream); job != nil {
			h2_fail(job, {kind = .IO_Failed, phase = .Protocol, status = job.status})
		}
	case h2.Not_Processed_Event:
		if job := h2_find(jobs, value.stream); job != nil {
			h2_fail(job, {kind = .IO_Failed, phase = .Protocol, status = job.status})
		}

		lane.reusable = false
	case h2.Promise_Event:
		lane.reusable = false
		return {kind = .IO_Failed, phase = .Protocol, write_effect = .Unknown}
	}

	return {}
}

@(private)
h2_find :: proc(jobs: []H2_Job, handle: h2.Stream_Handle) -> ^H2_Job {
	for &job in jobs {
		if job.opened && job.handle == handle {
			return &job
		}
	}

	return nil
}

@(private)
h2_copy_headers :: proc(job: ^H2_Job, fields: []hpack.Field, allocator: mem.Allocator) -> HTTP_Error {
	count, bytes := 0, 0

	for field in fields {
		if len(field.name) == 0 || field.name[0] == ':' {
			continue
		}

		count += 1
		bytes += len(field.name) + len(field.value)
	}

	if count > http.MAX_HEADERS {
		return {kind = .Header_Limit, phase = .Protocol, write_effect = h2_effect(job), status = job.status}
	}

	storage, allocation := make([]u8, bytes, allocator)

	if allocation != nil {
		return {
			kind = .Allocation_Failed,
			phase = .Admission,
			allocation = allocation,
			write_effect = h2_effect(job),
			status = job.status,
		}
	}

	headers, header_allocation := make([]http.Header, count, allocator)

	if header_allocation != nil {
		delete(storage, allocator)
		return {
			kind = .Allocation_Failed,
			phase = .Admission,
			allocation = header_allocation,
			write_effect = h2_effect(job),
			status = job.status,
		}
	}

	at := 0
	index := 0

	for field in fields {
		if len(field.name) == 0 || field.name[0] == ':' {
			continue
		}

		name := storage[at:][:len(field.name)]
		at += copy(name, field.name)
		value := storage[at:][:len(field.value)]
		at += copy(value, field.value)
		headers[index] = {
			name  = string(name),
			value = string(value),
		}

		index += 1
	}

	job.response.allocator = allocator
	job.response.header_storage = storage
	job.response.headers = headers
	job.response.status = job.status
	body, body_allocation := make([dynamic]u8, 0, 64, allocator)

	if body_allocation != nil {
		return {kind = .Allocation_Failed, phase = .Admission, allocation = body_allocation, status = job.status}
	}

	job.response.body_storage = body

	return {}
}

@(private)
h2_reset_open :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) {
	if !lane.engine_up {
		return
	}

	for &job in jobs {
		if job.opened && !job.reset_sent && !job.ended {
			error := h2.connection_reset(&lane.engine, job.handle, .Cancel)
			job.reset_sent = error.kind == .None || error.kind == .Closed
		}
	}
}

@(private)
h2_write_all :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) -> (bool, HTTP_Error) {
	wrote := false

	if lane.tls == nil || !lane.engine_up {
		return false, {kind = .IO_Failed, phase = .Protocol, write_effect = .Not_Sent}
	}

	for _ in 0 ..< 64 {
		view, ok := h2.connection_output_front(&lane.engine)

		if !ok {
			return wrote, {}
		}

		if len(view.bytes) == 0 {
			_ = h2.connection_output_release(&lane.engine, view.token)
			continue
		}

		n, write_error := tls_api.write(lane.tls, view.bytes)

		if n > 0 {
			advance_error := h2.connection_output_advance(&lane.engine, view.token, n)

			if advance_error.kind != .None {
				lane.dead = true
				lane.reusable = false
				return wrote, h2_map_error(advance_error, .Unknown, 0)
			}

			wrote = true

			for &job in jobs {
				if !job.opened {
					continue
				}

				job.on_wire = true

				if job.status == 0 && job.error.kind != .None && job.error.write_effect == .Not_Sent {
					job.error.write_effect = .Unknown
				}
			}
		}

		if write_error.kind != .None {
			if n == 0 {
				_ = h2.connection_output_release(&lane.engine, view.token)
			}

			lane.dead = true
			lane.reusable = false
			return wrote, h2_tls_error(write_error, .Unknown if wrote || n > 0 else .Not_Sent, 0)
		}

		if n == 0 {
			_ = h2.connection_output_release(&lane.engine, view.token)
			lane.dead = true
			return wrote, {kind = .IO_Failed, phase = .Write, write_effect = .Not_Sent}
		}
	}

	return wrote, {}
}

@(private)
h2_read :: proc(lane: ^HTTP_Lane) -> (int, HTTP_Error) {
	n, read_error := tls_api.read(lane.tls, lane.read_buf[:])

	if read_error.kind != .None {
		lane.dead = true
		lane.reusable = false
		return n, h2_tls_error(read_error, .Unknown, 0)
	}

	if n <= 0 || n > len(lane.read_buf) {
		lane.dead = true
		return 0, {kind = .IO_Failed, phase = .Read, write_effect = .Unknown}
	}

	return n, {}
}

@(private)
h2_finish :: proc(lane: ^HTTP_Lane, jobs: []H2_Job) {
	if lane != nil && lane.engine_up {
		for &job in jobs {
			if !job.opened {
				continue
			}

			if !job.sent {
				lane.reusable = false
				continue
			}

			// Retain only scalar identity, never the job's borrowed request storage.
			// The copy is required: escape analysis is not field-sensitive, so passing
			// job.handle marks the borrowed request as retained by the lane.
			handle := h2.Stream_Handle {
				owner_id   = job.handle.owner_id,
				slot       = job.handle.slot,
				generation = job.handle.generation,
				stream_id  = job.handle.stream_id,
			}

			h2_retire_request(lane, handle)
		}
	}

	for &job in jobs {
		if job.failed || job.error.kind != .None {
			continue
		}

		job.response.status = job.status
		job.response.body = job.response.body_storage[:]
	}
}

@(private)
h2_feed :: proc(lane: ^HTTP_Lane, jobs: []H2_Job, src: []u8) -> HTTP_Error {
	rest := src
	spins := 0

	for len(rest) > 0 && spins < 16 {
		result := h2.connection_feed(&lane.engine, rest)

		if result.error.kind != .None {
			lane.dead = true
			lane.reusable = false
			return h2_map_error(result.error, .Unknown, 0)
		}

		if result.consumed < 0 || result.consumed > len(rest) {
			lane.dead = true
			return {kind = .IO_Failed, phase = .Protocol, write_effect = .Unknown}
		}

		if result.consumed == 0 {
			spins += 1
			_, service_error := h2_service(lane, jobs)

			if service_error.kind != .None {
				return service_error
			}

			_, write_error := h2_write_all(lane, jobs)

			if write_error.kind != .None {
				return write_error
			}

			continue
		}

		rest = rest[result.consumed:]
		spins = 0
	}

	if len(rest) > 0 {
		lane.dead = true
		return {kind = .IO_Failed, phase = .Protocol, write_effect = .Unknown}
	}

	return {}
}

// Folded comparison without retaining a lowercased copy. The matched set is
// the connection-specific field names HTTP/2 forbids on a request.
@(private)
h2_name_forbidden :: proc(name: string) -> bool {
	switch len(name) {
	case 2:
		return strings.equal_fold(name, "te")
	case 7:
		return strings.equal_fold(name, "upgrade")
	case 10:
		return strings.equal_fold(name, "keep-alive") || strings.equal_fold(name, "connection")
	case 16:
		return strings.equal_fold(name, "proxy-connection")
	case 17:
		return strings.equal_fold(name, "transfer-encoding")
	}

	return false
}

@(private)
http_client_h3_cancelled :: proc(data: rawptr) -> bool {
	return h2_cancelled(&(cast(^HTTP_Client)data).cancel)
}

@(private)
HTTP_Client_Identity :: struct {
	store:      ^credential_store.Store,
	lease:      credential_store.Lease,
	generation: u64,
}
@(private)
http_identity_acquire :: proc(config: tls_api.Config) -> (HTTP_Client_Identity, HTTP_Error) {
	identity := HTTP_Client_Identity {
		store = config.client_credentials,
	}

	if identity.store == nil {
		if config.client_credential_lease != nil {
			return {}, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
		}

		return identity, {}
	}

	lease: credential_store.Lease
	e: credential_store.Error

	if config.client_credential_lease != nil {
		lease, e = credential_store.retain(identity.store, config.client_credential_lease^)
	} else {
		lease, e = credential_store.acquire(identity.store)
	}

	if e.kind != .None {
		return {}, {kind = .TLS_Failed, phase = .TLS, write_effect = .Not_Sent}
	}

	generation, ge := credential_store.lease_generation(identity.store, lease)

	if ge.kind != .None {
		_ = credential_store.release(identity.store, &lease)
		return {}, {kind = .TLS_Failed, phase = .TLS, write_effect = .Not_Sent}
	}

	identity.lease = lease
	identity.generation = generation

	return identity, {}
}
@(private)
http_identity_release :: proc(identity: ^HTTP_Client_Identity) {
	if identity.store != nil {
		_ = credential_store.release(identity.store, &identity.lease)
	}

	identity^ = {}
}
@(private)
http_tls_config_equal :: proc(a, b: tls_api.Config) -> bool {
	if a.client_credentials != b.client_credentials ||
	   a.session != b.session ||
	   a.session_cache != b.session_cache ||
	   a.early_data != b.early_data ||
	   a.remember_tickets != b.remember_tickets ||
	   a.handshake_timeout != b.handshake_timeout ||
	   len(a.root_cas) != len(b.root_cas) ||
	   len(a.alpn_protocols) != len(b.alpn_protocols) {
		return false
	}

	for root, i in a.root_cas {
		if root != b.root_cas[i] {
			return false
		}
	}

	for protocol, i in a.alpn_protocols {
		if protocol != b.alpn_protocols[i] {
			return false
		}
	}

	return true
}
@(private)
http_lane_has_tunnels :: proc(lane: ^HTTP_Lane) -> bool {
	for tunnel in lane.tunnels {
		if tunnel != nil {
			return true
		}
	}

	return false
}

// Matches the maximum accepted HTTP_Origin_Limits.max_streams. Closed request
// handles remain owned until event/output/credit disposal and the peer checkpoint
// permit physical reaping; returning a response is earlier than that boundary.
HTTP_RETIRED_REQUEST_SLOTS :: 32

@(private)
h2_retire_request :: proc(lane: ^HTTP_Lane, handle: h2.Stream_Handle) {
	error := h2.connection_reap(&lane.engine, handle)

	if error.kind == .None || error.kind == .Invalid_Input {
		return
	}

	if error.kind != .Invalid_State {
		lane.reusable = false
		return
	}

	available := -1

	for slot, index in lane.retired_requests {
		if slot == handle {
			return
		}

		if slot == {} && available < 0 {
			available = index
		}
	}

	if available >= 0 {
		lane.retired_requests[available] = handle
		return
	}

	// No handle may be forgotten at capacity. Lane close aborts and drains all
	// engine owners before a later request can select another connection.
	lane.reusable = false
}

@(private)
h2_retired_requests_reap :: proc(lane: ^HTTP_Lane) -> bool {
	if lane == nil || !lane.engine_up {
		return false
	}

	progress := false

	for &handle in lane.retired_requests {
		if handle == {} {
			continue
		}

		error := h2.connection_reap(&lane.engine, handle)

		if error.kind == .None || error.kind == .Invalid_Input {
			handle = {}
			progress = true
		} else if error.kind != .Invalid_State {
			lane.reusable = false
		}
	}

	return progress
}

@(private)
h2_retired_request_event :: proc(lane: ^HTTP_Lane, event: h2.Event_View) -> bool {
	handle: h2.Stream_Handle
	#partial switch value in event.payload {
	case h2.Headers_Event:
		handle = value.stream
	case h2.Data_Event:
		handle = value.stream
	case h2.Stream_End_Event:
		handle = value.stream
	case h2.Reset_Event:
		handle = value.stream
	case h2.Not_Processed_Event:
		handle = value.stream
	case:
		return false
	}

	for retired in lane.retired_requests {
		if retired == handle {
			return true
		}
	}

	return false
}
