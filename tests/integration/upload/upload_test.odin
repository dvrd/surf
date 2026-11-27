package tests

import "../../support/loopback"
import "core:fmt"
import "core:io"
import "core:strings"
import "core:testing"
import "core:time"
import "shared:async"
import "shared:surf"

Upload_Producer :: struct {
	bytes:                              []u8,
	at, reads, closes, largest_request: int,
	failure:                            io.Error,
	invalid_count:                      int,
	no_progress:                        bool,
	delay:                              time.Duration,
}

upload_producer :: proc(
	data: rawptr,
	mode: io.Stream_Mode,
	dst: []u8,
	offset: i64,
	whence: io.Seek_From,
) -> (
	i64,
	io.Error,
) {
	state := cast(^Upload_Producer)data
	#partial switch mode {
	case .Query:
		return io.query_utility({.Read, .Close})
	case .Close:
		state.closes += 1
		return 0, {}
	case .Read:
		state.reads += 1
		state.largest_request = max(state.largest_request, len(dst))
		if state.delay > 0 {
			time.sleep(state.delay)
		}

		if state.invalid_count < 0 {
			return -1, {}
		}

		if state.invalid_count > 0 {
			return i64(len(dst) + 1), {}
		}

		if state.no_progress {
			return 0, {}
		}

		if state.failure != .None {
			return 0, state.failure
		}

		if state.at == len(state.bytes) {
			return 0, .EOF
		}

		count := copy(dst, state.bytes[state.at:])
		state.at += count
		return i64(count), {}
	}

	return 0, .Unsupported
}

source_for :: proc(state: ^Upload_Producer, length: i64) -> surf.Upload_Source {
	return {stream = {procedure = upload_producer, data = state}, content_length = length}
}

UPLOAD_OK :: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

Upload_Peer :: struct {
	server: loopback.Server,
	base:   string,
}

upload_peer_start :: proc(
	t: ^testing.T,
	peer: ^Upload_Peer,
	answer: loopback.Answer,
	early := false,
) -> bool {
	peer.server.answer = answer
	peer.server.early = early

	if !testing.expect(t, loopback.server_start(&peer.server)) {
		return false
	}

	peer.base = fmt.aprintf("http://127.0.0.1:%d", peer.server.port)

	return true
}

upload_peer_stop :: proc(peer: ^Upload_Peer) {
	loopback.server_stop(&peer.server)
	delete(peer.base)
}

upload_url :: proc(peer: ^Upload_Peer, path: string) -> string {
	return fmt.tprintf("%s%s", peer.base, path)
}

UPLOAD_CONFIG :: surf.Config {
	allow_http = true,
	timeout    = 3 * time.Second,
}

@(test)
upload_streams_fixed_chunks_from_the_source :: proc(t: ^testing.T) {
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {wire = UPLOAD_OK}) {
		return
	}
	defer upload_peer_stop(&peer)

	body := make([]u8, 2 * surf.UPLOAD_BUFFER_SIZE + 3)
	defer delete(body)

	for &byte, index in body {
		byte = u8(index % 251)
	}

	producer := Upload_Producer {
		bytes = body,
	}

	response, error := surf.execute_upload(
		{method = .PUT, url = upload_url(&peer, "/object")},
		source_for(&producer, i64(len(body))),
		UPLOAD_CONFIG,
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect(t, producer.largest_request <= surf.UPLOAD_BUFFER_SIZE)
	testing.expect_value(t, producer.reads, 3)
	testing.expect_value(t, producer.closes, 0)
	actual := loopback.server_last(&peer.server, context.temp_allocator)
	end := strings.index(actual, "\r\n\r\n")

	if !testing.expect(t, end > 0) {
		return
	}

	testing.expect(t, strings.has_prefix(actual, "PUT /object HTTP/1.1\r\n"))
	length, _ := loopback.content_length(actual[:end])
	testing.expect_value(t, length, len(body))
	testing.expect(t, actual[end + 4:] == string(body))
}

@(test)
upload_leaves_excess_source_bytes_unread_and_never_probes_eof :: proc(t: ^testing.T) {
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {wire = UPLOAD_OK}) {
		return
	}
	defer upload_peer_stop(&peer)

	body := []u8{'a', 'b', 'c', 'd', 'e'}
	producer := Upload_Producer {
		bytes = body,
	}

	response, error := surf.execute_upload(
		{method = .POST, url = upload_url(&peer, "/")},
		source_for(&producer, 3),
		UPLOAD_CONFIG,
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, producer.at, 3)
	testing.expect_value(t, producer.reads, 1)
	testing.expect(
		t,
		strings.has_suffix(
			loopback.server_last(&peer.server, context.temp_allocator),
			"\r\n\r\nabc",
		),
	)
	zero := Upload_Producer {
		bytes = body,
	}

	empty_response, empty_error := surf.execute_upload(
		{method = .DELETE, url = upload_url(&peer, "/")},
		source_for(&zero, 0),
		UPLOAD_CONFIG,
	)
	defer surf.response_destroy(&empty_response)
	testing.expect_value(t, empty_error.kind, .None)
	testing.expect_value(t, zero.reads, 0)
	testing.expect_value(t, loopback.server_requests(&peer.server), 2)
}

// A source that ends early, fails, or reports a count outside its buffer fails
// the write: the request never carries more or fewer bytes than its length.
// Nothing of it may count as answered, and the source is never closed.
@(test)
upload_short_invalid_and_failed_sources_fail_the_write :: proc(t: ^testing.T) {
	for sample in ([]struct {
			bytes:         []u8,
			failure:       io.Error,
			invalid_count: int,
			no_progress:   bool,
			source_io:     io.Error,
		} {
			{[]u8{'a'}, {}, 0, false, .Unexpected_EOF},
			{nil, .Permission_Denied, 0, false, .Permission_Denied},
			{nil, {}, -1, false, .Unexpected_EOF},
			{nil, {}, 1, false, .None},
			{nil, {}, 0, true, .Unexpected_EOF},
		}) {
		peer: Upload_Peer

		if !upload_peer_start(t, &peer, {wire = UPLOAD_OK}) {
			return
		}

		producer := Upload_Producer {
			bytes         = sample.bytes,
			failure       = sample.failure,
			invalid_count = sample.invalid_count,
			no_progress   = sample.no_progress,
		}
		response, error := surf.execute_upload(
			{method = .POST, url = upload_url(&peer, "/")},
			source_for(&producer, 3),
			UPLOAD_CONFIG,
		)
		surf.response_destroy(&response)
		testing.expectf(t, error.kind == .IO_Failed, "%v: kind %v", sample, error.kind)
		testing.expectf(t, error.phase == .Write, "%v: phase %v", sample, error.phase)
		// .None in a sample: any source error will do.
		if sample.source_io == .None {
			testing.expectf(
				t,
				error.source_io != .None,
				"%v: source_io %v",
				sample,
				error.source_io,
			)
		} else {
			testing.expectf(
				t,
				error.source_io == sample.source_io,
				"%v: source_io %v",
				sample,
				error.source_io,
			)
		}

		testing.expect(t, error.write_effect != .Response_Received)
		testing.expect_value(t, error.status, 0)
		testing.expect_value(t, producer.closes, 0)
		testing.expect_value(t, loopback.server_requests(&peer.server), 0)

		// Not_Sent is a promise that no byte of the request reached the peer.
		if error.write_effect == .Not_Sent {
			testing.expect_value(t, loopback.server_received(&peer.server), 0)
		}

		upload_peer_stop(&peer)
	}
}

@(test)
upload_validation_and_redirect_rejection_happen_before_io :: proc(t: ^testing.T) {
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {wire = UPLOAD_OK}) {
		return
	}
	defer upload_peer_stop(&peer)

	url := upload_url(&peer, "/")
	producer := Upload_Producer {
		bytes = []u8{'a'},
	}

	_, invalid := surf.execute_upload(
		{method = .POST, url = url, body = []u8{'x'}},
		source_for(&producer, 1),
		UPLOAD_CONFIG,
	)
	testing.expect_value(t, invalid.phase, .Configuration)
	testing.expect_value(t, invalid.write_effect, .Not_Sent)
	redirecting := UPLOAD_CONFIG
	redirecting.max_redirects = 1
	_, redirected := surf.execute_upload(
		{method = .POST, url = url},
		source_for(&producer, 1),
		redirecting,
	)
	testing.expect_value(t, redirected.kind, .Invalid_Config)
	testing.expect_value(t, redirected.write_effect, .Not_Sent)
	_, negative := surf.execute_upload(
		{method = .POST, url = url},
		source_for(&producer, -1),
		UPLOAD_CONFIG,
	)
	testing.expect_value(t, negative.kind, .Invalid_Config)
	_, missing := surf.execute_upload(
		{method = .POST, url = url},
		{content_length = 1},
		UPLOAD_CONFIG,
	)
	testing.expect_value(t, missing.kind, .Invalid_Config)
	_, head := surf.execute_upload(
		{method = .HEAD, url = url},
		source_for(&producer, 1),
		UPLOAD_CONFIG,
	)
	testing.expect_value(t, head.kind, .Invalid_Method)
	h3 := UPLOAD_CONFIG
	h3.http3 = true
	_, cleartext := surf.execute_upload({method = .POST, url = url}, source_for(&producer, 1), h3)
	testing.expect_value(t, cleartext.kind, .Insecure_URL)
	testing.expect_value(t, cleartext.write_effect, .Not_Sent)
	testing.expect_value(t, producer.reads, 0)
	testing.expect_value(t, loopback.server_accepts(&peer.server), 0)
}

// A blocking source read cannot be preempted: the deadline is noticed once it
// returns, and the request fails as a deadline after its head went out.
@(test)
upload_deadline_waits_for_a_cooperative_source :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {action = .Silent}, early = true) {
		return
	}
	defer upload_peer_stop(&peer)

	producer := Upload_Producer {
		bytes = []u8{'a', 'b'},
		delay = 300 * time.Millisecond,
	}

	config := UPLOAD_CONFIG
	config.timeout = 100 * time.Millisecond
	_, cooperative := surf.execute_upload(
		{method = .POST, url = upload_url(&peer, "/")},
		source_for(&producer, 2),
		config,
	)
	testing.expect_value(t, cooperative.phase, .Deadline)
	testing.expect(t, cooperative.write_effect != .Response_Received)
	testing.expect_value(t, producer.reads, 1)
}

Upload_Runtime :: struct {
	r:      async.Runtime,
	client: surf.Client,
}

upload_runtime_start :: proc(t: ^testing.T, u: ^Upload_Runtime) -> bool {
	if !testing.expect_value(
		t,
		async.init(&u.r, {workers = 1, task_capacity = 16, io_capacity = 64}).kind,
		.None,
	) {
		return false
	}

	if !testing.expect_value(
		t,
		surf.client_init(&u.client, &u.r, {http = UPLOAD_CONFIG}).kind,
		.None,
	) {
		async.destroy(&u.r)
		return false
	}

	if !testing.expect_value(t, async.start(&u.r).kind, .None) {
		return false
	}

	return true
}

upload_runtime_stop :: proc(u: ^Upload_Runtime) {
	_ = surf.client_close(&u.client)

	for !surf.client_quiescent(&u.client) {
		time.sleep(2 * time.Millisecond)
	}

	_ = surf.client_destroy(&u.client)
	async.shutdown(&u.r)
	_ = async.join(&u.r)
	_ = async.destroy(&u.r)
}

upload_wait :: proc(
	c: ^surf.Client,
	handle: surf.Request_Handle,
	limit: time.Duration,
) -> (
	surf.HTTP_Error,
	bool,
) {
	started := time.tick_now()

	for time.tick_since(started) < limit {
		completion, done := surf.client_poll(c)
		if done && completion.request == handle {
			return completion.error, true
		}

		time.sleep(2 * time.Millisecond)
	}

	return {}, false
}

upload_push :: proc(t: ^testing.T, c: ^surf.Client, handle: surf.Request_Handle, data: []u8) {
	chunk, copied := surf.body_chunk_copy(data, len(data))
	assert(copied.kind == .None)
	status, pushed := surf.client_upload_submit(c, handle, &chunk)
	testing.expect_value(t, pushed.kind, .None)
	testing.expect_value(t, status, surf.Upload_Submit_Status.Accepted)
}

@(test)
upload_expired_deadline_is_not_sent :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {action = .Silent}, early = true) {
		return
	}
	defer upload_peer_stop(&peer)

	u := new(Upload_Runtime)
	defer free(u)

	if !upload_runtime_start(t, u) {
		return
	}
	defer upload_runtime_stop(u)

	handle, submitted := surf.client_submit_stream(
		&u.client,
		{method = .POST, url = upload_url(&peer, "/")},
		{upload_length = 1},
		time.tick_now(),
	)

	if !testing.expect_value(t, submitted.kind, .None) {
		return
	}
	defer surf.client_release(&u.client, handle)

	// The client may fail the expired request before the chunk arrives.
	chunk, copied := surf.body_chunk_copy([]u8{'a'}, 1)
	assert(copied.kind == .None)
	status, pushed := surf.client_upload_submit(&u.client, handle, &chunk)
	testing.expect_value(t, pushed.kind, .None)

	if status == .Accepted {
		testing.expect_value(t, surf.client_upload_finish(&u.client, handle).kind, .None)
	} else {
		testing.expect_value(t, status, surf.Upload_Submit_Status.Closed)
		surf.body_chunk_release(&chunk)
	}

	late, done := upload_wait(&u.client, handle, 3 * time.Second)

	if !testing.expect(t, done, "an expired request completes") {
		return
	}

	testing.expect_value(t, late.phase, .Deadline)
	testing.expect_value(t, late.write_effect, .Not_Sent)
	testing.expect_value(t, loopback.server_received(&peer.server), 0)
}

// The request's deadline also bounds the wait for upload chunks the caller has
// not pushed yet.
@(test)
upload_deadline_bounds_the_wait_for_chunks :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {action = .Silent}, early = true) {
		return
	}
	defer upload_peer_stop(&peer)

	u := new(Upload_Runtime)
	defer free(u)

	if !upload_runtime_start(t, u) {
		return
	}
	defer upload_runtime_stop(u)

	handle, submitted := surf.client_submit_stream(
		&u.client,
		{method = .POST, url = upload_url(&peer, "/")},
		{upload_length = 1},
		time.tick_add(time.tick_now(), 300 * time.Millisecond),
	)

	if !testing.expect_value(t, submitted.kind, .None) {
		return
	}
	defer surf.client_release(&u.client, handle)

	late, done := upload_wait(&u.client, handle, 3 * time.Second)

	if !testing.expect(t, done, "the deadline ends a request whose upload never arrives") {
		_ = surf.client_cancel(&u.client, handle)
		_, _ = upload_wait(&u.client, handle, 3 * time.Second)
		return
	}

	testing.expect_value(t, late.phase, .Deadline)
}

@(test)
upload_cancellation_after_the_head_is_explicit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	peer: Upload_Peer

	if !upload_peer_start(t, &peer, {action = .Silent}, early = true) {
		return
	}
	defer upload_peer_stop(&peer)

	u := new(Upload_Runtime)
	defer free(u)

	if !upload_runtime_start(t, u) {
		return
	}
	defer upload_runtime_stop(u)

	handle, submitted := surf.client_submit_stream(
		&u.client,
		{method = .POST, url = upload_url(&peer, "/")},
		{upload_length = 4},
	)

	if !testing.expect_value(t, submitted.kind, .None) {
		return
	}
	defer surf.client_release(&u.client, handle)

	upload_push(t, &u.client, handle, []u8{'a', 'b'})
	started := time.tick_now()

	for loopback.server_requests(&peer.server) == 0 && time.tick_since(started) < 5 * time.Second {
		time.sleep(2 * time.Millisecond)
	}

	testing.expect_value(t, loopback.server_requests(&peer.server), 1)
	testing.expect_value(t, surf.client_cancel(&u.client, handle).kind, .None)
	cancelled, done := upload_wait(&u.client, handle, 3 * time.Second)

	if !testing.expect(t, done, "a cancelled request completes") {
		return
	}

	testing.expect_value(t, cancelled.phase, .Cancellation)
	testing.expect_value(t, cancelled.write_effect, .Unknown)
}
