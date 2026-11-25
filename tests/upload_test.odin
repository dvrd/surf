package tests

import surf "shared:surf"
import "core:io"
import "core:net"
import "core:strings"
import "core:testing"
import "core:time"

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
		state.closes += 1; return 0, {}
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

Upload_Wire :: struct {
	producer:                                 ^Upload_Producer,
	bytes:                                    [3 * surf.UPLOAD_BUFFER_SIZE]u8,
	used, response_at, writes, reads, closes: int,
	write_step:                               int,
	write_error:                              net.Network_Error,
	max_prefetch:                             int,
}
upload_wire_read :: proc(data: rawptr, dst: []u8) -> (int, net.Network_Error) {
	wire := cast(^Upload_Wire)data
	wire.reads += 1
	reply := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

	if wire.response_at == len(reply) {
		return 0, net.Connection_Error.Peer_Closed
	}

	count := copy(dst, reply[wire.response_at:])
	wire.response_at += count

	return count, nil
}
upload_wire_write :: proc(data: rawptr, src: []u8) -> (int, net.Network_Error) {
	wire := cast(^Upload_Wire)data
	wire.writes += 1

	if wire.write_error != nil {
		return 0, wire.write_error
	}

	count := len(src)

	if wire.write_step > 0 {
		count = min(count, wire.write_step)
	}

	assert(count <= len(wire.bytes) - wire.used)
	copy(wire.bytes[wire.used:], src[:count])
	wire.used += count

	if wire.producer != nil {
		end := strings.index(string(wire.bytes[:wire.used]), "\r\n\r\n")
		body_count := 0

		if end >= 0 {
			body_count = wire.used - end - 4
		}

		wire.max_prefetch = max(wire.max_prefetch, wire.producer.at - body_count)
	}

	return count, nil
}
upload_wire_close :: proc(data: rawptr) -> net.Network_Error {
	wire := cast(^Upload_Wire)data
	wire.closes += 1

	return nil
}
connection_for_upload :: proc(wire: ^Upload_Wire) -> net.Connection {
	return {data = wire, read = upload_wire_read, write = upload_wire_write, close = upload_wire_close}
}

@(test)
upload_streams_fixed_chunks_through_partial_transport_writes :: proc(t: ^testing.T) {
	body := make([]u8, 2 * surf.UPLOAD_BUFFER_SIZE + 3)
	defer delete(body)

	for &byte, index in body {
		byte = u8(index % 251)
	}

	producer := Upload_Producer {
		bytes = body,
	}

	wire := Upload_Wire {
		producer   = &producer,
		write_step = 113,
	}

	response, error := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .PUT, url = "https://fixture.test/object"},
		source_for(&producer, i64(len(body))),
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect(
		t,
		producer.largest_request <= surf.UPLOAD_BUFFER_SIZE && wire.max_prefetch <= surf.UPLOAD_BUFFER_SIZE,
	)
	testing.expect_value(t, producer.reads, 3)
	testing.expect_value(t, producer.closes + wire.closes, 0)
	actual := string(wire.bytes[:wire.used])
	end := strings.index(actual, "\r\n\r\n")
	testing.expect(t, strings.has_prefix(actual, "PUT /object HTTP/1.1\r\n"))
	testing.expect(
		t,
		strings.contains(actual[:end], "Content-Length: 65539\r\n") ||
		strings.contains(actual[:end], "Content-Length: 65539"),
	)
	testing.expect_value(t, actual[end + 4:], string(body))
}

@(test)
upload_leaves_excess_source_bytes_unread_and_never_probes_eof :: proc(t: ^testing.T) {
	body := []u8{'a', 'b', 'c', 'd', 'e'}
	producer := Upload_Producer {
		bytes = body,
	}

	wire := Upload_Wire {
		producer = &producer,
	}

	response, error := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/"},
		source_for(&producer, 3),
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, producer.at, 3)
	testing.expect_value(t, producer.reads, 1)
	testing.expect(t, strings.has_suffix(string(wire.bytes[:wire.used]), "\r\n\r\nabc"))
	zero := Upload_Producer {
		bytes = body,
	}

	empty_wire := Upload_Wire {
		producer = &zero,
	}

	empty_response, empty_error := surf.exchange_upload(
		connection_for_upload(&empty_wire),
		{method = .DELETE, url = "https://fixture.test/"},
		source_for(&zero, 0),
	)
	defer surf.response_destroy(&empty_response)
	testing.expect_value(t, empty_error.kind, .None)
	testing.expect_value(t, zero.reads, 0)
}

@(test)
upload_short_invalid_and_failed_sources_keep_unknown_write_effect :: proc(t: ^testing.T) {
	for sample in ([]struct {
			bytes:         []u8,
			failure:       io.Error,
			invalid_count: int,
			no_progress:   bool,
			expected:      string,
		} {
			{[]u8{'a'}, {}, 0, false, "short"},
			{nil, .Permission_Denied, 0, false, "read"},
			{nil, {}, -1, false, "count"},
			{nil, {}, 1, false, "count"},
			{nil, {}, 0, true, "progress"},
		}) {
		producer := Upload_Producer {
			bytes         = sample.bytes,
			failure       = sample.failure,
			invalid_count = sample.invalid_count,
			no_progress   = sample.no_progress,
		}
		wire := Upload_Wire {
			producer = &producer,
		}
		response, error := surf.exchange_upload(
			connection_for_upload(&wire),
			{method = .POST, url = "https://fixture.test/"},
			source_for(&producer, 3),
		)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.phase, .Write)
		testing.expect_value(t, error.write_effect, .Unknown)
		testing.expect_value(t, wire.reads, 0)
		testing.expect_value(t, producer.closes + wire.closes, 0)
		switch sample.expected {
		case "short":
			testing.expect_value(t, error.kind, .Unexpected_EOF); testing.expect_value(t, error.source_io, .EOF)
		case "read":
			testing.expect_value(t, error.kind, .IO_Failed)
			testing.expect_value(t, error.source_io, .Permission_Denied)
		case "count":
			testing.expect_value(t, error.transport, net.Connection_Error.Invalid_Count)
		case "progress":
			testing.expect_value(t, error.kind, .No_Progress)
		}
	}
}

@(test)
upload_validation_and_redirect_rejection_happen_before_io :: proc(t: ^testing.T) {
	producer := Upload_Producer {
		bytes = []u8{'a'},
	}

	wire := Upload_Wire {
		producer = &producer,
	}

	_, invalid := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/", body = []u8{'x'}},
		source_for(&producer, 1),
	)
	testing.expect_value(t, invalid.phase, .Configuration)
	testing.expect_value(t, invalid.write_effect, .Not_Sent)
	_, redirected := surf.execute_upload(
		{method = .POST, url = "http://offline-fixture.test/"},
		source_for(&producer, 1),
		{allow_http = true, max_redirects = 1},
	)
	testing.expect_value(t, redirected.kind, .Invalid_Config)
	testing.expect_value(t, redirected.write_effect, .Not_Sent)
	_, negative := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/"},
		source_for(&producer, -1),
	)
	testing.expect_value(t, negative.kind, .Invalid_Config)
	_, missing := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/"},
		{content_length = 1},
	)
	testing.expect_value(t, missing.kind, .Invalid_Config)
	_, head := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .HEAD, url = "https://fixture.test/"},
		source_for(&producer, 1),
	)
	testing.expect_value(t, head.kind, .Invalid_Method)
	testing.expect_value(t, producer.reads + wire.writes, 0)
}

@(test)
upload_deadlines_cancellation_and_source_cooperation_are_explicit :: proc(t: ^testing.T) {
	for sample in ([]struct {
			cause:    net.Network_Error,
			phase:    surf.HTTP_Phase,
		} {
			{net.TCP_Send_Error.Timeout, .Deadline},
			{net.Connection_Error.Cancelled, .Cancellation},
		}) {
		producer := Upload_Producer {
			bytes = []u8{'a'},
		}

		wire := Upload_Wire {
			producer = &producer,
			write_error = sample.cause,
		}

		_, error := surf.exchange_upload(
			connection_for_upload(&wire),
			{method = .POST, url = "https://fixture.test/"},
			source_for(&producer, 1),
		)
		testing.expect_value(t, error.phase, sample.phase)
		testing.expect_value(t, error.write_effect, .Unknown)
		testing.expect_value(t, producer.reads, 0)
	}

	producer := Upload_Producer {
		bytes = []u8{'a'},
	}

	wire := Upload_Wire {
		producer = &producer,
	}

	_, expired := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/"},
		source_for(&producer, 1),
		deadline = time.time_add(time.now(), -time.Second),
	)
	testing.expect_value(t, expired.phase, .Deadline)
	testing.expect_value(t, expired.write_effect, .Not_Sent)
	testing.expect_value(t, producer.reads + wire.writes, 0)
	producer.delay = 60 * time.Millisecond
	_, cooperative := surf.exchange_upload(
		connection_for_upload(&wire),
		{method = .POST, url = "https://fixture.test/"},
		source_for(&producer, 1),
		deadline = time.time_add(time.now(), 50 * time.Millisecond),
	)
	testing.expect_value(t, cooperative.phase, .Deadline)
	testing.expect_value(t, cooperative.write_effect, .Unknown)
	testing.expect_value(t, producer.reads, 1)
}
