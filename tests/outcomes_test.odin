package tests

import surf "shared:surf"
import http "shared:http"
import "core:net"
import "core:mem"
import "base:runtime"
import "core:testing"

Fault_Stream :: struct {
	wire:        string,
	at:          int,
	write_error: net.Connection_Error,
	read_error:  net.Connection_Error,
	writes:      int,
}
fault_read :: proc(data: rawptr, dst: []u8) -> (int, net.Connection_Error) {
	state := cast(^Fault_Stream)data

	if state.at == len(state.wire) {
		return 0, state.read_error
	}

	n := copy(dst, state.wire[state.at:])
	state.at += n

	return n, {}
}
fault_write :: proc(data: rawptr, src: []u8) -> (int, net.Connection_Error) {
	state := cast(^Fault_Stream)data
	state.writes += 1

	if state.write_error.kind != .None {
		return 0, state.write_error
	}

	return len(src), {}
}
fault_close :: proc(data: rawptr) -> net.Connection_Error {
	return {}
}
fault_connection :: proc(state: ^Fault_Stream) -> net.Connection {
	return {data = state, read = fault_read, write = fault_write, close = fault_close}
}

@(test)
zero_legacy_outcomes_do_not_claim_no_write :: proc(t: ^testing.T) {
	zero: surf.Buffered_HTTP_Result
	named := surf.Buffered_HTTP_Result {
		status = 503,
		ok     = false,
	}

	testing.expect_value(t, zero.error.write_effect, .Unknown)
	testing.expect_value(t, named.error.write_effect, .Unknown)
	testing.expect(t, !zero.transport_ok && !named.transport_ok)
	_, error := surf.execute({method = .POST, url = "http://127.0.0.1/"}, {timeout = -1})
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	_, result := surf.buffered_http_execute("POST", "http://127.0.0.1/", nil, nil, "")
	testing.expect_value(t, result.error.kind, .Insecure_URL)
	testing.expect_value(t, result.error.phase, .Configuration)
	testing.expect_value(t, result.error.write_effect, .Not_Sent)
}

@(test)
public_exchange_distinguishes_write_read_timeout_and_cancel :: proc(t: ^testing.T) {
	request := http.Request {
		method = .POST,
		url    = "https://fixture.test/",
	}

	for sample in ([]struct {
			write, read: net.Connection_Error,
			expected:    surf.HTTP_Phase,
		} {
			{{kind = .Write_Failed}, {}, .Write},
			{{}, {kind = .Read_Failed}, .Read},
			{{}, {kind = .Timeout}, .Deadline},
			{{}, {kind = .Cancelled}, .Cancellation},
		}) {
		state := Fault_Stream {
			write_error = sample.write,
			read_error  = sample.read,
		}
		_, error := surf.exchange(fault_connection(&state), request)
		testing.expect_value(t, error.kind, .IO_Failed)
		testing.expect_value(t, error.phase, sample.expected)
		testing.expect_value(t, error.write_effect, .Unknown)
		testing.expect_value(t, state.writes, 1) // No hidden retry after an ambiguous POST.
	}
}

@(test)
public_exchange_retains_observed_status_after_body_failure :: proc(t: ^testing.T) {
	for sample in ([]struct {
			wire:   string,
			limit:  int,
			phase:  surf.HTTP_Phase,
			status: int,
		} {
			{"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nx", 8, .Read, 503},
			{"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 8, .Body_Limit, 200},
			{"not an HTTP response\r\n\r\n", 8, .Protocol, 0},
			{"HTTP/1.1 200 OK\r\nBrokenHeader\r\n\r\n", 8, .Protocol, 0},
			{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n", 8, .Protocol, 200},
		}) {
		state := Fault_Stream {
			wire = sample.wire,
			read_error = {kind = .Peer_Closed},
		}
		response, error := surf.exchange(
			fault_connection(&state),
			{method = .POST, url = "https://fixture.test/"},
			sample.limit,
		)
		defer surf.response_destroy(&response)
		testing.expect_value(t, error.phase, sample.phase)
		testing.expect_value(t, error.status, sample.status)
		testing.expect_value(t, error.write_effect, sample.status == 0 ? .Unknown : .Response_Received)
	}
}

@(test)
native_dns_failure_classifies_as_dns :: proc(t: ^testing.T) {
	native_dns := surf.http_error_classify(
		{kind = .Dial_Failed, network = net.Resolve_Error.Unable_To_Resolve},
		.Connect,
		.Not_Sent,
	)
	testing.expect_value(t, native_dns.phase, .DNS)
}

@(test)
validated_status_survives_response_allocation_failure :: proc(t: ^testing.T) {
	state := Fault_Stream {
		wire = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
	}

	response, error := surf.exchange(
		fault_connection(&state),
		{method = .POST, url = "https://fixture.test/"},
		allocator = runtime.nil_allocator(),
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Allocation_Failed)
	testing.expect_value(t, error.status, 503)
	testing.expect_value(t, error.write_effect, .Response_Received)
}

@(test)
tls_record_failures_preserve_tls_but_transport_causes_remain_specific :: proc(t: ^testing.T) {
	broken_record := surf.http_error_classify(
		{kind = .IO_Failed, tls_io = {kind = .Decryption_Failed}},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, broken_record.phase, .TLS)
	transport_read := surf.http_error_classify(
		{kind = .IO_Failed, tls_io = {kind = .Transport_Read_Failed, transport = {kind = .Read_Failed}}},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, transport_read.phase, .Read)
	timed_out := surf.http_error_classify(
		{kind = .IO_Failed, tls_io = {kind = .Transport_Read_Failed, transport = {kind = .Timeout}}},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, timed_out.phase, .Deadline)
}

Outcome_Failing_Allocator :: struct {
	backing:        mem.Allocator,
	count, fail_at: int,
}
outcome_fail_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Outcome_Failing_Allocator)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		state.count += 1

		if state.count == state.fail_at {
			return nil, .Out_Of_Memory
		}
	}
	return state.backing.procedure(state.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
partial_response_allocation_failures_release_all_owned_storage :: proc(t: ^testing.T) {
	for fail_at in 1 ..= 4 {
		tracker: mem.Tracking_Allocator
		mem.tracking_allocator_init(&tracker, context.allocator)
		defer mem.tracking_allocator_destroy(&tracker)
		allocation := Outcome_Failing_Allocator {
			backing = mem.tracking_allocator(&tracker),
			fail_at = fail_at,
		}

		state := Fault_Stream {
			wire = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nx",
			read_error = {kind = .Peer_Closed},
		}

		response, error := surf.exchange(
			fault_connection(&state),
			{method = .POST, url = "https://fixture.test/"},
			allocator = {procedure = outcome_fail_allocate, data = &allocation},
		)
		testing.expect(t, error.kind != .None)
		testing.expect_value(t, error.status, 503)
		testing.expect_value(t, error.write_effect, .Response_Received)
		testing.expect(
			t,
			response.allocator.procedure == nil &&
			response.body == nil &&
			response.headers == nil &&
			cap(response.body_storage) == 0,
		)
		testing.expect_value(t, tracker.current_memory_allocated, 0)
		surf.response_destroy(&response)
		surf.response_destroy(&response)
	}
}

@(test)
legacy_cstring_allocation_failure_is_typed_and_stops_setup :: proc(t: ^testing.T) {
	previous := context.temp_allocator
	state := Outcome_Failing_Allocator {
		backing = previous,
		fail_at = 1,
	}

	context.temp_allocator = {
		procedure = outcome_fail_allocate,
		data      = &state,
	}

	defer context.temp_allocator = previous
	_, result := surf.buffered_http_execute("POST", "http://127.0.0.1/", nil, nil, "", allow_http = true)
	testing.expect_value(t, result.error.kind, .Allocation_Failed)
	testing.expect_value(t, result.error.allocation, .Out_Of_Memory)
	testing.expect_value(t, result.error.phase, .Configuration)
	testing.expect_value(t, result.error.write_effect, .Not_Sent)
	testing.expect_value(t, state.count, 1)
}

@(test)
setup_timeout_retains_not_sent_before_tcp_connection :: proc(t: ^testing.T) {
	error := surf.http_error_classify({kind = .Dial_Failed, network = net.Dial_Error.Timeout}, .Connect, .Not_Sent)
	testing.expect_value(t, error.kind, .Dial_Failed)
	testing.expect_value(t, error.phase, .Deadline)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, error.status, 0)
	testing.expect_value(t, error.provider_code, 0)
}
