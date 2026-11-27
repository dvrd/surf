package tests

import "../../support/loopback"
import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:strings"
import "core:testing"
import "core:time"
import "shared:surf"

Outcome_Peer :: struct {
	server: loopback.Server,
	url:    string,
}

outcome_start :: proc(t: ^testing.T, peer: ^Outcome_Peer, answer: loopback.Answer) -> bool {
	peer.server.answer = answer

	if !testing.expect(t, loopback.server_start(&peer.server)) {
		return false
	}

	peer.url = fmt.aprintf("http://127.0.0.1:%d/", peer.server.port)

	return true
}

outcome_stop :: proc(peer: ^Outcome_Peer) {
	loopback.server_stop(&peer.server)
	delete(peer.url)
}

@(test)
invalid_config_is_not_sent :: proc(t: ^testing.T) {
	_, error := surf.execute({method = .POST, url = "http://127.0.0.1/"}, {timeout = -1})
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	_, insecure := surf.execute({method = .POST, url = "http://127.0.0.1/"}, {})
	testing.expect_value(t, insecure.kind, .Insecure_URL)
	testing.expect_value(t, insecure.phase, .Configuration)
	testing.expect_value(t, insecure.write_effect, .Not_Sent)
}

// Each failure after the request reached the peer keeps the write effect
// unknown, and the POST is never sent a second time.
@(test)
public_execute_distinguishes_read_and_timeout_after_the_write :: proc(t: ^testing.T) {
	for sample in ([]struct {
			action: loopback.Action,
			kind:   surf.HTTP_Error_Kind,
			phase:  surf.HTTP_Phase,
		} {
			{.Close, .Unexpected_EOF, .Read},
			{.Reset, .IO_Failed, .Read},
			{.Silent, .Deadline_Failed, .Deadline},
		}) {
		peer: Outcome_Peer

		if !outcome_start(t, &peer, {action = sample.action}) {
			return
		}

		_, error := surf.execute(
			{method = .POST, url = peer.url, body = transmute([]u8)string("payload")},
			{allow_http = true, timeout = 500 * time.Millisecond},
		)
		testing.expect_value(t, error.kind, sample.kind)
		testing.expect_value(t, error.phase, sample.phase)
		testing.expect_value(t, error.write_effect, .Unknown)
		testing.expect_value(t, error.status, 0)
		testing.expect_value(t, loopback.server_requests(&peer.server), 1)
		outcome_stop(&peer)
	}
}

@(test)
public_client_cancel_after_the_write_is_cancellation :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	peer: Outcome_Peer

	if !outcome_start(t, &peer, {action = .Silent}) {
		return
	}
	defer outcome_stop(&peer)

	c: surf.Client

	if !testing.expect_value(
		t,
		surf.client_start(&c, {http = {allow_http = true, timeout = 5 * time.Second}}).kind,
		.None,
	) {
		return
	}
	defer surf.client_destroy(&c)

	handle, submitted := surf.client_submit(
		&c,
		{method = .POST, url = peer.url, body = transmute([]u8)string("x")},
	)

	if !testing.expect_value(t, submitted.kind, .None) {
		return
	}

	for loopback.server_requests(&peer.server) == 0 {
		time.sleep(5 * time.Millisecond)
	}

	testing.expect_value(t, surf.client_cancel(&c, handle).kind, .None)
	completion: surf.Completion
	done := false

	for !done {
		completion, done = surf.client_poll(&c)
		if !done {
			time.sleep(5 * time.Millisecond)
		}
	}

	testing.expect(t, completion.request == handle)
	testing.expect_value(t, completion.error.phase, .Cancellation)
	testing.expect_value(t, completion.error.write_effect, .Unknown)
	testing.expect_value(t, surf.client_release(&c, handle).kind, .None)
	testing.expect_value(t, loopback.server_requests(&peer.server), 1)
}

@(test)
public_execute_retains_observed_status_after_body_failure :: proc(t: ^testing.T) {
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
			{
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n",
				8,
				.Protocol,
				200,
			},
		}) {
		peer: Outcome_Peer

		if !outcome_start(t, &peer, {wire = sample.wire, close = true}) {
			return
		}

		response, error := surf.execute(
			{method = .POST, url = peer.url},
			{allow_http = true, max_body_size = sample.limit, timeout = 2 * time.Second},
		)
		surf.response_destroy(&response)
		testing.expectf(t, error.phase == sample.phase, "%q: phase %v", sample.wire, error.phase)
		testing.expectf(
			t,
			error.status == sample.status,
			"%q: status %v",
			sample.wire,
			error.status,
		)
		effect: surf.HTTP_Write_Effect = sample.status == 0 ? .Unknown : .Response_Received
		testing.expectf(
			t,
			error.write_effect == effect,
			"%q: effect %v",
			sample.wire,
			error.write_effect,
		)
		outcome_stop(&peer)
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
	peer: Outcome_Peer

	if !outcome_start(
		t,
		&peer,
		{wire = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"},
	) {
		return
	}
	defer outcome_stop(&peer)

	response, error := surf.execute(
		{method = .POST, url = peer.url},
		{allow_http = true, timeout = 2 * time.Second},
		runtime.nil_allocator(),
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Allocation_Failed)
	testing.expect_value(t, error.status, 503)
	testing.expect_value(t, error.write_effect, .Response_Received)
}

@(test)
tls_record_failures_preserve_tls_but_transport_causes_remain_specific :: proc(t: ^testing.T) {
	broken_record := surf.http_error_classify(
		{kind = .IO_Failed, tls_error = .Bad_Record_Mac},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, broken_record.phase, .TLS)
	transport_read := surf.http_error_classify(
		{
			kind = .IO_Failed,
			tls_error = .Transport,
			transport = net.TCP_Recv_Error.Connection_Closed,
		},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, transport_read.phase, .Read)
	timed_out := surf.http_error_classify(
		{kind = .IO_Failed, tls_error = .Transport, transport = net.TCP_Recv_Error.Timeout},
		.Read,
		.Unknown,
	)
	testing.expect_value(t, timed_out.phase, .Deadline)
	cancelled := surf.http_error_classify(
		{kind = .TLS_Failed, tls_error = .Cancelled},
		.TLS,
		.Not_Sent,
	)
	testing.expect_value(t, cancelled.phase, .Cancellation)
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
	if mode == .Alloc ||
	   mode == .Alloc_Non_Zeroed ||
	   mode == .Resize ||
	   mode == .Resize_Non_Zeroed {
		state.count += 1

		if state.count == state.fail_at {
			return nil, .Out_Of_Memory
		}
	}

	return state.backing.procedure(
		state.backing.data,
		mode,
		size,
		alignment,
		old_memory,
		old_size,
		location,
	)
}

@(test)
partial_response_allocation_failures_release_all_owned_storage :: proc(t: ^testing.T) {
	peer: Outcome_Peer
	body := strings.repeat("x", 40000, context.temp_allocator)

	if !outcome_start(
		t,
		&peer,
		{
			wire = fmt.tprintf(
				"HTTP/1.1 503 Service Unavailable\r\nX-A: 1\r\nContent-Length: %d\r\n\r\n%s",
				len(body),
				body,
			),
		},
	) {
		return
	}
	defer outcome_stop(&peer)

	for fail_at in 1 ..= 4 {
		tracker: mem.Tracking_Allocator
		mem.tracking_allocator_init(&tracker, context.allocator)
		defer mem.tracking_allocator_destroy(&tracker)
		allocation := Outcome_Failing_Allocator {
			backing = mem.tracking_allocator(&tracker),
			fail_at = fail_at,
		}

		response, error := surf.execute(
			{method = .POST, url = peer.url},
			{allow_http = true, timeout = 2 * time.Second},
			{procedure = outcome_fail_allocate, data = &allocation},
		)
		testing.expectf(t, error.kind == .Allocation_Failed, "fail_at %d: %v", fail_at, error.kind)
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
setup_timeout_retains_not_sent_before_tcp_connection :: proc(t: ^testing.T) {
	error := surf.http_error_classify(
		{kind = .Dial_Failed, network = net.Dial_Error.Timeout},
		.Connect,
		.Not_Sent,
	)
	testing.expect_value(t, error.kind, .Dial_Failed)
	testing.expect_value(t, error.phase, .Deadline)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, error.status, 0)
	testing.expect_value(t, error.provider_code, 0)
}
