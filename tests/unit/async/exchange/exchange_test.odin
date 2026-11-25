package surf_exchange

import surf "../.."
import "shared:async/tls"
import "core:mem"
import "core:testing"
import "core:time"
import http "shared:async/http"
import charged "shared:async/mem/budget"
import scopes "shared:async/sync/budget"
import "core:net"
import channel "../stream"
import h1 "shared:async/http/v1"
import deflate "shared:async/compress/step"
import "shared:async/mem/owned"

config_test_normalize :: proc(input: Options) -> (Resolved_Options, surf.HTTP_Error) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous

	return options_normalize(input)
}

@(test)
exchange_options_defaults_and_independent_exact_bounds :: proc(t: ^testing.T) {
	result, error := config_test_normalize({})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{8 << 20, 7})

	for body in ([4]int{1, 17, (64 << 20) - 1, 64 << 20}) {
		for interim in ([3]int{1, 6, 7}) {
			input := Options{body, interim}
			before := input
			result, error = config_test_normalize(input)
			testing.expect_value(t, error.kind, .None)
			testing.expect_value(t, result, Resolved_Options{body, interim})
			testing.expect_value(t, input, before)
		}
	}

	result, error = config_test_normalize({body_limit = 23})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{23, 7})
	result, error = config_test_normalize({informational_limit = 1})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{8 << 20, 1})
}

@(test)
exchange_options_reject_without_partial_normalization :: proc(t: ^testing.T) {
	for bad in ([4]int{-1, min(int), (64 << 20) + 1, max(int)}) {
		input := Options {
			body_limit          = bad,
			informational_limit = 1,
		}

		before := input
		result, error := config_test_normalize(input)
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, result, Resolved_Options{})
		testing.expect_value(t, input, before)
	}

	// Seven is the legacy maximum number of interim heads, not eight.
	for bad in ([4]int{-1, min(int), 8, max(int)}) {
		result, error := config_test_normalize({body_limit = 17, informational_limit = bad})
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, result, Resolved_Options{})
	}
}

@(test)
exchange_budget_requires_paired_clocks_without_sampling_or_extending :: proc(t: ^testing.T) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous
	testing.expect_value(t, budget_validate({}).kind, .None)

	for cutoff in ([3]i64{1, 37, max(i64)}) {
		for wall in ([4]time.Time {
				time.Time{_nsec = 1},
				time.Time{_nsec = -1},
				time.Time{_nsec = min(i64)},
				time.Time{_nsec = max(i64)},
			}) {
			input := Budget{cutoff, wall}
			before := input
			testing.expect_value(t, budget_validate(input).kind, .None)
			testing.expect_value(t, input, before)
		}
	}

	for input in ([6]Budget{{-1, {}}, {min(i64), {}}, {1, {}}, {max(i64), {}}, {0, {_nsec = 1}}, {0, {_nsec = -1}}}) {
		testing.expect_value(t, budget_validate(input).kind, .Invalid_Config)
	}
}

@(test)
exchange_state_has_stable_full_record_and_separate_head_storage :: proc(t: ^testing.T) {
	x: Exchange
	testing.expect(t, len(x._read_buffer) >= tls.MAX_PLAINTEXT_SIZE)
	testing.expect_value(t, len(x._read_buffer), 16 << 10)
	testing.expect_value(t, len(x._request_head), 16 << 10)
	testing.expect_value(t, len(x._response_head), 16 << 10)
	testing.expect(t, raw_data(x._request_head[:]) != raw_data(x._response_head[:]))
	testing.expect_value(t, x._read.operation.pending, false)
	testing.expect_value(t, x._write.operation.pending, false)
	testing.expect_value(t, x._read.accepted, false)
	testing.expect_value(t, x._write.accepted, false)
	testing.expect_value(t, x._self, nil)
	testing.expect_value(t, x._response.status, 0)
	testing.expect_value(t, len(x._response.body), 0)
	testing.expect_value(t, len(x._response.headers), 0)
	testing.expect_value(t, x._response.allocator.procedure, nil)
	testing.expect_value(t, x._phase, .Idle)
}

Exchange_Test_Stream :: struct {
	wire:                                          string,
	at, fragment, wakes, submits, cancels, closes: int,
	pending:                                       ^net.Async_Operation,
	buffer:                                        []u8,
	deadline:                                      time.Tick,
	written:                                       [65536]u8,
	written_at:                                    int,
	reject:                                        bool,
	short_write:                                   bool,
	cancelled:                                     bool,
}
exchange_test_wake :: proc(data: rawptr) {
	f := cast(^Exchange_Test_Stream)data
	f.wakes += 1
}
exchange_test_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Tick,
) -> net.Network_Error {
	f := cast(^Exchange_Test_Stream)data
	f.submits += 1
	if kind == .Close {
		f.closes += 1
		return net.Connection_Error.Close_Failed
	}
	if f.reject {
		return net.TCP_Recv_Error.Connection_Closed
	}
	assert(f.pending == nil)
	f.pending = op
	f.buffer = buffer
	f.deadline = deadline
	op.kind = kind
	op.pending = true
	return {}
}
exchange_test_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Network_Error {
	f := cast(^Exchange_Test_Stream)data
	assert(op == f.pending)
	f.cancels += 1
	f.cancelled = true

	return {}
}
exchange_test_complete :: proc(f: ^Exchange_Test_Stream, success_after_cancel := false) {
	op := f.pending
	assert(op != nil)
	result: net.Async_Result

	if f.cancelled && !success_after_cancel {
		result.err = net.Connection_Error.Cancelled
	} else if op.kind == .Write {
		n := len(f.buffer)

		if f.short_write {
			n = max(0, n - 1)
		}

		assert(f.written_at + n <= len(f.written))
		copy(f.written[f.written_at:], f.buffer[:n])
		f.written_at += n
		result.count = n
	} else {
		if f.at == len(f.wire) {
			result.err = net.Connection_Error.Peer_Closed
		} else {
			n := min(len(f.buffer), len(f.wire) - f.at)

			if f.fragment > 0 {
				n = min(n, f.fragment)
			}

			copy(f.buffer[:n], f.wire[f.at:f.at + n])
			f.at += n
			result.count = n
		}
	}

	f.pending = nil
	f.buffer = nil
	f.cancelled = false
	op.pending = false
	op.result = result
	op.callback(op)
	// Provider does not touch operation or Exchange after callback.
}
exchange_test_start :: proc(
	t: ^testing.T,
	x: ^Exchange,
	f: ^Exchange_Test_Stream,
	request: http.Request,
	options := Options{},
	budget := Budget{},
) {
	testing.expect_value(t, exchange_init(x, options, context.allocator).kind, .None)
	testing.expect_value(
		t,
		exchange_begin(x, {f, exchange_test_submit, exchange_test_cancel}, request, budget, {f, exchange_test_wake}).kind,
		.None,
	)
	testing.expect_value(t, f.wakes, 0)
}
exchange_test_run :: proc(
	t: ^testing.T,
	x: ^Exchange,
	f: ^Exchange_Test_Stream,
	now: i64 = 1,
	cancelled := false,
) -> Drive_Result {
	result: Drive_Result
	for _ in 0 ..< 100000 {
		result = exchange_drive(x, now, cancelled, 1)
		testing.expect(t, result.work_used >= 0 && result.work_used <= 1)

		if result.status == .Done {
			return result
		}

		if f.pending != nil {
			exchange_test_complete(f)
		}
	}
	testing.expect(t, false, "finite literal exchange must terminate")
	return result
}

@(test)
exchange_literal_framing_fragmentation_and_exact_request :: proc(t: ^testing.T) {
	Case :: struct {
		wire, body: string,
		method:     http.Method,
		reuse:      bool,
		status:     int,
	}

	cases := [9]Case {
		{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Test: value\r\n\r\nabc", "abc", .GET, true, 200},
		{
			"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\nX-Trailer: yes\r\n\r\n",
			"abc",
			.GET,
			true,
			200,
		},
		{"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc", "abc", .GET, true, 200},
		{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc", "abc", .GET, false, 200},
		{"HTTP/1.1 200 OK\r\n\r\nabc", "abc", .GET, false, 200},
		{"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", "", .HEAD, true, 200},
		{"HTTP/1.1 204 No Content\r\n\r\n", "", .GET, true, 204},
		{"HTTP/1.1 304 Not Modified\r\n\r\n", "", .GET, true, 304},
		{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nJUNK", "", .GET, false, 200},
	}

	for item, index in cases {
		for fragment in ([3]int{0, 1, 7}) {
			// Surplus detection concerns a SAME read. The split form is deliberately
			// excluded: generic HTTP completion cannot prove separate-record idleness.
			if index == 8 && fragment != 0 {
				continue
			}

			x: Exchange
			f := Exchange_Test_Stream {
				wire     = item.wire,
				fragment = fragment,
			}

			exchange_test_start(t, &x, &f, {method = item.method, url = "http://example.test/path?q=1"})
			result := exchange_test_run(t, &x, &f)
			testing.expect_value(t, result.error.kind, .None)
			testing.expect_value(t, result.reuse_eligible, item.reuse)
			testing.expect(t, exchange_quiescent(&x))
			response: surf.Response
			testing.expect_value(t, exchange_take(&x, &response).kind, .None)
			testing.expect_value(t, response.status, item.status)
			testing.expect_value(t, string(response.body), item.body)
			expected :=
				"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n" if \
					item.method == .GET else \
					"HEAD /path?q=1 HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n"
			testing.expect_value(t, string(f.written[:f.written_at]), expected)
			testing.expect_value(t, f.closes, 0)
			testing.expect_value(t, exchange_reset(&x).kind, .None)
			testing.expect_value(t, exchange_destroy(&x).kind, .None)
			// Response backing is independent of the reset/destroyed Exchange.
			testing.expect_value(t, string(response.body), item.body)
			surf.response_destroy(&response)
		}
	}
}

@(test)
exchange_literal_rejections_and_finite_body_limits :: proc(t: ^testing.T) {
	Case :: struct {
		wire:     string,
		expected: http.Error_Kind,
		limit:    int,
	}

	cases := [7]Case {
		{"HTTP/1.1 101 Switching Protocols\r\n\r\n", .Invalid_Status, 8},
		{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc", .Conflicting_Framing, 8},
		{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na", .Unexpected_EOF, 8},
		{"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", .Body_Oversized, 2},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", .Body_Oversized, 2},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n", .Invalid_Chunk, 8},
		{"HTTP/1.1 200 OK\r\n\r\nabc", .Body_Oversized, 2},
	}

	for item in cases {
		for fragment in ([2]int{0, 1}) {
			x: Exchange
			f := Exchange_Test_Stream {
				wire     = item.wire,
				fragment = fragment,
			}

			exchange_test_start(t, &x, &f, {method = .GET, url = "http://example.test/"}, {body_limit = item.limit})
			result := exchange_test_run(t, &x, &f)
			testing.expect_value(t, result.error.kind, item.expected)
			testing.expect(t, exchange_quiescent(&x))
			testing.expect_value(t, f.closes, 0)
			testing.expect_value(t, exchange_destroy(&x).kind, .None)
		}
	}
}

@(test)
exchange_cancel_deadline_and_late_callback_ownership :: proc(t: ^testing.T) {
	for expired in ([2]bool{false, true}) {
		x: Exchange
		f := Exchange_Test_Stream {
			wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		}

		budget := Budget {
			at = 5,
			wall = {_nsec = 1234},
		}

		body := "abc"
		exchange_test_start(
			t,
			&x,
			&f,
			{method = .POST, url = "http://example.test/", body = transmute([]u8)body},
			{},
			budget,
		)
		first := exchange_drive(&x, 1, false, 1)
		testing.expect(t, first.status != .Done && f.pending != nil)
		testing.expect(t, f.deadline != {} && time.tick_since(f.deadline) > 0)
		testing.expect(t, exchange_destroy(&x).kind != .None)
		testing.expect(t, exchange_reset(&x).kind != .None)
		next := exchange_drive(&x, 5 if expired else 2, !expired, 1)
		testing.expect(t, next.status != .Done && f.cancels == 1 && f.pending != nil)
		// A successful terminal callback after cancellation still owns borrowed data
		// until it arrives; success cannot override the latched cancel/deadline.
		exchange_test_complete(&f, true)
		done := exchange_test_run(t, &x, &f, 6, !expired)
		testing.expect(t, done.error.kind != .None)
		testing.expect_value(t, done.error.phase, .Deadline if expired else .Cancellation)
		testing.expect(t, exchange_quiescent(&x))
		testing.expect_value(t, exchange_destroy(&x).kind, .None)
	}
}

Exchange_Test_Grant :: struct {
	raw, reported: []u8,
}
Exchange_Test_Allocator :: struct {
	backing:                                          mem.Allocator,
	fail_at, mode, calls, live, bad_frees, reentries: int,
	grants:                                           [32]Exchange_Test_Grant,
	owner:                                            ^Exchange,
	no_free, dispose_owner, owner_freed:              bool,
}
exchange_test_allocator :: proc(
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
	p := cast(^Exchange_Test_Allocator)data
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.calls += 1

		if p.owner != nil {
			before := p.owner._phase
			assert(exchange_reset(p.owner).kind != .None)
			assert(exchange_destroy(p.owner).kind != .None)
			assert(p.owner._phase == before)
			p.reentries += 1
		}

		selected := p.mode if p.calls == p.fail_at else 0

		if selected == 1 {
			return nil, .Out_Of_Memory
		}

		if selected == 3 {
			return nil, nil
		}

		actual := size

		if selected == 4 {
			actual = max(0, size - 1)
		}

		if selected == 5 || selected == 6 {
			actual = size + 1
		}

		raw, error := p.backing.procedure(p.backing.data, .Alloc, actual, max(alignment, 16), nil, 0, location)
		assert(error == nil)
		reported := raw

		if selected == 6 {
			reported = raw[1:]
		}

		for &grant in p.grants {
			if raw_data(grant.raw) == nil {
				grant = {raw, reported}
				p.live += len(raw)
				break
			}
		}

		if selected == 2 {
			return reported, .Out_Of_Memory
		}

		return reported, nil
	case .Free:
		if old_memory == nil {
			return nil, nil
		}

		for &grant in p.grants {
			if raw_data(grant.raw) != nil && raw_data(grant.reported) == old_memory {
				if old_size != len(grant.reported) {
					p.bad_frees += 1
				}

				raw := grant.raw
				grant = {}
				p.live -= len(raw)

				if p.dispose_owner && p.owner != nil && p.owner._phase == .Done {
					owner := p.owner
					p.owner = nil
					assert(exchange_destroy(owner).kind == .None)
					free(owner, p.backing)
					p.owner_freed = true
				}

				return p.backing.procedure(
					p.backing.data,
					.Free,
					0,
					max(alignment, 16),
					raw_data(raw),
					len(raw),
					location,
				)
			}
		}

		p.bad_frees += 1
		return nil, nil
	case .Query_Features:
		if p.no_free {
			(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Query_Features}
			return nil, nil
		}

		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		return nil, nil
	case .Free_All, .Resize, .Resize_Non_Zeroed, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, .Mode_Not_Implemented
}

@(test)
exchange_all_owned_allocation_failures_rollback_and_reentrant_mutation_rejects :: proc(t: ^testing.T) {
	// Header bytes, descriptor array and body are distinct exact grants. Every
	// tested malformed grant is physically released with its reported extent.
	points := 0

	for failure in 0 ..< 4 {
		for mode in 1 ..< 7 {
			x: Exchange
			p := Exchange_Test_Allocator {
				backing = context.allocator,
				fail_at = failure,
				mode    = mode,
			}

			allocator := mem.Allocator{exchange_test_allocator, &p}
			testing.expect_value(t, exchange_init(&x, {}, allocator).kind, .None)
			p.owner = &x
			f := Exchange_Test_Stream {
				wire = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Test: yes\r\n\r\nabc",
			}

			testing.expect_value(
				t,
				exchange_begin(&x, {&f, exchange_test_submit, exchange_test_cancel}, {method = .GET, url = "http://example.test/"}, {}, {&f, exchange_test_wake}).kind,
				.None,
			)
			result := exchange_test_run(t, &x, &f)

			if failure == 0 {
				testing.expect_value(t, result.error.kind, .None)
				points = p.calls
				response: surf.Response
				testing.expect_value(t, exchange_take(&x, &response).kind, .None)
				p.owner = nil
				testing.expect_value(t, exchange_destroy(&x).kind, .None)
				surf.response_destroy(&response)
			} else {
				// A one-byte-aligned body/header grant cannot be misaligned; shifting its
				// exact-sized view is valid, so that cell verifies successful ownership.
				if mode == 6 && failure != 2 {
					testing.expect_value(t, result.error.kind, .None)
				} else {
					testing.expect_value(t, result.error.kind, .Allocation_Failed)
				}

				p.owner = nil
				testing.expect_value(t, exchange_destroy(&x).kind, .None)
			}

			testing.expect_value(t, p.live, 0)
			testing.expect_value(t, p.bad_frees, 0)
			testing.expect(t, p.reentries > 0)
		}
	}

	testing.expect_value(t, points, 3)
}

@(test)
exchange_submission_rejection_invalid_counts_and_begin_atomicity :: proc(t: ^testing.T) {
	for short in ([2]bool{false, true}) {
		x: Exchange
		f := Exchange_Test_Stream {
			reject      = !short,
			short_write = short,
		}

		exchange_test_start(t, &x, &f, {method = .GET, url = "http://example.test/"})
		done := exchange_test_run(t, &x, &f)
		testing.expect_value(t, done.error.kind, .IO_Failed)

		if short {
			testing.expect_value(t, done.error.transport, net.Connection_Error.Invalid_Count)
		}

		testing.expect_value(t, f.wakes, 1 if short else 0)
		testing.expect_value(t, exchange_destroy(&x).kind, .None)
	}

	x: Exchange
	f: Exchange_Test_Stream
	testing.expect_value(t, exchange_init(&x, {}, context.allocator).kind, .None)
	before := x
	bad := http.Request {
		method  = .GET,
		url     = "http://example.test/",
		headers = (cast([^]http.Header)nil)[:1],
	}

	cause := exchange_begin(&x, {&f, exchange_test_submit, exchange_test_cancel}, bad, {}, {&f, exchange_test_wake})
	testing.expect_value(t, cause.kind, .Invalid_Header)
	testing.expect_value(t, x._phase, before._phase)
	testing.expect_value(t, x._self, before._self)
	testing.expect_value(t, f.submits, 0)
	cause = exchange_begin(
		&x,
		{&f, exchange_test_submit, exchange_test_cancel},
		{method = .GET, url = string(x._request_head[:1])},
		{},
		{&f, exchange_test_wake},
	)
	testing.expect_value(t, cause.kind, .Overlapping_Buffers)
	testing.expect_value(t, exchange_destroy(&x).kind, .None)
}

@(test)
exchange_fresh_clock_after_allocation_and_callback_frees_terminal_owner :: proc(t: ^testing.T) {
	// No allocator capability fallback may silently accept a nonfreeing owner.
	p := Exchange_Test_Allocator {
		backing = context.allocator,
		no_free = true,
	}

	empty: Exchange
	testing.expect_value(t, exchange_init(&empty, {}, {exchange_test_allocator, &p}).kind, .Invalid_Config)
	testing.expect_value(t, empty._self, nil)
	testing.expect_value(t, p.calls, 0)

	for physical_free in ([2]bool{false, true}) {
		x := new(Exchange, context.allocator)
		q := Exchange_Test_Allocator {
			backing       = context.allocator,
			fail_at       = 3,
			mode          = 1,
			dispose_owner = physical_free,
		}

		testing.expect_value(t, exchange_init(x, {}, {exchange_test_allocator, &q}).kind, .None)
		q.owner = x
		f := Exchange_Test_Stream {
			wire = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Test: yes\r\n\r\nabc",
		}

		budget := Budget {
			at = 10,
			wall = {_nsec = 1},
		}

		testing.expect_value(
			t,
			exchange_begin(x, {&f, exchange_test_submit, exchange_test_cancel}, {method = .GET, url = "http://example.test/"}, budget, {&f, exchange_test_wake}).kind,
			.None,
		)
		sampled_after_allocation := false
		result: Drive_Result

		for _ in 0 ..< 1000 {
			now: i64 = 1

			if sampled_after_allocation && !physical_free {
				now = 10
			}

			result = exchange_drive(x, now, false, 1)

			if result.status == .Done {
				break
			}

			if q.calls > 0 {
				testing.expect_value(t, result.status, .Progress)
				sampled_after_allocation = true
			}

			if f.pending != nil {
				exchange_test_complete(&f)
			}
		}

		testing.expect_value(t, result.status, .Done)
		testing.expect_value(t, result.error.kind, .Allocation_Failed if physical_free else .Deadline_Failed)
		testing.expect_value(t, result.error.write_effect, .Response_Received)
		testing.expect_value(t, q.live, 0)
		testing.expect_value(t, q.bad_frees, 0)
		testing.expect_value(t, q.owner_freed, physical_free)

		if !physical_free {
			testing.expect_value(t, exchange_destroy(x).kind, .None)
			free(x, context.allocator)
		}
	}
}

@(test)
exchange_taken_managed_response_retains_physical_budget_after_binding_destroy :: proc(t: ^testing.T) {
	scope, cause := scopes.create_root({bytes = 1 << 20, streams = 1, jobs = 1}, context.allocator)
	testing.expect_value(t, cause, .None)
	defer scopes.release_scope(&scope)
	binding, failure := charged.create(scope, {backing = context.allocator})
	testing.expect_value(t, failure.kind, .None)
	x: Exchange
	f := Exchange_Test_Stream {
		wire = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Test: retained\r\n\r\nabc",
	}

	testing.expect_value(t, exchange_init(&x, {}, charged.allocator(binding)).kind, .None)
	testing.expect_value(
		t,
		exchange_begin(&x, {&f, exchange_test_submit, exchange_test_cancel}, {method = .GET, url = "http://example.test/"}, {}, {&f, exchange_test_wake}).kind,
		.None,
	)
	done := exchange_test_run(t, &x, &f)
	testing.expect_value(t, done.error.kind, .None)
	response: surf.Response
	testing.expect_value(t, exchange_take(&x, &response).kind, .None)
	testing.expect_value(t, exchange_destroy(&x).kind, .None)
	charged.release(&binding)
	testing.expect_value(t, scopes.close(scope), .None)
	before, error := scopes.snapshot(scope)
	testing.expect_value(t, error, .None)
	testing.expect(t, before.used.bytes > 0)
	testing.expect_value(t, string(response.body), "abc")
	found := false

	for field in response.headers {
		if field.name == "X-Test" {
			found = true
			testing.expect_value(t, field.value, "retained")
		}
	}

	testing.expect(t, found)
	surf.response_destroy(&response)
	after, _ := scopes.snapshot(scope)
	testing.expect_value(t, after.used, scopes.Usage{})
}

Phase_Provider :: struct {
	owner:                                                    ^Exchange,
	pending:                                                  ^net.Async_Operation,
	buffer:                                                   []u8,
	wire:                                                     string,
	read_at, reads, writes, write_bytes, busy_queries, wakes: int,
	cancelled:                                                bool,
}
phase_bytes :: proc(x: ^Exchange) -> []u8 {
	return (cast([^]u8)x)[:size_of(Exchange)]
}
phase_query :: proc(x: ^Exchange) -> (Exchange_Phase, bool) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous

	return exchange_phase(x)
}
phase_reject_preserved :: proc(x: ^Exchange) {
	before: [size_of(Exchange)]u8

	if x != nil {
		copy(before[:], phase_bytes(x))
	}

	phase, valid := phase_query(x)
	assert(!valid && phase == .Idle)

	if x != nil {
		assert(mem.compare(before[:], phase_bytes(x)) == 0)
	}
}
phase_provider_submit :: proc(
	data: rawptr,
	op: ^net.Async_Operation,
	kind: net.Async_Operation_Kind,
	buffer: []u8,
	deadline: time.Tick,
) -> net.Network_Error {
	f := cast(^Phase_Provider)data
	// The provider is invoked inside public drive. Reentrant rejection is part
	// of the getter contract and must preserve the entire busy owner byte image.
	phase_reject_preserved(f.owner)
	f.busy_queries += 1
	assert(f.pending == nil && kind != .Close)
	f.pending = op
	f.buffer = buffer
	op.kind = kind
	op.pending = true
	if kind == .Write {
		f.writes += 1
	} else {
		f.reads += 1
	}
	return {}
}
phase_provider_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Network_Error {
	f := cast(^Phase_Provider)data
	assert(op == f.pending)
	phase_reject_preserved(f.owner)
	f.busy_queries += 1
	f.cancelled = true

	return {}
}
phase_provider_wake :: proc(data: rawptr) {
	f := cast(^Phase_Provider)data
	f.wakes += 1
}
phase_provider_complete :: proc(f: ^Phase_Provider) {
	op := f.pending
	assert(op != nil)
	result: net.Async_Result

	if f.cancelled {
		result.err = net.Connection_Error.Cancelled
	} else if op.kind == .Write {
		result.count = len(f.buffer); f.write_bytes += result.count
	} else {
		count := min(len(f.buffer), len(f.wire) - f.read_at)
		// A literal header plus half a body arrives first; the next read provides
		// the remaining two bytes, independently of the SDK parser's decisions.
		if f.read_at == 0 {
			count = min(count, len(f.wire) - 2)
		}

		assert(count > 0)
		copy(f.buffer[:count], f.wire[f.read_at:f.read_at + count])
		f.read_at += count
		result.count = count
	}

	f.pending = nil
	f.buffer = nil
	f.cancelled = false
	op.pending = false
	op.result = result
	op.callback(op)
}
phase_expect :: proc(t: ^testing.T, x: ^Exchange, want: Exchange_Phase) {
	before: [size_of(Exchange)]u8
	copy(before[:], phase_bytes(x))
	got, valid := phase_query(x)
	testing.expect(t, valid)
	testing.expect_value(t, got, want)
	testing.expect_value(t, mem.compare(before[:], phase_bytes(x)), 0)
}
phase_start :: proc(t: ^testing.T, x: ^Exchange, f: ^Phase_Provider, body: []u8) {
	f.owner = x
	f.wire = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nheld"
	testing.expect_value(t, exchange_init(x, {}, context.allocator).kind, .None)
	phase_expect(t, x, .Idle)
	testing.expect_value(
		t,
		exchange_begin(x, {f, phase_provider_submit, phase_provider_cancel}, {method = .POST, url = "http://phase.test/upload", body = body}, {}, {f, phase_provider_wake}).kind,
		.None,
	)
	phase_expect(t, x, .Writing_Head)
}

@(test)
phase_committed_write_callbacks_precede_reading_and_literal_body_completion :: proc(t: ^testing.T) {
	x: Exchange
	f: Phase_Provider
	body: [READ_BUFFER_SIZE + 3]u8
	for &b in body {b = 'p'}
	phase_start(t, &x, &f, body[:])
	// A head and two body chunks all require real accepted terminal callbacks.
	for index in 0 ..< 3 {
		result := exchange_drive(&x, 1, false, 1)
		testing.expect(t, result.error.kind == .None && f.pending != nil)
		testing.expect_value(t, f.pending.kind, .Write)
		want: Exchange_Phase = .Writing_Head if index == 0 else .Writing_Body
		phase_expect(t, &x, want)
		phase_provider_complete(&f)
		// Callback arrival alone does not commit the byte count or advance phase.
		phase_expect(t, &x, want)
	}

	testing.expect_value(t, f.writes, 3)
	testing.expect(t, f.write_bytes > len(body))
	result := exchange_drive(&x, 1, false, 1)
	testing.expect_value(t, result.error.kind, .None)
	phase_expect(t, &x, .Reading_Head)
	testing.expect_value(t, f.pending, nil)
	result = exchange_drive(&x, 1, false, 1)
	testing.expect_value(t, result.status, .Waiting)
	testing.expect_value(t, f.pending.kind, .Read)
	phase_expect(t, &x, .Reading_Head)
	phase_provider_complete(&f)
	phase_expect(t, &x, .Reading_Head)
	result = exchange_drive(&x, 1, false, 1)
	testing.expect_value(t, result.error.kind, .None)
	phase_expect(t, &x, .Copying_Head)
	result = exchange_drive(&x, 1, false, 1)
	testing.expect_value(t, result.error.kind, .None)
	phase_expect(t, &x, .Reading_Body)
	done := false

	for _ in 0 ..< 20 {
		result = exchange_drive(&x, 1, false, 1)

		if result.status == .Done {
			done = true; break
		}

		if f.pending != nil {
			testing.expect_value(t, f.pending.kind, .Read); phase_expect(t, &x, .Reading_Body)
			phase_provider_complete(&f)
		}
	}

	testing.expect(t, done)
	testing.expect_value(t, result.error.kind, .None)
	phase_expect(t, &x, .Done)
	testing.expect(t, f.busy_queries >= 5 && f.wakes >= 5)
	response: surf.Response
	testing.expect_value(t, exchange_take(&x, &response).kind, .None)
	testing.expect_value(t, string(response.body), "held")
	testing.expect_value(t, exchange_reset(&x).kind, .None)
	phase_expect(t, &x, .Idle)
	testing.expect_value(t, exchange_destroy(&x).kind, .None)
	phase_reject_preserved(&x)
	surf.response_destroy(&response)
}

@(test)
phase_invalid_nil_zero_copied_moved_owners_preserve_whole_bytes :: proc(t: ^testing.T) {
	phase_reject_preserved(nil)
	original: Exchange
	phase_reject_preserved(&original)
	testing.expect_value(t, exchange_init(&original, {}, context.allocator).kind, .None)
	before: [size_of(Exchange)]u8
	copy(before[:], phase_bytes(&original))
	copied := original
	phase_reject_preserved(&copied)
	testing.expect_value(t, mem.compare(before[:], phase_bytes(&original)), 0)
	// Moving the public concrete value is forbidden; its original-address witness
	// remains in the copied bytes and cannot become a valid owner at this address.
	moved := original
	original = {}
	phase_reject_preserved(&moved)
	phase_reject_preserved(&original)
	// No response/request/provider was constructed in this case, so the invalid
	// moved snapshots own no allocation or accepted callback to dispose.
}

@(test)
phase_cancellation_drain_remains_observable_until_pending_callback_retires :: proc(t: ^testing.T) {
	x: Exchange
	f: Phase_Provider
	phase_start(t, &x, &f, nil)
	result := exchange_drive(&x, 1, false, 1)
	testing.expect(t, result.error.kind == .None && f.pending != nil)
	result = exchange_drive(&x, 2, true, 1)
	testing.expect(t, result.status != .Done && f.pending != nil && f.cancelled)
	phase_expect(t, &x, .Draining)
	phase_provider_complete(&f)
	phase_expect(t, &x, .Draining)
	result = exchange_drive(&x, 3, true, 1)
	testing.expect_value(t, result.status, .Done)
	testing.expect_value(t, result.error.phase, .Cancellation)
	phase_expect(t, &x, .Done)
	testing.expect_value(t, exchange_destroy(&x).kind, .None)
}

@(test)
stream_content_coding_uses_http_whitespace :: proc(t: ^testing.T) {
	for wire in ([]string {
			"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Encoding: \u00a0gzip\u00a0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Encoding: \u2003gzip\r\n\r\n",
		}) {
		head, _, parse := h1.response_header_decode(transmute([]u8)wire)
		testing.expect_value(t, parse.kind, .None)
		cell := channel.Channel {
			options = {decoding = .Gzip},
		}
		x := Stream_Exchange {
			channel = &cell,
		}
		x.base._head = head
		x.base._response.headers = head.headers[:head.header_count]
		error := stream_encoding(&x)
		testing.expect_value(t, error.kind, .Unsupported_Content_Encoding)
		testing.expect(t, !x.decoded)
	}

	cell := channel.Channel {
		options = {decoding = .Gzip, max_encoded_bytes = 100, max_decoded_bytes = 100},
	}

	x := Stream_Exchange {
		channel = &cell,
	}

	x.base._head.framing = .Length
	x.base._response.headers = {{"Content-Encoding", "\tGZip \t"}}
	testing.expect_value(t, stream_encoding(&x).kind, .None)
	testing.expect(t, x.decoded)
}

@(test)
stream_gzip_footer_finishes_while_last_chunk_held :: proc(t: ^testing.T) {
	bank, bank_error := channel.bank_create(
		{
			streams = 1,
			response_chunks = 1,
			upload_chunks = 1,
			max_chunk_bytes = 16,
			max_retained_bytes_per_stream = 32,
		},
		context.allocator,
	)
	testing.expect_value(t, bank_error.kind, .None)

	if bank_error.kind != .None {
		return
	}

	defer channel.bank_close(&bank)
	cell, cell_error := channel.channel_create(bank, {decoding = .Gzip})
	testing.expect_value(t, cell_error.kind, .None)

	if cell_error.kind != .None {
		return
	}

	defer channel.release_request(cell)
	x: Stream_Exchange
	testing.expect_value(t, exchange_init(&x.base, {}, context.allocator).kind, .None)
	x.channel = cell
	x.tx = .Done
	x.decoded = true
	x.entity_done = true
	x.base._phase = .Reading_Body
	x.base._head.framing = .Length
	// Independent Python gzip encoding of the single byte "x". The raw payload
	// is already delivered; only checksum/ISIZE validation remains at this seam.
	wire := [21]u8{31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 0, 0, 131, 22, 220, 140, 1, 0, 0, 0}
	testing.expect_value(t, deflate.inflate_gzip_decoder_init(&x.decoder), .None)
	slot, output := channel.reserve_output(cell)
	decoded := deflate.inflate_gzip_decoder_step(&x.decoder, wire[:13], output, false)
	testing.expect(t, decoded.err == .None && decoded.consumed == 13 && decoded.produced == 1)
	testing.expect(t, channel.publish_output(slot, decoded.produced))
	held: owned.Chunk
	status, error := channel.next(cell, &held)
	testing.expect(t, status == .Chunk && error.kind == .None)
	defer owned.destroy(&held)
	testing.expect_value(t, string(held.data), "x")
	copy(x.encoded[:], wire[13:])
	x.encoded_used = 8
	finished := false

	for _ in 0 ..< 8 {
		result := stream_exchange_drive(&x, 1, false, 64)
		testing.expect_value(t, result.error.kind, .None)

		if result.status == .Done {
			finished = true
			break
		}
	}

	testing.expect(t, finished, "Footer validation must not require another output slot")
	testing.expect_value(t, string(held.data), "x")
}

@(test)
stream_identity_terminal_framing_finishes_while_last_chunk_held :: proc(t: ^testing.T) {
	for chunked in ([2]bool{false, true}) {
		bank, bank_error := channel.bank_create(
			{
				streams = 1,
				response_chunks = 1,
				upload_chunks = 1,
				max_chunk_bytes = 16,
				max_retained_bytes_per_stream = 32,
			},
			context.allocator,
		)
		assert(bank_error.kind == .None)
		defer channel.bank_close(&bank)
		cell, cell_error := channel.channel_create(bank, {})
		assert(cell_error.kind == .None)
		defer channel.release_request(cell)
		x: Stream_Exchange
		assert(exchange_init(&x.base, {}, context.allocator).kind == .None)
		x.channel = cell
		x.tx = .Done
		x.base._phase = .Reading_Body

		if chunked {
			x.base._head.framing = .Chunked
			assert(h1.chunk_decoder_init(&x.base._chunk, 100).kind == .None)
			x.base._read_used = copy(x.base._read_buffer[:], transmute([]u8)string("0\r\nX-Note: end\r\n\r\n"))
		} else {
			x.base._head.framing = .EOF
			x.base._read.ready = true
			x.base._read.result.err = net.Connection_Error.Peer_Closed
		}

		slot, output := channel.reserve_output(cell)
		output[0] = 'x'
		assert(channel.publish_output(slot, 1))
		held: owned.Chunk
		status, error := channel.next(cell, &held)
		assert(status == .Chunk && error.kind == .None)
		defer owned.destroy(&held)
		finished := false

		for _ in 0 ..< 8 {
			result := stream_exchange_drive(&x, 1, false, 64)
			testing.expect_value(t, result.error.kind, .None)

			if result.status == .Done {
				finished = true
				break
			}
		}

		testing.expect(t, finished, "Chunk terminator/EOF must not require another output slot")
		testing.expect_value(t, string(held.data), "x")
	}
}
