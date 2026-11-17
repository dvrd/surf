package surf_exchange

import surf "../.."
import http "../../../http"
import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"
import "core:net"
import "core:testing"
import "core:time"

// A literal byte provider, independent of the HTTP codec. Submission never
// invokes callbacks. The test explicitly retires every accepted operation.
Exchange_Test_Stream :: struct {
	wire:                                          string,
	at, fragment, wakes, submits, cancels, closes: int,
	pending:                                       ^net.Async_Operation,
	buffer:                                        []u8,
	deadline:                                      time.Time,
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
	deadline: time.Time,
) -> net.Connection_Error {
	f := cast(^Exchange_Test_Stream)data
	f.submits += 1
	if kind == .Close {
		f.closes += 1
		return {kind = .Close_Failed}
	}
	if f.reject {
		return {kind = .Read_Failed}
	}
	assert(f.pending == nil)
	f.pending = op
	f.buffer = buffer
	f.deadline = deadline
	op.kind = kind
	op.pending = true
	return {}
}
exchange_test_cancel :: proc(data: rawptr, op: ^net.Async_Operation) -> net.Connection_Error {
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
		result.err.kind = .Cancelled
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
			result.err.kind = .Peer_Closed
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
		testing.expect_value(t, f.deadline, budget.wall)
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
			testing.expect_value(t, done.error.transport.kind, .Invalid_Count)
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
