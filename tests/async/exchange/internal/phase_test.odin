package surf_exchange

import surf "../.."
import "core:mem"
import "core:net"
import "core:testing"
import "core:time"

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
