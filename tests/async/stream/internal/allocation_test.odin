package surf_stream

import "base:runtime"
import "core:mem"
import "core:testing"

Bank_Test_Grant :: struct {
	raw, view: []u8,
	alignment: int,
}
Bank_Test_Allocator :: struct {
	backing:                               mem.Allocator,
	grants:                                [16]Bank_Test_Grant,
	calls, fail_at, mode, live, bad_frees: int,
}
bank_test_allocator :: proc(
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
	p := cast(^Bank_Test_Allocator)data
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.calls += 1
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
		raw, error := p.backing.procedure(p.backing.data, mode, actual, max(alignment, 16), nil, 0, location)
		assert(error == nil)
		view := raw
		if selected == 6 {
			view = raw[1:]
		}
		recorded := false
		for &grant in p.grants {
			if raw_data(grant.raw) == nil {
				grant = {raw, view, max(alignment, 16)}
				p.live += len(raw)
				recorded = true
				break
			}
		}
		assert(recorded)
		if selected == 2 {
			return view, .Out_Of_Memory
		}
		return view, nil
	case .Free:
		if old_memory == nil {
			return nil, nil
		}
		for &grant in p.grants {
			if raw_data(grant.view) == old_memory {
				if old_size != 0 && old_size != len(grant.view) {
					p.bad_frees += 1
				}

				old := grant
				grant = {}
				p.live -= len(old.raw)
				return p.backing.procedure(
					p.backing.data,
					.Free,
					0,
					old.alignment,
					raw_data(old.raw),
					len(old.raw),
					location,
				)
			}
		}
		p.bad_frees += 1
		return nil, .Invalid_Pointer
	case .Query_Features:
		(cast(^mem.Allocator_Mode_Set)old_memory)^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Query_Features}
		return nil, nil
	case:
		return nil, .Mode_Not_Implemented
	}
}

@(test)
allocation_failures_and_malformed_grants_refund_bank_admission :: proc(t: ^testing.T) {
	for point in 1 ..= 4 {
		for mode in 1 ..= 6 {
			tracker: mem.Tracking_Allocator
			mem.tracking_allocator_init(&tracker, runtime.heap_allocator(), runtime.heap_allocator())
			p := Bank_Test_Allocator {
				backing = mem.tracking_allocator(&tracker),
				fail_at = point,
				mode    = mode,
			}

			bank, error := bank_create(bank_test_limits(), {bank_test_allocator, &p})

			if point <= 2 {
				testing.expect(t, bank == nil && error.kind == .Allocation_Failed)
			} else {
				testing.expect(t, bank != nil && error.kind == .None)
				cell, failure := channel_create(bank, {})
				// u8 storage has alignment1: a shifted exact-size grant is valid.
				// The allocator owns that view and can free its original backing.
				if point == 4 && mode == 6 {
					testing.expect(t, cell != nil && failure.kind == .None)
					release_request(cell)
				} else {
					testing.expect(t, cell == nil && failure.kind == .Allocation_Failed)
				}

				testing.expect_value(t, bank_stats(bank).streams, 0)
				// A failed constructor must not strand its sole admission cell.
				retry, retry_error := channel_create(bank, {})
				testing.expect(t, retry != nil && retry_error.kind == .None)
				release_request(retry)
			}

			bank_close(&bank)
			testing.expect(t, p.live == 0 && p.bad_frees == 0)
			testing.expect_value(t, tracker.current_memory_allocated, 0)
			testing.expect_value(t, len(tracker.bad_free_array), 0)
			mem.tracking_allocator_destroy(&tracker)
		}
	}
}

@(test)
invalid_limits_and_options_fail_before_allocation_or_reservation :: proc(t: ^testing.T) {
	p := Bank_Test_Allocator {
		backing = context.allocator,
	}

	allocator := mem.Allocator{bank_test_allocator, &p}

	for limits in ([]Limits {
			{streams = -1},
			{streams = MAX_STREAMS + 1},
			{response_chunks = MAX_SLOTS + 1},
			{upload_chunks = MAX_SLOTS + 1},
			{max_chunk_bytes = MAX_CHUNK_BYTES + 1},
			{response_chunks = 2, max_chunk_bytes = 16, max_retained_bytes_per_stream = 31},
			{max_retained_bytes_per_stream = (64 << 20) + 1},
		}) {
		bank, error := bank_create(limits, allocator)
		testing.expect(t, bank == nil && error.kind == .Invalid && p.calls == 0)
	}

	bank, error := bank_create(bank_test_limits(), allocator)
	assert(error.kind == .None)
	before := p.calls

	for options in ([]Options {
			{upload_length = i64(-1)},
			{decoding = cast(Content_Decoding)99},
			{max_encoded_bytes = (64 << 20) + 1},
			{max_decoded_bytes = (64 << 20) + 1},
		}) {
		cell, failure := channel_create(bank, options)
		testing.expect(t, cell == nil && failure.kind == .Invalid && p.calls == before)
		testing.expect_value(t, bank_stats(bank).streams, 0)
	}

	bank_close(&bank)
	testing.expect(t, p.live == 0 && p.bad_frees == 0)
}
