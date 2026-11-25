package surf_stream

import "base:runtime"
import "core:mem"
import "core:testing"
import surf "../.."
import "core:bytes"
import charged "shared:async/mem/budget"
import "shared:async/mem/owned"
import "core:sync"
import scopes "shared:async/sync/budget"

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

bank_test_same :: proc(a, b: $T) -> bool {
	aa, bb := a, b

	return bytes.equal(mem.byte_slice(&aa, size_of(T)), mem.byte_slice(&bb, size_of(T)))
}
bank_test_limits :: proc(chunks := 2, retained := 64) -> Limits {
	return {
		streams = 1,
		response_chunks = chunks,
		upload_chunks = 2,
		max_chunk_bytes = 16,
		max_retained_bytes_per_stream = retained,
	}
}
bank_test_create :: proc(allocator := context.allocator, options := Options{}) -> (^Bank, ^Channel) {
	bank, error := bank_create(bank_test_limits(), allocator)
	assert(error.kind == .None)
	cell, failure := channel_create(bank, options)
	assert(failure.kind == .None)

	return bank, cell
}
Bank_Callback :: struct {
	bank:                             ^Bank,
	cell:                             ^Channel,
	releases, bytes, expected_credit: int,
	healthy:                          bool,
}
bank_test_release :: proc(storage: []u8, data: rawptr) {
	p := cast(^Bank_Callback)data
	p.releases += 1
	p.bytes += len(storage)
	// Try-lock first so a regression fails instead of hanging a test runner.
	unlocked := sync.try_lock(&p.cell.mu)
	p.healthy = p.healthy && unlocked

	if !unlocked {
		return
	}

	sync.unlock(&p.cell.mu)
	unlocked = sync.try_lock(&p.bank.mu)
	p.healthy = p.healthy && unlocked

	if !unlocked {
		return
	}

	sync.unlock(&p.bank.mu)
	stats := bank_stats(p.bank)
	p.healthy = p.healthy && stats.streams == 1 && stats.upload_bytes == p.expected_credit
	denied, error := channel_create(p.bank, {})
	p.healthy = p.healthy && denied == nil && error.kind == .Capacity
}
bank_test_chunk :: proc(storage: []u8, payload: int, p: ^Bank_Callback) -> owned.Chunk {
	return {data = storage[:payload], storage = storage, release = bank_test_release, user_data = p}
}

@(test)
whole_storage_credit_survives_upload_take_and_destructor :: proc(t: ^testing.T) {
	bank, cell := bank_test_create(options = {upload_length = i64(20)})
	probe := Bank_Callback {
		bank            = bank,
		cell            = cell,
		healthy         = true,
		expected_credit = 32,
	}

	a, b, c: [16]u8
	first := bank_test_chunk(a[:], 1, &probe)
	second := bank_test_chunk(b[:], 1, &probe)
	third := bank_test_chunk(c[:], 1, &probe)
	status, error := upload_submit(cell, &first)
	testing.expect(t, status == .Accepted && error.kind == .None && bank_test_same(first, owned.Chunk{}))
	status, error = upload_submit(cell, &second)
	testing.expect(t, status == .Accepted && error.kind == .None && bank_test_same(second, owned.Chunk{}))
	stats := bank_stats(bank)
	testing.expect(t, stats.upload_chunks == 2 && stats.upload_bytes == 32 && stats.response_backing_bytes == 32)
	original := third
	status, error = upload_submit(cell, &third)
	testing.expect(t, status == .Backpressure && error.kind == .None && bank_test_same(third, original))
	active: owned.Chunk
	taken, _, failure := upload_take(cell, &active)
	testing.expect(t, taken && failure.kind == .None && len(active.storage) == 16 && len(active.data) == 1)
	testing.expect_value(t, bank_stats(bank).upload_bytes, 32)
	status, _ = upload_submit(cell, &third)
	testing.expect(t, status == .Backpressure && bank_test_same(third, original))
	// Queued cleanup is outside locks, and credits remain reserved through callbacks.
	stop_upload(cell)
	testing.expect(t, probe.healthy && probe.releases == 1 && probe.bytes == 16)
	testing.expect_value(t, bank_stats(bank).upload_bytes, 16)
	probe.expected_credit = 16
	upload_release(cell, &active)
	testing.expect(
		t,
		bank_test_same(active, owned.Chunk{}) && probe.healthy && probe.releases == 2 && probe.bytes == 32,
	)
	testing.expect_value(t, bank_stats(bank).upload_bytes, 0)
	// Caller still owns the rejected source. Its destructor also runs safely.
	probe.expected_credit = 0
	owned.destroy(&third)
	owned.destroy(&third)
	testing.expect(t, probe.healthy && probe.releases == 3)
	release_request(cell)
	bank_close(&bank)
	bank_close(&bank)
}

@(test)
output_credit_follows_taken_owner_and_cell_cannot_be_reused_early :: proc(t: ^testing.T) {
	bank, cell := bank_test_create()
	first, first_bytes := reserve_output(cell)
	second, second_bytes := reserve_output(cell)
	first_bytes[0] = 'a'
	second_bytes[0] = 'b'
	testing.expect(t, publish_output(first, 1) && publish_output(second, 1))
	held: owned.Chunk
	status, error := next(cell, &held)
	testing.expect(t, status == .Chunk && error.kind == .None && len(held.storage) == 16 && string(held.data) == "a")
	testing.expect_value(t, bank_stats(bank).response_backing_bytes, 32)
	blocked, _ := reserve_output(cell)
	testing.expect(t, blocked == nil)
	release_request(cell)
	stats := bank_stats(bank)
	testing.expect(t, stats.streams == 1 && stats.retiring_streams == 1 && stats.held_response_chunks == 1)
	denied, failure := channel_create(bank, {})
	testing.expect(t, denied == nil && failure.kind == .Capacity)
	testing.expect_value(t, string(held.data), "a")
	owned.destroy(&held)
	owned.destroy(&held)
	testing.expect_value(t, bank_stats(bank).streams, 0)
	replacement, success := channel_create(bank, {})
	testing.expect(t, replacement != nil && success.kind == .None)
	release_request(replacement)
	bank_close(&bank)
}

@(test)
late_head_chunk_and_managed_binding_outlive_detached_request_and_bank :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, runtime.heap_allocator(), runtime.heap_allocator())
	allocator := mem.tracking_allocator(&tracker)
	scope, scope_error := scopes.create_root({bytes = 1 << 20, streams = 1}, allocator)
	assert(scope_error == .None)
	binding, binding_error := charged.create(scope, {backing = allocator, metadata_allocator = allocator})
	assert(binding_error.kind == .None)
	bank, cell := bank_test_create(charged.allocator(binding))
	lease, lease_error := scopes.reserve(scope, {streams = 1})
	assert(lease_error == .None)
	adopt_lease(cell, &lease)
	response := surf.Response {
		status    = 200,
		allocator = charged.allocator(binding),
	}

	response.header_storage = make([]u8, 16, response.allocator) or_else panic("test allocation")
	copy(response.header_storage, []u8{114, 101, 116, 97, 105, 110, 101, 100, 45, 104, 101, 97, 100})
	testing.expect(t, publish_head(cell, &response, 42, .Decoded_Gzip) && bank_test_same(response, surf.Response{}))
	head: Head
	testing.expect_value(t, take_head(cell, &head).kind, .None)
	slot, storage := reserve_output(cell)
	storage[0] = 123
	testing.expect(t, publish_output(slot, 1))
	chunk: owned.Chunk
	status, error := next(cell, &chunk)
	testing.expect(t, status == .Chunk && error.kind == .None)
	release_request(cell)
	borrowed_bank := bank
	bank_close(&bank)
	bank_close(&bank)
	charged.release(&binding)
	testing.expect_value(t, scopes.close(scope), .None)
	snapshot, _ := scopes.snapshot(scope)
	testing.expect(t, snapshot.used.bytes > 0 && snapshot.used.streams == 1)
	testing.expect(t, head.wire_content_length == 42 && head.delivery == .Decoded_Gzip && head.response.status == 200)
	head_destroy(&head)
	head_destroy(&head)
	testing.expect_value(t, bank_stats(borrowed_bank).held_response_chunks, 1)
	testing.expect_value(t, chunk.data[0], 123)
	owned.destroy(&chunk)
	owned.destroy(&chunk)
	snapshot, _ = scopes.snapshot(scope)
	testing.expect(t, snapshot.used.bytes == 0 && snapshot.used.streams == 0)
	scopes.release_scope(&scope)
	testing.expect_value(t, tracker.current_memory_allocated, 0)
	testing.expect_value(t, len(tracker.bad_free_array), 0)
	mem.tracking_allocator_destroy(&tracker)
}

@(test)
head_and_chunk_destinations_with_hidden_owners_reject_atomically :: proc(t: ^testing.T) {
	bank, cell := bank_test_create()
	response := surf.Response {
		status = 200,
	}

	testing.expect(t, publish_head(cell, &response, -1, .Wire))
	scope, scope_error := scopes.create_root({bytes = 1024})
	assert(scope_error == .None)
	retained, retain_error := scopes.retain_scope(scope)
	assert(retain_error == .None)
	destination := Head {
		response = {_allocator_scope = retained},
	}

	original := destination
	testing.expect_value(t, take_head(cell, &destination).kind, .Invalid)
	testing.expect(t, bank_test_same(destination, original))
	head_destroy(&destination)
	body := make([dynamic]u8, 0, 16)
	destination = {
		response = {body_storage = body},
	}

	original = destination
	testing.expect_value(t, take_head(cell, &destination).kind, .Invalid)
	testing.expect(t, bank_test_same(destination, original))
	// response_destroy frees body_storage only when allocator is populated; the
	// deliberately partial destination still belongs to this test.
	destination = {}
	delete(body)
	empty: Head
	testing.expect_value(t, take_head(cell, &empty).kind, .None)
	head_destroy(&empty)
	slot, storage := reserve_output(cell)
	storage[0] = 7
	testing.expect(t, publish_output(slot, 1))
	marker: u8

	for occupied in ([]owned.Chunk {
			{user_data = &marker},
			{allocator = {data = &marker}},
			{data = mem.byte_slice(&marker, 0)},
			{storage = mem.byte_slice(&marker, 0)},
		}) {
		chunk := occupied
		before := chunk
		status, error := next(cell, &chunk)
		testing.expect(t, status == .Pending && error.kind == .Invalid && bank_test_same(chunk, before))
	}

	chunk: owned.Chunk
	status, error := next(cell, &chunk)
	testing.expect(t, status == .Chunk && error.kind == .None)
	owned.destroy(&chunk)
	release_request(cell)
	bank_close(&bank)
	scopes.release_scope(&scope)
}

@(test)
rejected_uploads_preserve_payload_storage_owner_and_callback :: proc(t: ^testing.T) {
	bank, cell := bank_test_create(options = {upload_length = i64(1)})
	probe := Bank_Callback {
		bank    = bank,
		cell    = cell,
		healthy = true,
	}

	backing: [17]u8
	too_large := bank_test_chunk(backing[:], 1, &probe)
	before := too_large
	status, error := upload_submit(cell, &too_large)
	testing.expect(t, status == .Limit_Exceeded && error.kind == .None && bank_test_same(too_large, before))
	empty := bank_test_chunk(backing[:16], 0, &probe)
	before = empty
	status, error = upload_submit(cell, &empty)
	testing.expect(t, status == .Invalid && error.kind == .Invalid && bank_test_same(empty, before))
	invalid := bank_test_chunk(backing[:1], 1, &probe)
	invalid.data = backing[2:3]
	before = invalid
	status, error = upload_submit(cell, &invalid)
	testing.expect(t, status == .Invalid && error.kind == .Invalid && bank_test_same(invalid, before))
	testing.expect_value(t, probe.releases, 0)
	owned.destroy(&too_large)
	owned.destroy(&empty)
	// The forged invalid descriptor is not another owner of this stack storage.
	invalid = {}
	testing.expect(t, probe.healthy && probe.releases == 2)
	valid := bank_test_chunk(backing[:16], 1, &probe)
	testing.expect(t, retain(cell))
	release_request(cell)
	before = valid
	status, error = upload_submit(cell, &valid)
	testing.expect(t, status == .Closed && error.kind == .None && bank_test_same(valid, before))
	owned.destroy(&valid)
	testing.expect(t, probe.healthy && probe.releases == 3)
	release(cell)
	bank_close(&bank)
}

@(test)
retained_backing_byte_limit_applies_before_upload_slot_count :: proc(t: ^testing.T) {
	// Two response buffers reserve32bytes. The remaining16bytes permit one
	// full backing owner, even though two upload slots and tiny payloads fit.
	bank, error := bank_create(bank_test_limits(retained = 48), context.allocator)
	assert(error.kind == .None)
	cell, failure := channel_create(bank, {upload_length = i64(2)})
	assert(failure.kind == .None)
	probe := Bank_Callback {
		bank            = bank,
		cell            = cell,
		healthy         = true,
		expected_credit = 16,
	}

	a, b: [16]u8
	first := bank_test_chunk(a[:], 1, &probe)
	second := bank_test_chunk(b[:], 1, &probe)
	status, _ := upload_submit(cell, &first)
	testing.expect_value(t, status, .Accepted)
	before := second
	status, _ = upload_submit(cell, &second)
	testing.expect(t, status == .Backpressure && bank_test_same(second, before))
	testing.expect_value(t, bank_stats(bank).upload_chunks, 1)
	active: owned.Chunk
	taken, _, _ := upload_take(cell, &active)
	testing.expect(t, taken)
	status, _ = upload_submit(cell, &second)
	testing.expect(t, status == .Backpressure && bank_test_same(second, before))
	upload_release(cell, &active)
	testing.expect(t, probe.healthy && probe.releases == 1)
	status, _ = upload_submit(cell, &second)
	testing.expect_value(t, status, .Accepted)
	stop_upload(cell)
	testing.expect(t, probe.healthy && probe.releases == 2 && probe.bytes == 32)
	release_request(cell)
	bank_close(&bank)
}
