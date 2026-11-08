package tests

import surf ".."
import exchange "../../http/exchange"
import rt "base:runtime"
import "core:mem"
import charged "core:mem/budget"
import owned "core:mem/owned"
import "core:net"
import scopes "core:sync/budget"
import "core:testing"

budget_usage :: proc(scope: scopes.Scope) -> scopes.Snapshot {
	snapshot, error := scopes.snapshot(scope); assert(error == .None)
	return snapshot
}
budget_stream :: proc(fixture: ^Fixture) -> net.Connection {
	return {data = fixture, read = read, write = write, close = close}
}
BUDGET_WIRE :: "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"

@(test)
managed_results_charge_full_backing_transfer_without_duplication_and_recover :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 2000, streams = 2}, allocator); assert(re == .None)
	conn, ce := scopes.create_child(root, {bytes = 2000, streams = 2}); assert(ce == .None)
	a, ae := scopes.create_child(conn, {bytes = 2000, streams = 1}); assert(ae == .None)
	b, be := scopes.create_child(conn, {bytes = 2000, streams = 1}); assert(be == .None)
	first := Fixture {
		wire = BUDGET_WIRE,
	}
	response, error := surf.exchange_scoped(
		budget_stream(&first),
		{method = .GET, url = "https://fixture.invalid/"},
		1024,
		allocator,
		scope = a,
	)
	assert(error.kind == .None)
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	before := budget_usage(root).used.bytes
	testing.expect(t, before > u64(len(response.body)))
	second := Fixture {
		wire = BUDGET_WIRE,
	}
	failed, rejected := surf.exchange_scoped(
		budget_stream(&second),
		{method = .GET, url = "https://fixture.invalid/"},
		1024,
		allocator,
		scope = b,
	)
	testing.expect_value(t, rejected.kind, .Allocation_Failed)
	testing.expect_value(t, rejected.write_effect, .Response_Received)
	testing.expect_value(t, budget_usage(root).used.bytes, before)
	testing.expect_value(t, budget_usage(b).used.bytes, u64(0))
	surf.response_destroy(&failed)
	chunk, taken := surf.response_take_body(&response); assert(taken.kind == .None)
	info, known := charged.allocation_info(chunk.allocator, raw_data(chunk.storage)); assert(known)
	testing.expect_value(t, info.size, 1024)
	scopes.release_scope(&a); surf.response_destroy(&response)
	testing.expect_value(t, string(chunk.data), "body")
	testing.expect_value(t, budget_usage(root).used.bytes, info.backing_bytes)
	owned.destroy(&chunk)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	third := Fixture {
		wire = BUDGET_WIRE,
	}
	recovered, retry := surf.exchange_scoped(
		budget_stream(&third),
		{method = .GET, url = "https://fixture.invalid/"},
		1024,
		allocator,
		scope = b,
	)
	assert(retry.kind == .None); surf.response_destroy(&recovered)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	scopes.release_scope(&b); scopes.release_scope(&conn); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
stream_exhaustion_and_foreign_allocator_reject_before_any_write :: proc(t: ^testing.T) {
	root, re := scopes.create_root({bytes = 8192, streams = 1}); assert(re == .None)
	defer scopes.release_scope(&root)
	other, oe := scopes.create_root({bytes = 8192, streams = 1}); assert(oe == .None)
	defer scopes.release_scope(&other)
	lease, admitted := scopes.reserve(root, {streams = 1}); assert(admitted == .None)
	fixture := Fixture {
		wire = BUDGET_WIRE,
	}
	_, denied := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		scope = root,
	)
	testing.expect_value(t, denied.budget, .Limit_Exceeded)
	testing.expect_value(t, denied.phase, .Admission)
	testing.expect_value(t, denied.write_effect, .Not_Sent)
	testing.expect_value(t, fixture.written_count, 0)
	scopes.release(&lease)
	binding, created := charged.create(other); assert(created.kind == .None)
	defer charged.release(&binding)
	_, mismatch := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		charged.allocator(binding),
		scope = root,
	)
	testing.expect_value(t, mismatch.budget, .Foreign_Root)
	testing.expect_value(t, mismatch.write_effect, .Not_Sent)
	testing.expect_value(t, fixture.written_count, 0)
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
}

@(test)
covered_arena_is_not_double_wrapped_and_retains_actual_backing_until_arena_destroy :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 65536, streams = 2}, allocator); assert(re == .None)
	a, ae := scopes.create_child(root, {bytes = 65536, streams = 1}); assert(ae == .None)
	b, be := scopes.create_child(root, {bytes = 65536, streams = 1}); assert(be == .None)
	binding, created := charged.create(a, {backing = allocator, metadata_allocator = allocator})
	assert(created.kind == .None)
	managed := charged.allocator(binding)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = managed,
		array_allocator = managed,
		block_size = 4096,
		out_band_size = 8192,
	)
	view := mem.dynamic_arena_allocator(&arena)
	fixture := Fixture {
		wire = BUDGET_WIRE,
	}
	_, unknown := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		view,
		scope = a,
	)
	testing.expect_value(t, unknown.kind, .Invalid_Config)
	_, sibling := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		view,
		scope = a,
		allocator_scope = b,
	)
	testing.expect_value(t, sibling.kind, .Invalid_Config)
	testing.expect_value(t, fixture.written_count, 0)
	response, accepted := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		view,
		scope = a,
		allocator_scope = a,
	)
	assert(accepted.kind == .None)
	before := budget_usage(root).used.bytes
	testing.expect_value(t, before, charged.stats(binding).backing_bytes)
	chunk, taken := surf.response_take_body(&response); assert(taken.kind == .None)
	scopes.release_scope(&a); charged.release(&binding); surf.response_destroy(&response)
	testing.expect_value(t, string(chunk.data), "body")
	owned.destroy(&chunk)
	testing.expect_value(t, budget_usage(root).used.bytes, before)
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	scopes.release_scope(&b); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
surf_body_moves_to_sibling_http_exchange_without_charging_common_ancestors_twice :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 65536, streams = 2}, allocator); assert(re == .None)
	conn, ce := scopes.create_child(root, {bytes = 65536, streams = 2}); assert(ce == .None)
	a, ae := scopes.create_child(conn, {bytes = 65536, streams = 1}); assert(ae == .None)
	b, be := scopes.create_child(conn, {bytes = 65536, streams = 1}); assert(be == .None)
	fixture := Fixture {
		wire = BUDGET_WIRE,
	}
	response, fetched := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		allocator,
		scope = a,
	)
	assert(fetched.kind == .None)
	chunk, taken := surf.response_take_body(&response); assert(taken.kind == .None)
	backing := len(chunk.storage)
	info, known := charged.allocation_info(chunk.allocator, raw_data(chunk.storage)); assert(known)
	surf.response_destroy(&response)
	ex: exchange.Exchange
	assert(exchange.init(&ex, .GET, {scope = b}, allocator).kind == .None)
	assert(exchange.respond(&ex, {status = 200, content_length = 4}).kind == .None)
	before := budget_usage(root).used.bytes
	target := budget_usage(b).used.bytes
	assert(exchange.submit(&ex, &chunk) == .Accepted)
	testing.expect_value(t, budget_usage(root).used.bytes, before)
	testing.expect_value(t, budget_usage(conn).used.bytes, before)
	testing.expect_value(t, budget_usage(a).used.bytes, u64(0))
	testing.expect_value(t, budget_usage(b).used.bytes, target + info.backing_bytes)
	testing.expect_value(t, exchange.retained_bytes(&ex), backing)
	bytes, available := exchange.body(&ex); assert(available)
	testing.expect_value(t, string(bytes), "body")
	testing.expect(t, chunk.allocator.procedure == nil && chunk.data == nil)
	assert(exchange.finish(&ex).kind == .None)
	assert(exchange.release_body(&ex))
	assert(exchange.complete(&ex).kind == .None)
	exchange.destroy(&ex); surf.response_destroy(&response)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	scopes.release_scope(&a); scopes.release_scope(&b)
	scopes.release_scope(&conn); scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

Budget_Free_Owner :: struct {
	backing:  mem.Allocator,
	response: ^surf.Response,
	freed:    bool,
}
budget_free_owner :: proc(
	p: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	state := cast(^Budget_Free_Owner)p
	if mode == .Free && state.response != nil {
		owner := state.response; state.response = nil
		surf.response_destroy(owner) // Must observe an already cleared owner.
		free(owner, state.backing); state.freed = true
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
managed_response_destructor_detaches_before_callback_can_free_response_frame :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	root, re := scopes.create_root({bytes = 8192, streams = 1}, allocator); assert(re == .None)
	backend := Budget_Free_Owner {
		backing = allocator,
	}
	fixture := Fixture {
		wire = BUDGET_WIRE,
	}
	value, error := surf.exchange_scoped(
		budget_stream(&fixture),
		{method = .GET, url = "https://fixture.invalid/"},
		64,
		{budget_free_owner, &backend},
		scope = root,
	)
	assert(error.kind == .None)
	owner := new(surf.Response, allocator); owner^ = value
	backend.response = owner
	surf.response_destroy(owner) // The first backing callback frees this actual heap frame.
	testing.expect(t, backend.freed)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	scopes.release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}
