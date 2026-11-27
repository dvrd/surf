package tests

import "../../support/loopback"
import "base:runtime"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import "shared:async"
import "shared:async/http/exchange"
import "shared:surf"

budget_usage :: proc(scope: async.Budget_Scope) -> async.Budget_Snapshot {
	snapshot, error := async.budget_snapshot(scope)
	assert(error == .None)

	return snapshot
}

BUDGET_WIRE :: "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"

Budget_Peer :: struct {
	server: loopback.Server,
	url:    string,
}

budget_peer_start :: proc(t: ^testing.T, peer: ^Budget_Peer, wire: string) -> bool {
	peer.server.answer = {
		wire = wire,
	}

	if !testing.expect(t, loopback.server_start(&peer.server)) {
		return false
	}

	peer.url = fmt.aprintf("http://127.0.0.1:%d/", peer.server.port)

	return true
}

budget_peer_stop :: proc(peer: ^Budget_Peer) {
	loopback.server_stop(&peer.server)
	delete(peer.url)
}

budget_fetch :: proc(
	peer: ^Budget_Peer,
	allocator: mem.Allocator,
	scope: async.Budget_Scope,
	allocator_scope: async.Budget_Scope = {},
	limit := 64,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	return surf.execute(
		{method = .GET, url = peer.url},
		{
			allow_http = true,
			timeout = 3 * time.Second,
			max_body_size = limit,
			scope = scope,
			allocator_scope = allocator_scope,
		},
		allocator,
	)
}

// A held response keeps its whole backing charged; a sibling request that no
// longer fits fails after its head, and the bytes come back once the body chunk
// is destroyed.
@(test)
managed_results_charge_full_backing_transfer_without_duplication_and_recover :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	body := strings.repeat("b", 1500, context.temp_allocator)
	peer: Budget_Peer

	if !budget_peer_start(
		t,
		&peer,
		fmt.tprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body),
	) {
		return
	}
	defer budget_peer_stop(&peer)

	root, re := async.budget_create_root({bytes = 3000, streams = 2}, allocator)
	assert(re == .None)
	conn, ce := async.budget_create_child(root, {bytes = 3000, streams = 2})
	assert(ce == .None)
	a, ae := async.budget_create_child(conn, {bytes = 3000, streams = 1})
	assert(ae == .None)
	b, be := async.budget_create_child(conn, {bytes = 3000, streams = 1})
	assert(be == .None)
	response, error := budget_fetch(&peer, allocator, a, limit = 4096)
	assert(error.kind == .None)
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	before := budget_usage(root).used.bytes
	testing.expect(t, before > u64(len(response.body)))
	failed, rejected := budget_fetch(&peer, allocator, b, limit = 4096)
	testing.expect_value(t, rejected.kind, .Allocation_Failed)
	testing.expect_value(t, rejected.status, 200)
	testing.expect_value(t, rejected.write_effect, .Response_Received)
	testing.expect_value(t, budget_usage(root).used.bytes, before)
	testing.expect_value(t, budget_usage(b).used.bytes, u64(0))
	surf.response_destroy(&failed)
	chunk, taken := surf.response_take_body(&response)
	assert(taken.kind == .None)
	info, known := async.budget_allocation_info(
		chunk._owned.allocator,
		raw_data(chunk._owned.storage),
	)
	assert(known)
	testing.expect_value(t, info.size, len(chunk._owned.storage))
	async.budget_release_scope(&a)
	surf.response_destroy(&response)
	testing.expect_value(t, string(chunk.data), body)
	testing.expect_value(t, budget_usage(root).used.bytes, info.backing_bytes)
	surf.body_chunk_release(&chunk)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	recovered, retry := budget_fetch(&peer, allocator, b, limit = 4096)
	assert(retry.kind == .None)
	surf.response_destroy(&recovered)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	async.budget_release_scope(&b)
	async.budget_release_scope(&conn)
	async.budget_release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
stream_exhaustion_and_foreign_allocator_reject_before_any_write :: proc(t: ^testing.T) {
	peer: Budget_Peer

	if !budget_peer_start(t, &peer, BUDGET_WIRE) {
		return
	}
	defer budget_peer_stop(&peer)

	root, re := async.budget_create_root({bytes = 8192, streams = 1})
	assert(re == .None)
	defer async.budget_release_scope(&root)
	other, oe := async.budget_create_root({bytes = 8192, streams = 1})
	assert(oe == .None)
	defer async.budget_release_scope(&other)
	lease, admitted := async.budget_reserve(root, {streams = 1})
	assert(admitted == .None)
	_, denied := budget_fetch(&peer, context.allocator, root)
	testing.expect_value(t, denied.budget, .Limit_Exceeded)
	testing.expect_value(t, denied.phase, .Admission)
	testing.expect_value(t, denied.write_effect, .Not_Sent)
	testing.expect_value(t, loopback.server_accepts(&peer.server), 0)
	async.budget_release(&lease)
	binding, created := async.budget_binding_create(other)
	assert(created.kind == .None)
	defer async.budget_binding_release(&binding)
	_, mismatch := budget_fetch(&peer, async.budget_allocator(binding), root)
	testing.expect_value(t, mismatch.budget, .Foreign_Root)
	testing.expect_value(t, mismatch.write_effect, .Not_Sent)
	testing.expect_value(t, loopback.server_accepts(&peer.server), 0)
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
}

@(test)
covered_arena_is_not_double_wrapped_and_retains_actual_backing_until_arena_destroy :: proc(
	t: ^testing.T,
) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	peer: Budget_Peer

	if !budget_peer_start(t, &peer, BUDGET_WIRE) {
		return
	}
	defer budget_peer_stop(&peer)

	root, re := async.budget_create_root({bytes = 65536, streams = 2}, allocator)
	assert(re == .None)
	a, ae := async.budget_create_child(root, {bytes = 65536, streams = 1})
	assert(ae == .None)
	b, be := async.budget_create_child(root, {bytes = 65536, streams = 1})
	assert(be == .None)
	binding, created := async.budget_binding_create(
		a,
		{backing = allocator, metadata_allocator = allocator},
	)
	assert(created.kind == .None)
	managed := async.budget_allocator(binding)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(
		&arena,
		block_allocator = managed,
		array_allocator = managed,
		block_size = 4096,
		out_band_size = 8192,
	)
	view := mem.dynamic_arena_allocator(&arena)
	_, unknown := budget_fetch(&peer, view, a)
	testing.expect_value(t, unknown.kind, .Invalid_Config)
	_, sibling := budget_fetch(&peer, view, a, b)
	testing.expect_value(t, sibling.kind, .Invalid_Config)
	testing.expect_value(t, loopback.server_accepts(&peer.server), 0)
	response, accepted := budget_fetch(&peer, view, a, a)
	assert(accepted.kind == .None)
	before := budget_usage(root).used.bytes
	testing.expect_value(t, before, async.budget_stats(binding).backing_bytes)
	chunk, taken := surf.response_take_body(&response)
	assert(taken.kind == .None)
	async.budget_release_scope(&a)
	async.budget_binding_release(&binding)
	surf.response_destroy(&response)
	testing.expect_value(t, string(chunk.data), "body")
	surf.body_chunk_release(&chunk)
	testing.expect_value(t, budget_usage(root).used.bytes, before)
	mem.dynamic_arena_destroy(&arena)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	async.budget_release_scope(&b)
	async.budget_release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}

@(test)
surf_body_bytes_round_trip_through_the_async_http_exchange :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	peer: Budget_Peer

	if !budget_peer_start(t, &peer, BUDGET_WIRE) {
		return
	}
	defer budget_peer_stop(&peer)

	root, re := async.budget_create_root({bytes = 65536, streams = 2}, allocator)
	assert(re == .None)
	conn, ce := async.budget_create_child(root, {bytes = 65536, streams = 2})
	assert(ce == .None)
	a, ae := async.budget_create_child(conn, {bytes = 65536, streams = 1})
	assert(ae == .None)
	response, fetched := budget_fetch(&peer, allocator, a)
	assert(fetched.kind == .None)
	chunk, taken := surf.response_take_body(&response)
	assert(taken.kind == .None)
	_, known := async.budget_allocation_info(
		chunk._owned.allocator,
		raw_data(chunk._owned.storage),
	)
	assert(known)
	surf.response_destroy(&response)
	moved, copy_error := async.owned_copy_bounded(chunk.data, len(chunk.data), allocator)
	assert(copy_error.kind == .None)
	http_root, http_root_error := async.budget_create_root({bytes = 65536, streams = 1}, allocator)
	assert(http_root_error == .None)
	http_scope, http_scope_error := async.budget_create_child(
		http_root,
		{bytes = 65536, streams = 1},
	)
	assert(http_scope_error == .None)
	ex: async.Exchange_Body
	assert(async.exchange_init(&ex, .GET, {scope = http_scope}, allocator).kind == .None)
	assert(async.exchange_respond(&ex, {status = 200, content_length = 4}).kind == .None)
	assert(async.exchange_submit(&ex, &moved) == .Accepted)
	testing.expect(t, moved.allocator.procedure == nil && moved.data == nil)
	bytes, available := exchange.body(&ex)
	assert(available)
	testing.expect_value(t, string(bytes), "body")
	assert(async.exchange_finish(&ex).kind == .None)
	assert(exchange.release_body(&ex))
	assert(exchange.complete(&ex).kind == .None)
	async.exchange_destroy(&ex)
	async.budget_release_scope(&http_scope)
	async.budget_release_scope(&http_root)
	surf.body_chunk_release(&chunk)
	surf.response_destroy(&response)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	async.budget_release_scope(&a)
	async.budget_release_scope(&conn)
	async.budget_release_scope(&root)
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
		owner := state.response
		state.response = nil
		// Must observe an already cleared owner.
		surf.response_destroy(owner)
		free(owner, state.backing)
		state.freed = true
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
	mem.tracking_allocator_init(&track, runtime.heap_allocator(), runtime.heap_allocator())
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	peer: Budget_Peer

	if !budget_peer_start(t, &peer, BUDGET_WIRE) {
		return
	}
	defer budget_peer_stop(&peer)

	root, re := async.budget_create_root({bytes = 8192, streams = 1}, allocator)
	assert(re == .None)
	backend := Budget_Free_Owner {
		backing = allocator,
	}

	value, error := budget_fetch(&peer, {budget_free_owner, &backend}, root)
	assert(error.kind == .None)
	owner := new(surf.Response, allocator)
	owner^ = value
	backend.response = owner
	// The first backing callback frees this actual heap frame.
	surf.response_destroy(owner)
	testing.expect(t, backend.freed)
	testing.expect_value(t, budget_usage(root).used.bytes, u64(0))
	testing.expect_value(t, budget_usage(root).used.streams, u64(0))
	async.budget_release_scope(&root)
	testing.expect_value(t, track.current_memory_allocated, i64(0))
}
