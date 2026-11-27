package main

import "shared:async"
import "shared:surf"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:sys/posix"
import "core:time"

Context :: struct {
	root, connection, a, b: async.Budget_Scope,
}
Record :: struct {
	calls, descriptors_before, descriptors_after: int,
	limit, peak:                                  u64,
}
roots: surf.Trust_Roots
main :: proc() {
	assert(len(os.args) == 4 || len(os.args) == 5)

	if len(os.args) == 5 {
		assert(surf.trust_roots_load_file(&roots, os.args[4]) == .None)
	}

	defer surf.trust_roots_destroy(&roots)
	mode, url, scenario := os.args[1], os.args[2], os.args[3]
	warm, error := perform(mode, url, {}, rt.heap_allocator(), scenario)

	if scenario == "oversize" {
		assert(error.kind == .Body_Oversized)
	} else if scenario == "empty" {
		assert(error.kind == .None && len(warm.body) == 0)
	} else {
		if error.kind != .None {
			fmt.eprintln(error)
		}

		assert(error.kind == .None && len(warm.body) == 1024)
	}

	surf.response_destroy(&warm)
	record := Record {
		calls              = 1,
		descriptors_before = count_fds(),
	}

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)

	if scenario == "tls-allow" || scenario == "tls-deny" {
		tls_budget(url, scenario == "tls-deny", allocator, &record)
	} else if scenario == "empty" {
		empty(url, allocator, &record)
	} else if scenario == "managed" {
		managed(url, allocator, &record)
	} else if scenario == "oversize" {
		oversize(mode, url, allocator, &record)
	} else {
		retained(mode, url, allocator, &record)
	}

	assert(track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)
	record.descriptors_after = count_fds()
	assert(record.descriptors_before == record.descriptors_after)
	fmt.print("{")
	fmt.printf(
		"\"calls\":%d,\"limit\":%d,\"peak\":%d,\"fd_before\":%d,\"fd_after\":%d",
		record.calls,
		record.limit,
		record.peak,
		record.descriptors_before,
		record.descriptors_after,
	)
	fmt.println("}")
}
count_fds :: proc() -> int {
	count := 0

	for fd in 0 ..< 4096 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			count += 1
		}
	}

	return count
}
usage :: proc(scope: async.Budget_Scope) -> async.Budget_Snapshot {
	snapshot, error := async.budget_snapshot(scope)
	assert(error == .None)

	return snapshot
}
context_create :: proc(limit: u64, allocator: mem.Allocator) -> Context {
	ctx: Context
	root, re := async.budget_create_root({bytes = limit, streams = 2}, allocator)
	assert(re == .None)
	conn, ce := async.budget_create_child(root, {bytes = limit, streams = 2})
	assert(ce == .None)
	a, ae := async.budget_create_child(conn, {bytes = limit, streams = 1})
	assert(ae == .None)
	b, be := async.budget_create_child(conn, {bytes = limit, streams = 1})
	assert(be == .None)
	ctx = {root, conn, a, b}

	return ctx
}
context_destroy :: proc(ctx: ^Context) {
	async.budget_release_scope(&ctx.a)
	async.budget_release_scope(&ctx.b)
	async.budget_release_scope(&ctx.connection)
	async.budget_release_scope(&ctx.root)
}
perform :: proc(
	mode, url: string,
	scope: async.Budget_Scope,
	allocator: mem.Allocator,
	scenario: string = "retained",
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	return surf.execute(
		{method = .GET, url = url},
		{
			allow_http = true,
			max_body_size = 1024,
			timeout = 3 * time.Second,
			scope = scope,
			tls = {roots = &roots},
		},
		allocator,
	)
}
// One response under a roomy scope: what it retains and the scope's peak.
calibrate :: proc(mode, url: string, allocator: mem.Allocator, record: ^Record) -> (retained, peak: u64) {
	ctx := context_create(16 * 1024 * 1024, allocator)
	response, error := perform(mode, url, ctx.a, allocator)
	record.calls += 1
	assert(error.kind == .None && len(response.body) == 1024)
	retained = usage(ctx.root).used.bytes
	surf.response_destroy(&response)
	peak = usage(ctx.root).peak.bytes
	assert(retained > 0 && peak >= retained && usage(ctx.root).used.bytes == 0)
	context_destroy(&ctx)

	return
}

retained :: proc(mode, url: string, allocator: mem.Allocator, record: ^Record) {
	// One request fits alone. A second cannot fit while the first is retained.
	held, peak := calibrate(mode, url, allocator, record)
	ctx := context_create(peak + held / 2, allocator)
	first, accepted := perform(mode, url, ctx.a, allocator)
	record.calls += 1
	assert(accepted.kind == .None && len(first.body) == 1024)
	before := usage(ctx.root).used.bytes
	failed, rejected := perform(mode, url, ctx.b, allocator)
	record.calls += 1
	assert(rejected.kind == .Allocation_Failed && rejected.write_effect == .Response_Received)
	surf.response_destroy(&failed)
	assert(usage(ctx.root).used.bytes == before && usage(ctx.b).used.bytes == 0)
	assert(usage(ctx.root).used.streams == 0 && usage(ctx.root).rejected > 0)
	chunk, transferred := surf.response_take_body(&first)
	assert(transferred.kind == .None)
	info, known := async.budget_allocation_info(chunk._owned.allocator, raw_data(chunk._owned.storage))
	assert(known)
	async.budget_release_scope(&ctx.a)
	surf.response_destroy(&first)
	assert(usage(ctx.root).used.bytes == info.backing_bytes)
	for byte in chunk.data {
		assert(byte == 'B')
	}
	surf.body_chunk_release(&chunk)
	assert(usage(ctx.root).used.bytes == 0)
	recovered, retry := perform(mode, url, ctx.b, allocator)
	record.calls += 1
	assert(retry.kind == .None && len(recovered.body) == 1024)
	surf.response_destroy(&recovered)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	context_destroy(&ctx)
}
oversize :: proc(mode, url: string, allocator: mem.Allocator, record: ^Record) {
	ctx := context_create(256 * 1024, allocator)
	response, error := perform(mode, url, ctx.a, allocator, "oversize")
	record.calls += 1
	assert(error.kind == .Body_Oversized && error.write_effect == .Response_Received)
	surf.response_destroy(&response)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	context_destroy(&ctx)
}
managed :: proc(url: string, allocator: mem.Allocator, record: ^Record) {
	block := block_cost(allocator)
	// Only the arena blocks that hold retained responses are charged: room for
	// three, so the peer's bound is never reached first.
	ctx := context_create(3 * block + 512, allocator)
	binding, created := async.budget_binding_create(ctx.a, {backing = allocator, metadata_allocator = allocator})
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
	previous := context.temp_allocator
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	// Each retained body stays in the arena until the scope refuses more.
	views: [16][]byte
	count := 0
	denied := false

	for _ in 0 ..< len(views) {
		response, error := surf.execute(
			{method = .GET, url = url},
			{allow_http = true, timeout = 3 * time.Second, scope = ctx.a, allocator_scope = ctx.a},
			context.temp_allocator,
		)
		bytes := response.body
		// The arena keeps the body; only the scope reference is released.
		surf.response_destroy(&response)

		if error.write_effect != .Not_Sent {
			record.calls += 1
		}

		if error.kind != .None {
			assert(error.kind == .Allocation_Failed)
			denied = true
			break
		}

		assert(len(bytes) == 1024)
		views[count] = bytes
		count += 1
	}

	assert(denied && count > 0)

	for bytes in views[:count] {
		for byte in bytes {
			assert(byte == 'B')
		}
	}

	assert(usage(ctx.root).used.streams == 0 && usage(ctx.root).rejected > 0)
	context.temp_allocator = previous
	mem.dynamic_arena_destroy(&arena)
	assert(usage(ctx.root).used.bytes == 0)
	managed_retry(url, &arena, managed, ctx.a, record)
	mem.dynamic_arena_destroy(&arena)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	async.budget_binding_release(&binding)
	context_destroy(&ctx)
}

// What one 4 KiB arena block charges, as a scope observes it.
block_cost :: proc(allocator: mem.Allocator) -> u64 {
	ctx := context_create(1024 * 1024, allocator)
	defer context_destroy(&ctx)
	binding, created := async.budget_binding_create(ctx.a, {backing = allocator, metadata_allocator = allocator})
	assert(created.kind == .None)
	defer async.budget_binding_release(&binding)
	managed := async.budget_allocator(binding)
	before := usage(ctx.root).used.bytes
	block, error := mem.alloc(4096, mem.DEFAULT_ALIGNMENT, managed)
	assert(error == nil)
	cost := usage(ctx.root).used.bytes - before
	assert(mem.free(block, managed) == nil)

	return cost
}

managed_retry :: proc(
	url: string,
	arena: ^mem.Dynamic_Arena,
	managed: mem.Allocator,
	scope: async.Budget_Scope,
	record: ^Record,
) {
	mem.dynamic_arena_init(
		arena,
		block_allocator = managed,
		array_allocator = managed,
		block_size = 4096,
		out_band_size = 8192,
	)
	previous := context.temp_allocator
	context.temp_allocator = mem.dynamic_arena_allocator(arena)
	defer context.temp_allocator = previous
	response, error := surf.execute(
		{method = .GET, url = url},
		{allow_http = true, timeout = 3 * time.Second, scope = scope, allocator_scope = scope},
		context.temp_allocator,
	)
	bytes := response.body
	surf.response_destroy(&response)
	assert(error.kind == .None && len(bytes) == 1024)
	record.calls += 1
}

empty :: proc(url: string, allocator: mem.Allocator, record: ^Record) {
	ctx := context_create(256 * 1024, allocator)
	response, error := perform("native", url, ctx.a, allocator, "empty")
	record.calls += 1
	assert(error.kind == .None && len(response.body) == 0 && cap(response.body_storage) == 0)
	// No allocation reference remains in this zero-capacity moved owner; the
	// headers are charged until the response is destroyed.
	chunk, taken := surf.response_take_body(&response)
	assert(taken.kind == .None)
	surf.response_destroy(&response)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	context_destroy(&ctx)
	surf.body_chunk_release(&chunk)
	surf.body_chunk_release(&chunk)
}

// TLS state belongs to the connection, not to the request scope. A denied
// request has had its handshake and been sent; only its response is refused.
tls_budget :: proc(url: string, denied: bool, allocator: mem.Allocator, record: ^Record) {
	limit := u64(4 * 1024 * 1024)

	if denied {
		limit = 512
	}

	ctx := context_create(limit, allocator)
	response, error := perform("tls", url, ctx.a, allocator)
	record.calls += 1

	if denied {
		assert(error.kind == .Allocation_Failed && error.write_effect == .Response_Received)
		assert(usage(ctx.root).rejected > 0)
	} else {
		assert(error.kind == .None && len(response.body) == 1024)
		assert(usage(ctx.root).peak.bytes >= 1024)
	}

	surf.response_destroy(&response)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	context_destroy(&ctx)
}
