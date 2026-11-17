package main

import surf "../../.."
import http "../../../../http"
import rt "base:runtime"
import tls "core:crypto/tls"
import "core:fmt"
import "core:mem"
import charged "core:mem/budget"
import owned "core:mem/owned"
import "core:os"
import scopes "core:sync/budget"
import "core:sys/posix"
import "core:time"

Context :: struct {
	root, connection, a, b: scopes.Scope,
}
Record :: struct {
	calls, descriptors_before, descriptors_after: int,
	limit, peak:                                  u64,
}
roots: tls.Root_Pool
main :: proc() {
	assert(len(os.args) == 4 || len(os.args) == 5)

	if len(os.args) == 5 {
		assert(tls.root_pool_load_file(&roots, os.args[4]).kind == .None)
	}

	defer tls.root_pool_destroy(&roots)
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
	} else if scenario == "legacy" {
		legacy(url, allocator, &record)
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
usage :: proc(scope: scopes.Scope) -> scopes.Snapshot {
	snapshot, error := scopes.snapshot(scope)
	assert(error == .None)

	return snapshot
}
context_create :: proc(limit: u64, allocator: mem.Allocator) -> Context {
	ctx: Context
	root, re := scopes.create_root({bytes = limit, streams = 2}, allocator)
	assert(re == .None)
	conn, ce := scopes.create_child(root, {bytes = limit, streams = 2})
	assert(ce == .None)
	a, ae := scopes.create_child(conn, {bytes = limit, streams = 1})
	assert(ae == .None)
	b, be := scopes.create_child(conn, {bytes = limit, streams = 1})
	assert(be == .None)
	ctx = {root, conn, a, b}

	return ctx
}
context_destroy :: proc(ctx: ^Context) {
	scopes.release_scope(&ctx.a)
	scopes.release_scope(&ctx.b)
	scopes.release_scope(&ctx.connection)
	scopes.release_scope(&ctx.root)
}
perform :: proc(
	mode, url: string,
	scope: scopes.Scope,
	allocator: mem.Allocator,
	scenario: string = "retained",
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	if mode == "curl" || scenario == "legacy" {
		response, result := surf.buffered_http_execute_owned(
			"GET",
			url,
			nil,
			nil,
			"",
			allow_http = true,
			timeout_ms = 3000,
			allocator = allocator,
			scope = scope,
		)
		return response, result.error
	}
	return surf.execute(
		{method = .GET, url = url},
		{
			allow_http = true,
			max_body_size = 1024,
			timeout = 3 * time.Second,
			scope = scope,
			tls = {root_cas = roots.roots[:roots.count]},
		},
		allocator,
	)
}
retained_limit :: proc(mode: string) -> u64 {
	body, _ := charged.allocation_cost(1024, 1)

	if mode == "curl" {
		setup, _ := charged.allocation_cost(1024, mem.DEFAULT_ALIGNMENT)
		return 65536 + setup + body + body / 2
	}

	head, _ := charged.allocation_cost(len("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n"), 1)
	table, _ := charged.allocation_cost(size_of(http.Header), align_of(http.Header))
	total := body + head + table

	return total + total / 2
}
retained :: proc(mode, url: string, allocator: mem.Allocator, record: ^Record) {
	ctx := context_create(retained_limit(mode), allocator)
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
	info, known := charged.allocation_info(chunk.allocator, raw_data(chunk.storage))
	assert(known)
	scopes.release_scope(&ctx.a)
	surf.response_destroy(&first)
	assert(usage(ctx.root).used.bytes == info.backing_bytes)
	for byte in chunk.data {
		assert(byte == 'B')
	}
	owned.destroy(&chunk)
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
legacy :: proc(url: string, allocator: mem.Allocator, record: ^Record) {
	block, _ := charged.allocation_cost(4096, mem.DEFAULT_ALIGNMENT)
	ctx := context_create(65536 + block + 512, allocator)
	binding, created := charged.create(ctx.a, {backing = allocator, metadata_allocator = allocator})
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
	previous := context.temp_allocator
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	views: [8][]byte
	count := 0
	denied := false

	for _ in 0 ..< 8 {
		bytes, result := surf.buffered_http_execute_managed(
			"GET",
			url,
			nil,
			nil,
			"",
			allow_http = true,
			timeout_ms = 3000,
			scope = ctx.a,
			allocator_scope = ctx.a,
		)
		if result.error.write_effect != .Not_Sent {
			record.calls += 1
		}

		if result.error.kind != .None {
			assert(result.error.kind == .Allocation_Failed)
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
	legacy_retry(url, &arena, managed, ctx.a, record)
	mem.dynamic_arena_destroy(&arena)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	charged.release(&binding)
	context_destroy(&ctx)
}
legacy_retry :: proc(
	url: string,
	arena: ^mem.Dynamic_Arena,
	managed: mem.Allocator,
	scope: scopes.Scope,
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
	bytes, result := surf.buffered_http_execute_managed(
		"GET",
		url,
		nil,
		nil,
		"",
		allow_http = true,
		timeout_ms = 3000,
		scope = scope,
		allocator_scope = scope,
	)
	assert(result.error.kind == .None && len(bytes) == 1024)
	record.calls += 1
}

empty :: proc(url: string, allocator: mem.Allocator, record: ^Record) {
	ctx := context_create(256 * 1024, allocator)
	response, error := perform("curl", url, ctx.a, allocator, "empty")
	record.calls += 1
	assert(error.kind == .None && len(response.body) == 0 && cap(response.body_storage) == 0)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	context_destroy(&ctx)
	// No allocation reference remains in this zero-capacity moved owner.
	chunk, taken := surf.response_take_body(&response)
	assert(taken.kind == .None)
	surf.response_destroy(&response)
	owned.destroy(&chunk)
	owned.destroy(&chunk)
}

tls_budget :: proc(url: string, denied: bool, allocator: mem.Allocator, record: ^Record) {
	conn, _ := charged.allocation_cost(size_of(tls.Conn), align_of(tls.Conn))
	flight, _ := charged.allocation_cost(tls.MAX_SERVER_FLIGHT_SIZE, 1)
	limit := u64(4 * 1024 * 1024)
	if denied {
		limit = conn + flight - 1
	}
	ctx := context_create(limit, allocator)
	response, error := perform("tls", url, ctx.a, allocator)

	if denied {
		assert(error.kind != .None && error.write_effect == .Not_Sent)
		assert(usage(ctx.root).rejected > 0)
	} else {
		assert(error.kind == .None && len(response.body) == 1024)
		assert(usage(ctx.root).peak.bytes >= conn + flight)
		record.calls += 1
	}

	surf.response_destroy(&response)
	assert(usage(ctx.root).used.bytes == 0 && usage(ctx.root).used.streams == 0)
	record.limit, record.peak = usage(ctx.root).limits.bytes, usage(ctx.root).peak.bytes
	assert(record.peak <= record.limit)
	context_destroy(&ctx)
}
