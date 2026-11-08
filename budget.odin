package surf

import http "../http"
import "core:mem"
import charged "core:mem/budget"
import resources "core:sync/budget"

@(private)
Budget_Context :: struct {
	binding:               charged.Binding,
	stream:                resources.Lease,
	coverage:              resources.Scope,
	temporary:             mem.Dynamic_Arena,
	temporary_initialized: bool,
}

// Scope/coverage handles borrow host ownership during entry. An annotation is a
// trusted host promise about an arena's backing, not inference from its pointer.
@(private)
budget_begin :: proc(
	scope, coverage: resources.Scope,
	backing: mem.Allocator,
) -> (
	Budget_Context,
	mem.Allocator,
	HTTP_Error,
) {
	if scope == (resources.Scope{}) {
		if coverage != (resources.Scope{}) do return {}, {}, budget_error(.Invalid_Config)
		return {}, backing, {}
	}
	if coverage != (resources.Scope{}) && !resources.covers(coverage, scope) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	managed_scope, managed := charged.allocator_scope(backing)
	if managed && !resources.covers(managed_scope, scope) {
		reason: resources.Error = .Invalid_Config
		if !resources.same_root(managed_scope, scope) do reason = .Foreign_Root
		return {}, {}, budget_error(reason)
	}
	if !managed && coverage == (resources.Scope{}) && .Free not_in mem.query_features(backing) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	ctx: Budget_Context
	lease, admission := resources.reserve(scope, {streams = 1})
	if admission != .None do return {}, {}, budget_error(admission)
	ctx.stream = lease
	allocator := backing
	failure: HTTP_Error
	if managed {
		ctx.binding, failure = budget_retain_allocator(backing)
	} else if coverage == (resources.Scope{}) {
		ctx.binding, failure = budget_create_allocator(scope, backing)
		if failure.kind == .None do allocator = charged.allocator(ctx.binding)
	}
	if failure.kind == .None && coverage != (resources.Scope{}) {
		retained, error := resources.retain_scope(coverage)
		if error != .None do failure = budget_error(error)
		else do ctx.coverage = retained
	}
	if failure.kind != .None {
		budget_cleanup(&ctx); return {}, {}, failure
	}
	return ctx, allocator, {}
}

@(private)
budget_retain_allocator :: proc(source: mem.Allocator) -> (charged.Binding, HTTP_Error) {
	binding, error := charged.retain_allocator(source)
	return binding, budget_allocator_error(error)
}
@(private)
budget_create_allocator :: proc(
	scope: resources.Scope,
	backing: mem.Allocator,
) -> (
	charged.Binding,
	HTTP_Error,
) {
	binding, error := charged.create(scope, {backing = backing})
	return binding, budget_allocator_error(error)
}
@(private)
budget_allocator_error :: proc(error: charged.Error) -> HTTP_Error {
	if error.kind == .None do return {}
	result := budget_error(error.budget)
	result.allocation = error.allocation
	if error.kind == .Invalid_Config || error.kind == .Invalid_Handle {
		result.kind = .Invalid_Config
	}
	return result
}
@(private)
budget_error :: proc(reason: resources.Error) -> HTTP_Error {
	kind: http.Error_Kind = .Allocation_Failed
	if reason == .Invalid_Config || reason == .Invalid_Handle || reason == .Foreign_Root {
		kind = .Invalid_Config
	}
	return {kind = kind, budget = reason, phase = .Admission, write_effect = .Not_Sent}
}
@(private)
budget_cleanup :: proc(ctx: ^Budget_Context) {
	old := ctx^; ctx^ = {}
	if old.temporary_initialized do mem.dynamic_arena_destroy(&old.temporary)
	charged.release(&old.binding)
	resources.release_scope(&old.coverage)
	resources.release(&old.stream)
}
@(private)
budget_response :: proc(ctx: ^Budget_Context, response: ^Response) {
	response._allocator_scope = ctx.coverage
	ctx.coverage = {}
}

// Called only after the context has reached its final caller-owned stack address.
// Returned temporary allocator views must not escape the blocking operation.
@(private)
budget_temporary :: proc(ctx: ^Budget_Context, allocator: mem.Allocator) -> mem.Allocator {
	assert(!ctx.temporary_initialized)
	mem.dynamic_arena_init(
		&ctx.temporary,
		block_allocator = allocator,
		array_allocator = allocator,
		block_size = 16 * mem.Kilobyte,
		out_band_size = 8 * mem.Kilobyte,
	)
	ctx.temporary_initialized = true
	return mem.dynamic_arena_allocator(&ctx.temporary)
}
