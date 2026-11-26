package surf

import "core:mem"
import "shared:async"

Budget_Context :: struct {
	binding:               async.Budget_Binding,
	stream:                async.Budget_Lease,
	coverage:              async.Budget_Scope,
	temporary:             mem.Dynamic_Arena,
	temporary_initialized: bool,
}

// Scope/coverage handles borrow host ownership during entry. An annotation is a
// trusted host promise about an arena's backing, not inference from its pointer.
budget_begin :: proc(
	scope, coverage: async.Budget_Scope,
	backing: mem.Allocator,
) -> (
	Budget_Context,
	mem.Allocator,
	HTTP_Error,
) {
	if scope == (async.Budget_Scope{}) {
		if coverage != (async.Budget_Scope{}) {
			return {}, {}, budget_error(.Invalid_Config)
		}
		return {}, backing, {}
	}
	if coverage != (async.Budget_Scope{}) && !async.budget_covers(coverage, scope) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	managed_scope, managed := async.budget_allocator_scope(backing)
	if managed && !async.budget_covers(managed_scope, scope) {
		reason: async.Budget_Error = .Invalid_Config
		if !async.budget_same_root(managed_scope, scope) {
			reason = .Foreign_Root
		}
		return {}, {}, budget_error(reason)
	}
	if !managed && coverage == (async.Budget_Scope{}) && .Free not_in mem.query_features(backing) {
		return {}, {}, budget_error(.Invalid_Config)
	}
	ctx: Budget_Context
	lease, admission := async.budget_reserve(scope, {streams = 1})
	if admission != .None {
		return {}, {}, budget_error(admission)
	}
	ctx.stream = lease
	allocator := backing
	failure: HTTP_Error
	if managed {
		ctx.binding, failure = budget_retain_allocator(backing)
	} else if coverage == (async.Budget_Scope{}) {
		ctx.binding, failure = budget_create_allocator(scope, backing)
		if failure.kind == .None {
			allocator = async.budget_allocator(ctx.binding)
		}
	}
	if failure.kind == .None && coverage != (async.Budget_Scope{}) {
		retained, error := async.budget_retain_scope(coverage)
		if error != .None {
			failure = budget_error(error)
		} else {
			ctx.coverage = retained
		}
	}
	if failure.kind != .None {
		budget_cleanup(&ctx)
		return {}, {}, failure
	}
	return ctx, allocator, {}
}

budget_retain_allocator :: proc(source: mem.Allocator) -> (async.Budget_Binding, HTTP_Error) {
	binding, error := async.budget_retain_allocator(source)

	return binding, budget_allocator_error(error)
}
budget_create_allocator :: proc(
	scope: async.Budget_Scope,
	backing: mem.Allocator,
) -> (
	async.Budget_Binding,
	HTTP_Error,
) {
	binding, error := async.budget_binding_create(scope, {backing = backing})

	return binding, budget_allocator_error(error)
}
budget_allocator_error :: proc(error: async.Budget_Allocator_Error) -> HTTP_Error {
	if error.kind == .None {
		return {}
	}
	result := budget_error(error.budget)
	result.allocation = error.allocation

	if error.kind == .Invalid_Config || error.kind == .Invalid_Handle {
		result.kind = .Invalid_Config
	}

	return result
}
budget_error :: proc(reason: async.Budget_Error) -> HTTP_Error {
	kind: async.Http_Error_Kind = .Allocation_Failed

	if reason == .Invalid_Config || reason == .Invalid_Handle || reason == .Foreign_Root {
		kind = .Invalid_Config
	}

	return {kind = kind, budget = reason, phase = .Admission, write_effect = .Not_Sent}
}
budget_cleanup :: proc(ctx: ^Budget_Context) {
	old := ctx^
	ctx^ = {}
	if old.temporary_initialized {
		mem.dynamic_arena_destroy(&old.temporary)
	}
	async.budget_binding_release(&old.binding)
	async.budget_release_scope(&old.coverage)
	async.budget_release(&old.stream)
}
budget_response :: proc(ctx: ^Budget_Context, response: ^Response) {
	response._allocator_scope = ctx.coverage
	ctx.coverage = {}
}

// Called only after the context has reached its final caller-owned stack address.
// Returned temporary allocator views must not escape the blocking operation.
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

