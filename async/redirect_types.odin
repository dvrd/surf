package surf_async

// Internal accepted-request handoff. Preparing is a construction/reentry guard,
// not permission to publish a Kernel request or move an incomplete target.
Redirect_Phase :: enum {Empty, Preparing, Ready}

// Move-only target custody at a stable address across physical close callbacks.
// The original Request_Handle, Scope stream lease and total deadline belong to
// the Kernel. Only the handle is copied here: no second lease is admitted.
//
// Preparing must be installed before the first arbitrary allocator callback or
// intermediate Response disposal. Ready owns both input and origin; its target
// slices never borrow the consumed Response, temporary URL or caller request.
// A destructor snapshots and clears the whole handoff before physical frees.
// Do not relocate this value while Preparing, nor copy its Ready owners.
Redirect_Handoff :: struct {
 phase: Redirect_Phase,
 // Survives session_reset_io clearing actor.request. Never use a later actor
 // mailbox's handle to resolve this already accepted request's ledger ticket.
 request: Request_Handle,
 input: Request_Owner,
 origin: Prepared_Origin,
 // First followed redirect is1; Ready is bounded by http.MAX_REDIRECTS (5).
 next_hop: int,
 // Original request's remaining finite DNS draw allowance, before reserving
 // the next hop's block. Moving a block to an actor deducts exactly once.
 queries_remaining: int,
 // Most recent validated redirect response. Fill missing error status only;
 // an ambiguous later-hop Unknown write effect must remain Unknown.
 last_status: int,
}
