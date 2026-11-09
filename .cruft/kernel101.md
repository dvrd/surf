# OKAMI-101 phase2 kernel ABI

Schema freeze for task101-05. `async/types.odin` and `async/config.odin` are the
actual schema and pure implementation. Signatures below are assigned future
phase2 implementations, not available functions or placeholders. No network
Client API, actor, scheduler registration, DNS preparation or HTTP exchange exists
in this slice. The phase3 owner can embed Kernel alongside separate actor arrays.

## Public schema and normalization

`config_normalize(Client_Config)->(Normalized_Config,Client_Error)` allocates,
retains and admits nothing; it does not inspect runtime state or read a clock.
It borrows all Config strings/slices/root objects and Scope. Root config errors
preserve `surf.config_validate`'s HTTP cause. Negative TLS handshake timeout,
negative idle/age, nonzero allocator_scope, >8 explicit resolver endpoints, and
endpoint port0 reject. Scope0 and closed-but-valid Scope metadata normalize;
actual constructor/lease admission is a separate operation. No claim of valid
roots, live Scope, valid runtime epoch or unexpired deadline follows.

Nil capacities select 32/16/8/2/32/256/128; explicit capacities use exact values.
Bounds are requests1..4096, origins1..1024, connections1..256,
connections_per_origin1..connections, waiters_per_origin0..requests,
dns_ids0..65536, work_per_resume1..4096. Zero waiters means a Preparing request
must reserve an assignable session. Zero DNS IDs allows numeric-only progress;
it does not trigger filesystem/entropy work in this pure phase.

Idle0 selects30s, max_age0 selects5min, HTTP timeout0 selects Root Surf30s,
bodylimit0 selects HTTP8MiB. Positive maximum duration values remain valid: later
deadline arithmetic must saturate rather than overflow. Lifetime is either
{epoch0,at0} or {epoch!=0,at>0}; runtime epoch/expiry checks belong to phase3.
Input HTTP configuration is preserved rather than rewritten to its defaults.

The public Client is only `{_self:^Client,_state:rawptr}`. It preserves the
original-address check without declaring a nonexistent network State. Handles
are scalar aliases; zero owner/generation invalid, and slot indices are one-based.
Generation exhaustion retires a cell permanently rather than wrapping. Client
Stats distinguishes held requests, sessions, task owners and scoped usage; its
Signal count reports fixed control cells outside Scope, never RSS.

## Concrete stable owners

Kernel is move-forbidden and self-address checked. It borrows initialized stable
Profile and Kernel_Resources through kernel destruction, stores its normalized
Config, immutable owner identity, metadata mutex, three fixed cell arrays and
three preallocated free-index stacks. `references` includes one base owner plus
out-of-lock Preparing/Returning keepalives. Neither Client header nor future
Runtime pointers are stored in detached request/result owners.

Profile owns one aligned physical storage slice containing copied ALPN/root
pointer/endpoint descriptors and strings. Checked layout arithmetic and exact
reported grants precede typed views. It owns its copied server_name and ALPN
bytes; TLS always uses the request origin hostname later. Root certificate
objects themselves remain borrowed immutable through all session TLS closes.
Profile owner_id is globally unique/nonzero; identity exhaustion fails rather
than wraps. Kernel owner_id equals its unique Profile identity; one Kernel may
use each Profile. Config equality never uses mutable root hashes or shared IPs.

Prepared_Origin owns its hostname backing independently. Origin_Key is exactly
profile_id + secure scheme + canonical validated host + effective port. Only
ASCII DNS case and default port normalize; no endpoint/certificate coalescing.
Origin_Slot owns the moved Prepared_Origin until no requests, Preparing claims,
waiters or sessions remain. Session_Model has only metadata: state, generational
origin/request association and explicit monotonic created/idle timestamps.
`reserved_from` records Free versus Idle when a session claim becomes Reserved,
so clone rollback restores an existing Idle transport rather than forgetting it.
Connecting, Busy, Idle, Retiring and Preparing Reserved session claims all consume
connection capacity. No network Task or TLS owner is hidden in this model.

Request_Owner owns one checked aligned backing containing Request descriptors,
URL/header octets and fixed body. Request_Slot owns it after commit, one stream
lease, the pending/result Response, cancellation/deadline and separate intrusive
wait/completion links. `completion_queued` is independent of terminal state.
Completion membership is removed under mutex on poll OR direct take/release;
reuse never leaves phantom nodes. Request_Disposal is a move-only detached
snapshot for frees outside mutex, including optional Origin_Disposal.
Request_Slot.returning_to distinguishes Free rollback/release from Completed
publication; Request_Disposal repeats that target for checked cleanup.
Returning slots remain occupied and hold a
Kernel reference through the last physical cleanup callback.

Every free/live index is 1..array length; zero is absent. Generation initially1;
only physical retirement makes a slot Free with generation+1. At max(u64) it
becomes Retired and is never put on a free stack. New cell admission never scans
unallocated capacity. Pool fairness may scan occupied origin/session indices only
with explicit bounded work/cursor accounting; no hidden unbounded timer/I/O work.

## Frozen phase2 handoffs

Names are package internal by convention, in package surf_async. They are real
operations to implement in the assigned modules; there are no dummy SDK bodies.
Errors use Client_Error and preserve lower cause where available. `^Owner`
parameters move/zero only on success; failed calls preserve sources. All dispose
functions zero the caller owner before invoking physical frees, then use locals.
No allocator/free, scheduler, TLS/net or user callback is called under Kernel.mu.

Task101-06, profile.odin/origin.odin (depends only on schema/core/Root Surf/HTTP):

```odin
profile_init(p:^Profile,config:Normalized_Config,allocator:mem.Allocator)->Client_Error
profile_destroy(p:^Profile)
origin_prepare(profile:^Profile,url:string,allocator:mem.Allocator)->(Prepared_Origin,Client_Error)
origin_equal(a,b:Origin_Key)->bool
origin_destroy(owner:^Prepared_Origin)
```

Profile initialization creates the nonreused identity. Origin preparation uses
existing public HTTP URL parsing and Root Surf policy; it does not resolve DNS,
open a socket or mutate Profile. Caller destroys all session owners before
profile_destroy. Rejection leaves destination zero and cleans all grants.

Task101-07, resources.odin/ownership.odin (does not call task06 functions):

```odin
resources_init(r:^Kernel_Resources,scope:scopes.Scope,backing:mem.Allocator)->Client_Error
resources_destroy(r:^Kernel_Resources)
resources_request_lease(r:^Kernel_Resources)->(scopes.Lease,Client_Error)
request_clone(request:http.Request,allocator:mem.Allocator)->(Request_Owner,Client_Error)
request_owner_destroy(owner:^Request_Owner)
kernel_init(k:^Kernel,profile:^Profile,resources:^Kernel_Resources)->Client_Error
kernel_destroy(k:^Kernel)->Client_Error
request_disposal_destroy(disposal:^Request_Disposal)
kernel_origin_retain_locked(k:^Kernel,origin:Cell_Handle,reference:Origin_Reference)->Client_Error
kernel_origin_release_locked(k:^Kernel,origin:Cell_Handle,reference:Origin_Reference)->(Origin_Disposal,Client_Error)
origin_disposal_destroy(disposal:^Origin_Disposal)
kernel_origin_cleanup_finish(k:^Kernel,origin:Cell_Handle)->Client_Error
```

resources_init uses existing Binding ABI and a supplied thread-safe individually
freeable allocator; it retains compatible managed Binding rather than nesting it.
Scope0 unmanaged accepts ordinary backing and makes no hierarchical charge claim.
Nonzero Scope requires exact compatible coverage. Response allocations retain
Binding physically after transfer independently of resources_destroy/Kernel.
request_clone validates the existing finite HTTP URL/header/body limits before
allocation, checks arithmetic and all malformed allocator grants, and never
retains a caller arena. It does not parse origin policy or call profile helpers.

kernel_init receives initialized stable borrowers, rejects duplicate/live owner
headers, and allocates exact fixed request/origin/session arrays/free stacks
outside locks. It reads Profile's frozen fields, not its functions. No tasks or
signals are created. Initial generations1; references1; free stacks prefilled.
kernel_destroy rejects any Preparing/Returning/request/session/origin owner or
extra reference; clear/snapshot before physical frees. Profile and Resources are
not implicitly destroyed by it. Their caller-controlled order is Kernel, Profile,
Resources; detached Responses retain their own allocation ownership.

Shared origin retain/release/generation bookkeeping belongs to verified task07,
so both later writers call one implementation rather than duplicating it. The
_locked helpers require Kernel.mu held, perform only checked counter/index/state
mutation, and never allocate/free or call a concurrent identity module helper.
Origin_Reference selects Request/Session/Preparing/Waiter; overflow/underflow or
stale owner rejects without mutation. Final release with all four counters0
moves Prepared_Origin into Origin_Disposal and marks the cell Returning, absent
from free stacks and lookups, with its own Kernel references keepalive. Caller unlocks, destroys detached storage, then
calls kernel_origin_cleanup_finish to advance generation/free or permanently
retire an exhausted cell. Nonfinal release returns empty disposal. Origin cleanup
finish requires the exact Returning generation and releases that origin keepalive
only after its physical free returned. request_disposal_destroy clears
its caller snapshot first, physically releases input/Response/lease/origin from
locals without accessing Kernel, then caller performs corresponding finalize
operations. Snapshot only scalar request/origin handles before destroying the
disposal (which clears them along with owners); never copy owned payloads for a
second destruction. These helpers don't depend on profile/origin functions from task06.

Task101-08, admission.odin/completion.odin (may call verified task06/07 functions,
never functions being concurrently authored by task09):

```odin
kernel_reserve(k:^Kernel,deadline:runtime_async.Deadline,lease:^scopes.Lease)->(Preparing_Request,Client_Error)
kernel_commit(k:^Kernel,preparing:Preparing_Request,input:^Request_Owner,now:runtime_async.Deadline)->Client_Error
kernel_rollback(k:^Kernel,preparing:Preparing_Request)->(Request_Disposal,Client_Error)
kernel_cancel(k:^Kernel,request:Request_Handle)->Client_Error
kernel_close(k:^Kernel)->Client_Error
kernel_stage(k:^Kernel,request:Request_Handle)->(Request_Stage,Client_Error)
kernel_begin_complete(k:^Kernel,request:Request_Handle,response:^surf.Response,error:surf.HTTP_Error)->(Request_Disposal,Client_Error)
kernel_cleanup_finish(k:^Kernel,request:Request_Handle,now:runtime_async.Deadline)->(Request_Disposal,bool,Client_Error)
kernel_poll(k:^Kernel)->(Completion,bool)
kernel_take(k:^Kernel,request:Request_Handle,destination:^surf.Response)->Client_Error
kernel_release(k:^Kernel,request:Request_Handle)->Client_Error
```

reserve moves an already acquired single request lease, counts Preparing and a
keepalive. It does not accept a request or publish a completion. Caller then
obtains a pool claim and clones outside locks. commit verifies matching live pool
claim, close/cancel and caller-supplied current epoch/cutoff before moving input;
close/expiry rejection leaves input untouched and requires rollback. No public
request is accepted until commit. Rollback removes any claim using the
frozen session/queue metadata and verified task07 origin-ref helpers, not
a dependency on concurrent task09 code. A Reserved session claim restores its
reserved_from Idle/Free state. Rollback enters Returning targeting Free and
returns detached physical owners; caller destroys them and calls cleanup_finish.
Prepared-origin physical cleanup is detached outside locks. A rejected admission
gets no completion. Active cancellation only sets the flag; pure kernel cannot
claim to have canceled I/O. Coordinator/actor later drains and calls begin_complete.

begin_complete requires accepted queued/active work after its actor callbacks
have drained. It moves a successful Response into the slot, snapshots input and
stream lease in Request_Disposal, and enters Returning targeting Completed with
keepalive. Caller invokes request_disposal_destroy outside all locks, finalizes
any origin ticket, obtains a fresh current Deadline from the same runtime epoch,
and calls cleanup_finish. Only then may completion become observable.

cleanup_finish checks the stored original cutoff, cancellation and epoch again
before terminal success. Cleanup never extends the cutoff. If an otherwise
successful Response must now fail, it records the appropriate terminal cause,
detaches that Response into another Request_Disposal and returns done=false;
the caller physically disposes it and repeats with fresh now. Existing primary
HTTP failure is preserved. No destructor or callback runs while locked, and no
failure result retains a hidden successful Response. Once owners have drained,
finish returns done=true and either enqueues Completed exactly once or increments
generation/frees the rollback/release slot according to returning_to. Epoch
mismatch cannot validate success. A stale/wrong-target finish rejects unchanged.

Completion release/take similarly unlinks first, detaches owners, disposes outside
lock and only then advances generation through the same cleanup finalization.
take requires terminal success and empty destination, preserving both on reject.
Their synchronous wrappers can finish Free-target cleanup with now={} because
no successful request completion is being validated; they must still use the
same checked Returning machinery. poll removes just scalar notification and
retains slot/result. close rejects future reserve/commit and marks accepted work
canceled; it does not pretend callbacks or external sessions already retired.

Task101-09, pool.odin/queue.odin (may call verified task06/07 functions, never
functions being concurrently authored by task08):

```odin
pool_reserve(k:^Kernel,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error)
pool_dispatch(k:^Kernel,work:int,now:i64)->(Assignment,int,Client_Error)
pool_session_state(k:^Kernel,session:Cell_Handle,state:Session_State,now:i64)->Client_Error
pool_retire(k:^Kernel,session:Cell_Handle)->Client_Error
pool_idle_candidate(k:^Kernel,work:int,now:i64)->(Cell_Handle,int,Client_Error)
```

pool_reserve atomically finds/creates exact origin and reserves either an Idle/new
session or finite FIFO waiter; moves Prepared_Origin only if creating an origin.
Existing equal-origin success leaves the redundant candidate for caller cleanup.
With waiter0 it fails unless a session claim is held throughout clone commit.
The claim is stored in the same Preparing slot; commit/rollback manipulate that
metadata under the same mutex with no cross-stream function dependency.
pool_dispatch takes accepted queued work only, round-robin by origin and FIFO
within it; assignment changes Request_Slot to Active and Session to Busy exactly
once. Work includes every examined origin/session, and persistent cursors permit
work1 progress. pool_session_state validates the transition, keeps Retiring in
capacity, never claims physical callback retirement. pool_retire is allowed only
after the current transport generation's TLS/raw operations and accepted callbacks
physically drained. The persistent session Task may remain registered and own the
next transport generation; its on_done is NOT required for per-transport reuse.
Task retirement is a separate Client quiescence condition. pool_retire releases
association metadata using the verified task07 origin-ref helpers, disposes empty origin
storage outside locks and finalizes its ticket, then advances session generation.
The session remains Retiring until physical cleanup/finalization completes. Idle
selection respects immutable timeout/max_age using saturating comparisons and does not itself close transports.

## Integration and review gates

All kernel functions verify original self address, owner and generation before
mutation; aliases of live owners are invalid copies. Publicly constructible
scalar handles alone prove no admission. Resource allocation, clone cleanup,
returned Response allocator lifetime, partial grants and free callbacks require
task07 independent probes. Preparing close races/FIFO take-without-poll and
bounded pool/work fairness require tasks08/09 model and paired sanitizers.

No phase2 result proves DNS/TLS/HTTP1 persistence, wake retirement, async Client
thread safety or full OKAMI-101 acceptance. Freeze phase3 resolver snapshot,
coordinator/actor integration and public Client methods only after this kernel's
independent model/source gates. Runtime/lifetime checks, actual callback counts,
DNS bank and Signals are added in that phase rather than inert fields here.

Phase3 Client init must also support a Runtime already running. Prepare all arrays,
immutable config and resolver/DNS state before registering any Task. A real
Constructing/publication gate prevents callbacks from driving partial State; each
successful registration retains State through on_done. Runtime.shutdown or a later
registration failure may cancel this partial set, so abort must preserve State
until every registered callback retires. Publish initialized Client only after
final commit; do not invent an init-before-Runtime.start restriction. This is a
network-freeze obligation, not an inert Task registration facility in this kernel.
