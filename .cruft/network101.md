# OKAMI-101 network phase and remaining acceptance

Review draft for task101-11. No implementation is enabled by this document until
root commits the reviewed plan and records Linear/continuation. Phase2 kernel
is committed at22d7c93. Original five criteria in spec101.md remain open. This
phase provides a real fixed-body asynchronous HTTP/HTTPS client with persistent
sessions; full redirect integration and final acceptance remain an explicit next
phase, not an omitted requirement. Blocking Surf/file uploads and legacy curl
stay unchanged; HTTP2integration102 and streaming104 remain separate.

## Decomposition and dependency direction

Use optional `surf/async/exchange` (package surf_exchange), a deep HTTP1 exchange
module consuming only generic `net.Async_Connection`, caller clock samples and
owned allocator. It imports Root Surf Response/error policy and existing HTTP/v1
encoders/head/chunk/reuse primitives, never the async Client/kernel/actor. Root
Surf does not import it. The exchange schema and actual engine are independently
verified before a session actor calls them. There is no cyclic actor/exchange
stub or blocking execute on an async worker.

Next freeze NEW async/network_types.odin and .cruft/network-abi101.md: concrete
Client_State, Session_Actor, network request metadata and callback signatures.
Client_State embeds the already frozen Kernel by value at a stable heap address.
Do not modify async/types.odin, whose two schema ownership slots are consumed.
Bootstrap, coordinator and actor depend on this actual frozen State ABI. Public
Client wiring waits until all three implementations are available; bootstrap is
a real allocation/preparation module, not a fake successful client_init.

Phase3 has20 tasks with API/test ownership separated and <=5files each. Generic
core resolver preparation, async task-group prerequisites and exchange schema can
proceed independently. Later
bootstrap and exchange verification can proceed independently, then coordinator
and actor are separate verified modules before public wiring. Every shared-file
integration edit gets an explicit serialized owner; no undeclared concurrent
module calls. New source files are primary-owned once; phase4 integration may
use second ownership slots where explicitly listed below.

## First prerequisite: owning core/net bounded resolver snapshot

The actual dns_os.odin has file-private loaders. Old load_resolv_conf and
load_hosts read/allocate without the required finite caps; merely exporting
those calls is insufficient. Add new public API in owning core/net, preserving
all old entrypoints/behavior. Implement bounded reads/parsing in core/net using
existing address/token primitives rather than copying a resolver into Surf.
No new worker file/entropy I/O or global DNS configuration mutation. Actual
legacy parse_hosts/parse_resolv_conf ignore some append failures and can orphan
allocations. A bounded wrapper cannot silently accept their partial output: use
one bounded failure-latching scratch arena for EVERY parser allocation, reject
on ANY latched allocation failure and whole-free scratch, or first fix the
checked parser in a separately verified owning core task. Add failure injection
at every parser allocation, not only final snapshot clone. No OOM-as-empty-policy
fallback is accepted.

Proposed public preparation contract, frozen by its API task before consumers:

```odin
Resolver_Snapshot_Limits :: struct {
 file_bytes, line_bytes, host_entries, host_name_bytes, name_servers:int,
}
Resolver_Snapshot_Options :: struct {
 // nil selects a copied view of dns_configuration paths. Explicit empty is not system default.
 name_servers:[]Endpoint,
 resolv_conf_path, hosts_file_path:string,
 limits:Resolver_Snapshot_Limits,
}
Resolver_Snapshot :: struct { /* stable owning self/header + nameservers/hosts/octet backing */ }
Resolver_Snapshot_Error :: struct {kind:Resolver_Snapshot_Error_Kind, allocation:mem.Allocator_Error, io:os.Error}
resolver_snapshot_prepare(s:^Resolver_Snapshot,options:Resolver_Snapshot_Options,allocator:mem.Allocator)->Resolver_Snapshot_Error
resolver_snapshot_name_servers(s:^Resolver_Snapshot)->([]Endpoint,bool)
resolver_snapshot_lookup(s:^Resolver_Snapshot,host:string,dst:[]Endpoint,port:int)->(count:int,found:bool,error:Resolver_Snapshot_Error)
resolver_snapshot_destroy(s:^Resolver_Snapshot)
```

The API task must replace the illustrative owner/comment with actual types and
precise errors before its independent tests. Suggested default hard caps:
file_bytes256KiB per file, line_bytes4KiB, host_entries1024, total hostname
bytes64KiB, name_servers8. At least these physical bounds must be finite before
any read/growth; cap+1 detection rejects overflow rather than truncating trusted
policy. Checked raw allocator grants, zero/snapshot before physical disposal,
atomic failure with no live destination and deterministic literal-file tests
are required. Root may tighten these values during this prerequisite review.
Nameserver ports1..65535; supported platform preparation matches actual core
support, with explicit Unsupported elsewhere. This phase's executable evidence
is Darwin only unless another platform is actually run.

Explicit nonnil name_servers bypass system resolver/hosts files. Explicit nonnil
empty rejects NoServers/InvalidConfig; it must not become system DNS because
Profile currently canonicalizes zero-length slices to nil. Bootstrap inspects
ORIGINAL Normalized_Config before profile cloning and prepares/copies a resolver
snapshot from that original choice. dns_ids0 performs no DNS file preparation
and supports numeric requests; accepted named requests must fail/park truthfully
under the documented bank policy, never silently invoke blocking OS fallback.
OS-default snapshot copies bounded nameservers/hosts off workers once. Hosts
lookup is local immutable data, no network. Default file failure/empty-server
semantics must be explicit in the owning core task; no invented fallback.

## Deep HTTP1 async exchange contract

Proposed types/functions for task13 schema freeze (not available yet):

```odin
Exchange :: struct { /* concrete stable state, two caller-owned async operations, fixed buffers */ }
Options :: struct {body_limit:int, informational_limit:int}
Budget :: struct {at:i64, wall:time.Time}
Notify :: struct {data:rawptr,wake:proc(rawptr)}
Drive_Status :: enum {Waiting,Progress,Done}
Drive_Result :: struct {status:Drive_Status,work_used:int,error:surf.HTTP_Error,reuse_eligible:bool}
exchange_init(x:^Exchange,options:Options,allocator:mem.Allocator)->surf.HTTP_Error
exchange_begin(x:^Exchange,stream:net.Async_Connection,request:http.Request,budget:Budget,notify:Notify)->surf.HTTP_Error
exchange_drive(x:^Exchange,now:i64,cancelled:bool,work:int)->Drive_Result
exchange_take(x:^Exchange,destination:^surf.Response)->surf.HTTP_Error
exchange_quiescent(x:^Exchange)->bool
exchange_reset(x:^Exchange)->surf.HTTP_Error
exchange_destroy(x:^Exchange)->surf.HTTP_Error
```

A schema task concretizes all state fields before the implementation task. Begin
validates/snapshots request metadata and retains a borrowed fixed Request.body
through the last accepted write callback; actor owns that cloned Request_Owner.
One request per exchange, no pipelining and no user completion callback. Returned
responses move only through take to an empty destination. Result physical allocator
retains Binding independently; no Client/Task/Exchange pointer in its disposal.
The engine never closes the connection; actor owns close/drain and reuse decision.

Read into a stable buffer >=tls.MAX_PLAINTEXT_SIZE(16KiB); the initial exact size
is16KiB. Separate bounded header scratch up toHTTP.MAX_HEADER_SIZE16KiB. Use
request_encode_profile Keep_Alive, response_header_decode/apply_method,
Chunk_Decoder and response_reuse_allowed. Do not add a second framing parser.
Handle at most Root Surf's existing informational bound, reject101; support
length/chunked/trailers, HEAD/204/304 and EOF-framed nonreusable responses. Copy
headers into managed owned backing before scratch reuse; body storage bounded
by the same configured limit on every response. Detect malformed/truncated/body
limit and same-read surplus bytes. Every accepted request write completes before
reuse, including zero-body framing. An ambiguous write is never retried.

Read/write callbacks only capture terminal count/error and wake the owning actor
using a retained internal notification. They run on the stream owner loop,
perform no Client/kernel publication and return without accessing callback state
after notifying a possibly reentrant owner. Notify may enqueue/wake, not destroy
an Exchange with pending operations. Cancel requests cancellation of accepted
operations, keeps buffers/operations through callbacks, and gates buffered-success
publication by fresh now/cancel checks. No fake immediate callback on rejection.
Drive/CPU bounds are truthful: per-call work is finite transitions/byte chunks,
allocator/TLS crypto itself is not preemptible; check cutoff after expensive work.
No callback or allocator operation under Client/Kernel mutex.

Budget.at is the retained monotonic cutoff, wall is the actor's stable adapter
wall-budget mapping for submitted operations. Engine rejects nonprogress counts,
uses original cutoff through every header/body operation, and never samples wall
time to extend it. Actor performs runtime epoch/budget_error checks after adapter
jobs and before taking/publishing success. Done requires accepted read/write
callbacks drained. reuse_eligible only certifies HTTP boundary+empty lookahead;
actor separately proves TLS/raw live-operation idle, pending jobs/callbacks drained,
no accepted idle read and immutable origin/profile match. Same-read surplus
retires; separate encrypted idle-record/KeyUpdate policy has an explicit test gate
and must not access private TLS fields or pretend metadata proves transport health.

## Network State, preparation and task publication

New Client_State owns stable Kernel_Resources, Profile, Kernel, prepared resolver,
DNS ID ring, per-session Actor/Task arrays, coordinator Task, retained Signals,
network request bookkeeping and references. Client header remains the original
{self,opaqueState} ABI; no new network fields in frozen Kernel/types. Types task
freezes actual original-address/constructing/closing/published flags and counters,
network mutex vs Kernel.mu lock order, typed return/disposal snapshots and all
handoff signatures. The coordinator owns Kernel operations; actor completions
must use begin_complete→physical cleanup→fresh cleanup_finish exactly as verified.
If both locks are needed, freeze one order and never acquire them inversely.
Prefer one metadata critical section and detached command snapshots.

Resource bootstrap cannot move a self-guarded Kernel_Resources from a stack
local into Client_State. Before typed State construction, reserve its full raw
backing lease under configured Scope with an ordinary compatible backing, OR use
a covered managed allocation with no duplicate charge. Validate exact raw grant,
length/alignment/error before cast. Initialize Resources in final stable State,
then Profile/Kernel/Actor arrays. Zero/snapshot and retain State while freeing
outside locks; no custom allocator/free/user callback under mutex. Returned
Responses retain compatible core managed allocation Binding until actual free.
Scope0 preserves unmanaged compatibility. Existing signal.create heap cells are
fixed bounded metadata outside Scope and reported separately, not hidden as full
physical-scope coverage. Roots/certificate data remain borrowed immutable until
all session TLS-close callbacks drain. No caller arena retained.

Prepare all resolver files, initial trusted DNS entropy, fixed buffers and config
snapshots before Task registration. Init rejects worker context if it needs file
or entropy preparation. Register coordinator plus one fixed Task/session, maximum
connections+1; each successful registration retains State through on_done. A
Constructing gate makes callbacks on an already-running Runtime do no network
work until final commit. Partial registration failure or Runtime.shutdown marks
abort, drains that registered subset and publishes no usable Client when atomic registration itself fails; fixed storage
and construction ref survive every on_done. The reviewed task-group prerequisite
below makes this failure synchronous with no opaque Pending owner. Successful
group registration commits a real Client even if concurrent Runtime.shutdown has
already marked it Closing; its prepared state/registered refs remain valid and
normal close/quiescent/destroy applies. Runtime start/join/destroy remain controller-serialized with Client init/destroy
and prestart group retirement. shutdown may race producers normally; this does
not promise arbitrary concurrent start/destroy/registration. No arbitrary
requirement that init precede Runtime.start.

Construction ownership BECOMES the Client base on publication and is not dropped;
only Client.destroy releases this base. Each registered Task holds an additional
reference through its final on_done access. Never free a Task in resume: only
on_done or after callback retirement. The session must latch physical close and
callback-drained facts BEFORE returning Done: scheduler clears current_task
before on_done, so adapter drive/quiescent/TLS APIs are invalid there. on_done
detaches Signals, records final accounting then drops its registration ref and
returns without further State/Task access. Shutdown stops new external wakes, so
on_cancel uses bounded Yield/drain and checks state directly rather than waiting
forever for a rejected Signal wake. After all Tasks retire/runtime joins, public
poll/take/release/destroy use only retained State/owners, never dead Runtime.
Quiescence includes task registration/on_done, callbacks, Preparing and Returning;
held terminal result handles do not prevent quiescence but do prevent destroy.
Existing Runtime.destroy before start invokes on_done synchronously WITHOUT
on_cancel. The first/last unstarted callback paths mark Client Closing, detach
signals and cancel/finalize queued no-I/O Kernel owners without Task/TLS/adapter
calls. The last registered witness clears Runtime before it can die. Public clock
reads capture deadline_after while State.mu protects this registered witness, or
use a separately validated stored clock mapping. Never check count, unlock and
then dereference Runtime; last on_done uses the same mutex for witness removal.
Scheduler/signal notifications remain outside State/Kernel mutexes.

## DNS bank, coordinator and session actors

DNS bank is a fixed ring of trusted host-prepared draws, copied on refill outside
worker entropy. Each reserved draw is consumed at most once; release discards
unused reserved draws rather than recycling private Query state. Names get a
bounded per-query block (up to16 entries, at least1), with max_queries equal to
that supplied finite block and an explicit finite TOTAL send/query budget across
families/restarts (proposed32, schema task freezes exact limit). Preserve Root
resolve_endpoint_until's preference: A_Only first, then AAAA_Only only if needed;
do not use Both_A_First which always needs a second family and clears prior
results on a1-ID Limit. Capacity1 can serve direct A success; alias/multi-query
quota exhaustion is a real typed bounded failure, never an infinite restart or
fabricated fallback success. Any fallback uses fresh draws and original cutoff.

Bank empty parks named requests as Awaiting_DNS_IDs without holding unopened
physical sessions. Reserve IDs before granting a new named Free-session claim;
otherwise use an unassigned bounded waiter claim. Healthy same-origin Idle reuse,
numeric hosts and prepared hosts entries bypass DNS/bank. Refill reserves a block
before making a parked request dispatchable. Caller/actor synchronization for
these block views is frozen in network-abi101.md. A waiter cap0 may reject such
admission with Capacity; it must not bypass configured queue limits. Idle or
numeric work on other origins stays eligible rather than losing all session
capacity to names that cannot query. dns_ids0 never reads DNS files; names may
remain in bounded queue until total deadline/cancel, with no invented fallback.
Refills reject oversized/closed sources atomically and preserve source; no worker
prepare_dns_ids, random-ID reuse, derived PRNG or extra thread.

Coordinator Task has its own timer for queued expiry, idle_deadline and fairness;
it does not call connection.drive/DNS/TLS or overwrite session timers. It uses
verified bounded pool_dispatch/idle scans with dirty-pass semantics and fresh
clock samples. Session actor holds its fixed pinned Task/Executor across physical
transport generations. An assignment snapshot includes Request_Handle and
contextual Session handle; actor validates generation before using it. New dial
uses existing DNS_Query/DNS_Connect, then numeric TCP, async/connection Executor
and coreTLS.Async_Conn on that actor only. HTTP plain requests use raw async
stream; HTTPS uses TLS async stream with origin hostname, immutable roots and
http/1.1 ALPN. No request-thread socket driving or general blocking executor.

Idle carries no pending raw/application read or queued adapter job. The old
request cap is allowed to expire while healthy Idle; do not call old-cap
budget_error/drive to turn that into a new request failure. The next request
installs its fresh retained cap via set_request_budget, which explicitly allows
replacing an expired old request while preserving Client lifetime. Coordinator
idle/lifetime timers are independent from the completed request cutoff.

Executor immutable init cap is Client lifetime, not requestA cutoff. Install
request cap with set_request_budget only after operations/jobs are quiescent;
retain through cleanup and rotate only for a genuinely idle next exchange.
`connection.quiescent` specifically means CLOSED, not live idle. Healthy reuse
uses known accepted Exchange/TLS application operations plus successful live-idle
set_request_budget checks on the owning Task; never call quiescent as proof of
healthy active transport reuse. The
actor passes the same original monotonic cutoff and capped setup cutoff through
DNS/TCP/TLS/HTTP. TLS crypto is synchronous nonpreemptible; post-work cutoff check
prevents late success. A request cancel sets only its flag and wakes owner;
never async.cancel the persistent Task. Ambiguous/canceled/EOF/error transport
retirement drains accepted operations and physical close before completion.
Healthy connection may Idle only after full HTTP boundary, no lookahead or
accepted read, all TLS/application callbacks and executor jobs drained. TLS close
submitted once; close_notify Timeout under expired cap is allowed if physical
close+TLS-close callback+adapter quiescent complete. Never extend cap for close or
overwrite primary HTTP failure. Separate transport generation retirement from
persistent Task on_done. After TLS-close callback, closed adapter.quiescent and
retirement of ALL old interface copies/exchange operations, the caller-owned
Executor/Transport/TLS values may be zeroed at their SAME stable addresses and
initialized again on the SAME pinned Task with unchanged Client lifetime. This
is a whole closed-owner generation reset, not private-field introspection or a
live-stream budget escape. Existing pin_current_task accepts the already pinned
worker. An actual paired same-Task successive-physical-generation/latecallback
test is mandatory; only an actual failed proof can justify an additive reset API.
Idle invalidity never transparently replays a request.

## Public wiring and first native boundary

Only task19 defines real client_init/submit/cancel/stage/poll/take/release/refill/
close/quiescent/stats/destroy from session101.md. No dummy native functions are
published earlier. Public submit clones Request and starts total cutoff before
copy/admission. Preparing holds out-of-lock State ref and session/waiter claim;
close/expiry before commit rejects without completion and leaves source owned.
Clients can be called by concurrent producers via bounded metadata operations;
all scheduler wakes, allocator and physical disposal happen outside locks.
One terminal notification, no duplicate callbacks, completion FIFO direct-take
unlink and late Response owner behavior remain verified kernel contracts.

For this first native phase only, client_init explicitly rejects max_redirects>0
with Invalid_Config. It does not silently ignore redirects. This is temporary
feature gating, not full101 acceptance or a narrower spec. Blocking Surf redirect
behavior remains unchanged. A phase4 reviewed API removes the gate only together
with real same-deadline redirect/requeue behavior below.

Task20 actual public native smoke drives owned fixture CONTRACT.md endpoints via
Client APIs, not private Kernel injection: HTTP/TLS GET/HEAD/POST, repeated
peer-observed connection ID and requestB afterA's old cutoff, copied request
inputs, length/chunk/trailers/interim/EOF/close/malformed/truncated/surplus,
one-worker held DNS/TLS/body with unrelated cheap progress, cancellation and
queue/bank-empty expiry, scope/heap/FD retirement. Literal fixture traces report
actual requests/completions/ALPN/thread counts. ASan+TSan and standalone blocking
consumers required; fixture preparation's native_execution_count0 is never reused
as proof. New native fixture source stays in tests/testdata, runtime code has no
peer-specific branches.

## Concrete follow-up phase4 before full101 closure

Phase4 must be frozen/committed separately (<=20 tasks) after this public path is
source-bound and reviewed. Proposed bounded12-task follow-up, each<=5files:

1. Accepted-hop requeue API: NEW async/requeue.odin and async/redirect_queue.odin;
   pool.odin/queue.odin ownership slots are consumed by phase3 integration. Preserve Request handle, original deadline,
   lease and terminal-once ownership while atomically moving origin/session refs;
   do not fake an unaccepted Preparing request or reset the request timeout.
2. Independent requeue model tests: origin/session exhaustion, same/cross origin,
   close/cancel/expiry during moved URL allocation, FIFO and completed owners.
3. Redirect driver: new async/redirect.odin, second network_types.odin, session.odin
   and client.odin integration (<=4files). Reuse Root Surf execute_redirect,
   redirect_origin_safe/redirect_url; fixed original body stays owned, temporary
   URL/header owners bounded and disposed outside mutex. Each intermediate body
   observes same size limit; max5 hops; preserve existing method/cross-origin
   credentials/secure-downgrade policy. Remove max_redirects gate only here.
4. Public redirect test host+literal peer+runner (<=3files): 301/302/303/307/308,
   cumulative cutoff, loops, unsafe origin/header/body ownership and no ambiguous
   request replay. Original fixture currently covers only307: extend explicit
   owned fixtures and do not infer other status coverage.
5. Complete identity/reuse matrix: independent origins/ports/profile trust/ALPN,
   DNS alias sharing IP, roots borrowed lifetime and new Client rotation, HTTP1.0,
   stale sockets, separate TLS surplus and KeyUpdate/close/callback retirement.
6. Cancel/deadline matrix: every queue/DNS/TCP/TLS/write/read/body/redirect phase,
   all actors parked and bank empty, late success gate and one-worker independent
   cheap request progress. Actual phase traces, original cutoff comparison.
7. Multithread producer/result/close/Runtime.shutdown races and bounded fairness;
   no Task cancellation for one request, no wake-on-dead Runtime after on_done.
8. All raw grant/admission/partial-registration failures, closed managed source,
   constructor/clone/Response disposal callbacks physically freeing headers, held
   results after Client/Runtime and real heap/scope/FD cleanup.
9. Standalone final native consumer and unchanged blocking/legacy consumer gate,
   dependency closure+source/compiled/copied SHA maps and sanitizer executables.
10. Independent release runner with required matrix flags/offline validation and
    negative controls; no perf/production-scale claim from timing fixtures.
11. Crossreview every acceptance criterion against actual evidence; unresolved
    source findings get scoped second-owner fixes and re-bound affected gates.
12. API/README/results, local owning commits then Linear/continuation readback.

Ownership slots reserved: current frozen Kernel/types never changed; phase3
network_types gets one schema owner then phase4 redirect integration second;
phase3 session/client implementation gets one owner then redirect integration
second. pool/queue task09 first owner, phase3 coordinator eligibility integration second;
phase4 requeue uses NEW modules and shared verified helpers without a third edit.
Core resolver helper/test ownership separate; old core resolver APIs unchanged.
All extra fixes/handoffs must be explicitly planned rather than bypassing owner
limits or claiming a no-op path completed a criterion.

Full criterion map: asynchronous owned response/cancel/deadline = phases3real
exchange+actor/public,4lateowner/cancel/races; bounded trust/origin pool = phase2
model+phase3reuse+phase4identity; independent stalled caller progress = phase3
smoke+phase4fulloneworker matrix; Saba independence/service Client = optional
subpackage+native/legacyconsumer closure; original cutoff through every redirect,
body and cleanup = phase3 retained budget+phase4 real redirect/requeue and exact
cumulative phase traces. Full101 stays InProgress until every criterion verified.


## Repository/toolchain preparation and current review points

The proposed owning core worktree is .webtools-worktrees/surf101/odin, preserving
existing canonical/native133 work. Root creates/selects it before task12 and
merges its repository mapping into the plan index. Use the source-matched LLVM22
compiler with ODIN_ROOT=WEBTOOLS_CORE for EVERY new-core consumer, and pass
--core-root/--shared-root to subprocess runners. Reports bind the selected core
source and actual compiler digest; never silently compile against canonical core
when exercising an uncommitted snapshot API. Planned new directories are listed
in phase3 metadata for root preparation/plan-validator registration.

## Reviewed atomic task publication prerequisite

Add public owning shared/async API with separate paired verification BEFORE
network State/bootstrap use:

```odin
register_group(r:^Runtime,tasks:[]^Task)->Error
retire_group_unstarted(r:^Runtime,tasks:[]^Task)->Error
```

register_group preflights all task pointers/resume functions, uniqueness,
registration state, scheduler capacity and stopping under Scheduler.mu. It
allocates nothing, changes all tasks or none, and initially leaves tasks Waiting.
Extract/reuse existing private register_locked implementation rather than duplicate
registration behavior. Freeze finite group length against runtime capacity; Client
uses at most257. A rejected group gets no callback and retains every caller owner.

retire_group_unstarted applies only when runtime has never started/is not starting.
Under existing reactor→scheduler lock order it preflights the whole group, removes
only its registered Waiting/Queued members (including shutdown-queued prestart
members), closes attached I/O using existing reactor cleanup, and returns ownership
WITHOUT on_done. Existing unregister semantics remain unchanged. Started runtime
rejects this operation. Ready queue removal preserves unrelated groups. Caller
manually releases each returned registration reference exactly once.

Document/test additive signal.create preparation for an unregistered but stable
target (implementation currently requires only nonnil Runtime/Task): wake returns
false until registered; target/runtime are borrowed; detach before freeing either.
This permits all fallible Signal allocation before atomic group publication.
All other existing Signal behavior stays compatible.

Client prepares State/config/files/entropy/all Signals first, prearms one State
reference per group member plus construction owner, then calls register_group.
Group failure has registered NONE, so releases the prearmed refs and synchronously
frees all prepared state with zero Client. Group success publishes the initialized
Client with its retained base and only then wakes tasks; a concurrent shutdown may run ready prepared
on_cancel/on_done and mark Closing before return, but cannot execute unready state
or free the construction owner. A successful init can return an already Closing
Client due to shutdown; it remains a valid cleanup owner, not failed-init Pending.

Client.close before Runtime.start uses retire_group_unstarted, detaches Signals,
manually drops returned registration refs, cancels/completes queued model work and
releases resources without waiting for nonexistent workers. Normal started close
uses cancellation/drain/on_done. retire_group_unstarted rejects starting/started
under Scheduler.mu without mutation; Pending/AlreadyStarted does NOT prove
quiescence. If Runtime.start fails thread creation after STARTING won, later
Client.close/destroy retries unstarted retirement or Runtime.destroy's synchronous
on_done fallback completes ownership. Never infer drain from the failed start.
Distinguish unregister ownership return from callback retirement; never count
both. After join/on_done no API accesses Runtime.
Paired tests must exercise prestart/running success, capacity/duplicate rejection,
shutdown races, Runtime.destroy before start with accepted queued requests,
Runtime.start ThreadCreationFailed/retry, unrelated tasks, IO/ready cleanup and
exact callback/ref counts.

## Coordinator integration handoff requiring second pool ownership

Task17 also serially owns SECOND edits to pool.odin/queue.odin, explicitly bounded
at4files total. Preserve the EXACT existing pool_reserve callable type. Add
pool_reserve_policy(k,preparing,origin,now,allow_new:bool) as a separate function;
the old pool_reserve wrapper calls it with true. allow_new=false may claim
healthy same-origin Idle but forbids an unopened Free-session claim and otherwise
uses configured waiter capacity. Extend dispatcher
eligibility to skip Awaiting_DNS_IDs stage, preserving FIFO within eligible origin
policy and other-origin progress. Network queue reserves fresh query blocks before
marking a named request eligible for a new session. A new Idle session must also
unpark an Awaiting_DNS_IDs FIFO head when it can reuse without DNS; refills are
not the only eligibility wake. Numeric/hosts preparation also bypasses DNS. Returning a partially prepared
submission burns its reserved fresh block rather than reusing a Query's private
consumption count. These are real eligibility semantics, not no-op placeholders.

Task15's network-abi101.md must freeze the genuine task17 internal selection
handoff before parallel sources: a pure pool_select_locked(k,key,now,allow_new)
returns a concrete Pool_Selection describing existing/new origin, eligible
Idle/Free session or bounded waiter, without mutating owners. Its exact type and
function live in task17's pool.odin and are actually used by both old-wrapper
and policy admission; no network types/imports/callbacks enter the pool module.
The selector centralizes full origin equality, capacity and idle/age selection so
phase4 NEW accepted-hop requeue can use it without copying the pool algorithm.
No phase4 consumer exists before task17 verifies this real selector.

Before phase4, accepted-hop requeue gets an explicit NEW-module commit handoff
using this verified selector plus shared task07 origin ref/disposal helpers;
no third pool/queue owner is available.
The phase4 freeze cannot just rename an accepted request Preparing or route it
through kernel_rollback. Review actual extracted pool selection helpers in task17
for this ownership boundary without implementing unused redirect functions early.


## Blocking TLS idle-health validation before session implementation

Task101-14-exchange-verify has a REQUIRED idle-health subgate before task101-18
may start. It does not block independent resolver, task-group, exchange schema/API,
State/bootstrap or coordinator work. Its source-bound public TLS/adapter probe
and reviewed idle-policy101.md must identify the exact observation used at Idle
entry AND checkout, operation/callback/partial-record ownership and retirement.
Report approved only after root/independent review of that concrete public-seam
policy; the runner's --require-idle-policy fails on blocked/unproved policy.

Source constraints: async.wait_stream Pending only arms interest/returns a hint,
not a synchronous empty receive queue. tls.async_connection_state reports TLS
state/ALPN, not buffered plaintext/partial ciphertext. Canceling a speculative TLS
read may leave a partial encrypted record. set_request_budget proves raw op/job
idleness, not absence of a separate old TLS response. Private field inspection,
blind cancel-probe reuse and a fabricated peek API are prohibited proofs.

The probe must use actual public APIs and literal peer schedules for same-read
surplus, a second TLS record already pending at checkout, split partial record,
KeyUpdate/deferred jobs, peer close and genuinely healthy repeated exchanges.
Bind exact source/compiler/peer observations and run ASan+TSan; record logical
claims separately from actual observations. Callback completion/old-interface
retirement and same pinned Task across closed transport generations remain
mandatory independent facts. A typecheck or readiness hint is no health pass.

Pending a validated public policy, conservative behavior is retirement whenever
old data/partial state cannot be excluded; NO verified HTTPS reuse claim follows.
If the existing public surface cannot meet the gate, keep actor implementation
blocked and add a reviewed owning prerequisite/phase refinement before new SDK
seams. Do not silently weaken full101 persistence or accept a fresh-connection-only
fallback as completion. This explicit unresolved gate is not a reason to delay
the three independent foundation streams enabled by the reviewed plan.


## Reviewed exchange engine schema amendment

Task14 is the explicit second types.odin owner, with five total files. Add only
Exchange._busy to reject reentrant public calls from allocator callbacks while
state is partially transitioned. No callback/allocator may publish an unfinished
owner. After physical allocations/frees and HTTP completion, return Progress and
require another caller-supplied fresh clock sample before publishing success;
the actor separately rechecks runtime epoch/deadline and kernel completion.
The generic engine cannot invent its own monotonic clock or extend Budget.
