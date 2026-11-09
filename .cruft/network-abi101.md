# OKAMI-101 network State ABI

Task15 schema. async/network_types.odin contains actual concrete types and pure
network_config_normalize only. The functions assigned below are future real
implementations, not callable stubs. Bootstrap/API/test checkpoints precede
coordinator and actor source. Existing async/types.odin and kernel invariants are
unchanged. Exchange engine, resolver snapshot and task-group capabilities are
separate verified dependencies; their callbacks do not imply full Client success.

## Pure mode and size validation

`network_config_normalize(Normalized_Config)->(Network_Config,Client_Error)` is
allocation/retention/clock/Runtime/I/O free. It revalidates base configuration and
requires resolved request_timeout, response_body_limit, idle_timeout and max_age
to equal base normalization. Forged zero resolved idle/age therefore rejects.
Malformed borrowed descriptor/string shapes reject before iteration. Root lower
configuration cause is retained where present. All failure outputs are zero.

Evaluate ORIGINAL normalized resolver choice BEFORE profile_init. Explicit
nonnil-empty rejects even though Profile canonicalizes len0 slices to nil. With
DNS IDs0 choose Numeric_Only and do no system file/entropy preparation; explicit
nonempty or nil with positive ID capacity selects Explicit or System. Explicit
endpoints require address+valid port and use no system hosts files. After Profile
clone, State.config.config must point to Profile.config's owned copied views;
State retains the already determined DNS mode rather than recomputing original
intent. Certificate objects remain immutable borrowed until all TLS closes.

Phase3 max_redirects>0 explicitly rejects Invalid_Config. This gate is removed
only by the reviewed phase4 accepted-hop/redirect integration; it does not narrow
the full101 acceptance criteria. All other normalized options/capacities retain
their previously frozen meaning. No new per-request policy override.

Network_Config.task_count is connections+1. Its state/actor/request/task-index/DNS
byte fields are checked exact typed allocation sizes, not RSS, total metadata,
Signal memory or resource admission. Products are checked before multiplication;
Scope0 stays unmanaged and nonzero Scope still needs physical backing charges.
DNS constants:16 IDs per reserved block,32 total sends per accepted request,
64 accepted messages/query,2 rounds,1s attempt timeout,4096-byte TX/RX workspaces,
9 alias entries and64 endpoint results. Queries use A_Only first and AAAA_Only
fallback only when needed, fresh IDs and original cutoff. No Both-family+one-ID
success claim, private _sent inspection or unlimited reset/retry loop.

## Stable object and lock ownership

Client_State is one stable self-checked heap allocation with embedded Resources,
Profile, Kernel, Resolver and coordinator; actors, request metadata, DNS ring and
Task pointer index are finite separate allocations. Every actor contains its
stable Task, adapter Executor/Transport, TLS Async_Conn/handshake/close operations,
generic Exchange, DNS Query/Connect/workspaces and owner-only retirement latches.
No Client header pointer is stored. The public header can disappear after a
method clears it; retained State/local snapshots must finish cleanup without it.

State.mu protects lifecycle refs, group registration witness, Task/Signal metadata,
DNS ring, request-network metadata and actor mailboxes. Kernel.mu protects existing
Kernel association/queues/generations/counters. If both are needed: State.mu FIRST,
Kernel.mu SECOND; never reverse. Physical alloc/free, scheduler APIs, signals and
TLS/net calls occur outside both. Clock sampling is the specific permitted read:
while State.mu protects registered_tasks/runtime, deadline_after may capture the
Runtime clock/epoch (it does not acquire scheduler locks). Last on_done removes
that witness under the same mutex and sets runtime=nil. A check/unlock/raw-clock
read is forbidden. No raw Runtime pointer is treated as an independent owner.

Session_Actor.command is the cross-thread mailbox under State.mu. Other mutable
actor fields belong exclusively to its pinned owner Task. A Session_Assignment
snapshot borrows admitted Request/host bytes only through the actor's terminal
accepted callbacks and cleanup; Request_Handle owner/generation and contextual
Session handle are validated before use. Only actor may complete an Active
request. Coordinator completes Queued no-I/O work or requests cancel/wakes an
active owner. Request_Network.generation matches its Kernel request generation;
clear it only after physical slot cleanup, not merely poll/cancel.

## Bootstrap and physical disposal handoffs (task16)

Freeze/implement these names in bootstrap.odin,dns_bank.odin,runtime_ownership.odin:

```odin
network_prepare(runtime:^runtime_async.Runtime,config:Normalized_Config,allocator:mem.Allocator)->(^Client_State,Client_Error)
network_dispose_prepared(state:^Client_State)->Client_Error
network_state_retain(state:^Client_State)->bool
network_state_release(state:^Client_State)
network_clock(state:^Client_State)->(runtime_async.Deadline,Client_Error)
network_dns_refill(state:^Client_State,ids:[]u16)->Client_Error
network_dns_reserve(state:^Client_State,maximum:int)->(DNS_ID_Block,Client_Error)
network_dns_burn(state:^Client_State,block:^DNS_ID_Block)
network_assignment_take(actor:^Session_Actor)->(Session_Assignment,Client_Error)
```

network_prepare is a real constructor, not public Client.init: no Task is
registered, no producer is published and no protocol I/O occurs. It validates
network config before Profile clone, prepares system files/initial trusted draws
off workers, allocates all arrays and creates every prepared unregistered Signal.
It rejects async.worker_thread_active when file/entropy preparation would occur.
All Signal failures and raw grants unwind synchronously while caller Runtime
remains valid/controller-serialized. At success references1/base_owned=true,
phaseConstructing, registered_tasks0; the construction/base owns every child.
Prepare task callbacks/data/index at stable addresses using the frozen task
function types; actual resume callbacks are attached by public wiring only after
coordinator/actor modules exist. No Task-group call inside this constructor.

Bootstrap State bytes require either (a) ordinary backing+one full State-byte
lease under nonzero Scope, or (b) an already compatible covered managed grant
whose physical charge is retained without another lease. Scope0 reserves no
hierarchical lease. Validate raw reported pointer/size/alignment/error BEFORE
zero/cast. Never move a stack Kernel_Resources with its self guard into State.
Initialize every self-guarded child at its FINAL address. Remaining arrays/profile/
Kernel/snapshot allocations use compatible Resources allocator. No nested managed
Binding or duplicate full-backing reservation. Signals' existing fixed heap
control cells are explicitly outside Scope and counted separately.

network_state_retain/release mutate refs under State.mu; no callbacks/free there.
Base construction ref becomes Client base at publication and is not dropped.
Public methods retain through out-of-lock clone/disposal. Each registration owns
another ref. Final release is allowed only after child/registration/request
owners retired; physical cleanup runs outside locks. Dispose Kernel, Profile,
Resolver and Resources at their ORIGINAL embedded addresses. Copying whole State
to a stack local invalidates their self guards and is forbidden. Detach Signals
before Task/Runtime death; free raw arrays only after their final on_done access.
Snapshot raw State_Backing only after stable child destructors; free the whole
State then release its detached bootstrap lease using locals. No State access
or allocator-callback reread after whole-State physical free. Returned Response
allocations retain independent Binding provenance until physical disposal.

network_dispose_prepared rejects any registered/published/active owner. It may
unwind only unregistered constructed State. network_clock requires a protected
registered Runtime witness for live reads; after last witness it returns a typed
Closed/Invalid_State instead of dereferencing dead Runtime. A separately tested
stored mapping can support no-Runtime result APIs; they do not need a live read.

DNS reserve copies1..min(maximum,16,available) fresh entries atomically and removes
them from the fixed ring. Empty returns Pending; invalid maximum rejects unchanged.
Refill copies caller entries atomically if total fits, preserving caller source;
closed/oversized rejects with no partial append. Work is explicitly bounded by
capacity<=65536. reserve/burn never invokes entropy or reads DNS private state.
Burn clears the caller block and records consumed/discarded draws, never returns
potentially used entries. Calls needing producer notifications snapshot retained
signals under lock and wake/release them outside it.

## Task publication and retirement (public task19)

After all constructors/callback implementations are ready, public init attaches
coordinator/session resume,on_cancel,on_done and prearms one ref per Task plus
the existing construction base BEFORE atomic register_group. Group rejection
registers none: drop prearmed refs and synchronously dispose zero Client. Group
success publishes Client; the construction reference BECOMES its base. Concurrent
shutdown may mark it Closing before init returns, but all callback data are ready
and this remains a valid cleanup owner. No opaque Pending failed-init owner.

Normal actor owner drains TLS/raw/Exchange callbacks and latches owner_drained
before returning Done. `_current_task` is cleared before on_done: that callback
MUST NOT call adapter drive/quiescent/TLS APIs. It detaches its signal, updates
accounting/removes registered witness, then drops its ref as its FINAL access.
State base remains until Client.destroy. Coordinator cancellation yields/drains
without relying on new external Signal wakes accepted by a stopping Runtime.

Existing Runtime.destroy before start invokes on_done synchronously WITHOUT
on_cancel. The first/last unstarted callbacks mark Closing and perform one guarded
no-I/O cancellation/finalization of queued model work; they never invoke TLS or
Task-only APIs. Flags unstarted_cleanup_started/done protect reentrant cleanup.
Last witness nulls Runtime. Poll/take/release/destroy afterward use State only.

Runtime start/join/destroy and Client init/destroy/prestart group retirement are
controller-serialized. shutdown may race producers. retire_group_unstarted checks
starting/started under scheduler mutex; Pending/AlreadyStarted is NOT quiescence.
If thread creation fails, later close/destroy retries unstarted retirement or
Runtime.destroy's no-I/O on_done fallback finishes. Prestart group retirement
returns ownership WITHOUT on_done, so manually detach/drop each ref exactly once.
No new init-before-start restriction or callback-based task free in resume.

network_assignment_take is implemented/verified by task16 runtime_ownership,
BEFORE parallel tasks17/18. It performs a real bounded metadata mailbox/Kernel
snapshot, moves the reserved DNS block once, validates request/model generation
and returns borrowed admitted input plus scalar cutoff/host/port/endpoints. It
calls no coordinator/actor functions or protocol I/O. Thus actor task18 never
references an undeclared function authored concurrently by task17.

## Coordinator, actor and pool handoffs (tasks17/18)

```odin
network_coordinator_resume(data:rawptr)->runtime_async.Resume_Result
network_coordinator_cancel(data:rawptr)->runtime_async.Resume_Result
network_coordinator_done(data:rawptr)
network_session_resume(data:rawptr)->runtime_async.Resume_Result
network_session_cancel(data:rawptr)->runtime_async.Resume_Result
network_session_done(data:rawptr)
network_assignment_finish(actor:^Session_Actor,response:^surf.Response,error:surf.HTTP_Error)->Client_Error
network_queue_claim(state:^Client_State,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error)
```

task17 owns coordinator callbacks and network_queue_claim; task18 owns session
callbacks and network_assignment_finish. Neither calls functions still being
authored by the other. Both use verified task16 mailbox/ref/DNS operations and
frozen shared types.

Coordinator writes Session_Command+matching actor generation only under locks,
then wakes a retained actor Signal outside. Actor takes assignment/IDs/endpoints
under locks, then alone owns I/O. assignment_finish uses verified begin_complete,
physical detached cleanup, fresh clock and repeated cleanup_finish rounds; it
never publishes after only the old pre-allocation sample. Request lease and
Request_Owner stay until accepted I/O/source callbacks physically drain. Empty
bank cannot monopolize unopened physical sessions: prepare block before allowing
new named claim; otherwise use bounded waiter with Awaiting_DNS_IDs. Healthy Idle,
numeric and hosts addresses bypass bank. Coordinator unparks the head when an
Idle connection appears, not just on refill. Original cutoff remains unchanged.

Task17 preserves exact old pool_reserve callable, adds separate
pool_reserve_policy(k,preparing,origin,now,allow_new:bool), and factors real pure
pool_select_locked(k,key,now,allow_new)->(Pool_Selection,Client_Error). The concrete
selection records existing/new origin, eligible Idle/Free session or bounded
waiter, without mutation; actual types/functions live in pool.odin and are used
by normal admission. No network imports/callbacks in pool. Task17 implementation
freezes exact selection fields before phase4 consumer, which uses NEW accepted-hop
requeue modules plus shared task07 origin refs/disposal. No third pool/queue edit,
no duplicate full selection policy and no pretending an accepted hop Preparing.

Actor is blocked until approved public TLS idle+raw-probe gate. Healthy checkout
requires local TLS Ready, fresh request-cap installation on owner Task, then raw
probe Empty before B write; any other result retires before write. No native queue
claim from TLS Ready, speculative read/cancel, private state inspection or
ambiguous retry. Whole transport/TLS/Executor reset only after TLS-close callback,
closed adapter quiescence and all old interface copies/operations gone on SAME
pinned Task, preserving immutable Client lifetime. Old request cap can expire
while healthy Idle; do not drive old-cap work to turn B into A's timeout.

## Verification boundaries

Schema tests exercise actual pure normalization/layout/bounds only. Constructors,
refs/physical grants/taskgroups/on_done/clock witnesses require task16/17/18/19
real implementation and native gates; declarations/scalar flags are not evidence.
Full101 remains open through complete redirect/requeue and phase4 failure/race/
identity/public-native evidence. Existing blocking/curl APIs stay untouched.


## Task16 common callback retirement amendment

The explicit second ABI-document owner is task16 (four files total). Implement
`network_task_done(state:^Client_State,actor_index:int,owner_drained:bool)` in
runtime_ownership.odin, shared by task17/18 callbacks and public prestart group
ownership return. Index0 is coordinator,1..N are sessions. Normal coordinator
latches coordinator.done before Done; normal actors latch owner_drained before
Done. False is permitted ONLY for caller-certified never-started/no-I/O cleanup,
including Runtime.destroy before start and manual retire_group_unstarted return.
Do not read scheduler-owned Task fields to infer that fact or call Task/TLS/
adapter APIs in on_done.

The common helper detaches Signals outside State.mu, guards duplicate retirement,
and performs one guarded queued no-I/O cancellation/finalization before removing
the final Runtime witness. All physical disposals are outside both mutexes; fresh
clock capture is protected by the existing witness. Last callback nulls runtime
under State.mu; releasing its registration reference is the FINAL State access.
No duplicated coordinator/actor lifetime algorithm or new owner-retirement stubs.

Task17 must provide network_queue_committed_locked and network_queue_changed_locked
under State.mu for task19. Keep commit and Awaiting_DNS_IDs stage repair atomic
against coordinator dispatch, using State.mu then Kernel.mu. A late bounded-scan
repair alone is insufficient. Queue changes preserve persistent cursor, refresh
remaining-capacity work and earliest-deadline scratch; do not repeatedly restart
cursor0 and starve cells behind sustained producers. Idle unpark may expose the
SAME Awaiting-DNS FIFO head only to a healthy same-origin Idle session; Free/new
session dispatch still requires prepared addresses or fresh reserved IDs. Shared
assignment_take accepts IDs0 for actual Busy/reuse assignments, but Connecting
requires addresses or a fresh block. Original request/cutoff/generation stay fixed.


Task16 implementation precision: empty DNS refill is an accepted no-op on open
prepared/published State, still Closed after close. Internal State/actor/request/
task-index/DNS-ring aliases reject before copying. DNS statistics saturate; burn
clears its move-only scalar block even for invalid count and records only counts
within0..16. It does not manufacture foreign-bank provenance from a scalar block.
Prepared disposal requires Constructing/base-only/no operation refs; final
network_state_release requires the controller to clear base_owned before dropping
the base (as future Client.destroy does). Registration/method releases never
silently consume that base. Constructor rollback marks Disposing before any
child/raw free so reentrant APIs cannot acquire an unpublished dying State.
