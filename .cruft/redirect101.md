# OKAMI-101 accepted redirects and final acceptance

Phase3 is verified through public Client and isolated consumers. This phase retains
all five spec101 criteria; nothing is Done until the final required matrix passes.
The user authorized the remaining backlog and parallel implementation with local
commits. This is the concrete continuation of task22, not a new product scope.

## Fixed behavior

Use the existing Root Surf redirect helpers and policy. GET may follow
301/302/303/307/308; nonGET (including HEAD) follows only307/308. Cross-origin
GET permits only the existing public media headers; credentials/cookies/other
nonpublic headers reject Unsafe_Redirect, without a second-origin request.
HTTPS downgrade rejects. Never silently strip credentials and continue, rewrite
POST303, or replay an ambiguous write. Preserve max5, relative URL policy,
intermediate body caps, per-hop trust/hostname validation and the original total
cutoff. Direct proxy policy and immutable per-Client trust remain unchanged.
Fixed cloned Request.body is101; streaming104 and blocking file callbacks remain
separate. Root legacy buffered curl entrypoints stay unchanged.

Redirects conservatively close the old physical connection before requeueing.
This matches blocking Surf's fresh-connection policy and avoids a cap1 deadlock
when an old origin would otherwise retain Idle capacity. Ordinary nonredirect
requests retain verified healthy reuse. No extra workers or entropy thread.

## Ownership and ABI

New redirect_types.odin owns a stable Redirect_Handoff type, initially separate
from the existing State schema. It holds the original Request_Handle (IO reset clears actor.request), target Request_Owner, Prepared_Origin,
next hop count, remaining prepared DNS draw budget and previous response status.
An explicit Empty/Preparing/Ready phase rejects allocator reentry while building; set Preparing BEFORE helper QueryFeatures or Response consumption. Destroy clears owner/phase before arbitrary physical callbacks.
No temporary allocator/URL descriptor may escape its preparation stack.

Pure redirect preparation consumes the intermediate owned Response using
surf.execute_redirect outside State/Kernel mutexes. It clones the target request,
prepares its origin, frees the temporary target URL, and owns every failure
prefix. Use a checked temporary allocator adapter for the legacy helper's raw
make grants; reject malformed grants and preserve typed budget causes. Permanent
input/origin use the actual managed resources allocator. Fresh clock/cancellation
checks follow every physical preparation/disposal before any commit.

Accepted-hop ledger functions live in new redirect_kernel.odin:

- kernel_redirect_begin(k,handle,now) -> (Request_Disposal,Client_Error): caller
  certifies old IO closed, model Retiring. Validate Active, original deadline and
  cancellation first. Detach model association, old input and old Origin.Request;
  KEEP the original Scope stream lease and deadline. Active becomes Returning
  with returning_to=Preparing and stage Redirecting; one Kernel reference is added.
- Dispose old input/origin and physically retire the old model outside owner
  locks. The original request handle/generation never changes.
- kernel_redirect_ready(k,handle,now) -> Client_Error: check the original cutoff
  after all old physical frees, then Returning->Preparing, transferring the SAME
  Kernel reference and lease. No intermediate completion.
- kernel_redirect_fail(k,handle,primary_error) -> (Request_Disposal,Client_Error):
  accepts Returning-to-Preparing or accepted Preparing; detaches any new reserved
  or waiter claim and Origin.Preparing/Request, moves the lease exactly once,
  and transitions to Returning-to-Completed. Preserve the ticket reference.
  Only after physical disposal may ordinary kernel_cleanup_finish publish once.

Never call ordinary kernel_rollback for an already accepted redirect, or ordinary
cleanup_finish on a Returning-to-Preparing ticket. Every arbitrary callback runs
outside State.mu/Kernel.mu. State->Kernel lock order and persistent actor task,
Signal, thread pin and stable addresses remain unchanged.

A separate budget-aware queue prerequisite preserves the exact old
network_queue_claim callable as a wrapper with32 initial draws. New
network_queue_claim_budget takes explicit remaining0..32 and reserves at most
min(16,remaining) BEFORE admission. Moving IDs into the actor deducts once, as
already implemented; unused entries burn and never refill the original allowance.
The total32 prepared draws span ALL hops. Zero total allowance with a named new
dial fails promptly with a typed generic DNS Request_Error, distinct from an
empty fresh-ID bank with allowance remaining, which may park until refill/deadline.
Numeric/prepared-host/healthy Idle zero-ID work remains valid. Reuse the existing
pool selector, never a duplicate policy. No private DNS query inspection.

The actor integration task is the sole second owner of network_types.odin,
session.odin and session_close.odin. It embeds Handoff, stores per-request hop
metadata, opens the max_redirects gate only WITH the working actor path, and adds
new redirect_actor/redirect_network modules (five files total). Capture remaining
DNS allowance before generation-matched metadata forget, restore hop metadata
under State.mu before commit, and use actual queue commit atomically. Physical
close can cross resumes; no owning disposal is left as an untracked stack copy.
The next actor can receive the same handle only after old interfaces/callbacks
and model quota are retired. Intercept close_step after all old callback/adapter/
exchange quiescence but BEFORE ordinary assignment_finish and pool_retire.
Redirect begin must detach the model request before pool retirement can succeed.
Resolve Ready/claim/commit or Fail cleanup before ANY Idle/Waiting/Done return,
including global Closing; the coordinator does not service Returning/Preparing.
Yield and keep the actor ownership/bookkeeping reference until resolution.
Check Kernel.closed as well as cancel flags: kernel_close does not mark a
Returning-to-Preparing ticket by itself. Cancellation/runtime shutdown/lifetime all drain the
handoff, including accepted Preparing failure, before on_done/ref release.

Preserve Root error classification: fill status from the last response only when
zero; upgrade Not_Sent to Response_Received when a previous response exists, but
NEVER replace Unknown for an ambiguous later-hop write. Preserve the first real
failure through physical retirement and fresh-clock late-success checks.

## Validation and parallel work

Schema precedes three disjoint API streams (ledger, preparation, budget queue),
then three independent focused test streams. All must pass before actor wiring.
Public test streams then own disjoint fixtures for redirects, identity/framing,
held-phase cancellation, concurrent callers and physical ownership faults.

Redirect vectors cover all statuses/methods, relative and cross-origin targets,
loop/max hops/body caps, unsafe credentials, downgrade/authentication, cap1,
original chain cutoff, cancel/close during handoff, finite32 DNS draws across
hops and exactly one terminal result/lease. Test allocator reentry and every NEW
owned preparation/accepted-requeue failure boundary; reference unchanged prior
constructor414 and primitive protocol proofs without claiming application proof.

Public composition gates add host/port/scheme and separate Client trust/ALPN
isolation; idle/maxage/stale/surplus/KeyUpdate; literal HTTP framing and
GET/HEAD/POST; held positive-ID DNS/TLS/write/header/body with one-worker cheap
progress; queued/global/per-origin/waiter/request/byte exhaustion; real concurrent
producers/poll/take/close/shutdown, stale handles and late Responses. Scope/heap/FD
baselines, peer IDs/bytes/events, statuses/effects and source/toolchain manifests
are mandatory. No fake Kernel completions in public proof. A delayed accept alone is not parked TCP-connect evidence; use a verified pending connection barrier (for example owned saturated backlog) or report that phase honestly. Trust/ALPN isolation needs actual separate authentication and peer connection IDs, not only profile IDs. Zero-capacity tests
respect the declared configuration: zero requests/connections/origins invalid,
zero waiters/DNS/Scope bytes have their documented behavior.

Valid callback reentry includes close/stats/cancel during clone/free. Physical
header-free tests use failed init or successful destroy AFTER clearing the header;
init/destroy and Runtime start/join/destroy remain controller-serialized.
Non-preemptible allocation, resolver preparation and synchronous crypto latency
must be documented with post-work deadline barriers; no hard real-time promise.

The final runner requires every selected matrix/cell, rejects skips/duplicates/
stale source maps, and has negative controls for omitted/failed required evidence.
Run current-source whole package/facade/consumer checks once at final freeze;
reuse unchanged prerequisite evidence only at its exact stated scope. Inspect
actual import/call/link evidence: no Saba dependency or native easy_perform call;
Root's legacy vendor curl import is not a claim that all Surf imports omit it.
Darwin evidence does not certify Linux. Only after independent acceptance review
may spec101 checkboxes and Linear become Done. Update continuation first, then
move to the next ready issue. Never push; preserve all worktrees and Mesa.


## Verified stage-observability amendment

A real public held-phase probe observed eight Connecting samples during each of
TCP partial body, authenticated TLS partial body, and held TLS ClientHello.
The existing actor changed only its internal phase; the Kernel public stage
never received Handshaking/Reading updates. This is an API reporting bug, not
a failed redirect wire proof. Exact copied source/wire/log evidence remains
under the Task30 stage probe.

Add two separately owned tasks (phase4 now18): read-only exchange_phase in a
new file using existing Exchange_Phase, then independent callback-boundary tests.
No new enum/schema/private-field access or transport-health inference. Within
the SAME Task27 session source ownership, publish at endofresume after adapter
drive, with State->Kernel generation/association checks and Active ONLY. Map
actual actor TLS state and committed exchange Writing/Reading/Draining phases;
skip Idle/invalid and all nonActive cells so Redirecting/terminal tickets remain
untouched. Preserve original callback/physical teardown order. Root/current
source final matrices must include this correction; old122wire results remain
accurate historical evidence.
