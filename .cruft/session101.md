# OKAMI-101 persistent asynchronous HTTP/1 client

Reviewed execution contract. No runtime is implemented by this
file. Phase1 prerequisites are committed: async4798f93, HTTP4aa66a7. Preserve all
five requirements in spec101.md and blocking Surf/legacy buffered curl APIs.

## Package and public contract

Add optional `shared:surf/async`, package surf_async. Root Surf does not import
it; this package imports Root Surf, shared/http/v1, shared/async, async/connection,
async/signal and existing core TLS/owned/budget primitives. It does not import
Saba, HTTP2, curl or a second executor. Fixed Request.body requests are101; file
callback upload helpers stay blocking/unchanged and streaming responses stay104.

Public contract for schema freeze (no network implementation yet):

- `Client`: stable serialized-init/destroy header; thread-safe operational methods
  while header/runtime live. Private heap State owns stable cells.
- `Request_Handle {owner_id:u64,slot:u32,generation:u64}`; zero invalid, generation
  exhaustion retires a slot. Handle copies are aliases, not retained owners.
- `Capacities {requests,origins,connections,connections_per_origin,waiters_per_origin,
  dns_ids,work_per_resume:int}`; defaults32/16/8/2/32/256/128. Explicit positive
  ceilings: requests4096, origins1024, connections256, dns_ids65536, work4096;
  connections_per_origin<=connections, waiters_per_origin<=requests;
  connections/origins/requests/work at least1; waiter0 means
  no waiting if no assignable session. DNS IDs0 permits numeric-only progress and
  queued name-resolution wait. Metadata capacity never raises scope admission.
- `Client_Config {http:surf.Config,capacities:Maybe(Capacities),
  idle_timeout,max_age:time.Duration,lifetime:async.Deadline}`. Default idle30s,
  max age5min. Zero lifetime is unlimited; nonzero is immutable session/client cap.
  Negative durations reject. One immutable trust/policy snapshot per Client;
  no per-request TLS/proxy/redirect/response-limit overrides. Proxy policy Direct
  only; neither environment proxy nor ignored proxy settings are introduced.
- `Client_Error {kind:Client_Error_Kind,http:surf.HTTP_Error,runtime:async.Error}`;
  kinds None/Invalid_Config/Invalid_State/Capacity/Closed/Invalid_Handle/Pending/
  Allocation_Failed/Budget_Rejected/Request_Error/Runtime_Error. Preserve typed lower causes in http/runtime.
- `Request_Stage {Queued,Awaiting_DNS_IDs,Connecting,Handshaking,Writing,Reading,
  Redirecting,Retiring,Completed}`.
- `Completion {request:Request_Handle,error:surf.HTTP_Error}` contains scalar
  metadata only. A success Response is moved separately, never copied in a view.
- `client_init(c:^Client,runtime:^async.Runtime,config:Client_Config,
  allocator:mem.Allocator)->Client_Error`.
- `client_submit(c:^Client,request:http.Request,deadline:async.Deadline={})
  ->(Request_Handle,Client_Error)`: clone bounded URL/header/body inputs before
  success; no caller arena retained. Deadline starts before cloning/admission.
- `client_cancel(c:^Client,handle:Request_Handle)->Client_Error`.
- `client_request_stage(c:^Client,handle:Request_Handle)->(Request_Stage,Client_Error)`.
- `client_poll(c:^Client)->(Completion,bool)`: pops each terminal notification
  once under mutex. Slot remains held until response take or completion release.
- `client_take(c:^Client,handle:Request_Handle,destination:^surf.Response)->Client_Error`:
  terminal success only, empty destination; moves Response and retires handle.
- `client_release(c:^Client,handle:Request_Handle)->Client_Error`: terminal only;
  disposal occurs outside mutex. Pending release rejects; cancel does not release.
- `client_refill_dns_ids(c:^Client,ids:[]u16)->Client_Error`: bounded atomic copy of
  fresh host-prepared cryptographic draws; caller keeps input only through call.
- `client_close(c:^Client)->Client_Error`: reject new admission, cancel/drain
  queued/active requests and retire sessions, retaining all terminal completions.
- `client_quiescent(c:^Client)->bool`, `client_stats(c:^Client)->(Client_Stats,bool)`,
  `client_destroy(c:^Client)->Client_Error`: destroy only after tasks/jobs/IO
  retired and all request handles released/taken. Init/destroy externally
  serialized, not raced with operational methods. Detached Responses can outlive.
  Quiescent requires registered/retiring task references, Preparing/Returning
  work and accepted callback owners to drain; it may still retain terminal result
  handles. Destroy additionally requires every terminal handle taken/released.

`Client_Stats` reports capacity and real queued/active/completed/returning requests,
connecting/active/idle/retiring connections, origin occupancy, DNS IDs/waiters,
task count, reuse/close/cancel/deadline counts and scope snapshots. No RSS claim.

## Ownership and bounded coordination

One persistent pinned Task/Executor owns each TCP/TLS session through reuse/idle
and final on_done. One additional Client coordinator Task owns only admission,
queued deadlines and idle policy; no network I/O/executor/global worker. Maximum
registered Client tasks is connections+1. Runtime's one timer per Task means the
coordinator never overwrites a session's DNS/connection timer.

Stable request/session cells are allocated before publication. Client mutex only
protects fixed slot/index/FIFO/pool metadata and state transitions. No custom
allocator/free, TLS/net operation, user/source disposal or scheduler call runs
under it. Reserve a slot under lock, clone/validate outside lock while state stays
Preparing, then commit or roll back; retain State through all out-of-lock work.
All rejected admission preserves caller source. Close racing an out-of-lock clone
marks Preparing for rollback; commit rechecks close/deadline under mutex, with no
acceptance/completion after close wins and no early State/slot free. Slot counts include Preparing,
queued, active, completed-unclaimed and Returning until actual cleanup completes.
Generation advances only after IO callbacks and physical cleanup drain. Completion
uses one intrusive FIFO node per slot: poll OR direct terminal take/release
unlinks it atomically before retirement/reuse. Test take/release without polling
for more than capacity cycles and concurrent poll/take races; no phantom nodes.

Use retained async.signal handles for producers/coordinator/session notifications,
not published raw Task/Runtime pointers. Signals do not retain targets. Detach
before each on_done returns and before freeing Task/Runtime; task storage may be freed in on_done or later after retirement, never before.
Fixed task arrays are freed only after all their retirement callbacks have made
their final access and all retained state/producer/returning references drain. A retained State/returning-cell keepalive allows physical
callbacks outside locks without later access to a freed public Client header.
Default signal.create allocates one bounded heap State outside the supplied
scope; report this fixed metadata separately unless a separately verified
allocator-aware signal API is selected. No whole-process/full-physical-scope claim.

Each request cancellation is a flag+owner wake. Never async.cancel the persistent
session Task for one request. Cancel queued requests promptly; active ambiguous
wire work retires its transport, drains accepted callbacks, then publishes one
completion. Other requests can obtain another session. Runtime shutdown cancels
all tasks irreversibly: coordinator on_cancel uses bounded Yield/drain rather
than depending on a new external wake which a stopping runtime rejects. After
runtime join, poll/release/destroy do not dereference a dead Runtime. Quiescence
counts on_done, callbacks, Preparing and Returning owners; runtime.wait_idle alone
is not proof of Client physical retirement.

Use core scope/Binding/owned ABI, no second budget subsystem. One request stream
lease is acquired once and released after its terminal accepted IO/source cleanup;
idle session metadata does not acquire another request stream lease. Response
allocations remain charged until physical free, independently of the request
slot. Retain managed Binding/scope through returned surf.Response allocations.
Scope0 is explicitly unmanaged compatibility: configured retention bounds remain,
but no hierarchical charge is claimed. Nonzero Scope retains compatible core
Binding and physical Response charges after transfer; no nested managed allocator
or duplicate full-backing reservation. Signal State fixed heap metadata remains
outside Scope and is reported separately. Private Root Surf budget helpers are not callable from the subpackage; implement
its resource owner using core primitives, or propose an additive shared ownership
seam explicitly before code. Arenas are not accepted for persistent internal owners.

## Identity and pool model

Client owns cloned Config slices/strings and explicit bounded resolver snapshot.
Root certificate pointer entries may be copied, but certificate data/root pool is
borrowed immutable through all TLS session-close callbacks. It is never identified
only by a mutable pointer/hash. Rotation creates a new Client identity; sessions
never migrate between Clients. URL-derived hostname is always TLS server_name.

Pool equality is exact scheme + validated canonical hostname + effective port +
immutable Client profile identity (trust/ALPN/direct-proxy/policy). Do not coalesce
origins sharing DNS endpoints, certificates or IPs. DNS ASCII case folding/default
ports may normalize; avoid speculative URI equivalence. Scope identity is resource
policy, not permission to reuse authentication across Clients.

Global/per-origin caps count connecting+active+idle+retiring sessions. Fixed origin
slots have active/waiter/session refs; eviction only after none remain. Per-origin
FIFO waiters and round-robin eligible-origin dispatch avoid a stalled origin
blocking unrelated ready work. Full limits reject before source move or enter only
the explicitly bounded wait queue. Completed unclaimed requests retain their slots.

No HTTP1 pipelining: one exchange per session. Keep-alive metadata eligibility is
necessary, not sufficient. Complete request write/body/chunk trailers, HTTP response
body boundary, callbacks and executor jobs must drain before Idle. Read TLS into
stable buffer >=tls.MAX_PLAINTEXT_SIZE, consuming each returned plaintext record.
Keep same-record HTTP suffix; unexpected bytes after an exact response retire the
connection instead of becoming another request's response. No accepted idle read.
Checkout health/race policy must never replay an ambiguous request; conservative
explicit failure is allowed for stale sessions. No automatic application retry.

## Deadlines, DNS and TLS retirement

Retain one monotonic request cutoff beginning before submission/copy/queue wait:
min(optional caller cutoff, configured timeout, immutable Client/session lifetime).
Setup_timeout further caps new DNS/TCP/TLS work, never resets total budget. Each
redirect/body transfer uses the same cutoff. Session Executor init uses Client
lifetime (possibly0), not requestA deadline. Install each request cap only when
quiescent via committed set_request_budget; never extend accepted operations.
Budget_error gates any success after non-preemptible crypto or delayed callback.

Client init is outside runtime workers when preparing system resolver state and
initial DNS entropy. Clone explicit resolver.name_servers (<=8), otherwise prepare
OS nameservers/hosts once outside callbacks, preserving explicit-server behavior.
Actual public-consumer check proves net.load_resolv_conf/load_hosts are NOT exported
(dns_os.odin is file-private), although net.dns_configuration is public. Before
phase3 Surf integration, add an approved PUBLIC bounded preparation snapshot seam
in owning parent core/net, with off-worker preparation, finite file/server/host
caps, owned destruction and paired public fixture/consumer tests. Preserve old
helpers and APIs. No private imports, duplicated Surf resolver, worker file I/O
or fake OS-default fallback. Explicit nameservers bypass OS hosts/file preparation
as existing resolve_endpoint_until does. DNS ID bank0 supports numeric-only
progress and needs no DNS file preparation.

Maintain a bounded prepared-ID bank. Each query reserves its own sufficient ID
slice and consumes prepared values once per send; never recycle a prepared draw,
derive an insecure PRNG, or invoke prepare_dns_ids in a worker. Refills are fresh
trusted cryptographic draws prepared outside workers; equal random numeric values
can occur by chance but prepared entries are never reused. Exhaustion parks name
requests as Awaiting_DNS_IDs; coordinator still expires/cancels them and numeric
requests/healthy pooled sessions continue. No unbounded automatic entropy thread.

Use existing DNS_Connect numeric retries only before HTTP bytes; one pinned session
Task owns DNS and subsequently its single async/connection Executor+TLS Async_Conn.
No blocking resolver/execute/curl/file callback is put on a connection worker.
Synchronous core TLS crypto remains non-preemptible; document cancellation latency.

Leave expired request cap through cleanup. Submit TLS close exactly once; a
close_notify timeout is not failure to retire physically and never replaces the
primary HTTP error. Continue drive until all handshake/application callbacks,
TLS close callback and adapter quiescent are observed. Transport may retire before
final TLS jobs; Executor/Task persist through on_done. Never extend a deadline to
make close succeed. KeyUpdate/deferred jobs prevent Idle/request-cap rotation
until drain, without reading another application response speculatively.

## HTTP1 and redirect reuse

Use request_encode_profile Keep_Alive and response_header_decode/apply_method,
response_reuse_allowed, Chunk_Decoder and existing public Surf config/error/redirect
helpers. No header splicing or duplicate framing parser. Fixed Content-Length,
chunked/trailer end, HEAD/204/304 and bounded informational responses are distinct;
EOF framed, 101, CONNECT2xx, malformed, truncated and surplus streams retire.
Copy response head fields into owned Response backing before scratch reuse.

Reuse surf.config_validate/effective_timeout/http_error_classify/execute_redirect/
redirect_origin_safe/redirect_url where applicable. execute_redirect consumes the
intermediate Response and allocates a new URL: run outside Client mutex with the
same bounded allocator/deadline. Reevaluate origin/TLS hostname per hop; preserve
existing GET/public-header cross-origin policy, secure downgrade restrictions,
method rules and max5 redirect bound. Never replay an ambiguous POST/upload.

## Phase boundary and acceptance mapping

Phase2 (12 tasks in phase-2-101.yaml) freezes concrete Kernel/Slot/Profile/Origin/
Session_Model layouts and internal handoff signatures in kernel101.md before
parallel API writers, then bounded client/admission/clone ownership
ownership and pure origin/pool model plus independent tests. It intentionally
contains no network driver/public client_init stubs. Internal functions are real
kernel operations, not advertised async completion APIs. First model/admission
sources can compile/test independently of future networking. Full public API above
is contract for subsequent phases, not a claim of availability after phase2.

Phase3 must be concretized/committed before driver edits (<=20 tasks): prerequisite
parent core/net public bounded resolver-snapshot API plus paired tests, then host resolver
preparation+ID bank; coordinator deadlines/signals; persistent DNS/TCP/TLS actor;
incremental HTTP1 write/read; public Client API wiring; redirect/reuse/idle/close;
paired independent public smoke and source/legacy consumer checks. Each source
gets one primary task; integration handoffs/review fixes use at most second owner.

Phase4 must be concretized before final verification (<=20 tasks): independent
HTTP/TLS/DNS/concurrent-client matrix, cancellation/deadline at every phase,
identity/stale/late-response tests, all grant/admission failures, reentrant physical
callbacks, ASan/TSan, standalone consumers and final API/results/Linear acceptance.
No full101 completion follows from phase2 kernel or foundation gates.

Criterion mapping: async response ownership/cancel/total deadline = phases2kernel,
3driver,4 public cancellation+lateowner evidence; bounded origin/trust pool =
phase2 model +phase3 actor/reuse +phase4 isolation/exhaustion; independent stalled
concurrent callers =phase4 one-worker DNS/TLS/body stalls plus cheap origins;
Surf independence/service client = optional package/no Saba/curl and consumer gate;
original cutoff through redirects/body/offload =phase3 retained deadline plus
phase4 cumulative-delay/clock/cancel tests. Streaming response104, HTTP2102 and
curl replacement133 remain separate. Blocking file upload remains132 behavior.

## Review-required decisions before network phase

1. Freeze the new parent core/net public preparation snapshot contract and execute
   its paired public consumers/fixtures before relying on default OS DNS in Surf.
2. Confirm TLS idle encrypted-record/readability policy without consuming future
   response or importing core private fields. Full-record plaintext read+job drain
   is necessary; test extra data in same/separate TLS records and KeyUpdate.
3. Scope0 is resolved as unmanaged compatibility. Keep detached Response charges
   and retention claims honest, do not nest managed allocators/double-charge
   backing, and report fixed Signal heap metadata outside Scope separately.
4. Pin exact defaults/zero semantics in schema tests; no request callback API or
   file upload offload is silently promised by the fixed-body request interface.

Independent acceptance matrix: acceptance101.md. Required
public evidence includes one-worker independent DNS/TLS/body stalls with cheap
progress, same-session requestB after A deadline, queue expiry with all sessions
parked/ID bank empty, complete identity isolation, exact framing/leftover handling,
RST/stale no ambiguous replay, allocator/Response callback late disposal, full scope/FD cleanup,
and Runtime.shutdown while producers wake retained signals. Record actual parsed
wire/connection IDs/ALPN/worker counts; no typecheck or fake transport as full proof.


## Schema gate and concurrency discipline

Task101-05 freezes actual Kernel/Request_Slot/Profile/Origin_Slot/Session_Model
layouts and each internal handoff signature in kernel101.md before parallel
identity/ownership/admission/pool edits. No undeclared future owner types or dummy
network functions may be introduced to pass compilation. Later Client network
state can embed the completed pure kernel rather than smuggling protocol state
into it. Independent API streams depend only on frozen types/core ABI, not on
undeclared functions from another concurrent stream. Test writers freeze all
owned files before execution/source binding; each command has a unique output
binary to prevent parallel test collisions.

With waiters_per_origin0, a successful Preparing reservation must hold its
assignable session claim until clone commit/rollback; another submit cannot steal
that reservation. Close or expiry winning before clone commit rolls back and
returns rejection with no handle/completion. Fixed per-slot intrusive completion
links are removed by poll OR direct take/release before retirement, so repeated
completion→take-without-poll→reuse never produces phantom queue pressure.
