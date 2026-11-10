# Persistent asynchronous HTTP/1 Client

Import `shared:surf/async` for a bounded HTTP/1 client on an existing
`shared:async.Runtime`. Each connection has one persistent, pinned task for DNS,
TCP, TLS and HTTP work. A coordinator handles queues, deadlines and idle expiry.
Requests on one HTTP/1 connection are serialized; different connections can
progress independently, including with one Runtime worker.

The package uses native sockets and core TLS. It does not call blocking
`surf.execute` or curl from a worker. Root Surf's blocking API and its file-upload
helpers remain separate. This Client accepts a fixed `http.Request.body`, clones
it at submission and buffers a bounded response. HTTP/2, streaming uploads and
streaming responses are separate work.

## Minimal HTTP example

Run this example against an owned numeric HTTP endpoint, such as
`http://127.0.0.1:8080/`. `allow_http` is an explicit plaintext opt-in.

```odin
package main

import client "shared:surf/async"
import async "shared:async"
import surf "shared:surf"
import "core:fmt"
import "core:os"
import "core:thread"
import "core:time"

main :: proc() {
    assert(len(os.args) == 2)
    runtime: async.Runtime
    assert(async.init(&runtime, {
        workers=1, task_capacity=2, io_capacity=2,
        allocator=context.allocator,
    }).kind == .None)

    c: client.Client
    config := client.Client_Config{
        http={allow_http=true, timeout=5*time.Second},
        capacities=client.Capacities{
            requests=4, origins=4, connections=1,
            connections_per_origin=1, waiters_per_origin=4,
            dns_ids=0, work_per_resume=128,
        },
    }
    assert(client.client_init(&c, &runtime, config, context.allocator).kind == .None)
    assert(async.start(&runtime).kind == .None)
    handle, error := client.client_submit(&c, {url=os.args[1]},
        async.deadline_after(&runtime, 2*time.Second))
    assert(error.kind == .None)

    for {
        completion, available := client.client_poll(&c)
        if !available {thread.yield(); continue}
        assert(completion.request == handle)
        if completion.error.kind == .None {
            response: surf.Response
            assert(client.client_take(&c, handle, &response).kind == .None)
            fmt.printf("status=%d bytes=%d\n", response.status, len(response.body))
            surf.response_destroy(&response)
        } else {
            fmt.eprintf("request failed: %v\n", completion.error)
            assert(client.client_release(&c, handle).kind == .None)
        }
        break
    }

    closing := client.client_close(&c)
    assert(closing.kind == .None || closing.kind == .Pending)
    for !client.client_quiescent(&c) {thread.yield()}
    assert(client.client_destroy(&c).kind == .None)
    assert(async.wait_idle(&runtime).kind == .None)
    assert(async.destroy(&runtime).kind == .None)
}
```

Initialize and destroy the original `Client` address; do not copy a live header.
The example uses a zero DNS bank, so a hostname without an existing reusable
session waits for IDs rather than resolving. Use a positive DNS capacity for
normal hostname service clients.

## Admission and response ownership

`client_submit(c, request, deadline={})` returns an accepted `Request_Handle` or
an error and a zero handle. Before success it clones URL bytes, header descriptors,
header names/values and the fixed body. Caller storage may be reused immediately
after the call. Rejection preserves caller inputs and creates no completion.
A rejected `Capacity` can be handled by caller policy; an accepted request is
never silently retried, including after an ambiguous write.

Handles contain Client ownership, slot and generation. Copies are aliases to one
request, not extra retained owners. Foreign or retired handles are invalid.
`client_poll` removes a terminal notification once; it does not free its slot.
`client_take` moves a successful response into an empty destination and retires
the handle. Direct take without polling also removes the notification.
A terminal failure returns `Request_Error` from take and must be retired with
`client_release`. Release also discards an unwanted successful response.
Pending release does not cancel a request; call `client_cancel` explicitly.

A taken `surf.Response` is move-only by convention. Destroy it exactly once with
`surf.response_destroy`, or move its body with `surf.response_take_body` and
release that owner through the existing body API. Response headers and body can
outlive Client and Runtime destruction. Their allocator and Scope charges remain
held until the physical backing is freed; taking a response is not a byte refund.
The backing allocator must support concurrent allocation/free when operational
methods or Runtime workers run concurrently. Keep its context alive through every
late response free.

`client_request_stage` returns a synchronized observation of Queued,
Awaiting_DNS_IDs, Connecting, Handshaking, Writing, Reading, Redirecting, Retiring
or Completed. A stage is not permission to reuse a transport or proof of how many
HTTP bytes reached a peer. Inspect `HTTP_Error.write_effect` for failure context.

## Configuration, identity and limits

`Client_Config.http` is one immutable policy snapshot. Configuration slices and
strings are cloned. **TLS certificate objects referenced by `tls.root_cas` remain
borrowed and immutable** until all Client sessions have physically closed; keep
their root pool alive through that point. Create a new Client for trust rotation.
TLS server-name verification always uses the URL hostname. ALPN offers may contain
only `http/1.1`; other protocols reject configuration. Connections use direct
transport only, without an environment-proxy policy.

Pool identity includes scheme, canonical hostname, effective port and the Client
profile. Two hostnames sharing an IP/certificate do not share sessions. Sessions
never migrate between Clients. Eligible keep-alive responses may reuse a session;
EOF framing, malformed/truncated bodies, upgrades and surplus bytes retire it.
Checkout also checks TLS quiescence and a nonconsuming raw-socket probe. A stale or
contaminated session can fail a new accepted request as Not_Sent; it is not replayed.

An omitted `capacities` selects the following defaults. An explicit value supplies
all fields; zero does not select the default for an individual field.

| Capacity | Default | Valid range |
|---|---:|---:|
| requests | 32 | 1..4096 |
| origins | 16 | 1..1024 |
| connections | 8 | 1..256 |
| connections_per_origin | 2 | 1..connections |
| waiters_per_origin | 32 | 0..requests |
| dns_ids | 256 | 0..65536 |
| work_per_resume | 128 | 1..4096 |

Runtime task capacity must accommodate `connections + 1` Client tasks in addition
to other Runtime users. Connecting, busy, idle, reserved and physically retiring
sessions occupy bounded connection capacity. Request capacity includes preparation,
queued/active work, unclaimed terminal results and returning cleanup. Waiter zero
allows an immediate session claim but no unassigned per-origin waiting slot.
Completed handles must be taken/released before their request capacity is reusable.

Zero durations select defaults: HTTP timeout30s, idle timeout30s and max age5min.
Zero response-body limit selects8MiB; explicit limits are bounded by shared HTTP.
Negative durations or out-of-range capacities reject configuration. Idle/age expiry
retires sockets without waiting for a later request.

`http.scope` optionally supplies hierarchical admission and physical-byte charging.
Use `http.scope`, not `http.allocator_scope`, for this package. A zero `http.scope` omits logical request-Scope admission while retaining
configured capacity/body bounds. If the supplied allocator is already managed,
its existing Binding and physical byte charges are still retained; a zero logical
Scope does not disable them. With an unmanaged allocator, no hierarchical charge
is claimed. Each
accepted logical request holds one stream lease across every redirect. Response
bytes remain charged after terminal publication and transfer. Fixed Signal control
cells use bounded heap metadata outside the Scope; `Client_Stats.signal_cells`
reports that exception. Neither Scope nor Client statistics are process RSS.
An arena without individual Free support is unsuitable for persistent ownership.

## Deadlines, cancellation and shutdown

One request cutoff starts before validation, allocation and copying. It is the
minimum of the optional caller deadline, configured HTTP timeout and immutable
`Client_Config.lifetime`; all use the Runtime's monotonic epoch. Setup/TLS limits
can shorten setup but never restart the total allowance. Queue wait, DNS, redirects,
write and response-body work all consume the same original cutoff.

`client_cancel` flags one request and wakes its owners. It does not cancel the
persistent session task. Active cancellation retires/drains accepted I/O before
publishing one terminal result. A primary failure is preserved during cleanup;
late success is checked against a fresh cutoff after nonpreemptible work.
Synchronous allocation/free, off-worker resolver preparation and TLS crypto are
not preemptible. Work budgets bound coordinator/protocol steps, not a hard
wall-clock cancellation latency or per-byte cost for a large ownership copy.

`client_close` rejects new requests, cancels queued/active work and retires all
sessions. It returns Pending while owners drain; call `client_quiescent` to observe
that drain. Quiescent can still retain terminal handles. Destroy returns Pending
until those handles are taken/released and all physical owners have retired.
The immutable Client lifetime also wakes and closes an otherwise idle/no-request
Client. Its queued work uses shutdown-style Cancellation; request-local deadline
failures remain distinct where observed. Do not infer every lifetime closure is
reported as Deadline_Failed.

Operational submit/cancel/poll/take/release/stats/refill calls may be concurrent
while the Client header is live. Serialize Client init/destroy and Runtime
start/join/destroy externally. Prestart `client_close` retires its unstarted task
group, so serialize that operation with Runtime start/join/destroy too. Runtime
shutdown may race operational calls.
After Runtime join/destruction, terminal results remain pollable/takeable/releasable;
close and destroy the Client without dereferencing a dead Runtime. Runtime
`wait_idle` alone does not prove Client quiescence. Physical disposal callbacks
run outside Client/kernel mutexes; valid reentry can use close/stats/cancel.
Free a public header only after failed initialization or successful destruction
has cleared it, never while it remains published to another operation.

## Resolver and redirect policy

With a positive DNS bank, initialization prepares a bounded resolver snapshot and
initial cryptographic ID draws outside Runtime workers. Explicit nonempty
`http.resolver.name_servers` bypass system files/hosts. Nil uses prepared system
configuration; an explicit nonnil empty override rejects rather than falling back.
Bank zero skips resolver files and entropy preparation, permits numeric requests
and healthy pooled reuse, and parks unresolved named requests as Awaiting_DNS_IDs.
Refilling a zero-capacity bank cannot create capacity.

Prepare fresh draws outside worker callbacks with `async.prepare_dns_ids`, then
copy them into available bank capacity using `client_refill_dns_ids`. The caller
retains its slice and may reuse it after the call, but must never resubmit consumed
or unused-reserved draws as fresh entropy. The API cannot certify the caller's
random source. Equal independently random numeric values can occur by chance.
Refill does not reset the original logical-request allowance of32 reserved/burned
DNS ID draws across all hops. Reservations take blocks of up to16, and unused
reserved draws are burned even if no query was sent. A named redirect chain can
therefore exhaust its allowance before5 hops or32 wire queries. Resolution tries
A then, when needed, AAAA within the remaining allowance.
Exhausted bank waits do not monopolize a physical connection or block numeric work.

`http.max_redirects` defaults to0 (return the3xx response) and accepts at most5.
GET follows301/302/303/307/308. Other methods, including HEAD/POST, follow only
307/308 while preserving method and fixed body. Relative targets are normalized;
each accepted hop retires the old physical session before requeue, even same-origin.
Cross-origin GET permits only Root Surf's public-header policy; unsafe credentials
or headers reject rather than being silently stripped. HTTPS downgrade is rejected.
There is one handle, completion, request lease, total cutoff and DNS allowance for
the entire chain. Errors retain the last validated status and write-effect context;
an earlier response never overwrites Unknown from an ambiguous later-hop write.

## Validation scope

The owned gates exercise public HTTP/TLS/DNS peers, copied inputs, connection
identity/framing, held-phase progress/cancellation, concurrent callers, new
allocation failures and late physical owners under ASan/TSan. Pair the compiler
and explicit core root as described in the parent `ci/WEBTOOLS_TOOLCHAIN.md`.
The held-phase evidence distinguishes68 public Client cases from12 layered core
boundary cases per sanitizer. A saturated SYN/connect stall is not certified by
those results; delaying peer accept alone does not prove a pending TCP connect.
These are Darwin loopback results; they do not certify Linux/Windows operation,
HTTP/2, QUIC, streaming responses or replacement of every blocking/curl API.

For a fresh full evidence run, select every source explicitly. The service
collection supplies the owning AWS/Google/auth sources; the gate first checks
that its Surf/HTTP/async Odin sources match the selected Client collection.
Service checks certify isolated import/build/run compatibility, not application
migration or a new offload implementation. Use a new report directory each time.

```sh
python3 "$WEBTOOLS_SHARED/surf/tests/final101.py" \
  --odin "$WEBTOOLS_ODIN" --core-root "$WEBTOOLS_CORE" \
  --shared-root "$WEBTOOLS_SHARED" \
  --service-shared-root "$WEBTOOLS_SERVICE_SHARED" \
  --report /tmp/webtools101-final/receipt.json
```

## Owned streaming (OKAMI-104)

Optional `Client_Config.streaming` enables bounded owned upload/response chunks
on the same Client actors. See [STREAMING.md](STREAMING.md) for APIs, detached
credits, late-owner destruction, gzip negotiation and limits. Matching Core must
include `18bd5dad0` (decoder plus owned-length guards); HTTP must include
`f557430`. Buffered defaults are unchanged.
