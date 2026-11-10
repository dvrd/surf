## Target

shared/surf; shared/async/core networking and TLS

## Problem

execute is blocking/buffered and each redirect establishes a fresh connection.

## Acceptance criteria

- [x] Provide a compatible async request API with explicit response ownership, cancellation and one total request/redirect deadline.
- [x] Add a bounded origin-aware reusable connection pool; never share authenticated connections across incompatible host/trust/proxy settings.
- [x] Test pool exhaustion, stale connections, redirects and concurrent callers without blocking connection workers.

## Prerequisites

* Async: add outbound TCP connect and bounded DNS integration
* Async: bridge task runtime to asynchronous TLS executors safely

Blocking relations link the prerequisite issues.

Planned work. Preserve existing consumers and owned-code provenance; obtain scoped approval before implementation.

## Agreed scope refinement — 2026-11-06

- [x] Surf is the single reusable native client for AWS, Google, auth and other consumers, independent of Saba.
- [x] Start the total deadline before DNS/connect and carry it through handshake, redirects, body transfer and offload; document cancellation latency.

## Backlog planning

* **Type:** Feature
* **Size:** XL — Too broad or uncertain for one implementation ticket; split into independently verifiable children before coding.
* **Importance:** High — Async requests and bounded connection reuse are a shared capability needed by many libraries.
* **Delivery phase:** 2 · Integration
* **Development order:** 25 of 56 actionable tickets (dependencies take precedence; independent tasks may run in parallel).
* **Prerequisites:** OKAMI-89, OKAMI-88
* **Sizing confidence:** high uncertainty; relative effort, not a calendar commitment.
* **Next action:** Split this ticket into smaller verifiable implementation children before starting; preserve its acceptance criteria and blockers.

Execution authorization: user requested resolving the remaining backlog with parallel streams, local commits only. Preserve blocking Surf and legacy buffered curl APIs; native async HTTP1/pooling are101, HTTP2integration102 and curl replacement133 remain separate.


## Verified completion record

All five original criteria above were independently reviewed and verified for the
agreed native, fixed-body, buffered HTTP/1 scope after the fresh current-source
required gate passed. Criterion text and scope are unchanged. See
[acceptance-final101.md](acceptance-final101.md) for the criterion mapping and
explicit evidence boundaries.

Final receipt: [`evidence/final101/required/receipt.json`](../../../evidence/final101/required/receipt.json).
SHA256: `051f3f2d4d7b0a7786b98251a79d9f24868d02bc15711525a055f076921b7c62`.
All nine required runners pass with no skips: 522 native cells split into 450
public Client, 48 fixture-controller actor and 24 layered Runtime Connecting-slot
cells. Whole async112, Exchange14 and unchanged-facade27 tests pass under each
ASan/TSan; 19 negative controls, two standalone consumer executions, 14 native
link/symbol audits and three isolated AWS/Google/auth compatibility builds pass.

Validation is Darwin arm64 only. The layered socket cases do not certify a public
Client stalled SYN or Client setup/lifetime behavior for the external raw Task.
Queued Client-lifetime closure uses Cancellation. No Linux/Windows, application
offload implementation, service/application migration, Mesa vendored-copy update,
production performance, HTTP/2/streaming integration or complete legacy curl
replacement is claimed. Those explicit limits and separate work remain as
recorded in the acceptance review and README.
