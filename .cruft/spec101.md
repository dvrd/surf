## Target

shared/surf; shared/async/core networking and TLS

## Problem

execute is blocking/buffered and each redirect establishes a fresh connection.

## Acceptance criteria

- [ ] Provide a compatible async request API with explicit response ownership, cancellation and one total request/redirect deadline.
- [ ] Add a bounded origin-aware reusable connection pool; never share authenticated connections across incompatible host/trust/proxy settings.
- [ ] Test pool exhaustion, stale connections, redirects and concurrent callers without blocking connection workers.

## Prerequisites

* Async: add outbound TCP connect and bounded DNS integration
* Async: bridge task runtime to asynchronous TLS executors safely

Blocking relations link the prerequisite issues.

Planned work. Preserve existing consumers and owned-code provenance; obtain scoped approval before implementation.

## Agreed scope refinement — 2026-11-06

- [ ] Surf is the single reusable native client for AWS, Google, auth and other consumers, independent of Saba.
- [ ] Start the total deadline before DNS/connect and carry it through handshake, redirects, body transfer and offload; document cancellation latency.

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
