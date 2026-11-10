# OKAMI-101 final acceptance review

All five original criteria are verified for the agreed fixed-body, buffered,
native HTTP/1 Client scope. Independent review found no concrete acceptance
blocker in the fresh current-source final gate. The original criterion wording
and scope in [spec101.md](spec101.md) are unchanged.

The required receipt is
[`evidence/final101/required/receipt.json`](../../../evidence/final101/required/receipt.json),
SHA256 `051f3f2d4d7b0a7786b98251a79d9f24868d02bc15711525a055f076921b7c62`.
It reports `passed=true`, all nine required runners, and no skipped evidence.
Earlier phase receipts remain historical evidence; this review uses the fresh
subreports referenced by this final receipt.

## Five original criteria

| Original criterion | Verified evidence and scope |
|---|---|
| Provide a compatible async request API with explicit response ownership, cancellation and one total request/redirect deadline. | The additive `surf/async` API uses existing `http.Request` and `surf.Response`. Public Client smoke, redirect, cancellation, concurrent poll/direct-take and failure matrices verify cloned caller inputs, one terminal result per accepted handle, late Response disposal after Client/Runtime destruction, and retained original cutoffs. The unchanged blocking facade also executes in the standalone consumer. |
| Add a bounded origin-aware reusable connection pool; never share authenticated connections across incompatible host/trust/proxy settings. | Pool and concurrency peers verify bounded actual socket counts, framing-safe reuse and retirement, idle/max-age expiry, stale/partial/KeyUpdate handling, scheme/hostname/port and separate-Client isolation. Wrong trust and hostname produce actual independent TLS authentication failures without data from a trusted session. Proxy policy is Direct only; alternate per-request proxy settings are not offered. |
| Test pool exhaustion, stale connections, redirects and concurrent callers without blocking connection workers. | Public tests combine bounded admission pressure, four producer threads, two competing consumers, literal stale/redirect peers and one-worker cheap-origin progress during real DNS/TLS/write/header/body/redirect/queue holds. The separate actor-fixture and Runtime socket-boundary evidence is identified below rather than represented as public Client coverage. |
| Surf is the single reusable native client for AWS, Google, auth and other consumers, independent of Saba. | Current native Client closures omit Saba; source review found no blocking `execute`, curl, sleep or per-request thread creation in the production async path. Fourteen native link/symbol audits omit Saba, curl/nghttp2 provider linkage and easy-perform/multi calls. Isolated AWS/Google/auth consumers build, link and run against production SDK sources verified identical to the tested candidate. These are compatibility checks, not service/application migration or behavioral tests. |
| Start the total deadline before DNS/connect and carry it through handshake, redirects, body transfer and offload; document cancellation latency. | Submission selects the original minimum cutoff before validation, admission, allocation and cloning. Public held-phase and redirect-chain cases verify queue/DNS/TLS/write/body and cumulative-hop expiry, setup shorter than total and total shorter than setup, post-work deadline checks and preserved failure context. The README documents nonpreemptible allocation/free, resolver preparation and TLS crypto. The fixed-body API has no application-offload implementation; no offload certification is implied. |

## Required execution and provenance

The final gate validates these literal native execution matrices under both
AddressSanitizer and ThreadSanitizer:

| Required runner | Native cells | Evidence layer |
|---|---:|---|
| `session_actor101.py` | 48 | Actual network actor with a fixture Kernel controller; not `Client.init` |
| `client101.py` | 12 | Public Client |
| `redirect101.py` | 122 | Public Client |
| `pool101.py` | 56 | Public Client |
| `cancel101.py` | 160 | 136 public Client plus 24 explicitly layered Runtime boundaries |
| `concurrency101.py` | 8 | Public Client |
| `failure101.py` | 116 | Public Client |
| **Total** | **522** | **450 public Client + 48 actor-fixture + 24 layered Runtime** |

These are scenario/process cells, not counts of individual HTTP requests or
assertions. Some framing and concurrency cells execute many requests. The other
two required runners are `redirect_foundations101.py` (18 independent focused
aggregates per sanitizer) and `consumer101.py` (two standalone public Client and
unchanged-facade executions, one per sanitizer).

Current-source whole-package checks pass with 112 `surf/async`, 14
`surf/async/exchange`, and 27 unchanged-facade `surf/tests` tests per sanitizer.
The whole Exchange14 includes the focused getter3; those are not 17 independent
tests. Nineteen negative controls pass. Three additional historical owned
stage probes verify Reading during held TCP/TLS bodies and Handshaking after a
received ClientHello; these are not added to the required 522-cell count.

Independent review rechecked every required subreport's literal cell set and
sanitizer selection, current source/copy/core and tool maps, recorded command logs,
artifact hashes, native-result/log correspondence and cancellation layer counts.
The final gate also verifies imported package inventories, fixture/source stability,
14 current native link/symbol audits, and the isolated service compatibility
source/copy maps. Each of the nine fresh subreports binds 168 physical closure
files; the final core map binds 2,675 standard-library source files.

The compiler is `dev-2026-11:c826157de`, SHA256
`dac83d6eb5faaf9f62cef37297f34a0e21dbe3976a8b8a52c81f3db3d90f0b9c`,
with the explicit candidate core root and recorded Go/helper identities. This is
Darwin arm64 evidence.

## Limits retained at acceptance

- A public Client stalled SYN is not certified. The owned Darwin listen-backlog
  experiment resets additional connections immediately; delayed accept is not
  called a pending-connect proof. No sysctl, route or firewall change was made.
- The 24 layered Runtime cells hold a real accepted `Connecting_Socket` before
  `finish_connect` on an external Task/socket outside the Client connection cap.
  They verify release, cancel, close, Runtime shutdown and original/shortened
  budgets while a cheap public Client TCP/TLS request progresses on the same
  single-worker Runtime. They are not Client setup/lifetime or stalled-SYN tests.
- Client lifetime expiry closes the whole Client. Still-queued requests may finish
  with shutdown-style Cancellation; request-local deadline failures remain
  distinct. Cancellation and deadline bounds do not preempt synchronous work or
  promise a hard wall-clock physical-drain latency.
- Fixed Signal control metadata remains outside the request Scope. Scope and
  allocator counters are not process RSS. TLS certificate objects remain borrowed
  immutable through physical session close.
- Linux/Windows, production load/performance, application offload, live AWS/Google/
  auth behavior, service/application migration and Mesa vendored-copy integration
  are not certified here. Existing worktrees and application copies are preserved.
- HTTP/2 integration remains OKAMI-102, streaming responses remain OKAMI-104, and
  replacement of legacy buffered curl APIs remains OKAMI-133. Blocking file-upload
  helpers remain separate; their removal or migration is not claimed.

Root authorized publication after the successful final gate. This review changes
only this acceptance record and the five checkboxes plus validation note in
`spec101.md`; it makes no Linear change, commit, push or SDK/fixture edit.
