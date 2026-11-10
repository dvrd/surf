# Independent streaming wire verification

`../stream104.py` builds a physical shared-package closure and this public Client
host, then runs an independent Go raw HTTP/1 peer over TCP and TLS 1.3. The peer
generates its own synthetic loopback certificate; the native client verifies it
through an explicit root pool and negotiates HTTP/1.1. No production endpoints,
credentials, application data, Mesa sources or system settings are used.

```sh
python3 surf/tests/stream104.py \
  --odin /absolute/path/to/matching/odin \
  --core-root /absolute/path/to/matching/Odin \
  --shared-root /absolute/path/to/shared \
  --evidence-dir /tmp/fresh-stream104-evidence \
  --report /tmp/fresh-stream104-evidence/receipt.json \
  --final
```

The compiler must match the selected standard library, including its incremental
gzip decoder. LLVM 22 must supply the intended ASan/TSan runtime. The runner adds
the configured local LLVM 22 directory to PATH; `--go` and `--go-root` select an
explicit Go toolchain. Owned loopback listeners require a permitted execution
environment. The runner does not change the selected toolchain.

`--sanitizers address` selects one sanitizer. Repeat `--case <exact-name>` for a
focused development subset. Without `--final`, a receipt is explicitly marked
`acceptance:false`; development success is not final frozen-source evidence.
Each run requires a fresh evidence directory. Failed attempts and peer/native
logs are retained. Final receipts bind source/resources, the physical closure,
compiler, executables, exact selected names and every observed native/peer row.

The matrix covers known-length 32 MiB, chunked and EOF responses, fragmented input,
malformed framing, raw buffered compatibility, bounded output and upload credits,
late independent head/chunk destruction, autonomous timeout/cancellation, owned
uploads and early final responses, gzip validation and byte ceilings, and the
existing safe redirect policy. Two TCP-only allocation cells fail the first actor
engine grant and the response descriptor grant after its header storage exists;
they check typed failure, no partial successful publication and physical cleanup.
The TLS-only downgrade case proves that the HTTP destination is never contacted.
The literal matrix and transport exclusions are in the runner; no unexecuted
Cartesian product is implied.

The normal Client work budget is 128, its documented finite default. The fairness
cell deliberately uses budget 1 and one worker: an unrelated cheap buffered GET
must finish while the streaming response holds all output credits. Its held peer
is independently observed to remain live until explicit cancellation.

Large identity responses use bounded 16 KiB peer scratch and an incremental native
digest. A first-chunk barrier prevents the peer from producing the remaining
entity until the native caller has already taken data. Native peak backing may
grow at most 4 MiB above initialized Client/Runtime storage; the output pool remains
at most 32 KiB. Gzip vectors use Go's implementation, then independently alter CRC,
ISIZE or trailer/member bytes. Only a successful End certifies the complete
encoding. A retained prefix remains valid even after a later checksum failure.
The peer computes each response mode's immutable expected pattern digest before
publishing its endpoint. Short client deadlines therefore measure the owned
protocol scenario rather than a 32MiB test-oracle preparation step.

Large gzip correctness cells that decode at least 4 MiB use a finite 30-second
total request cutoff and a 40-second native process/consumer guard. The decoded
amplification-limit case still uses its short output ceiling and original budget;
explicit deadline, cancellation and fairness cutoffs are unchanged. An initial
10-second large-gzip fixture budget failed under concurrent sanitizer CPU load
and is preserved as a failed development attempt, not a throughput claim.
The TLS fragmentation cell also retains all 4,096 one-byte application records
under that 30-second cutoff and 40-second guard: TSan instrumentation exceeded
the original ten-second fixture budget. The plaintext fragmentation payload and
budget, all data/End/cleanup assertions, and dedicated short deadlines are
unchanged. This record-boundary correctness workload supplies no throughput SLO.

HEAD/204/304 responses advertise gzip and a 12345-byte representation while the
configured encoded/decoded limits are 1: they must retain wire metadata, return
no chunks and finish without invoking a body decoder. Unsupported coding chains
and repeated Content-Encoding are rejected before head publication.

For backpressure deadlines, the caller stops all Client API calls after taking
both output slots. The blocked peer must observe physical transport retirement
before polling resumes. For early413, the peer first confirms the request head,
then waits for 100 ms stable upload-credit backpressure with no owner releases.
It sends the complete final response before boundedly discarding at most 4 MiB of
in-flight upload bytes, below the 32 MiB declared body. This prevents an unread-data
TCP reset from erasing the response while still rejecting a sequential writer
that requires producer EOF. Accepted/rejected source owners and actual received
bytes are recorded separately; acceptance never claims peer receipt.

The held-write producer-error cell uses the same stable backpressure barrier,
then calls `client_upload_finish(Unexpected_EOF)`. Its peer refuses to drain any
body until the native request has already completed. The source error must retain
its Write phase and finish within two seconds, before the ten-second request
cutoff, while cancelling pending writes and releasing every accepted owner.

The redirect tests preserve the existing policy: public GETs can follow a changed
origin; credentialed/custom-header requests are rejected rather than silently
forwarded or rewritten. Intermediate heads and bodies are private. The 250 ms
request cutoff remains authoritative across new connections and TLS handshakes;
the peer permits its second handshake to abort when that original budget expires.

Every native cell checks scope/heap/TCP-descriptor cleanup and exact accepted
source disposal. Held heads/chunks are read and destroyed after Client, Runtime
and their public headers are physically freed. Seven deliberately incorrect
measurement controls must be rejected by the independent runner. These finite
Darwin protocol/ownership checks make no performance, cross-platform runtime,
general fuzzing or release-certification claim.
