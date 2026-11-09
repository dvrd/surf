# Conservative TLS checkout prerequisite

Current public APIs cannot establish absence of encrypted bytes left by an old
HTTP response: set_request_budget proves operation idleness only; wait_stream is
sticky readiness, and cancellation of a speculative TLS read can retain partial
records. The source-only review selected two owning additive capabilities rather
than a speculative read/cancel algorithm or raw byte-counter inference.

core:crypto/tls adds async_idle_state(^Async_Conn) -> Async_Idle_State, an opaque
Ready/Busy/Buffered/Closed/Invalid classification on the executor owner thread.
It allocates nothing, performs no I/O and mutates no connection state. The API
implementation freezes exact precedence and exhaustively audits both Async_Conn
and embedded protocol receive/plaintext/posthandshake/keyupdate/transmit states.
Only a complete authenticated live handshake with no pending jobs, accepted raw
or application operations, partial record or buffered plaintext/control output can
be Ready. Ready is a local snapshot, never a network liveness promise.

shared/async adds probe_stream(Socket) -> (Stream_Probe, Error), where Stream_Probe
is Empty/Data/Closed on success; errors must not be interpreted as Empty. Validate
live generation, Stream kind, current task and cancellation under reactor.mu.
Use exactly one 1-byte MSG_PEEK receive on the already nonblocking registered
socket; EAGAIN/EWOULDBLOCK means Empty, positive means Data, zero means Closed.
EINTR is an error, not a retry loop. Unsupported platforms return Unsupported.
No consumption, allocation, callbacks, timer, interest or sticky-readiness mutation.
The socket remains actor-owned; no raw descriptor or encrypted bytes are exposed.

Before writing request B on an idle authenticated connection, the actor requires
local TLS Ready, successfully installs B's fresh retained request cap preserving
Client lifetime, then requires the owned raw probe Empty. Any buffered/ciphertext
bytes, including KeyUpdate, stale closure or error cause conservative retirement
BEFORE B is written. No automatic replay follows an ambiguous request write.
Plain streams require the same raw Empty check plus no pending Exchange/adapter
operations. Bytes arriving after the probe remain an ordinary protocol/transport
race; this API does not promise race-free peer health.

Four separate API/test tasks in phase3a precede the generic exchange native idle
policy gate, which precedes session actor implementation. Resolver/task-group/
exchange schema may continue independently. The mandatory real TLS gate includes
healthy same-TLS A-to-B after A's expired cutoff, separately queued ciphertext,
partial record headers/body, locally retained partial record after cancelled read,
buffered plaintext/control output, KeyUpdate, EOF/reset and no byte consumption.
The independent gate must preserve hashes/actual traces and run ASan/TSan. A unit
classification test is not a substitute for that actual wire evidence.

No original OKAMI-101 criterion is completed by this prerequisite. Full redirects,
request deadline, ownership, identity, concurrency and shutdown acceptance remain
in the reviewed network and subsequent redirect/final phases.
