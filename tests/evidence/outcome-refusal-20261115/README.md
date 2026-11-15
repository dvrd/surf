# Refused-connect fixture expectation

The original retained monitor-verification failure is preserved byte-for-byte
inside original.log.gz. All202 canonical Surf files matched Mesa at diagnosis;
the failure was not a library-copy mismatch. The42-case compatibilityASan gate
contained no refused-connect case and independently passed its completed503.

A single owned diagnosticASan run retained the original assertion and printed
only fixed typed error fields. It reproduced Dial_Failed/Deadline/Not_Sent,
status0/provider0/networkTimeout/transportNone, then trapped at the same refusal
assertion. No URL/header/body/credential was logged. The adapter is native;
existing curl labels are retained without unrelated renaming.

The cleartext buffered path returns bounded_socket setup failure directly before
TCP establishment. Typed Dial_Error.Timeout classifies as Deadline while retaining
Not_Sent, matching OUTCOMES.md. The old fixture instead required Unknown for every
Deadline. The corrected refused-port predicate accepts Connect or Deadline but
requires Not_Sent in both cases; it no longer accepts ambiguous Unknown as the
owned pre-TCP refusal outcome. It does not widen runtime behavior or replay safety.

A deterministic typed setup-timeout classification regression was added in the
existing outcomes_test.odin. The focused package passes29ASan tests; the corrected
owned outcome harness passes all16cases, including completed503 and exact POST
counts. Diagnostic pre-change failure and post-change logs/source bindings are
retained here. The harness owns its loopback peers and bound non-listening port;
there are no provider calls, CI dispatches, grants or production runtime changes.

This evidence fixes a fixture acceptance gap. Why this platform produced a connect
Timeout rather than immediate refusal is not diagnosed, and no network runtime
fix is claimed. Canonical adoption and Mesa consumer integration remain root-owned.
