# Bounded native connection setup (OKAMI-138)

Native `execute` and `execute_upload` now carry a total deadline through hostname resolution, TCP connection establishment, TLS authentication and request/response I/O. No event loop, extra thread or callback pumping is involved. `buffered_http_execute` uses this client and does not link libcurl.

`Config.timeout = 0` retains the 30-second total default. `Config.setup_timeout = 0` spends the remaining total budget on a new connection; a positive value caps DNS, TCP and TLS together for each connection, always within that same total deadline. Negative values fail before I/O. Redirects retain the original total deadline. TLS also retains its own configured handshake limit (zero selects ten seconds), capped by the remaining setup budget. The new fields follow the existing fields; zero and named aggregates remain supported. Applications using positional aggregates should move to named fields when updating this public configuration type.

The legacy adapter's policy can eventually be represented by `timeout = timeout_ms * time.Millisecond`, `setup_timeout = min(timeout_ms, 5000) * time.Millisecond`, with redirects disabled. This prerequisite alone does not replace that adapter or establish all compatibility requirements.

`Config.resolver.name_servers` optionally borrows explicit numeric DNS endpoints for a call. Nil reads the existing platform resolver configuration; no global timeout, resolver list or hosts configuration is mutated. The endpoint resolver prefers IPv4 and only queries IPv6 when no IPv4 answer is found. Unlike the old two-family `resolve`, it does not wait for an unnecessary AAAA lookup after obtaining a usable A record. `resolve_endpoint_until` still returns that one address. Dialing a hostname walks later A answers and then AAAA answers inside the caller deadline, at most eight candidates. Happy Eyeballs is not implemented.

## Core APIs and platform scope

New core entrypoints leave existing exported signatures intact:

- `tls.handshake_until(conn, deadline)` caps the configured/default handshake limit with the exact absolute cutoff, without rebasing a previously computed duration or mutating initialized configuration. It checks expiry after synchronous deadline callbacks, allocation, Finished writes and successful activation before exposing application state. Zero preserves the old `handshake` behavior.

- `net.dial_tcp_until(endpoint, deadline, options)` connects to a numeric endpoint and returns a blocking socket. A zero deadline delegates to the old endpoint dialer. Explicit deadlines use nonblocking connect, readiness, `SO_ERROR`, and restored blocking mode on Darwin/Linux. Other platforms return `Dial_Error.Unsupported`.
- `net.get_dns_records_from_nameservers_until(..., deadline, allocator)` shares one absolute deadline across nameservers. Zero preserves the existing receive policy. Nonzero socket timeouts are never rounded down to zero, which would disable the timeout.
- `net.get_dns_records_from_os_until(...)` uses the existing Unix resolver configuration/hosts path. A nonzero deadline on an OS-only resolver without a bounded implementation returns `DNS_Error.Unsupported`, including Windows.
- `net.resolve_endpoint_until(hostname, port, deadline, options, allocator)` also accepts numeric addresses without DNS and returns one endpoint. DNS `Timeout` remains visible as Surf phase `Deadline`, with `Not_Sent` write effect during setup.

Nonzero DNS deadlines are supported by the existing Unix UDP timeout backends; other platforms explicitly return `Unsupported`, even with custom nameservers. Numeric TCP setup is implemented only for Darwin/Linux. Executable certification in this change is Darwin arm64; Linux arm64 has semantic compilation coverage, not runtime certification. Blocking local resolver-file reads, allocator callbacks and cryptographic CPU work are cooperative. Socket deadlines are not hard real-time scheduling guarantees.

TLS keeps certificate and hostname verification. A nil root list fails before dial. A non-nil empty list, including `ca_file == ""`, loads Darwin system anchors and still rejects an unknown private CA. An explicit `ca_file` is the only trust set for that call and is not merged with the system store. The client offers TLS 1.3 and the two fresh-ECDHE TLS 1.2 suites `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. There is no session ticket, resumption, renegotiation, or fallback reconnect. A failed handshake does not send a TLS alert; the peer can observe an unexpected EOF. The buffered client ignores proxy environment variables, follows no redirects, and caps the response at 64 KiB. HTTP/1 sends the method token unchanged. HTTP/2 accepts only `GET`, `POST`, `PATCH`, `HEAD`, `PUT`, `DELETE`, and `OPTIONS`, and does not forward the buffered header list. `provider_code` on a native transfer is zero. No generic retry is introduced; write outcomes retain their existing conservative meaning. A timeout after TCP exists is `write_effect` `Unknown` on the buffered result, including a handshake that wrote no HTTP request. `execute` still reports that handshake timeout as `Not_Sent`. `Unknown` is never replay-safe.

## Offline evidence

Use clang from the LLVM version matching the compiler when enabling ASan. For the tested compiler:

```sh
export PATH=/opt/homebrew/opt/llvm@22/bin:$PATH
/path/to/native-core/odin test core/net -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
/path/to/native-core/odin test core/crypto/tls -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
/path/to/native-core/odin test shared/surf/tests -thread-count:1 -warnings-as-errors \
  -sanitize:address -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
python3 shared/surf/tests/setup_loopback.py --odin /path/to/native-core/odin
```

The local fixture owns every listener and child. Fifteen scenarios are available, with eight repetitions per executed scenario; the backlog probe explicitly skips when its owned queue cannot be saturated. They cover silent DNS through core and public Surf, successful A resolution, tiny deadlines, delayed DNS followed by stalled TLS, TCP success/blocking restoration, refused TCP, total/setup/TLS handshake limits a saturated backlog, and successful authenticated TLS handshakes with deliberately delayed Finished-write or deadline-clear callbacks under both an earlier caller deadline and an earlier configured handshake limit. Every attempt verifies zero retained tracked allocations; every scenario verifies unchanged descriptor count and that an already queued caller nbio callback runs only after explicit `nbio.run`. The Darwin backlog probe can return immediate resets or admit more connections as the kernel queue changes; both outcomes must be bounded and successful sockets are closed. That scenario verifies resource cleanup and bounded completion, not deterministic execution of a pending-connect timeout branch.

The deterministic baseline request configured for 40 ms spent about 1.004 seconds in a silent TLS peer with a one-second handshake setting. With this prerequisite, eight equivalent requests finish in about 328 ms combined. Delaying DNS by 25 ms before the silent TLS peer still takes about 328 ms for eight requests, demonstrating one shared setup budget. Callbacks that deliberately overrun their budget return typed deadline failure when they return; they cannot be preempted. The earlier configured handshake deadline remains effective through those terminal callbacks even when the caller deadline is later. No authenticated application state is exposed after that expiry. These are local failure-path checks, not Internet-provider interoperability or throughput benchmarks.
