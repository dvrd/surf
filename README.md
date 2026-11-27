# surf

An HTTP client for Odin: HTTP/1.1, HTTP/2 and HTTP/3 (opt-in), with TLS,
redirects, address policies, streaming bodies and WebSocket sessions. It runs
on `shared:async`, but its API is surf's own: callers build and
read surf types and never need an async type, except to join a runtime they
already run.

surf is pre-1.0. Until v1.0.0 a breaking change raises the minor version.

## Install

surf is imported from the `shared` collection:

```sh
ln -s "$PWD/src" ~/dev/oss/Odin/shared/surf    # and shared:async beside it
```

```odin
import "shared:surf"
```

## One request

`execute` runs a request on the calling thread and returns when it has the
whole response.

```odin
response, error := surf.execute(
	{method = .GET, url = "https://example.com/", headers = {{"Accept", "text/html"}}},
	{timeout = 10 * time.Second},
)
defer surf.response_destroy(&response)

if error.kind != .None {
	// error.phase and error.write_effect say where it failed and whether the
	// request may have reached the server.
	return
}

value, found := surf.response_header(&response, "Content-Type")
```

`execute_upload` sends a body from an `io.Stream` of a known length.

## Config

`Config` applies to every request it is given (a zero value is usable):

- `timeout` (30 s) bounds DNS, connect, TLS, I/O and redirects together;
  `setup_timeout` bounds connection setup alone.
- `max_body_size` (8 MiB) bounds every response body, including redirects.
- `max_redirects` (0, at most 5) follows redirects; POST follows only 307 and
  308.
- `allow_http` permits `http://` and `ws://`.
- `tls`: trust roots (nil trusts the platform's), client credentials and a
  session cache.
- `address_policy` sees the host and the exact addresses before any socket
  opens; `address_policy_public_only` refuses private and loopback ranges.
- `http3` opts in to HTTP/3; `alt_svc` lets an Alt-Svc advertisement turn it on
  per origin.

```odin
roots: surf.Trust_Roots
if surf.trust_roots_load_file(&roots, "ca.pem") != .None {
	return
}
defer surf.trust_roots_destroy(&roots)

config := surf.Config {
	tls            = {roots = &roots},
	max_redirects  = 3,
	address_policy = surf.address_policy_public_only,
}
```

## Errors

Every failure is an `HTTP_Error`:

- `kind`: what failed (`Dial_Failed`, `TLS_Failed`, `Deadline_Failed`,
  `Body_Oversized`, ...).
- `phase`: where it failed (`DNS`, `Connect`, `TLS`, `Write`, `Read`,
  `Protocol`, ...).
- `write_effect`: whether the request reached the server. `Unknown` is the zero
  value, so a non-idempotent request is never assumed safe to replay.
  `Not_Sent` means nothing reached the server; `Response_Received` means it
  answered.
- `status`: the last status seen, also when its body then failed.
- `tls_error`, `network`, `transport`, `allocation`, `decoding`, `budget`: the
  cause, when there is one.

## A Client

A `Client` keeps connections per origin and runs any number of requests at
once on one task. Every `client_` call is safe from any thread.

```odin
client: surf.Client
if error := surf.client_start(&client, {http = config}); error.kind != .None {
	return
}
defer surf.client_destroy(&client)

// Blocking, on this thread:
response, error := surf.client_execute(&client, {method = .GET, url = "https://example.com/"})

// Or submitted, then polled:
handle, submitted := surf.client_submit(&client, {method = .GET, url = "https://example.com/"})
for {
	completion, ready := surf.client_poll(&client)
	if ready && completion.request == handle {
		break
	}
	// wait on Client_Config.notify, or do other work
}
taken: surf.Response
surf.client_take(&client, handle, &taken)
surf.client_release(&client, handle)
```

There are three ways to run a client:

- `client_start` gives it a thread of its own.
- `client_init` joins an `async.Runtime` the caller already runs. Then
  `client_close`, wait for `client_quiescent`, and `client_destroy`.
- `execute` uses a client for one request, then tears it down.

`Client_Config.notify` is an `async.Signal` that wakes whenever a completion,
a stream event or a WebSocket operation is ready. It is the one wait for
everything the client does.

## Streaming

`client_submit_stream` hands the response head out with
`client_stream_take_head` and the body chunk by chunk with
`client_stream_next`, without buffering it. With `Stream_Options.upload_length`
the request body is pushed the same way: `client_upload_submit` takes
`Body_Chunk`s, then `client_upload_finish`. `Backpressure` means retry after
the next notify.

```odin
chunk, copied := surf.body_chunk_copy(data, len(data))
status, error := surf.client_upload_submit(&client, handle, &chunk)
// The client owns an accepted chunk. Anything else leaves it yours:
// surf.body_chunk_release(&chunk)
```

## WebSockets

Sessions run on a Client and share its `Config`: TLS, resolver, address
policy, and `allow_http` for `ws://`. Every operation completes through its
callback on the client's task, outside the client's lock, so a callback may
start the next operation.

```odin
on_open :: proc(op: ^surf.WebSocket_Op) {
	if op.error.kind != .None {
		return // op.error.status, .upgrade, .tls_error say why
	}
	// start a client_websocket_read
}

open: surf.WebSocket_Op = {callback = on_open}
socket, error := surf.client_websocket_open(
	&client,
	"wss://example.com/chat",
	{origin = "https://example.com", subprotocols = {"chat"}},
	&open,
)
```

- `client_websocket_read` completes with one whole message copied into the
  buffer.
- `client_websocket_write` completes once the message is queued.
- `client_websocket_close` sends any queued messages, then the Close
  handshake.
- `client_websocket_cancel` cancels one pending operation.
- `client_websocket_release` ends the session and frees it.

`WebSocket_Error.close` reports how a session ended.

## Tests

```sh
task test                 # every suite
task test INTERNAL=1      # unit suite only
task gate                 # acceptance gates
task gate GATE=stream VERBOSE=1
```

`WEBTOOLS_SHARED` selects the collection that holds `shared:async`
(default `~/dev/oss/Odin/shared`).
