# WebSockets on HTTP/2

`websocket_http2_open` negotiates RFC8441 Extended CONNECT on a native
`HTTP_Client` lane. The client's TLS ALPN offers must include `h2`; an absent
`SETTINGS_ENABLE_CONNECT_PROTOCOL=1` returns a pre-send protocol error while
leaving the ordinary HTTP pool usable. There is no implicit HTTP1 retry.

```odin
protocols := []string{"h2", "http/1.1"}
client: surf.HTTP_Client
error := surf.http_client_init(&client,
    {tls={root_cas=roots, alpn_protocols=protocols}, timeout=5*time.Second},
    {}, context.allocator)
assert(error.kind == .None)
defer surf.http_client_close(&client)
tunnel: surf.HTTP2_Tunnel
socket: surf.WebSocket_Conn
error = surf.websocket_http2_open(&client, &tunnel, &socket,
    "https://example.test/socket", {origin="https://example.test"})
assert(error.kind == .None)
// Existing websocket_write_message/read_message/close use HTTP2 DATA here.
```

The caller owns the stable client, tunnel and WebSocket and serializes all their
operations. Closing a tunnel half-closes only its HTTP2 stream; abort sends
RST_STREAM(CANCEL). It does not close unrelated streams or the shared TCP/TLS
connection. Ordinary `http_client_exchange` calls may run between WebSocket
operations; they service all streams on the lane. Multiple tunnels are supported
within the configured stream and lane limits. A single client is not concurrently
thread-safe merely because HTTP2 multiplexes streams.

The handshake uses CONNECT, `:protocol=websocket`, scheme/authority/path and
Sec-WebSocket-Version13. It validates the selected subprotocol and rejects
unoffered/duplicate selections or unsupported extensions. It sends no HTTP1
Upgrade/Connection or Sec-WebSocket-Key/Accept exchange. Request headers can be
supplied explicitly through the final `headers` argument. Shared WebSocket
framing retains masking, UTF8/message limits and close/ping/pong behavior.

Incoming DATA retains bounded owned chunks until consumed. Empty and padding-only
DATA is not an EOF. Connection/stream flow credit returns as callers read; finite
per-tunnel chunk admission can reset only an overloaded stream, never silently
consume unlimited unread messages. Writes transfer bounded chunk copies into the
engine; local acceptance is not peer delivery. Late END_STREAM after a closed
WebSocket is handled without corrupting the next ordinary request.

A lane is bound to immutable TLS trust/ALPN configuration and the exact retained
client-credential Store generation. Identity rotation opens a new lane for new
requests while admitted WebSockets keep their original authenticated connection.
Pool close releases every retained credential generation. The implementation
uses the matching Core TLS `client_credential_lease` and credential-store identity
helpers; copying only Surf is insufficient.

Owned validation: `saba/tests/http2_connect.py` runs an independent Go wire peer
and native Surf client against Saba, including concurrent streams, ordinary
request fairness,128KiB backpressure, half-close/reset and optional mutual TLS
credential rotation. See Saba's `HTTP2_WEBSOCKET.md` for the server configuration.
