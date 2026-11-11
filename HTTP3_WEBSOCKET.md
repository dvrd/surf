# WebSockets over HTTP3

`websocket_http3_open(&client, &tunnel, &socket, url, config, headers)` opens an
RFC9220 stream using the existing WebSocket codec. The caller supplies stable
`HTTP3_Tunnel` and `WebSocket_Conn` storage and a persistent `Config.http3_pool`.
Set `Config.http3=true` to make ordinary `http_client_exchange` calls use that
same pool. Calls remain serialized; several live WebSockets share their QUIC
connection with those ordinary requests. HTTP3 batches are explicitly rejected.

The server must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1 before any CONNECT
is sent. A successful response is2xx with an optional offered subprotocol; HTTP1
Upgrade/Key/Accept fields are not used. Origin/subprotocol options and framing,
masking, ping/pong, message limits and close handling use the shared codec.

Read/write backpressure pumps all retained tunnels and the normal HTTP response.
Each endpoint has bounded8KiB receive/output queues; large H3 DATA payloads are
parsed incrementally. Deadlines/cancellation reset only the affected stream with
H3_REQUEST_CANCELLED. Closing a WebSocket finishes its stream; abort resets both
directions. Closing HTTP_Client detaches its own live handles safely. The external
pool remains caller-owned and must be closed separately to release TLS pins.

Keep the HTTP_Client and each live tunnel at stable addresses until close/abort.
The pool may serve several callers but its operations must be serialized. Active
tunnels pin their owning pool lane across identity rotation and ordinary request
admission; a full pinned pool rejects admission. Existing finite capacities and
server resource defaults are preserved.
