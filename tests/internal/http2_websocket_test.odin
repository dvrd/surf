package surf

import tls "core:crypto/tls"
import "core:testing"
import "core:time"

@(test)
http2_websocket_requires_negotiated_permission_without_sending_or_poisoning_pool :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	peer := http102_start(t, "h2")

	if peer == nil {
		return
	}

	defer free(peer); defer http102_stop(peer)
	roots := http102_roots(t, "tests/testdata/credentials/root.pem")

	if roots == nil {
		return
	}

	defer free(roots); defer tls.root_pool_destroy(roots)
	protocols := [1]string{"h2"}
	client := http102_client(t, http102_config(roots.roots[:roots.count], protocols[:], 3 * time.Second), {})

	if client == nil {
		return
	}

	defer free(client); defer http_client_close(client)
	text: [96]u8
	url := http102_url(text[:], peer.port, "/echo")
	conn: WebSocket_Conn
	tunnel: HTTP2_Tunnel
	error := websocket_http2_open(client, &tunnel, &conn, url, {})
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, error.phase, .Protocol)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, conn.phase, .Uninitialized)
	testing.expect(t, tunnel._lane == nil)
	response, normal := http_client_exchange(client, {method = .GET, url = url})
	defer response_destroy(&response)
	testing.expect_value(t, normal.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "/echo")
	testing.expect_value(t, http_client_dials(client), 1)
}

@(test)
http2_websocket_invalid_owners_are_rejected_before_networking :: proc(t: ^testing.T) {
	client: HTTP_Client
	conn: WebSocket_Conn
	tunnel: HTTP2_Tunnel
	error := websocket_http2_open(&client, &tunnel, &conn, "https://127.0.0.1:9/", {})
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, client.dials, 0)
}
