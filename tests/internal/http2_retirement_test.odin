package surf

import http "shared:async/http"
import "core:testing"
import "shared:async/tls"
import "core:time"

@(test)
http2_completed_stream_retirement_reuses_single_slot_after_resets :: proc(t: ^testing.T) {
	http_retirement_sequence(t, 1)
}

@(test)
http2_completed_stream_retirement_exceeds_default_capacity_after_resets :: proc(t: ^testing.T) {
	http_retirement_sequence(t, 8)
}

@(test)
http2_completed_stream_retirement_exceeds_maximum_capacity_after_resets :: proc(t: ^testing.T) {
	http_retirement_sequence(t, 32)
}

http_retirement_sequence :: proc(t: ^testing.T, streams: int) {
	testing.set_fail_timeout(t, 120 * time.Second)
	peer := http102_start(t, "h2")

	if peer == nil {
		return
	}

	defer free(peer); defer http102_stop(peer)
	roots := http102_roots(t, "tests/testdata/credentials/root.pem")

	if roots == nil {
		return
	}

	defer free(roots)
	// http102_roots owns a native root pool; cleanup matches the existing peer tests.
	defer tls.root_pool_destroy(roots)
	protocols := [?]string{"h2", "http/1.1"}
	client := http102_client(
		t,
		http102_config(roots.roots[:roots.count], protocols[:], 2 * time.Second),
		{max_streams = streams},
	)

	if client == nil {
		return
	}

	defer free(client); defer http_client_close(client)
	echo_buffer, reset_buffer: [96]u8
	echo := http102_url(echo_buffer[:], peer.port, "/echo")
	reset := http102_url(reset_buffer[:], peer.port, "/reset")

	for pass in 0 ..< 2 {
		for index in 0 ..< 64 {
			if pass == 1 && (index == 0 || index == 32 || index == 63) {
				before := http102_count(&peer.log, `"path":"/reset"`)
				response, error := http_client_exchange(client, {method = .GET, url = reset})
				response_destroy(&response)
				testing.expect_value(t, error.kind, .IO_Failed)
				testing.expect_value(t, error.phase, .Protocol)
				testing.expect_value(t, error.write_effect, .Unknown)
				testing.expect_value(t, http102_wait_count(&peer.log, `"path":"/reset"`, before + 1) - before, 1)

				if testing.failed(t) {
					return
				}
			}

			response, error := http_client_exchange(client, {method = .GET, url = echo})
			testing.expectf(
				t,
				error.kind == .None,
				"streams=%d pass=%d index=%d error=%v",
				streams,
				pass,
				index,
				error,
			)
			testing.expect_value(t, string(response.body), "/echo")
			response_destroy(&response)

			if testing.failed(t) {
				return
			}
		}
	}

	response, error := http_retirement_stack_borrow(client, echo)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, string(response.body), "/echo")
	response_destroy(&response)
	testing.expect_value(t, http_client_dials(client), 1)
}

// The caller's request borrows end when exchange returns. Retaining the completed
// stream's scalar handle must not imply retaining these stack-backed headers/body.
http_retirement_stack_borrow :: proc(client: ^HTTP_Client, url: string) -> (Response, HTTP_Error) {
	headers := [1]http.Header{{"Content-Type", "text/plain"}}
	body := [2]u8{'o', 'k'}

	return http_client_exchange(client, {method = .POST, url = url, headers = headers[:], body = body[:]})
}

// Transport completion and the independent peer-log reader are separate events.
http102_wait_count :: proc(log: ^Http102_Log, needle: string, expected: int) -> int {
	start := time.tick_now()

	for time.tick_since(start) < 2 * time.Second {
		count := http102_count(log, needle)

		if count >= expected {
			return count
		}

		time.sleep(time.Millisecond)
	}

	return http102_count(log, needle)
}
