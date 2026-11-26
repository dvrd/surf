package tests

import "../../support/loopback"
import "base:runtime"
import "core:fmt"
import "core:testing"
import "core:time"
import "shared:surf"

@(test)
setup_negative_timeout_rejected_before_io :: proc(t: ^testing.T) {
	response, error := surf.execute({method = .POST, url = "https://fixture.invalid/"}, {setup_timeout = -time.Second})
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

// The caller's allocator owns only the Response: a nil one fails once the head
// is copied, with the allocation cause and the observed status kept.
@(test)
setup_nil_response_allocator_failure_is_typed :: proc(t: ^testing.T) {
	peer := loopback.Server {
		answer = {wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
	}

	if !testing.expect(t, loopback.server_start(&peer)) {
		return
	}
	defer loopback.server_stop(&peer)

	url := fmt.tprintf("http://127.0.0.1:%d/", peer.port)
	response, error := surf.execute(
		{method = .POST, url = url},
		{allow_http = true, timeout = 3 * time.Second},
		runtime.nil_allocator(),
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Allocation_Failed)
	testing.expect_value(t, error.allocation, .Out_Of_Memory)
	testing.expect_value(t, error.status, 200)
	testing.expect_value(t, error.write_effect, .Response_Received)
	testing.expect_value(t, loopback.server_requests(&peer), 1)
}
