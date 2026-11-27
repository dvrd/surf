package tests

import "../../support/loopback"
import "core:fmt"
import "core:mem"
import "core:testing"
import "core:time"
import "shared:surf"

body_fetch :: proc(t: ^testing.T, wire: string, allocator: mem.Allocator) -> (surf.Response, bool) {
	peer := loopback.Server {
		answer = {wire = wire},
	}

	if !testing.expect(t, loopback.server_start(&peer)) {
		return {}, false
	}
	defer loopback.server_stop(&peer)

	url := fmt.tprintf("http://127.0.0.1:%d/", peer.port)
	response, error := surf.execute({method = .GET, url = url}, {allow_http = true, timeout = 5 * time.Second}, allocator)

	if !testing.expect_value(t, error.kind, .None) {
		surf.response_destroy(&response)
		return {}, false
	}

	return response, true
}

@(test)
response_body_transfer_survives_response_destroy :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	allocator := mem.tracking_allocator(&tracker)
	response, ok := body_fetch(t, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Fixture: yes\r\n\r\nbody", allocator)

	if !ok {
		return
	}

	defer surf.response_destroy(&response)
	value, found := surf.response_header(&response, "x-fixture")
	testing.expect(t, found && value == "yes")
	original := raw_data(response.body)
	capacity := cap(response.body_storage)
	chunk, transfer_error := surf.response_take_body(&response)
	defer surf.body_chunk_release(&chunk)
	testing.expect_value(t, transfer_error.kind, .None)
	testing.expect(t, raw_data(chunk.data) == original && string(chunk.data) == "body")
	testing.expect_value(t, len(chunk._owned.storage), capacity)
	testing.expect(t, response.body == nil && cap(response.body_storage) == 0)
	_, again := surf.response_take_body(&response)
	testing.expect_value(t, again.kind, .Invalid_Input)
	surf.response_destroy(&response)
	testing.expect_value(t, string(chunk.data), "body")
	testing.expect_value(t, tracker.current_memory_allocated, i64(capacity))
	surf.body_chunk_release(&chunk)
	testing.expect_value(t, tracker.current_memory_allocated, 0)
	frees := tracker.total_free_count
	surf.body_chunk_release(&chunk)
	surf.response_destroy(&response)
	testing.expect_value(t, tracker.total_free_count, frees)
}

@(test)
response_body_rejection_preserves_original_response :: proc(t: ^testing.T) {
	borrowed := []u8{'a', 'b'}
	response := surf.Response {
		status = 200,
		body   = borrowed,
	}

	_, error := surf.response_take_body(&response)
	testing.expect_value(t, error.kind, .Invalid_Input)
	testing.expect(
		t,
		response.status == 200 && raw_data(response.body) == raw_data(borrowed) && len(response.body) == 2,
	)
	_, nil_error := surf.response_take_body(nil)
	testing.expect_value(t, nil_error.kind, .Invalid_Input)
	// Mismatched views must not drop the response's actual owning storage.
	response.body_storage = make([dynamic]u8, 2, 8)
	defer delete(response.body_storage)
	original := raw_data(response.body_storage)
	_, mismatch := surf.response_take_body(&response)
	testing.expect_value(t, mismatch.kind, .Invalid_Input)
	testing.expect(t, raw_data(response.body_storage) == original && cap(response.body_storage) == 8)
}

@(test)
empty_body_can_transfer_as_an_owned_zero_byte_chunk :: proc(t: ^testing.T) {
	response, ok := body_fetch(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", context.allocator)

	if !ok {
		return
	}

	defer surf.response_destroy(&response)
	capacity := cap(response.body_storage)
	chunk, error := surf.response_take_body(&response)
	defer surf.body_chunk_release(&chunk)
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, surf.body_chunk_valid(&chunk) && len(chunk.data) == 0 && len(chunk._owned.storage) == capacity)
	surf.response_destroy(&response)
	surf.body_chunk_release(&chunk)
}
