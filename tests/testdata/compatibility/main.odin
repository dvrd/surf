package main

import surf "../../.."
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:time"

// Arguments describe a request; the Python peer independently records its wire.
main :: proc() {
	assert(len(os.args) >= 9)
	method, url, ca, file_path := os.args[1], os.args[2], os.args[3], os.args[4]
	size, size_ok := strconv.parse_i64(os.args[5])
	assert(size_ok)
	timeout, timeout_ok := strconv.parse_i64(os.args[6])
	assert(timeout_ok)
	body: []byte
	if os.args[7] == "body" do body = transmute([]byte)string("body")
	headers := os.args[9:]
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&tracker)
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena, block_allocator = allocator, array_allocator = allocator)
	previous := context
	context.allocator = allocator
	context.temp_allocator = mem.dynamic_arena_allocator(&arena)
	file: ^os.File

	if file_path != "-" {
		opened, error := os.open(file_path)
		assert(error == nil)
		file = opened
	}

	started := time.now()
	data, result := surf.buffered_http_execute(
		method,
		url,
		body,
		headers,
		ca,
		allow_http = os.args[8] == "http",
		timeout_ms = timeout,
		upload_file = file,
		upload_size = size,
	)
	elapsed := f64(time.diff(started, time.now())) / f64(time.Millisecond)
	position: i64 = -1

	if file != nil {
		value, error := os.seek(file, 0, .Current)
		assert(error == nil)
		position = value
		assert(os.close(file) == nil)
	}

	all_r := true
	for byte in data do if byte != 'R' do all_r = false
	fmt.print("{")
	fmt.printf(
		"\"status\":%d,\"ok\":%v,\"transport_ok\":%v," +
		"\"kind\":\"%v\",\"phase\":\"%v\",\"effect\":\"%v\"," +
		"\"provider_code\":%d,\"error_status\":%d,\"length\":%d," +
		"\"all_r\":%v,\"file_position\":%d,\"elapsed_ms\":%.3f",
		result.status,
		result.ok,
		result.transport_ok,
		result.error.kind,
		result.error.phase,
		result.error.write_effect,
		result.error.provider_code,
		result.error.status,
		len(data),
		all_r,
		position,
		elapsed,
	)
	fmt.print("}")
	context = previous
	mem.dynamic_arena_destroy(&arena)
	assert(tracker.current_memory_allocated == 0 && len(tracker.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&tracker)
}
