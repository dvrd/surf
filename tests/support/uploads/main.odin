package main

import "shared:async"
import "shared:surf"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:time"

perform :: proc(
	base, path, file_path: string,
	length: i64,
	method: async.Http_Method,
	config: surf.Config,
	expected_status: int = 200,
) -> i64 {
	file, open_error := os.open(file_path)
	assert(open_error == nil)
	defer os.close(file)
	url := fmt.aprintf("%s%s", base, path)
	defer delete(url)
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	previous := context.allocator
	context.allocator = mem.tracking_allocator(&tracker)
	response, error := surf.execute_upload(
		{method = method, url = url},
		{stream = os.to_stream(file), content_length = length},
		config,
	)
	if path == "/short" {
		assert(error.kind == .IO_Failed && error.source_io == .Unexpected_EOF)
		assert(error.phase == .Write && error.write_effect == .Unknown)
	} else if path == "/stall" {
		assert(error.phase == .Deadline && error.write_effect == .Unknown)
	} else {
		assert(error.kind == .None && response.status == expected_status)
		assert(string(response.body) == "ok")
	}
	surf.response_destroy(&response)
	context.allocator = previous
	assert(tracker.current_memory_allocated == 0)
	assert(tracker.peak_memory_allocated < 4 * 1024 * 1024)
	position, position_error := os.seek(file, 0, .Current)
	assert(position_error == nil)
	if path == "/stall" {
		assert(position < length)
	} else if path == "/short" {
		assert(position < length)
	} else {
		assert(position == length)
	}
	fmt.println(path, "consumed", position, "peak_owned_bytes", tracker.peak_memory_allocated)
	return position
}

main :: proc() {
	http_url := os.get_env("SURF_UPLOAD_HTTP", context.allocator)
	tls_url := os.get_env("SURF_UPLOAD_TLS", context.allocator)
	file_path := os.get_env("SURF_UPLOAD_FILE", context.allocator)
	short_path := os.get_env("SURF_UPLOAD_SHORT", context.allocator)
	root_path := os.get_env("SURF_UPLOAD_ROOT", context.allocator)
	defer delete(http_url)
	defer delete(tls_url)
	defer delete(file_path)
	defer delete(short_path)
	defer delete(root_path)
	assert(http_url != "" && tls_url != "" && file_path != "" && short_path != "" && root_path != "")
	plain := surf.Config {
		allow_http    = true,
		max_body_size = 8,
		timeout       = 10 * time.Second,
	}

	large: i64 = 65 * 1024 * 1024
	perform(http_url, "/put", file_path, large, .PUT, plain)
	perform(http_url, "/post", file_path, 17, .POST, plain)
	perform(http_url, "/delete", file_path, 0, .DELETE, plain)
	perform(http_url, "/prefix", file_path, 3, .PUT, plain)
	perform(http_url, "/redirect", file_path, 17, .POST, plain, 307)
	perform(http_url, "/short", short_path, 3, .PUT, plain)
	stall := plain
	stall.timeout = 100 * time.Millisecond
	perform(http_url, "/stall", file_path, large, .PUT, stall)
	pool := new(async.Root_Pool)
	defer free(pool)
	defer async.root_pool_destroy(pool)
	assert(async.root_pool_load_file(pool, root_path) == nil)
	secure := surf.Config {
		tls = {roots = pool},
		max_body_size = 8,
		timeout = 20 * time.Second,
	}

	perform(tls_url, "/tls-put", file_path, 2 * 1024 * 1024, .PUT, secure)
	perform(tls_url, "/tls-post", file_path, 17, .POST, secure)
	perform(tls_url, "/tls-delete", file_path, 9, .DELETE, secure)
	fmt.println("10 public native TCP/TLS upload scenarios passed")
}
