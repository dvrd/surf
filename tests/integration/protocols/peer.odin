package tests

// The HTTP/2 peer (tests/support/http2) as a child process. It runs from its
// own directory, since it loads ../credentials relative to its working
// directory, and prints one JSON event per line on stdout.

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "shared:async"

PEER_DIR :: "tests/support/http2"

Peer_Log :: struct {
	mu:   sync.Mutex,
	text: [1 << 16]u8,
	n:    int,
	file: ^os.File,
}

Peer :: struct {
	process: os.Process,
	log:     Peer_Log,
	worker:  ^thread.Thread,
	port:    int,
	up:      bool,
}

peer_build_mu: sync.Mutex
peer_built: bool
peer_binary_buffer: [1024]u8
peer_binary: string

peer_build :: proc(t: ^testing.T) -> bool {
	sync.lock(&peer_build_mu)
	defer sync.unlock(&peer_build_mu)

	if peer_built {
		return true
	}

	compiler := os.get_env("ODIN", context.temp_allocator)
	if compiler == "" {
		compiler = "odin"
	}

	directory := os.get_env("TMPDIR", context.temp_allocator)
	if directory == "" {
		directory = "/tmp"
	}

	peer_binary = fmt.bprintf(peer_binary_buffer[:], "%s/surf-h2-peer", strings.trim_right(directory, "/"))
	process, start_error := os.process_start(
		{
			command = {compiler, "build", ".", fmt.tprintf("-out:%s", peer_binary)},
			working_dir = PEER_DIR,
			stderr = os.stderr,
		},
	)

	if !testing.expect(t, start_error == nil) {
		return false
	}

	state, wait_error := os.process_wait(process)
	peer_built = wait_error == nil && state.exit_code == 0
	testing.expect(t, peer_built, "the HTTP/2 peer builds")

	return peer_built
}

// mode is h2, http1, http1-noalpn or goaway.
peer_start :: proc(t: ^testing.T, mode: string) -> ^Peer {
	if !peer_build(t) {
		return nil
	}

	read_end, write_end, pipe_error := os.pipe()
	if !testing.expect(t, pipe_error == nil) {
		return nil
	}

	process, start_error := os.process_start(
		{
			command = {peer_binary, "-mode", mode},
			working_dir = PEER_DIR,
			stdout = write_end,
			stderr = os.stderr,
		},
	)
	os.close(write_end)

	if !testing.expect(t, start_error == nil) {
		os.close(read_end)
		return nil
	}

	peer := new(Peer)
	peer.process = process
	peer.up = true
	peer.log.file = read_end
	peer.worker = thread.create_and_start_with_poly_data(&peer.log, peer_read_log)

	if !testing.expect(t, peer.worker != nil) {
		peer_stop(peer)
		return nil
	}

	port, ok := peer_wait_int(peer, "\"port\":", 30 * time.Second)

	if !testing.expect(t, ok && port > 0 && port <= 65535, "the HTTP/2 peer is ready") {
		peer_stop(peer)
		return nil
	}

	peer.port = port

	return peer
}

peer_stop :: proc(peer: ^Peer) {
	if peer == nil {
		return
	}

	if peer.up {
		_ = os.process_kill(peer.process)
		_, _ = os.process_wait(peer.process)
		peer.up = false
	}

	if peer.worker != nil {
		thread.join(peer.worker)
		thread.destroy(peer.worker)
	}

	if peer.log.file != nil {
		os.close(peer.log.file)
	}

	free(peer)
}

peer_read_log :: proc(log: ^Peer_Log) {
	buffer: [512]u8

	for {
		got, error := os.read(log.file, buffer[:])

		if got > 0 {
			sync.lock(&log.mu)
			kept := copy(log.text[log.n:], buffer[:got])
			log.n += kept
			sync.unlock(&log.mu)
		}

		if error != nil || got == 0 {
			return
		}
	}
}

peer_count :: proc(peer: ^Peer, needle: string) -> int {
	sync.lock(&peer.log.mu)
	defer sync.unlock(&peer.log.mu)

	return strings.count(string(peer.log.text[:peer.log.n]), needle)
}

peer_wait_count :: proc(peer: ^Peer, needle: string, at_least: int, limit: time.Duration) -> bool {
	started := time.tick_now()

	for time.tick_since(started) < limit {
		if peer_count(peer, needle) >= at_least {
			return true
		}

		time.sleep(10 * time.Millisecond)
	}

	return peer_count(peer, needle) >= at_least
}

peer_wait_int :: proc(peer: ^Peer, key: string, limit: time.Duration) -> (int, bool) {
	started := time.tick_now()

	for time.tick_since(started) < limit {
		if value, ok := peer_find_int(peer, key); ok {
			return value, true
		}

		time.sleep(10 * time.Millisecond)
	}

	return peer_find_int(peer, key)
}

peer_find_int :: proc(peer: ^Peer, key: string) -> (int, bool) {
	sync.lock(&peer.log.mu)
	defer sync.unlock(&peer.log.mu)

	text := string(peer.log.text[:peer.log.n])
	at := strings.last_index(text, key)

	if at < 0 {
		return 0, false
	}

	rest := strings.trim_left(text[at + len(key):], " \"")
	end := 0

	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end += 1
	}

	return strconv.parse_int(rest[:end])
}

peer_url :: proc(peer: ^Peer, path: string) -> string {
	return fmt.tprintf("https://localhost:%d%s", peer.port, path)
}

peer_roots :: proc(t: ^testing.T, path: string) -> ^async.Root_Pool {
	pool := new(async.Root_Pool)

	if !testing.expect_value(t, async.root_pool_load_file(pool, path), nil) {
		free(pool)
		return nil
	}

	return pool
}

peer_roots_free :: proc(pool: ^async.Root_Pool) {
	async.root_pool_destroy(pool)
	free(pool)
}
