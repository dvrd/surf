package main

import "shared:surf"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:nbio"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import "core:sys/posix"

count_fds :: proc() -> int {
	count := 0

	for fd in 0 ..< 1024 {
		if posix.fcntl(posix.FD(fd), .GETFD) >= 0 {
			count += 1
		}
	}

	return count
}
callback_called: bool
callback :: proc(op: ^nbio.Operation) {
	callback_called = true
}

main :: proc() {
	assert(len(os.args) >= 4)
	mode := os.args[1]
	port, parsed := strconv.parse_int(os.args[2])
	assert(parsed)
	roots := new(surf.Trust_Roots)
	defer free(roots)
	defer surf.trust_roots_destroy(roots)

	if strings.has_prefix(mode, "tls") {
		assert(surf.trust_roots_load_file(roots, os.args[3]) == .None)
	}

	assert(nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	_ = nbio.timeout(0, callback)
	before := count_fds()
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	previous := context.allocator
	context.allocator = mem.tracking_allocator(&tracker)
	start := time.now()
	successes, failures, timeouts: int

	for iteration in 0 ..< 8 {
		budget := time.time_add(time.now(), 40 * time.Millisecond)

		if mode == "dns" || mode == "dns-tiny" {
			if mode == "dns-tiny" {
				budget = time.time_add(time.now(), 1)
			}

			records, error := net.get_dns_records_from_nameservers_until(
				"fixture.invalid",
				.IP4,
				{{address = net.IP4_Address{127, 0, 0, 1}, port = port}},
				nil,
				budget,
			)
			assert(error == .Timeout && len(records) == 0)
			net.destroy_dns_records(records)
		} else if mode == "resolve" {
			endpoint, error := net.resolve_endpoint_until(
				"fixture.invalid",
				80,
				budget,
				{name_servers = {{address = net.IP4_Address{127, 0, 0, 1}, port = port}}},
			)
			assert(error == nil && endpoint.address == net.Address(net.IP4_Address{127, 0, 0, 1}))
		} else if mode == "connect" || mode == "refuse" || mode == "backlog" {
			socket, error := net.dial_tcp_until({address = net.IP4_Address{127, 0, 0, 1}, port = port}, budget)

			if mode == "connect" {
				assert(error == nil)
				// Returned socket is blocking: an empty read must wait until the
				// peer sends data rather than report Would_Block.
				assert(net.set_option(socket, .Receive_Timeout, time.Second) == nil)
				data: [1]u8
				n, receive_error := net.recv(socket, data[:])
				assert(receive_error == nil && n == 1)
				net.close(socket)
			} else {
				if error == nil {
					net.close(socket)
					successes += 1
				} else {
					failures += 1
				}

				if error == net.Network_Error(net.Dial_Error.Timeout) {
					timeouts += 1
				}

				if mode == "refuse" {
					assert(error != nil)
				}
			}
		} else {
			config := surf.Config {
				timeout = 40 * time.Millisecond,
				tls = {roots = roots},
			}

			if mode == "tls-setup" {
				config.timeout = time.Second
				config.setup_timeout = 40 * time.Millisecond
			}

			// The peer finishes the handshake and then stays silent, so the
			// request is written and only the total deadline can end it.
			if mode == "tls-complete" {
				config.timeout = 150 * time.Millisecond
				config.setup_timeout = 40 * time.Millisecond
			}

			if mode == "tls-dns" {
				dns_port, ok := strconv.parse_int(os.args[4])
				assert(ok)
				config.resolver = {
					name_servers = {{address = net.IP4_Address{127, 0, 0, 1}, port = dns_port}},
				}
			}

			if mode == "surf-dns" {
				config.allow_http = true
				config.resolver = {
					name_servers = {{address = net.IP4_Address{127, 0, 0, 1}, port = port}},
				}
			}

			url := fmt.aprintf("https://127.0.0.1:%d/", port)

			if mode == "surf-dns" {
				delete(url)
				url = fmt.aprintf("http://fixture.invalid:80/")
			}

			if mode == "tls-dns" {
				delete(url)
				url = fmt.aprintf("https://fixture.invalid:%d/", port)
			}

			attempt := time.now()
			response, error := surf.execute({method = .POST, url = url}, config)

			if mode == "tls-complete" {
				assert(error.phase == .Deadline && error.write_effect == .Unknown)
				assert(time.diff(attempt, time.now()) >= 120 * time.Millisecond)
			} else {
				assert(error.phase == .Deadline && error.write_effect == .Not_Sent)
			}

			surf.response_destroy(&response)
			delete(url)
		}

		assert(tracker.current_memory_allocated == 0)
		assert(!callback_called, "Synchronous setup reentered unrelated nbio callbacks")
	}

	elapsed := time.diff(start, time.now())
	context.allocator = previous
	assert(elapsed < 2 * time.Second)
	assert(count_fds() == before, "Failed setup leaked a descriptor")
	assert(nbio.run() == nil && callback_called)

	if mode == "backlog" {
		fmt.println("backlog observed", successes, "successes", failures, "failures", timeouts, "timeouts")
	}

	fmt.println(
		mode,
		"8 attempts",
		elapsed,
		"retained_bytes",
		tracker.current_memory_allocated,
		"fd_delta",
		count_fds() - before,
	)
}
