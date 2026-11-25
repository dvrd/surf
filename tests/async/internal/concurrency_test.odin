package surf_async

import surf ".."
import http "shared:async/http"
import runtime_async "shared:async"
import rt "base:runtime"
import "base:intrinsics"
import "core:fmt"
import "core:mem"
import scopes "shared:async/sync/budget"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"

// Public-only controller/producer fixtures. Named requests use a zero-ID bank,
// so this file proves synchronization/ownership without claiming protocol IO.
Conc_Gate :: struct {
	backing:                  mem.Allocator,
	armed, entered, released: int,
}
conc_allocate :: proc(
	data: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	location := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	g := cast(^Conc_Gate)data
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		_, won := intrinsics.atomic_compare_exchange_strong(&g.armed, 1, 0)

		if won {
			intrinsics.atomic_store(&g.entered, 1)
			started := time.tick_now()

			for intrinsics.atomic_load(&g.released) == 0 {
				assert(time.tick_since(started) < 5 * time.Second)
				thread.yield()
			}
		}
	}
	return g.backing.procedure(g.backing.data, mode, size, alignment, old_memory, old_size, location)
}
Conc_Fixture :: struct {
	track:   mem.Tracking_Allocator,
	scope:   scopes.Scope,
	runtime: runtime_async.Runtime,
	client:  Client,
	gate:    Conc_Gate,
}
conc_init :: proc(f: ^Conc_Fixture) {
	mem.tracking_allocator_init(&f.track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&f.track)
	scope, error := scopes.create_root({bytes = 32 << 20, streams = 8, jobs = 8}, allocator)
	assert(error == .None)
	f.scope = scope
	f.gate.backing = allocator
	assert(
		runtime_async.init(&f.runtime, {workers = 1, task_capacity = 3, io_capacity = 1, allocator = allocator}).kind ==
		.None,
	)
	config := Client_Config {
		http = {allow_http = true, timeout = 30 * time.Second, scope = scope},
		capacities = Capacities {
			requests = 8,
			origins = 1,
			connections = 2,
			connections_per_origin = 1,
			waiters_per_origin = 8,
			dns_ids = 0,
			work_per_resume = 1,
		},
	}

	assert(client_init(&f.client, &f.runtime, config, {conc_allocate, &f.gate}).kind == .None)
}
Conc_Producer :: struct {
	client:                          ^Client,
	handles:                         [64]Request_Handle,
	accepted, rejected, closed, bad: int,
}
conc_produce :: proc(p: ^Conc_Producer) {
	for i in 0 ..< len(p.handles) {
		body := [3]u8{'a', u8(i), 'z'}
		fields := [1]http.Header{{name = "X-Producer", value = "original"}}
		request := http.Request {
			method  = .POST,
			url     = "http://bank-empty.invalid/owned",
			headers = fields[:],
			body    = body[:],
		}

		h, error := client_submit(p.client, request)

		if error.kind == .None {
			p.handles[p.accepted] = h
			p.accepted += 1
		} else {
			p.rejected += 1

			if error.kind == .Closed {
				p.closed += 1
			} else if error.kind != .Capacity && error.kind != .Budget_Rejected {
				p.bad += 1
			}

			if h != (Request_Handle{}) {
				p.bad += 1
			}
		}

		if body[0] != 'a' || body[1] != u8(i) || body[2] != 'z' || fields[0].value != "original" {
			p.bad += 1
		}
	}
}
Conc_Consumer :: struct {
	client:     ^Client,
	handles:    [8]Request_Handle,
	count, bad: int,
}
conc_consume :: proc(c: ^Conc_Consumer) {
	for {
		completion, available := client_poll(c.client)

		if !available {
			break
		}

		assert(c.count < len(c.handles))
		c.handles[c.count] = completion.request
		c.count += 1

		if completion.error.transport != net.Connection_Error.Cancelled {
			c.bad += 1
		}

		response: surf.Response

		if client_take(c.client, completion.request, &response).kind != .Request_Error {
			c.bad += 1
		}

		if response.status != 0 || response.body != nil {
			c.bad += 1
		}

		if client_release(c.client, completion.request).kind != .None {
			c.bad += 1
		}
	}
}
conc_collect :: proc(f: ^Conc_Fixture, producers: []Conc_Producer, expected: int, t: ^testing.T) {
	consumers: [4]Conc_Consumer
	workers: [4]^thread.Thread

	for &consumer, i in consumers {
		consumer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&consumer, conc_consume)
		assert(workers[i] != nil)
	}

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	total := 0

	for consumer in consumers {
		total += consumer.count
		testing.expect_value(t, consumer.bad, 0)
	}

	testing.expect_value(t, total, expected)

	for &producer in producers {
		for h in producer.handles[:producer.accepted] {
			seen := 0

			for &consumer in consumers {
				for actual in consumer.handles[:consumer.count] {
					if actual == h {
						seen += 1
					}
				}
			}

			testing.expect_value(t, seen, 1)
			testing.expect(
				t,
				client_cancel(&f.client, h).kind == .Invalid_Handle &&
				client_release(&f.client, h).kind == .Invalid_Handle,
			)
		}
	}

	_, again := client_poll(&f.client)
	testing.expect(t, !again)
}
conc_destroy :: proc(f: ^Conc_Fixture, t: ^testing.T, runtime_destroyed: bool = false) {
	testing.expect(t, client_quiescent(&f.client))
	testing.expect_value(t, client_destroy(&f.client).kind, .None)

	if !runtime_destroyed {
		testing.expect_value(t, runtime_async.destroy(&f.runtime).kind, .None)
	}

	snapshot, error := scopes.snapshot(f.scope)
	testing.expect(t, error == .None && snapshot.used == (scopes.Usage{}))
	scopes.release_scope(&f.scope)
	testing.expect(t, f.track.current_memory_allocated == 0 && len(f.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&f.track)
}

@(test)
public_concurrency_prestart_bounded_producers_and_parallel_terminal_consumers :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	f: Conc_Fixture
	conc_init(&f)
	producers: [4]Conc_Producer
	workers: [4]^thread.Thread

	for &producer, i in producers {
		producer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&producer, conc_produce)
		assert(workers[i] != nil)
	}

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	accepted, rejected := 0, 0

	for producer in producers {
		accepted += producer.accepted
		rejected += producer.rejected
		testing.expect_value(t, producer.bad, 0)
	}

	testing.expect(t, accepted == 8 && rejected == 248)
	stats, valid := client_stats(&f.client)
	testing.expect(
		t,
		valid &&
		stats.queued_requests == 8 &&
		stats.dns_waiters == 8 &&
		stats.reserved_connections == 0 &&
		stats.tasks == 3,
	)
	testing.expect_value(t, client_close(&f.client).kind, .None)
	testing.expect(t, client_quiescent(&f.client) && client_destroy(&f.client).kind == .Pending)
	conc_collect(&f, producers[:], accepted, t)
	conc_destroy(&f, t)
	fmt.println(
		"PUBLIC_CONCURRENCY producer_threads=4 attempts=256 accepted=8 consumer_threads=4 terminal_once=true protocol_io=0",
	)
}

@(test)
public_concurrency_shutdown_while_producer_is_in_real_allocation_callback :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	f: Conc_Fixture
	conc_init(&f)
	seed, error := client_submit(&f.client, {method = .GET, url = "http://bank-empty.invalid/seed"})
	assert(error.kind == .None)
	assert(runtime_async.start(&f.runtime).kind == .None)
	intrinsics.atomic_store(&f.gate.armed, 1)
	producers: [4]Conc_Producer
	workers: [4]^thread.Thread

	for &producer, i in producers {
		producer.client = &f.client
		workers[i] = thread.create_and_start_with_poly_data(&producer, conc_produce)
		assert(workers[i] != nil)
	}

	started := time.tick_now()

	for intrinsics.atomic_load(&f.gate.entered) == 0 {
		assert(time.tick_since(started) < 5 * time.Second)
		thread.yield()
	}

	// This is an actual out-of-lock producer callback, not a guessed timing race.
	runtime_async.shutdown(&f.runtime)
	closing := client_close(&f.client)
	testing.expect_value(t, closing.kind, .Pending)
	intrinsics.atomic_store(&f.gate.released, 1)

	for worker in workers {
		thread.join(worker)
		thread.destroy(worker)
	}

	accepted, rejected, closed := 1, 0, 0

	for producer in producers {
		accepted += producer.accepted
		rejected += producer.rejected
		closed += producer.closed
		testing.expect_value(t, producer.bad, 0)
	}

	testing.expect(t, accepted <= 8 && accepted + rejected == 257 && closed > 0)
	assert(runtime_async.join(&f.runtime).kind == .None)
	assert(runtime_async.destroy(&f.runtime).kind == .None)
	records: [5]Conc_Producer

	for producer, i in producers {
		records[i] = producer
	}

	records[4].handles[0] = seed
	records[4].accepted = 1
	conc_collect(&f, records[:], accepted, t)
	conc_destroy(&f, t, true)
	fmt.printf(
		"PUBLIC_CONCURRENCY shutdown_during_clone_callback=true producers=4 seeded=1 accepted=%d rejected=%d closed=%d runtime_gone_before_results=true protocol_io=0\n",
		accepted,
		rejected,
		closed,
	)
}
