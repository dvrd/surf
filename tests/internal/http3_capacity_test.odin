package surf
import h3 "../http/v3"
import "core:crypto/tls"
import "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

Surf_Large_H3 :: struct {
	listener: h3.Listener,
	stop:     bool,
	body:     [128 * 1024]u8,
	calls:    int,
	error:    [256]u8,
	error_n:  int,
}
@(private)
surf_large_h3_handler :: proc(
	data: rawptr,
	r: ^h3.Server_Request,
	response: ^h3.Server_Response,
) -> h3.Response_Status {
	f := cast(^Surf_Large_H3)data
	f.calls += 1
	response^ = {
		status = 200,
		body   = f.body[:],
	}
	return .Ready
}
@(test)
surf_http3_aggregates_more_than_inline_capacity_and_recovers_limit :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	credential, ce := credentials.create(
		#load("tests/http3/localhost.pem"),
		#load("../http/v3/testdata/rsa2048.pem"),
		{},
		context.allocator,
	)
	assert(ce == .None)
	owner, se := store.create({}, context.allocator)
	assert(se.kind == .None)
	defer store.destroy(&owner)
	assert(store.replace(owner, &credential).kind == .None)
	f := new(Surf_Large_H3)
	defer free(f)
	for &b in f.body {b = 1}
	f.listener.config = {
		endpoint = {net.IP4_Loopback, 0},
		credentials = owner,
		on_request = surf_large_h3_handler,
		on_request_user = f,
		on_request_release = proc(data: rawptr, r: ^h3.Server_Request) {
			f := cast(^Surf_Large_H3)data; for p in f.listener.peers {
				if p != nil && p.dead {
					f.error_n = len(fmt.bprintf(f.error[:], "%s; Core:%s", p.reason, p.transport.reason))
				}
			}
		},
	}

	port, ok := h3.listener_listen(&f.listener)
	assert(ok)
	worker := thread.create_and_start_with_poly_data(
		f,
		proc(s: ^Surf_Large_H3) {for !sync.atomic_load(&s.stop) {h3.listener_step(&s.listener); thread.yield()}},
	)
	defer thread.destroy(worker)
	joined := false
	defer {
		if !joined {
			sync.atomic_store(&f.stop, true); thread.join(worker)
		}; h3.listener_close(&f.listener)
	}

	roots: tls.Root_Pool
	assert(tls.root_pool_parse(&roots, #load("tests/http3/localhost.pem")).kind == .None)
	defer tls.root_pool_destroy(&roots)
	pool: h3.Pool
	assert(h3.pool_init(&pool, {}, context.allocator) == .None)
	defer h3.pool_close(&pool)
	url_buf: [100]u8
	url := fmt.bprintf(url_buf[:], "https://localhost:%d/", port)
	config := Config {
		http3 = true,
		http3_pool = &pool,
		timeout = 8 * time.Second,
		tls = {root_cas = roots.roots[:roots.count]},
	}

	response, e := execute({method = .GET, url = url}, config)
	defer response_destroy(&response)
	testing.expect_value(t, e.kind, .None)
	testing.expect_value(t, len(response.body), 128 * 1024)

	for b in response.body {
		if !testing.expect_value(t, b, 1) {
			break
		}
	}

	config.max_body_size = 32 * 1024
	limited, le := execute({method = .GET, url = url}, config)
	defer response_destroy(&limited)
	testing.expect_value(t, le.kind, .Body_Oversized)
	config.max_body_size = 0
	next, ne := execute({method = .GET, url = url}, config)
	defer response_destroy(&next)

	if ne.kind != .None {
		sync.atomic_store(&f.stop, true)
		thread.join(worker)
		joined = true
		fmt.printf("capturedservererror=%s calls=%d\n", string(f.error[:f.error_n]), f.calls)

		for peer in f.listener.peers {
			if peer != nil {
				fmt.printf(
					"server dead=%v reason=%s phase=%v requests=%d\n",
					peer.dead,
					peer.reason,
					peer.transport.phase,
					f.calls,
				)

				for b in peer.transport.bufs {
					if b.used {
						fmt.printf(
							"bufid%d n%d sent%d fin%v reset%v recv%d final%d\n",
							b.id,
							b.n,
							b.sent,
							b.fin,
							b.reset,
							b.recv_n,
							b.recv_final,
						)
					}
				}
			}
		}

		for slot in pool.slots {
			if slot.client != nil {
				fmt.printf(
					"capacity recovery h3 error=%v reason=%s\n",
					slot.client.err,
					string(slot.client.reason_buf[:slot.client.reason_len]),
				)
			}
		}
	}

	testing.expect_value(t, ne.kind, .None)
	testing.expect_value(t, len(next.body), 128 * 1024)
}
