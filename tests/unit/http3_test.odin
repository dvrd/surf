package surf

import "shared:async/tls"
import "shared:async/tls/credentials"
import store "shared:async/tls/credentials/store"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import http "shared:async/http"
import http3 "shared:async/http/v3"
import "core:os"
import "core:bytes"
import "core:io"

Surf_Large_H3 :: struct {
	listener: http3.Listener,
	stop:     bool,
	body:     [128 * 1024]u8,
	calls:    int,
	error:    [256]u8,
	error_n:  int,
}
surf_large_h3_handler :: proc(
	data: rawptr,
	r: ^http3.Server_Request,
	response: ^http3.Server_Response,
) -> http3.Response_Status {
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
		#load("../tests/support/http3/localhost.pem"),
		#load("../tests/support/http3/rsa2048.pem"),
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
		on_request_release = proc(data: rawptr, r: ^http3.Server_Request) {
			f := cast(^Surf_Large_H3)data; for p in f.listener.peers {
				if p != nil && p.dead {
					f.error_n = len(fmt.bprintf(f.error[:], "%s; Core:%s", p.reason, p.transport.reason))
				}
			}
		},
	}

	port, ok := http3.listener_listen(&f.listener)
	assert(ok)
	worker := thread.create_and_start_with_poly_data(
		f,
		proc(s: ^Surf_Large_H3) {for !sync.atomic_load(&s.stop) {http3.listener_step(&s.listener); thread.yield()}},
	)
	defer thread.destroy(worker)
	joined := false
	defer {
		if !joined {
			sync.atomic_store(&f.stop, true); thread.join(worker)
		}; http3.listener_close(&f.listener)
	}

	roots: tls.Root_Pool
	assert(tls.root_pool_parse(&roots, #load("../tests/support/http3/localhost.pem")) == nil)
	defer tls.root_pool_destroy(&roots)
	pool: http3.Pool
	assert(http3.pool_init(&pool, {}, context.allocator) == .None)
	defer http3.pool_close(&pool)
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

@(test)
surf_alt_svc_authenticated_only :: proc(t: ^testing.T) {
	cache: Alt_Svc_Cache
	now := time.now()
	value := "h3=\":443\"; ma=60"
	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", value, false, true, now))
	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", value, true, false, now))
	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", "h3=\":443\"; ma=0", true, true, now))
	testing.expect(t, !alt_svc_note(nil, "synthetic.invalid", value, true, true, now))
	testing.expect(t, alt_svc_note(&cache, "synthetic.invalid", value, true, true, now))
	port, ok := alt_svc_lookup(&cache, "synthetic.invalid", now)
	testing.expect(t, ok && port == 443)
	later := time.time_add(now, 61 * time.Second)
	port, ok = alt_svc_lookup(&cache, "synthetic.invalid", later)
	testing.expect(t, !ok && port == 0)
	_, still := alt_svc_lookup(&cache, "synthetic.invalid", now)
	testing.expect(t, !still)
}

@(test)
surf_http3_post_is_not_replayed :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	request := http.Request {
		method = .POST,
		url    = "https://127.0.0.1:9/saba",
	}

	_, error := execute(request, {http3 = true, timeout = 2 * time.Second})
	testing.expect_value(t, error.kind, .Deadline_Failed)
	testing.expect_value(t, error.phase, .Deadline)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
surf_http3_cleartext_refused :: proc(t: ^testing.T) {
	request := http.Request {
		method = .GET,
		url    = "http://127.0.0.1:9/saba",
	}

	_, error := execute(request, {http3 = true, allow_http = true, timeout = 2 * time.Second})
	testing.expect_value(t, error.kind, .Insecure_URL)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
surf_http3_get_falls_back_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	request := http.Request {
		method = .GET,
		url    = "https://127.0.0.1:9/saba",
	}

	_, error := execute(request, {http3 = true, timeout = 2 * time.Second})
	testing.expect(t, error.kind != .None)
	testing.expect(t, error.phase != .Protocol)
	testing.expect(t, !http3_fallback_allowed(.POST))
	testing.expect(t, http3_fallback_allowed(.GET) && http3_fallback_allowed(.HEAD))
}

@(test)
surf_http3_dial_port :: proc(t: ^testing.T) {
	cache: Alt_Svc_Cache
	now := time.now()
	testing.expect_value(t, http3_dial_port(&cache, "synthetic.invalid", 8443, now), 8443)
	testing.expect_value(t, http3_dial_port(&cache, "synthetic.invalid", 0, now), 443)
	testing.expect(t, alt_svc_note(&cache, "synthetic.invalid", "h3=\":9443\"; ma=60", true, true, now, 8443))
	testing.expect_value(t, http3_dial_port(&cache, "synthetic.invalid", 8443, now), 9443)
	later := time.time_add(now, 61 * time.Second)
	testing.expect_value(t, http3_dial_port(&cache, "synthetic.invalid", 8443, later), 8443)
	_, still := alt_svc_lookup(&cache, "synthetic.invalid", now)
	testing.expect(t, !still)
}

@(test)
surf_http3_hostname_resolves :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	soon := time.time_add(time.now(), time.Second)
	blocked := [1]net.Endpoint{{address = net.IP4_Loopback, port = 9}}
	literal, literal_error := http3_resolve("127.0.0.1", 9443, soon, {name_servers = blocked[:]})
	testing.expect_value(t, literal_error.kind, .None)
	testing.expect(t, literal.count == 1)
	testing.expect_value(t, literal.items[0].port, 9443)
	address, is_ip4 := literal.items[0].address.(net.IP4_Address)
	testing.expect(t, is_ip4 && address == net.IP4_Loopback)

	cache: Alt_Svc_Cache
	now := time.now()
	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9443\"; ma=60", true, true, now, 8443))
	port := http3_dial_port(&cache, "localhost", 8443, now)
	host, host_error := http3_resolve("localhost", port, time.time_add(now, time.Second), {})
	testing.expect_value(t, host_error.kind, .None)
	testing.expect(t, host.count >= 1)
	testing.expect_value(t, host.items[0].port, 9443)

	switch resolved in host.items[0].address {
	case net.IP4_Address:
		testing.expect_value(t, resolved, net.IP4_Loopback)
	case net.IP6_Address:
		testing.expect_value(t, resolved, net.IP6_Loopback)
	}

	past := time.time_add(time.now(), -time.Millisecond)
	_, late := http3_resolve("localhost", 443, past, {})
	testing.expect_value(t, late.kind, .Dial_Failed)
	testing.expect_value(t, late.phase, .Deadline)
	testing.expect_value(t, late.write_effect, .Not_Sent)

	_, bad := http3_resolve("not a host", 443, soon, {})
	testing.expect_value(t, bad.kind, .Dial_Failed)
	testing.expect_value(t, bad.phase, .Configuration)
	testing.expect_value(t, bad.write_effect, .Not_Sent)

	url := http.URL {
		host      = "localhost",
		authority = "localhost:9",
		port      = 9,
		target    = "/",
		secure    = true,
	}

	_, dial_error := execute_http3(
		url,
		{method = .GET},
		{},
		time.time_add(time.now(), 2 * time.Second),
		context.allocator,
	)
	testing.expect(t, dial_error.kind != .None)
	testing.expect_value(t, dial_error.write_effect, .Not_Sent)
	testing.expect(t, dial_error.phase != .DNS && dial_error.phase != .Configuration)
}

Http3_Policy_DNS :: struct {
	socket:  net.UDP_Socket,
	mu:      sync.Mutex,
	stop:    bool,
	v4:      [2][4]u8,
	v4n:     int,
	queries: int,
}

http3_policy_qtype :: proc(query: []u8) -> (qtype: int, question_end: int, ok: bool) {
	if len(query) < 12 {
		return 0, 0, false
	}

	at := 12

	for at < len(query) {
		length := int(query[at])

		if length == 0 {
			at += 1
			break
		}

		if length & 0xc0 == 0xc0 || length > 63 || at + 1 + length > len(query) {
			return 0, 0, false
		}

		at += 1 + length
	}

	if at + 4 > len(query) {
		return 0, 0, false
	}

	return int(query[at]) << 8 | int(query[at + 1]), at + 4, true
}

http3_policy_dns_loop :: proc(dns: ^Http3_Policy_DNS) {
	query: [512]u8

	for {
		sync.lock(&dns.mu)
		stopped := dns.stop
		sync.unlock(&dns.mu)

		if stopped {
			return
		}

		n, from, err := net.recv_udp(dns.socket, query[:])

		if err == .Timeout || err == .Would_Block || err == .Interrupted {
			continue
		}

		if err != nil || n < 12 {
			return
		}

		qtype, question_end, ok := http3_policy_qtype(query[:n])

		if !ok || (qtype != 1 && qtype != 28) {
			continue
		}

		sync.lock(&dns.mu)
		dns.queries += 1
		v4 := dns.v4
		v4n := dns.v4n
		sync.unlock(&dns.mu)
		reply: [512]u8
		count := v4n if qtype == 1 else 0
		n_out := copy(reply[:], query[:question_end])
		reply[2] = 0x81
		reply[3] = 0x80
		reply[6] = u8(count >> 8)
		reply[7] = u8(count)

		for i in 0 ..< count {
			if n_out + 16 > len(reply) {
				break
			}

			record := [16]u8 {
				0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4,
				v4[i][0], v4[i][1], v4[i][2], v4[i][3],
			}
			n_out += copy(reply[n_out:], record[:])
		}

		_, _ = net.send_udp(dns.socket, reply[:n_out], from)
	}
}

http3_policy_dns_start :: proc(dns: ^Http3_Policy_DNS) -> (net.Endpoint, ^thread.Thread, bool) {
	socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)

	if err != nil {
		return {}, nil, false
	}

	if net.set_option(socket, .Receive_Timeout, 200 * time.Millisecond) != nil {
		net.close(socket)
		return {}, nil, false
	}

	endpoint, bound := net.bound_endpoint(socket)

	if bound != .None {
		net.close(socket)
		return {}, nil, false
	}

	dns.socket = socket
	worker := thread.create_and_start_with_poly_data(dns, http3_policy_dns_loop)

	if worker == nil {
		net.close(socket)
		return {}, nil, false
	}

	return endpoint, worker, true
}

http3_policy_dns_stop :: proc(dns: ^Http3_Policy_DNS, worker: ^thread.Thread) {
	sync.lock(&dns.mu)
	dns.stop = true
	sync.unlock(&dns.mu)
	net.close(dns.socket)

	if worker != nil {
		thread.join(worker)
		thread.destroy(worker)
	}
}

@(test)
surf_http3_refuses_a_mixed_resolved_set_before_dial :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	dns := Http3_Policy_DNS {
		v4 = {{203, 0, 113, 1}, {127, 0, 0, 1}},
		v4n = 2,
	}
	endpoint, worker, started := http3_policy_dns_start(&dns)
	testing.expect(t, started)

	if !started {
		return
	}

	defer http3_policy_dns_stop(&dns, worker)
	servers := [1]net.Endpoint{endpoint}
	url := http.URL {
		host      = "mixed.invalid",
		authority = "mixed.invalid",
		port      = 443,
		target    = "/",
		secure    = true,
	}
	began := time.tick_now()
	_, error := execute_http3(
		url,
		{method = .GET},
		{
			address_policy = address_policy_public_only,
			resolver = {name_servers = servers[:]},
		},
		time.time_add(time.now(), 8 * time.Second),
		context.allocator,
	)
	testing.expect(t, time.tick_since(began) < 3 * time.Second)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	sync.lock(&dns.mu)
	dns.v4n = 1
	sync.unlock(&dns.mu)
	only, only_error := http3_resolve(
		"only.invalid",
		443,
		time.time_add(time.now(), 2 * time.Second),
		{name_servers = servers[:]},
	)
	testing.expect_value(t, only_error.kind, .None)
	testing.expect_value(t, only.count, 1)
	allowed := address_policy_check(
		{address_policy = address_policy_public_only},
		"only.invalid",
		only.items[:only.count],
	)
	testing.expect_value(t, allowed.kind, .None)
}

@(test)
surf_http3_empty_pool_resolves_before_refusing_a_mixed_set :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	dns := Http3_Policy_DNS {
		v4  = {{203, 0, 113, 1}, {127, 0, 0, 1}},
		v4n = 2,
	}
	endpoint, worker, started := http3_policy_dns_start(&dns)
	testing.expect(t, started)

	if !started {
		return
	}

	defer http3_policy_dns_stop(&dns, worker)
	pool: http3.Pool
	defer http3.pool_close(&pool)
	servers := [1]net.Endpoint{endpoint}
	url := http.URL {
		host      = "mixed.invalid",
		authority = "mixed.invalid",
		port      = 443,
		target    = "/",
		secure    = true,
	}
	began := time.tick_now()
	_, error := execute_http3(
		url,
		{method = .GET},
		{
			address_policy = address_policy_public_only,
			resolver = {name_servers = servers[:]},
			http3_pool = &pool,
		},
		time.time_add(time.now(), 8 * time.Second),
		context.allocator,
	)
	testing.expect(t, time.tick_since(began) < 3 * time.Second)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	sync.lock(&dns.mu)
	queries := dns.queries
	sync.unlock(&dns.mu)
	testing.expect(t, queries >= 1)
}

@(test)
surf_http3_peer_get :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	url_buf: [96]u8
	body_buf: [64]u8
	url, want, roots, ok := surf_peer_setup(t, false, url_buf[:], body_buf[:])
	if !ok {
		return
	}
	defer surf_roots_free(roots)
	response, error := execute(
		{method = .GET, url = url},
		{http3 = true, timeout = 8 * time.Second, tls = {root_cas = roots.roots[:roots.count]}},
	)
	defer response_destroy(&response)
	fmt.printf(
		"surf-h3 get status %d err %v phase %v effect %v body %s\n",
		response.status,
		error.kind,
		error.phase,
		error.write_effect,
		string(response.body),
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect(t, string(response.body) == want, string(response.body))
}

@(test)
surf_http3_peer_post_bad_cert :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	url_buf: [96]u8
	body_buf: [64]u8
	url, _, roots, ok := surf_peer_setup(t, true, url_buf[:], body_buf[:])
	if !ok {
		return
	}
	defer surf_roots_free(roots)
	_, error := execute(
		{method = .POST, url = url},
		{http3 = true, timeout = 8 * time.Second, tls = {root_cas = roots.roots[:roots.count]}},
	)
	fmt.printf("surf-h3 post phase %v effect %v kind %v\n", error.phase, error.write_effect, error.kind)
	testing.expect_value(t, error.kind, .IO_Failed)
	testing.expect_value(t, error.phase, .TLS)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

surf_peer_setup :: proc(
	t: ^testing.T,
	bogus: bool,
	url_buf, body_buf: []u8,
) -> (
	url, body: string,
	roots: ^tls.Root_Pool,
	ok: bool,
) {
	port_buf: [32]u8
	cert_buf: [512]u8
	port_s := os.get_env_buf(port_buf[:], "H3_PEER_PORT")
	cert := os.get_env_buf(cert_buf[:], "H3_PEER_CERT")
	body = os.get_env_buf(body_buf, "H3_PEER_BODY")
	if len(port_s) == 0 || len(cert) == 0 || len(body) == 0 {
		return
	}
	if bogus {
		cert = os.get_env_buf(cert_buf[:], "H3_BOGUS_CERT")
		if len(cert) == 0 {
			return
		}
	}
	url = fmt.bprintf(url_buf, "https://127.0.0.1:%s/", port_s)
	if len(url) == 0 {
		return
	}
	roots = new(tls.Root_Pool)
	load_error := tls.root_pool_load_file(roots, cert)
	testing.expect_value(t, load_error, nil)
	if load_error != nil {
		free(roots)
		roots = nil
		return
	}
	ok = true
	return
}

surf_roots_free :: proc(pool: ^tls.Root_Pool) {
	if pool == nil {
		return
	}
	tls.root_pool_destroy(pool)
	free(pool)
}

@(test)
surf_alt_svc_isolated_by_origin_port :: proc(t: ^testing.T) {
	cache: Alt_Svc_Cache
	now := time.now()
	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9443\"; ma=60", true, true, now, 8443))
	testing.expect_value(t, http3_dial_port(&cache, "localhost", 8443, now), 9443)
	testing.expect_value(t, http3_dial_port(&cache, "localhost", 443, now), 443)
	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9444\"; ma=60", true, true, now, 443))
	testing.expect_value(t, http3_dial_port(&cache, "localhost", 443, now), 9444)
	testing.expect_value(t, http3_dial_port(&cache, "localhost", 8443, now), 9443)
}

Surf_H3_Fixture :: struct {
	listener: http3.Listener,
	stop:     bool,
	calls:    int,
	valid:    bool,
	headers:  [3]http3.Field,
}
surf_h3_request_handler :: proc(
	data: rawptr,
	request: ^http3.Server_Request,
	response: ^http3.Server_Response,
) -> http3.Response_Status {
	fixture := cast(^Surf_H3_Fixture)data
	fixture.calls += 1
	valid :=
		request.method == "POST" &&
		request.target == "/probe?one=two" &&
		request.authority == "localhost:8443" &&
		string(request.body) == ("request-body" if fixture.calls <= 2 else "")
	auth, cookie, kind, duplicates := false, false, false, 0
	for h in request.headers {
		if h.name == "authorization" {
			auth = h.value == "Bearer fixture"
		}

		if h.name == "cookie" {
			cookie = h.value == "session=fixture"
		}

		if h.name == "content-type" {
			kind = h.value == "application/json"
		}

		if h.name == "x-review" {
			duplicates += 1
		}
	}
	fixture.valid = fixture.valid && valid && auth && cookie && kind && duplicates == 1
	fixture.headers = {
		{name = "www-authenticate", value = "Bearer"},
		{name = "set-cookie", value = "a=1"},
		{name = "set-cookie", value = "b=2"},
	}
	response^ = {
		status  = 401,
		headers = fixture.headers[:],
		body    = transmute([]u8)string("denied"),
	}
	return .Ready
}
@(test)
surf_http3_preserves_request_upload_origin_and_response_headers :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 40 * time.Second)
	credential, ce := credentials.create(
		#load("../tests/support/http3/localhost.pem"),
		#load("../tests/support/http3/rsa2048.pem"),
		{},
		context.allocator,
	)

	if !testing.expect_value(t, ce, .None) {
		return
	}

	owner, se := store.create({}, context.allocator)

	if !testing.expect_value(t, se.kind, .None) {
		credentials.destroy(&credential)
		return
	}

	defer store.destroy(&owner)
	assert(store.replace(owner, &credential).kind == .None)
	fixture := Surf_H3_Fixture {
		valid = true,
	}

	fixture.listener.config = {
		qpack = {table_capacity = 4096, blocked_streams = 4},
		endpoint = {net.IP4_Loopback, 0},
		credentials = owner,
		on_request = surf_h3_request_handler,
		on_request_user = &fixture,
	}

	port, ok := http3.listener_listen(&fixture.listener)

	if !testing.expect(t, ok) {
		return
	}

	worker := thread.create_and_start_with_poly_data(&fixture, proc(f: ^Surf_H3_Fixture) {
		for !sync.atomic_load(&f.stop) {
			if !http3.listener_step(&f.listener) {
				break
			}
		}
	})
	defer thread.destroy(worker)
	defer {
		sync.atomic_store(&fixture.stop, true)
		thread.join(worker)
		http3.listener_close(&fixture.listener)
	}

	roots: tls.Root_Pool
	assert(tls.root_pool_parse(&roots, #load("../tests/support/http3/localhost.pem")) == nil)
	defer tls.root_pool_destroy(&roots)
	cache: Alt_Svc_Cache
	alt_buf: [80]u8
	assert(
		alt_svc_note(
			&cache,
			"localhost",
			fmt.bprintf(alt_buf[:], "h3=\":%d\"; ma=60", port),
			true,
			true,
			time.now(),
			8443,
		),
	)
	pool: http3.Pool
	defer http3.pool_close(&pool)
	config := Config {
		http3 = true,
		http3_pool = &pool,
		http3_qpack = {table_capacity = 4096, blocked_streams = 4},
		alt_svc = &cache,
		timeout = 8 * time.Second,
		tls = {root_cas = roots.roots[:roots.count]},
	}

	headers := []http.Header {
		{"Authorization", "Bearer fixture"},
		{"Cookie", "session=fixture"},
		{"Content-Type", "application/json"},
		{"X-Review", "one"},
	}

	request := http.Request {
		method  = .POST,
		url     = "https://localhost:8443/probe?one=two",
		headers = headers,
		body    = transmute([]u8)string("request-body"),
	}

	response, error := execute(request, config)
	defer response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 401)
	testing.expect_value(t, string(response.body), "denied")
	cookies := 0

	for h in response.headers {
		if h.name == "set-cookie" {
			cookies += 1
		}
	}

	testing.expect_value(t, cookies, 2)
	// The second request consumes an io.Stream source rather than request.body.
	request.body = nil
	source: bytes.Buffer
	bytes.buffer_init_string(&source, "request-body")
	defer bytes.buffer_destroy(&source)
	uploaded, upload_error := execute_upload(
		request,
		{stream = bytes.buffer_to_stream(&source), content_length = 12},
		config,
	)
	defer response_destroy(&uploaded)
	testing.expect_value(t, upload_error.kind, .None)
	testing.expect_value(t, uploaded.status, 401)
	testing.expect_value(t, string(uploaded.body), "denied")
	// A source callback can return after the total deadline. Preserve the
	// conservative sent state and source error instead of making it replay-safe.
	slow_reads := 0
	config.timeout = 500 * time.Millisecond
	config.max_body_size = 0
	late, late_error := execute_upload(
		request,
		{stream = {procedure = surf_h3_slow_source, data = &slow_reads}, content_length = 1},
		config,
	)
	defer response_destroy(&late)
	testing.expect_value(t, slow_reads, 1)
	testing.expect_value(t, late_error.kind, .Deadline_Failed)
	testing.expect_value(t, late_error.phase, .Deadline)
	testing.expect_value(t, late_error.write_effect, .Unknown)
	testing.expect_value(t, late_error.source_io, io.Error.No_Progress)
	config.timeout = 8 * time.Second
	config.max_body_size = 3
	limited, limit_error := execute_upload(
		request,
		{stream = bytes.buffer_to_stream(&source), content_length = 0},
		config,
	)
	defer response_destroy(&limited)
	testing.expect_value(t, limit_error.kind, .Body_Oversized)
	testing.expect_value(t, limit_error.phase, .Body_Limit)
	sync.atomic_store(&fixture.stop, true)
	thread.join(worker)
	testing.expect_value(t, fixture.calls, 3)
	// Only the first two requests carry the asserted body.
	testing.expect(t, fixture.valid)
}

Surf_H3_Pool_DNS :: struct {
	listener: http3.Listener,
	stop:     bool,
}

surf_h3_pool_dns_handler :: proc(
	_: rawptr,
	_: ^http3.Server_Request,
	response: ^http3.Server_Response,
) -> http3.Response_Status {
	response^ = {
		status = 200,
		body   = transmute([]u8)string("ok"),
	}
	return .Ready
}

@(test)
surf_http3_live_lane_does_not_resolve_again :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	credential, ce := credentials.create(
		#load("../tests/support/http3/localhost.pem"),
		#load("../tests/support/http3/rsa2048.pem"),
		{},
		context.allocator,
	)

	if !testing.expect_value(t, ce, .None) {
		return
	}

	owner, se := store.create({}, context.allocator)

	if !testing.expect_value(t, se.kind, .None) {
		credentials.destroy(&credential)
		return
	}

	defer store.destroy(&owner)
	assert(store.replace(owner, &credential).kind == .None)
	dns := Http3_Policy_DNS {
		v4  = {{127, 0, 0, 1}, {0, 0, 0, 0}},
		v4n = 1,
	}
	dns_endpoint, dns_worker, dns_started := http3_policy_dns_start(&dns)
	testing.expect(t, dns_started)

	if !dns_started {
		return
	}

	defer http3_policy_dns_stop(&dns, dns_worker)
	fixture := Surf_H3_Pool_DNS {}
	fixture.listener.config = {
		endpoint    = {net.IP4_Loopback, 0},
		credentials = owner,
		on_request  = surf_h3_pool_dns_handler,
		on_request_user = &fixture,
	}
	port, listened := http3.listener_listen(&fixture.listener)

	if !testing.expect(t, listened) {
		return
	}

	worker := thread.create_and_start_with_poly_data(&fixture, proc(f: ^Surf_H3_Pool_DNS) {
		for !sync.atomic_load(&f.stop) {
			if !http3.listener_step(&f.listener) {
				break
			}
		}
	})

	if !testing.expect(t, worker != nil) {
		http3.listener_close(&fixture.listener)
		return
	}

	defer thread.destroy(worker)
	defer {
		sync.atomic_store(&fixture.stop, true)
		thread.join(worker)
		http3.listener_close(&fixture.listener)
	}
	roots: tls.Root_Pool
	assert(tls.root_pool_parse(&roots, #load("../tests/support/http3/localhost.pem")) == nil)
	defer tls.root_pool_destroy(&roots)
	pool: http3.Pool
	defer http3.pool_close(&pool)
	servers := [1]net.Endpoint{dns_endpoint}
	url_buf: [80]u8
	url := fmt.bprintf(url_buf[:], "https://localhost:%d/reuse", port)
	config := Config {
		http3      = true,
		http3_pool = &pool,
		timeout    = 8 * time.Second,
		resolver   = {name_servers = servers[:]},
		tls        = {root_cas = roots.roots[:roots.count]},
	}
	first, first_error := execute({method = .GET, url = url}, config)
	defer response_destroy(&first)

	if !testing.expect_value(t, first_error.kind, .None) {
		return
	}

	testing.expect_value(t, first.status, 200)
	testing.expect(t, string(first.body) == "ok")
	sync.lock(&dns.mu)
	after_first := dns.queries
	sync.unlock(&dns.mu)
	testing.expect(t, after_first >= 1)
	second, second_error := execute({method = .GET, url = url}, config)
	defer response_destroy(&second)

	if !testing.expect_value(t, second_error.kind, .None) {
		return
	}

	testing.expect_value(t, second.status, 200)
	sync.lock(&dns.mu)
	after_second := dns.queries
	sync.unlock(&dns.mu)
	testing.expect_value(t, after_second, after_first)
}

@(test)
http3_source_failure_is_a_write_until_a_status_exists :: proc(t: ^testing.T) {
	none := http3_map_error({error = .Source}, {})
	testing.expect_value(t, none.kind, .IO_Failed)
	testing.expect_value(t, none.phase, .Write)
	testing.expect_value(t, none.write_effect, .Not_Sent)
	seen := http3_map_error({error = .Source, status = 200}, {})
	testing.expect_value(t, seen.kind, .IO_Failed)
	testing.expect_value(t, seen.phase, .Read)
}

surf_h3_slow_source :: proc(
	data: rawptr,
	mode: io.Stream_Mode,
	p: []u8,
	offset: i64,
	whence: io.Seek_From,
) -> (
	i64,
	io.Error,
) {
	reads := cast(^int)data
	reads^ += 1
	time.sleep(time.Second)
	return 0, .No_Progress
}

@(test)
http3_websocket_invalid_owners_and_missing_pool_preflight :: proc(t: ^testing.T) {
	client: HTTP_Client
	tunnel: HTTP3_Tunnel
	connection: WebSocket_Conn
	testing.expect_value(
		t,
		websocket_http3_open(nil, &tunnel, &connection, "https://example.invalid/", {}).kind,
		.Invalid_Config,
	)
	testing.expect_value(t, http_client_init(&client, {http3 = true}, {}, context.allocator).kind, .None)
	defer http_client_close(&client)
	testing.expect_value(
		t,
		websocket_http3_open(&client, &tunnel, &connection, "https://example.invalid/", {}).kind,
		.Invalid_Config,
	)
	testing.expect_value(t, connection.phase, .Uninitialized)
}
@(test)
http3_http_client_batch_is_rejected_without_tcp_fallback :: proc(t: ^testing.T) {
	pool: http3.Pool
	client: HTTP_Client
	testing.expect_value(
		t,
		http_client_init(&client, {http3 = true, http3_pool = &pool}, {}, context.allocator).kind,
		.None,
	)
	defer http_client_close(&client)
	requests := [2]http.Request {
		{method = .GET, url = "https://example.invalid/"},
		{method = .GET, url = "https://example.invalid/"},
	}

	results: [2]HTTP_Result
	error := http_client_multiplex(&client, requests[:], results[:])
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, http_client_dials(&client), 0)
}
