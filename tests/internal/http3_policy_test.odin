package surf

import http "shared:async/http"
import http3 "shared:async/http/v3"
import "shared:async/tls"
import "core:fmt"
import "core:net"
import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

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
