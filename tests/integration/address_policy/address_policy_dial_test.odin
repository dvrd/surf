package tests

import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "shared:surf"

// 127.0.0.2 is not assigned here. A later answer uses a non-local address so a
// second lookup cannot reach the listener that accepted the first answer.

Dial_DNS :: struct {
	socket:       net.UDP_Socket,
	mu:           sync.Mutex,
	stop:         bool,
	a_queries:    int,
	aaaa_queries: int,
	first_v4:     [4][4]u8,
	first_v4_n:   int,
	later_v4:     [4][4]u8,
	later_v4_n:   int,
	first_v6:     [2][16]u8,
	first_v6_n:   int,
	later_v6:     [2][16]u8,
	later_v6_n:   int,
}

dial_dns_question :: proc(query: []u8) -> (qtype: int, question_end: int, ok: bool) {
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

	qtype = int(query[at]) << 8 | int(query[at + 1])

	return qtype, at + 4, true
}

dial_dns_reply :: proc(question: []u8, qtype: int, v4: [][4]u8, v6: [][16]u8) -> (reply: [512]u8, n: int) {
	n = copy(reply[:], question)
	reply[2] = 0x81
	reply[3] = 0x80
	reply[8] = 0
	reply[9] = 0
	reply[10] = 0
	reply[11] = 0
	count := len(v4) if qtype == 1 else len(v6)
	reply[6] = u8(count >> 8)
	reply[7] = u8(count)

	for i in 0 ..< count {
		if qtype == 1 {
			if n + 16 > len(reply) {
				break
			}

			record := [16]u8 {
				0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4,
				v4[i][0], v4[i][1], v4[i][2], v4[i][3],
			}
			n += copy(reply[n:], record[:])
		} else {
			if n + 28 > len(reply) {
				break
			}

			head := [12]u8{0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16}
			n += copy(reply[n:], head[:])
			n += copy(reply[n:], v6[i][:])
		}
	}

	return
}

dial_dns_stopped :: proc(dns: ^Dial_DNS) -> bool {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)

	return dns.stop
}

dial_dns_loop :: proc(dns: ^Dial_DNS) {
	query: [512]u8

	for {
		if dial_dns_stopped(dns) {
			return
		}

		n, from, err := net.recv_udp(dns.socket, query[:])

		if err == .Timeout || err == .Would_Block || err == .Interrupted {
			continue
		}

		if err != nil || n < 12 {
			return
		}

		qtype, question_end, ok := dial_dns_question(query[:n])

		if !ok || (qtype != 1 && qtype != 28) {
			continue
		}

		v4: [4][4]u8
		v6: [2][16]u8
		v4n, v6n: int
		sync.lock(&dns.mu)

		if qtype == 1 {
			dns.a_queries += 1

			if dns.a_queries == 1 || dns.later_v4_n == 0 {
				v4n = dns.first_v4_n
				v4 = dns.first_v4
			} else {
				v4n = dns.later_v4_n
				v4 = dns.later_v4
			}
		} else {
			dns.aaaa_queries += 1

			if dns.aaaa_queries == 1 || dns.later_v6_n == 0 {
				v6n = dns.first_v6_n
				v6 = dns.first_v6
			} else {
				v6n = dns.later_v6_n
				v6 = dns.later_v6
			}
		}

		sync.unlock(&dns.mu)
		reply, reply_n := dial_dns_reply(query[:question_end], qtype, v4[:v4n], v6[:v6n])
		_, _ = net.send_udp(dns.socket, reply[:reply_n], from)
	}
}

dial_dns_start :: proc(dns: ^Dial_DNS) -> (net.Endpoint, ^thread.Thread, bool) {
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
	worker := thread.create_and_start_with_poly_data(dns, dial_dns_loop)

	if worker == nil {
		net.close(socket)
		return {}, nil, false
	}

	return endpoint, worker, true
}

dial_dns_stop :: proc(dns: ^Dial_DNS, worker: ^thread.Thread) {
	sync.lock(&dns.mu)
	dns.stop = true
	sync.unlock(&dns.mu)
	net.close(dns.socket)

	if worker != nil {
		thread.destroy(worker)
	}
}

dial_dns_counts :: proc(dns: ^Dial_DNS) -> (int, int) {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)

	return dns.a_queries, dns.aaaa_queries
}

Dial_TCP :: struct {
	socket:    net.TCP_Socket,
	mu:        sync.Mutex,
	accepts:   int,
	message:   [384]u8,
	message_n: int,
}

dial_tcp_loop :: proc(peer: ^Dial_TCP) {
	for {
		client, _, err := net.accept_tcp(peer.socket)

		if err != nil {
			return
		}

		sync.lock(&peer.mu)
		peer.accepts += 1
		sync.unlock(&peer.mu)
		buffer: [256]u8
		_, _ = net.recv_tcp(client, buffer[:])
		net.close(client)
	}
}

dial_tcp_start :: proc(peer: ^Dial_TCP) -> (net.Endpoint, ^thread.Thread, bool) {
	listener, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})

	if err != nil {
		return {}, nil, false
	}

	endpoint, bound := net.bound_endpoint(listener)

	if bound != .None {
		net.close(listener)
		return {}, nil, false
	}

	peer.socket = listener
	worker := thread.create_and_start_with_poly_data(peer, dial_tcp_loop)

	if worker == nil {
		net.close(listener)
		return {}, nil, false
	}

	return endpoint, worker, true
}

dial_tcp_stop :: proc(peer: ^Dial_TCP, worker: ^thread.Thread) {
	net.close(peer.socket)

	if worker != nil {
		thread.destroy(worker)
	}
}

dial_tcp_accepts :: proc(peer: ^Dial_TCP) -> int {
	sync.lock(&peer.mu)
	defer sync.unlock(&peer.mu)

	return peer.accepts
}

dial_dns_prepare :: proc(dns: ^Dial_DNS) {
	dns.first_v4[0] = {127, 0, 0, 1}
	dns.first_v4_n = 1
	dns.later_v4[0] = {203, 0, 113, 2}
	dns.later_v4_n = 1
}

Dial_Witness :: struct {
	calls:    int,
	count:    int,
	endpoint: net.Endpoint,
	allow:    bool,
}

dial_policy :: proc(_: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	witness := cast(^Dial_Witness)user
	witness.calls += 1
	witness.count = len(addresses)

	if len(addresses) > 0 {
		witness.endpoint = addresses[0]
	}

	return witness.allow
}

expect_public :: proc(t: ^testing.T, text: string, allowed: bool) {
	parsed := net.parse_address(text)
	testing.expect(t, parsed != nil)

	if parsed == nil {
		return
	}

	endpoint := net.Endpoint {
		address = parsed,
		port    = 9,
	}
	got := surf.address_policy_public_only(text, []net.Endpoint{endpoint}, nil)
	testing.expect_value(t, got, allowed)
}

@(test)
address_policy_public_only_refuses_non_global_ranges :: proc(t: ^testing.T) {
	refused := [?]string {
		"127.0.0.1",
		"127.255.255.255",
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.1.1",
		"169.254.169.254",
		"0.0.0.0",
		"0.0.0.1",
		"0.255.255.255",
		"100.64.0.0",
		"100.64.0.1",
		"100.127.255.255",
		"224.0.0.1",
		"239.255.255.255",
		"240.0.0.1",
		"240.255.255.255",
		"255.255.255.255",
		"::1",
		"::",
		"fe80::1",
		"febf::",
		"fc00::1",
		"fd12:3456::1",
		"ff00::1",
		"ff02::1",
		"64:ff9b::",
		"64:ff9b::8.8.8.8",
		"::ffff:127.0.0.1",
		"::ffff:10.1.2.3",
		"::ffff:172.16.5.5",
		"::ffff:172.31.1.1",
		"::ffff:192.168.0.1",
		"::ffff:169.254.169.254",
		"::ffff:0.0.0.0",
		"::ffff:0.0.0.1",
		"::ffff:100.64.0.1",
		"::ffff:224.0.0.1",
		"::ffff:239.1.1.1",
		"::ffff:240.0.0.1",
	}
	allowed := [?]string {
		"1.1.1.1",
		"8.8.8.8",
		"11.0.0.1",
		"100.63.255.255",
		"100.128.0.1",
		"172.15.255.255",
		"172.32.0.1",
		"192.169.0.1",
		"169.255.1.1",
		"203.0.113.1",
		"223.255.255.255",
		"::2",
		"fec0::1",
		"64:ff9b:1::",
		"2001:4860:4860::8888",
		"::ffff:1.1.1.1",
		"::ffff:100.63.255.255",
		"::ffff:172.15.0.1",
		"::ffff:172.32.0.1",
		"::ffff:8.8.8.8",
	}

	for text in refused {
		expect_public(t, text, false)
	}

	for text in allowed {
		expect_public(t, text, true)
	}

	testing.expect(t, !surf.address_policy_public_only("example.test", nil, nil))
	mixed := [2]net.Endpoint {
		{address = net.parse_address("1.1.1.1"), port = 9},
		{address = net.parse_address("127.0.0.1"), port = 9},
	}
	testing.expect(t, !surf.address_policy_public_only("example.test", mixed[:], nil))
	both := [2]net.Endpoint {
		{address = net.parse_address("1.1.1.1"), port = 9},
		{address = net.parse_address("2001:4860:4860::8888"), port = 9},
	}
	testing.expect(t, surf.address_policy_public_only("example.test", both[:], nil))
	response, error := surf.execute(
		{method = .GET, url = "http://127.0.0.1:1/secret"},
		{allow_http = true, timeout = time.Second, address_policy = surf.address_policy_public_only},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
header_reserved_exports_the_request_fields_rejected_on_submit :: proc(t: ^testing.T) {
	reserved := [?]string {
		"Host",
		"host",
		"HOST",
		"Connection",
		"Content-Length",
		"Transfer-Encoding",
		"Accept-Encoding",
		"Expect",
		"Upgrade",
		"Trailer",
		"TE",
		"te",
	}

	for name in reserved {
		testing.expect(t, surf.header_reserved(name))
	}

	testing.expect(t, !surf.header_reserved("X-Forwarded-For"))
	testing.expect(t, !surf.header_reserved("Content-Type"))
	testing.expect(t, !surf.header_reserved("Accept"))
	testing.expect(t, !surf.header_reserved(""))
	headers := [1]surf.Header {
		{name = "Host", value = "example.test"},
	}
	response, error := surf.execute(
		{method = .GET, url = "http://127.0.0.1:1/", headers = headers[:]},
		{allow_http = true, timeout = time.Second},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Reserved_Header)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
http3_dials_the_endpoint_the_policy_checked :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 15 * time.Second)
	dns: Dial_DNS
	dial_dns_prepare(&dns)
	dns_endpoint, dns_worker, dns_ok := dial_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer dial_dns_stop(&dns, dns_worker)
	capture, capture_error := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	testing.expect(t, capture_error == nil)

	if capture_error != nil {
		return
	}

	defer net.close(capture)
	testing.expect(t, net.set_option(capture, .Receive_Timeout, 200 * time.Millisecond) == nil)
	bound, bound_error := net.bound_endpoint(capture)
	testing.expect_value(t, bound_error, .None)

	if bound_error != .None {
		return
	}

	drain: [1500]u8
	_, _, _ = net.recv_udp(capture, drain[:])
	witness: Dial_Witness
	witness.allow = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("https://checked.invalid:%d/", bound.port)
	defer delete(url)
	body := [1]u8{1}
	response, error := surf.execute(
		{method = .POST, url = url, body = body[:]},
		{
			http3 = true,
			timeout = 3 * time.Second,
			address_policy = dial_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
	)
	defer surf.response_destroy(&response)
	n, _, recv_error := net.recv_udp(capture, drain[:])
	a_queries, aaaa_queries := dial_dns_counts(&dns)
	testing.expect(t, error.kind != .Address_Rejected)
	testing.expect(t, recv_error == nil && n > 0)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.count, 1)
	testing.expect_value(t, witness.endpoint.port, bound.port)
	switch ip in witness.endpoint.address {
	case net.IP4_Address:
		testing.expect(t, ip == net.IP4_Loopback)
	case net.IP6_Address:
		testing.expect(t, false)
	}
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, aaaa_queries, 1)
}

@(test)
http3_refuses_the_resolved_endpoint_before_a_datagram :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Dial_DNS
	dial_dns_prepare(&dns)
	dns_endpoint, dns_worker, dns_ok := dial_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer dial_dns_stop(&dns, dns_worker)
	capture, capture_error := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	testing.expect(t, capture_error == nil)

	if capture_error != nil {
		return
	}

	defer net.close(capture)
	testing.expect(t, net.set_option(capture, .Receive_Timeout, 200 * time.Millisecond) == nil)
	bound, bound_error := net.bound_endpoint(capture)
	testing.expect_value(t, bound_error, .None)

	if bound_error != .None {
		return
	}

	witness: Dial_Witness
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("https://checked.invalid:%d/", bound.port)
	defer delete(url)
	body := [1]u8{1}
	response, error := surf.execute(
		{method = .POST, url = url, body = body[:]},
		{
			http3 = true,
			timeout = 3 * time.Second,
			address_policy = dial_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
	)
	defer surf.response_destroy(&response)
	buffer: [1500]u8
	n, _, recv_error := net.recv_udp(capture, buffer[:])
	a_queries, _ := dial_dns_counts(&dns)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect(t, recv_error != nil || n == 0)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.count, 1)
	testing.expect_value(t, witness.endpoint.port, bound.port)
	testing.expect_value(t, a_queries, 1)
}

// An HTTPS origin whose name resolves to the listener: the address the policy
// saw is the one connected to. The listener closes without TLS.
@(test)
tcp_dials_the_endpoint_the_policy_checked :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Dial_DNS
	dial_dns_prepare(&dns)
	dns_endpoint, dns_worker, dns_ok := dial_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer dial_dns_stop(&dns, dns_worker)
	peer: Dial_TCP
	listener, tcp_worker, tcp_ok := dial_tcp_start(&peer)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer dial_tcp_stop(&peer, tcp_worker)
	roots: surf.Trust_Roots
	defer surf.trust_roots_destroy(&roots)

	if !testing.expect_value(t, surf.trust_roots_load_file(&roots, "tests/support/credentials/root.pem"), surf.Trust_Roots_Error.None) {
		return
	}

	witness: Dial_Witness
	witness.allow = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("https://checked.invalid:%d/", listener.port)
	defer delete(url)
	response, error := surf.execute(
		{method = .GET, url = url},
		{
			tls = {roots = &roots},
			timeout = 3 * time.Second,
			address_policy = dial_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
	)
	defer surf.response_destroy(&response)
	a_queries, _ := dial_dns_counts(&dns)
	testing.expectf(t, error.kind != .None && error.kind != .Address_Rejected, "%v", error)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.count, 1)
	testing.expect_value(t, witness.endpoint.port, listener.port)
	switch ip in witness.endpoint.address {
	case net.IP4_Address:
		testing.expect(t, ip == net.IP4_Loopback)
	case net.IP6_Address:
		testing.expect(t, false)
	}

	testing.expect(t, a_queries >= 1)
	testing.expectf(t, dial_tcp_accepts(&peer) == 1, "%v", error)
}

@(test)
tcp_does_not_connect_when_the_hostname_is_refused :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Dial_DNS
	dial_dns_prepare(&dns)
	dns_endpoint, dns_worker, dns_ok := dial_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer dial_dns_stop(&dns, dns_worker)
	peer: Dial_TCP
	listener, tcp_worker, tcp_ok := dial_tcp_start(&peer)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer dial_tcp_stop(&peer, tcp_worker)
	witness: Dial_Witness
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://checked.invalid:%d/", listener.port)
	defer delete(url)
	response, error := surf.execute(
		{method = .GET, url = url},
		{
			allow_http = true,
			timeout = 3 * time.Second,
			address_policy = dial_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
	)
	defer surf.response_destroy(&response)
	a_queries, _ := dial_dns_counts(&dns)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.endpoint.port, listener.port)
	testing.expect(t, a_queries >= 1)
	testing.expect_value(t, dial_tcp_accepts(&peer), 0)
}
