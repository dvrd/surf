package surf_async

import surf ".."
import runtime_async "shared:async"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "core:bytes"
import "core:mem"
import signal "shared:async/signal"
import rt "base:runtime"
import scopes "shared:async/sync/budget"

Async_Witness :: struct {
	calls:          int,
	host:           [4][96]u8,
	host_n:         [4]int,
	addresses:      [4][8]net.Endpoint,
	counts:         [4]int,
	refuse_port:    int,
	refuse_loopback: bool,
	// False when every address is loopback, so a filtered set would be dialed.
	refuse_foreign: bool,
}

async_witness_host :: proc(witness: ^Async_Witness, call: int) -> string {
	return string(witness.host[call][:witness.host_n[call]])
}

async_witness_has_v4 :: proc(witness: ^Async_Witness, call: int, ip: net.IP4_Address) -> bool {
	if call < 0 || call >= witness.calls {
		return false
	}

	for i in 0 ..< witness.counts[call] {
		switch found in witness.addresses[call][i].address {
		case net.IP4_Address:
			if found == ip {
				return true
			}
		case net.IP6_Address:
		}
	}

	return false
}

async_witness_has_v6 :: proc(witness: ^Async_Witness, call: int, ip: net.IP6_Address) -> bool {
	if call < 0 || call >= witness.calls {
		return false
	}

	for i in 0 ..< witness.counts[call] {
		switch found in witness.addresses[call][i].address {
		case net.IP4_Address:
		case net.IP6_Address:
			if found == ip {
				return true
			}
		}
	}

	return false
}

async_policy :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	witness := cast(^Async_Witness)user
	call := witness.calls

	if call < len(witness.host) {
		witness.host_n[call] = copy(witness.host[call][:], transmute([]u8)host)
		witness.counts[call] = copy(witness.addresses[call][:], addresses)
	}

	witness.calls += 1

	if witness.refuse_port != 0 {
		for address in addresses {
			if address.port == witness.refuse_port {
				return false
			}
		}
	}

	if witness.refuse_loopback {
		for address in addresses {
			switch ip in address.address {
			case net.IP4_Address:
				if ip[0] == 127 {
					return false
				}
			case net.IP6_Address:
				if ip == net.IP6_Loopback {
					return false
				}
			}
		}
	}

	if witness.refuse_foreign {
		for address in addresses {
			switch ip in address.address {
			case net.IP4_Address:
				if ip != net.IP4_Loopback {
					return false
				}
			case net.IP6_Address:
				if ip != net.IP6_Loopback {
					return false
				}
			}
		}
	}

	return true
}

// 127.0.0.2 is not assigned on this host. A second address is a non-local
// answer, and a loopback listener proves it was not dialed either.
Policy_DNS :: struct {
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

policy_dns_question :: proc(query: []u8) -> (qtype: int, question_end: int, ok: bool) {
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

policy_dns_reply :: proc(question: []u8, qtype: int, v4: [][4]u8, v6: [][16]u8) -> (reply: [512]u8, n: int) {
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

policy_dns_stopped :: proc(dns: ^Policy_DNS) -> bool {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)

	return dns.stop
}

policy_dns_loop :: proc(dns: ^Policy_DNS) {
	query: [512]u8

	for {
		if policy_dns_stopped(dns) {
			return
		}

		n, from, err := net.recv_udp(dns.socket, query[:])

		if err == .Timeout || err == .Would_Block || err == .Interrupted {
			continue
		}

		if err != nil || n < 12 {
			return
		}

		qtype, question_end, ok := policy_dns_question(query[:n])

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
		reply, reply_n := policy_dns_reply(query[:question_end], qtype, v4[:v4n], v6[:v6n])
		_, _ = net.send_udp(dns.socket, reply[:reply_n], from)
	}
}

policy_dns_start :: proc(dns: ^Policy_DNS) -> (net.Endpoint, ^thread.Thread, bool) {
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
	worker := thread.create_and_start_with_poly_data(dns, policy_dns_loop)

	if worker == nil {
		net.close(socket)
		return {}, nil, false
	}

	return endpoint, worker, true
}

policy_dns_stop :: proc(dns: ^Policy_DNS, worker: ^thread.Thread) {
	sync.lock(&dns.mu)
	dns.stop = true
	sync.unlock(&dns.mu)
	net.close(dns.socket)

	if worker != nil {
		thread.destroy(worker)
	}
}

policy_dns_counts :: proc(dns: ^Policy_DNS) -> (int, int) {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)

	return dns.a_queries, dns.aaaa_queries
}

Policy_TCP :: struct {
	socket:     net.TCP_Socket,
	mu:         sync.Mutex,
	accepts:    int,
	message:    [384]u8,
	message_n:  int,
}

policy_tcp_loop :: proc(peer: ^Policy_TCP) {
	for {
		client, _, err := net.accept_tcp(peer.socket)

		if err != nil {
			return
		}

		sync.lock(&peer.mu)
		peer.accepts += 1
		n := peer.message_n
		message := peer.message
		sync.unlock(&peer.mu)
		buffer: [512]u8
		_, _ = net.recv_tcp(client, buffer[:])

		if n > 0 {
			_, _ = net.send_tcp(client, message[:n])
		}

		net.close(client)
	}
}

policy_tcp_start :: proc(peer: ^Policy_TCP, address: net.Address) -> (net.Endpoint, ^thread.Thread, bool) {
	listener, err := net.listen_tcp({address = address, port = 0})

	if err != nil {
		return {}, nil, false
	}

	endpoint, bound := net.bound_endpoint(listener)

	if bound != .None {
		net.close(listener)
		return {}, nil, false
	}

	peer.socket = listener
	worker := thread.create_and_start_with_poly_data(peer, policy_tcp_loop)

	if worker == nil {
		net.close(listener)
		return {}, nil, false
	}

	return endpoint, worker, true
}

policy_tcp_stop :: proc(peer: ^Policy_TCP, worker: ^thread.Thread) {
	net.close(peer.socket)

	if worker != nil {
		thread.destroy(worker)
	}
}

policy_tcp_accepts :: proc(peer: ^Policy_TCP) -> int {
	sync.lock(&peer.mu)
	defer sync.unlock(&peer.mu)

	return peer.accepts
}

POLICY_OK :: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

policy_tcp_ok :: proc(peer: ^Policy_TCP) {
	text := POLICY_OK
	peer.message_n = copy(peer.message[:], transmute([]u8)text)
}

ASYNC_POLICY_CAPACITIES :: Capacities {
	requests                = 4,
	origins                 = 4,
	connections             = 4,
	connections_per_origin  = 2,
	waiters_per_origin      = 0,
	dns_ids                 = 64,
	work_per_resume         = 32,
}

async_policy_exchange :: proc(
	config: surf.Config,
	capacities: Capacities,
	url: string,
	wait: time.Duration,
) -> (
	completion: Completion,
	status: int,
	ok: bool,
) {
	runtime: runtime_async.Runtime

	// One task per connection plus the coordinator. Registration rejects a group
	// larger than the runtime's task capacity.
	if runtime_async.init(&runtime, {workers = 1, task_capacity = capacities.connections + 1, io_capacity = 8, allocator = context.allocator}).kind != .None {
		return {}, 0, false
	}

	c: Client
	started := false
	cleaned := false
	defer if !cleaned {
		if c._self == &c {
			_ = client_close(&c)
			limit := time.tick_now()

			for !client_quiescent(&c) && time.tick_since(limit) < 3 * time.Second {
				time.sleep(time.Millisecond)
			}

			for {
				item, available := client_poll(&c)

				if !available {
					break
				}

				_ = client_release(&c, item.request)
			}

			_ = client_destroy(&c)
		}

		if started {
			runtime_async.shutdown(&runtime)
			_ = runtime_async.join(&runtime)
		}

		_ = runtime_async.destroy(&runtime)
	}

	if client_init(&c, &runtime, {http = config, capacities = capacities}, context.allocator).kind != .None {
		return {}, 0, false
	}

	if runtime_async.start(&runtime).kind != .None {
		return {}, 0, false
	}

	started = true
	handle, submit_error := client_submit(&c, {method = .GET, url = url})

	if submit_error.kind != .None {
		return {}, 0, false
	}

	deadline := time.tick_now()

	for time.tick_since(deadline) < wait {
		item, available := client_poll(&c)

		if available {
			completion = item
			ok = true
			break
		}

		time.sleep(time.Millisecond)
	}

	if ok && completion.request == handle {
		if completion.error.kind == .None {
			response: surf.Response

			if client_take(&c, handle, &response).kind == .None {
				status = response.status
			} else {
				ok = false
			}

			// take finishes the request. A later release is Invalid_Handle.
			surf.response_destroy(&response)
		} else if client_release(&c, handle).kind != .None {
			ok = false
		}
	} else {
		ok = false
	}

	closed := client_close(&c)
	limit := time.tick_now()

	for !client_quiescent(&c) && time.tick_since(limit) < 3 * time.Second {
		time.sleep(time.Millisecond)
	}

	if (closed.kind != .None && closed.kind != .Pending) || !client_quiescent(&c) || client_destroy(&c).kind != .None {
		ok = false
	}

	runtime_async.shutdown(&runtime)
	join_error := runtime_async.join(&runtime)
	destroy_error := runtime_async.destroy(&runtime)
	cleaned = true

	if join_error.kind != .None || destroy_error.kind != .None {
		ok = false
	}

	return completion, status, ok
}

// An IP literal is prepared, not looked up. Refusal must complete as
// Address_Rejected; a dial error would mean a socket was opened.
@(test)
address_policy_rejects_a_numeric_target_before_async_dial :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 8 * time.Second)
	witness: Async_Witness
	witness.refuse_loopback = true
	completion, _, ok := async_policy_exchange(
		{allow_http = true, timeout = time.Second, address_policy = async_policy, address_policy_data = &witness},
		{
			requests = 1,
			origins = 1,
			connections = 1,
			connections_per_origin = 1,
			waiters_per_origin = 0,
			dns_ids = 0,
			work_per_resume = 1,
		},
		"http://127.0.0.1:1/secret",
		3 * time.Second,
	)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, completion.error.phase, .Connect)
	testing.expect_value(t, completion.error.write_effect, .Not_Sent)
	testing.expect_value(t, completion.error.status, 0)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Loopback))
	testing.expect_value(t, witness.addresses[0][0].port, 1)
}

@(test)
address_policy_rejects_a_hostname_resolved_to_a_refused_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v4[0] = {127, 0, 0, 1}
	dns.first_v4_n = 1
	dns.later_v4[0] = {203, 0, 113, 9}
	dns.later_v4_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP4_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	witness.refuse_loopback = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://refused.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, _, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, aaaa_queries := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, completion.error.phase, .Connect)
	testing.expect_value(t, completion.error.write_effect, .Not_Sent)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Loopback))
	testing.expect_value(t, witness.counts[0], 1)
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, aaaa_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 0)
}

@(test)
address_policy_never_dials_a_refused_address_beside_an_allowed_one :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v4[0] = {127, 0, 0, 1}
	dns.first_v4[1] = {203, 0, 113, 1}
	dns.first_v4_n = 2
	dns.later_v4[0] = {203, 0, 113, 2}
	dns.later_v4_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP4_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	witness.refuse_foreign = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://mixed.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, _, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, _ := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.counts[0], 2)
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Loopback))
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Address{203, 0, 113, 1}))
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 0)
}

@(test)
address_policy_rejects_a_refused_aaaa_beside_an_allowed_a :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v4[0] = {1, 1, 1, 1}
	dns.first_v4_n = 1
	dns.first_v6[0] = policy_aaaa_loopback()
	dns.first_v6_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP4_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	witness.refuse_loopback = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://mixed-family.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, _, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	_, aaaa_queries := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, completion.error.write_effect, .Not_Sent)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.counts[0], 2)
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Address{1, 1, 1, 1}))
	testing.expect(t, async_witness_has_v6(&witness, 0, net.IP6_Loopback))
	testing.expect(t, aaaa_queries >= 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 0)
}

@(test)
address_policy_dials_the_address_the_policy_saw :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v4[0] = {127, 0, 0, 1}
	dns.first_v4_n = 1
	dns.later_v4[0] = {203, 0, 113, 2}
	dns.later_v4_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	policy_tcp_ok(&peer)
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP4_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://rebind.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, status, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, aaaa_queries := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .None)
	testing.expect_value(t, status, 200)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.counts[0], 1)
	testing.expect(t, async_witness_has_v4(&witness, 0, net.IP4_Loopback))
	testing.expect_value(t, witness.addresses[0][0].port, listener.port)
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, aaaa_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 1)
}

@(test)
address_policy_rejects_a_redirect_hostname_that_resolves_to_a_refused_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v4[0] = {127, 0, 0, 1}
	dns.first_v4_n = 1
	dns.later_v4[0] = {203, 0, 113, 2}
	dns.later_v4_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	first: Policy_TCP
	second: Policy_TCP
	first_endpoint, first_worker, first_ok := policy_tcp_start(&first, net.IP4_Loopback)
	testing.expect(t, first_ok)

	if !first_ok {
		return
	}

	defer policy_tcp_stop(&first, first_worker)
	second_endpoint, second_worker, second_ok := policy_tcp_start(&second, net.IP4_Loopback)
	testing.expect(t, second_ok)

	if !second_ok {
		return
	}

	defer policy_tcp_stop(&second, second_worker)
	location := fmt.bprintf(
		first.message[:],
		"HTTP/1.1 302 Found\r\nLocation: http://next.invalid:%d/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		second_endpoint.port,
	)
	first.message_n = len(location)
	witness: Async_Witness
	witness.refuse_port = second_endpoint.port
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://127.0.0.1:%d/start", first_endpoint.port)
	defer delete(url)
	completion, _, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			max_redirects = 1,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, _ := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, completion.error.phase, .Connect)
	testing.expect_value(t, completion.error.write_effect, .Response_Received)
	testing.expect_value(t, completion.error.status, 302)
	testing.expect(t, witness.calls >= 2)

	if witness.calls >= 1 {
		last := witness.calls - 1
		testing.expect_value(t, async_witness_host(&witness, last), "next.invalid")
		testing.expect(t, async_witness_has_v4(&witness, last, net.IP4_Loopback))
		testing.expect_value(t, witness.addresses[last][0].port, second_endpoint.port)
	}
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&second), 0)
}

policy_aaaa_loopback :: proc() -> (out: [16]u8) {
	out[15] = 1

	return
}

policy_aaaa_later :: proc() -> (out: [16]u8) {
	out[0] = 0x20
	out[1] = 0x01
	out[2] = 0x0d
	out[3] = 0xb8
	out[15] = 1

	return
}

@(test)
address_policy_rejects_an_aaaa_fallback_address :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v6[0] = policy_aaaa_loopback()
	dns.first_v6_n = 1
	dns.later_v6[0] = policy_aaaa_later()
	dns.later_v6_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP6_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	witness.refuse_loopback = true
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://aaaa.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, _, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, aaaa_queries := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .Address_Rejected)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, async_witness_has_v6(&witness, 0, net.IP6_Loopback))
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, aaaa_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 0)
}

@(test)
address_policy_dials_the_aaaa_fallback_the_policy_saw :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 12 * time.Second)
	dns: Policy_DNS
	dns.first_v6[0] = policy_aaaa_loopback()
	dns.first_v6_n = 1
	dns.later_v6[0] = policy_aaaa_later()
	dns.later_v6_n = 1
	dns_endpoint, dns_worker, dns_ok := policy_dns_start(&dns)
	testing.expect(t, dns_ok)

	if !dns_ok {
		return
	}

	defer policy_dns_stop(&dns, dns_worker)
	peer: Policy_TCP
	policy_tcp_ok(&peer)
	listener, tcp_worker, tcp_ok := policy_tcp_start(&peer, net.IP6_Loopback)
	testing.expect(t, tcp_ok)

	if !tcp_ok {
		return
	}

	defer policy_tcp_stop(&peer, tcp_worker)
	witness: Async_Witness
	servers := [1]net.Endpoint{dns_endpoint}
	url := fmt.aprintf("http://aaaa.invalid:%d/secret", listener.port)
	defer delete(url)
	completion, status, ok := async_policy_exchange(
		{
			allow_http = true,
			timeout = 4 * time.Second,
			address_policy = async_policy,
			address_policy_data = &witness,
			resolver = {name_servers = servers[:]},
		},
		ASYNC_POLICY_CAPACITIES,
		url,
		6 * time.Second,
	)
	a_queries, aaaa_queries := policy_dns_counts(&dns)
	testing.expect(t, ok)
	testing.expect_value(t, completion.error.kind, .None)
	testing.expect_value(t, status, 200)
	testing.expect_value(t, witness.calls, 1)
	testing.expect_value(t, witness.counts[0], 1)
	testing.expect(t, async_witness_has_v6(&witness, 0, net.IP6_Loopback))
	testing.expect_value(t, witness.addresses[0][0].port, listener.port)
	testing.expect_value(t, a_queries, 1)
	testing.expect_value(t, aaaa_queries, 1)
	testing.expect_value(t, policy_tcp_accepts(&peer), 1)
}

bank_refill :: proc(s: ^Client_State, ids: []u16) -> Client_Error {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous; return network_dns_refill(s, ids)
}
bank_reserve :: proc(s: ^Client_State, maximum: int) -> (DNS_ID_Block, Client_Error) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous; return network_dns_reserve(s, maximum)
}
bank_burn :: proc(s: ^Client_State, block: ^DNS_ID_Block) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous; network_dns_burn(s, block)
}
bank_prepare :: proc(r: ^runtime_async.Runtime, capacity: int, allocator: mem.Allocator) -> ^Client_State {
	config := bootstrap_config({}, capacity)
	servers := [1]net.Endpoint{{net.IP4_Loopback, 53}}
	// Positive capacity uses actual explicit snapshot+OS entropy, no system files
	// or DNS query/socket traffic. The endpoints are cloned before return.
	if capacity > 0 {
		config.http.resolver.name_servers = servers[:]
	}

	state, error := network_prepare(r, config, allocator)
	assert(error.kind == .None)

	return state
}
bank_empty :: proc(s: ^Client_State) {
	for s.dns_count > 0 {
		block, error := bank_reserve(s, 16)
		assert(error.kind == .None)
		bank_burn(s, &block)
	}
}
@(test)
dns_bank_actual_prepared_draws_refill_wrap_and_move_once :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	bootstrap_runtime(&r)
	f := Ownership_Fault {
		backing = context.allocator,
	}

	s := bank_prepare(&r, 17, {ownership_allocate, &f})
	testing.expect_value(t, s.config.dns_preparation, .Explicit)
	servers, valid := net.resolver_snapshot_name_servers(&s.resolver)
	testing.expect(t, valid && len(servers) == 1 && servers[0].port == 53)
	testing.expect_value(t, s.dns_count, 17)
	bank_empty(s)
	source: [17]u16

	for &v, i in source {
		v = u16(100 + i)
	}

	original := source
	calls := f.calls
	assert(bank_refill(s, source[:]).kind == .None)
	testing.expect_value(t, source, original)

	for &v in source {
		v = 999
	}

	first, error := bank_reserve(s, 12)
	assert(error.kind == .None && first.count == 12)

	for v, i in first.values[:first.count] {
		testing.expect_value(t, v, u16(100 + i))
	}

	bank_burn(s, &first)
	testing.expect_value(t, first, DNS_ID_Block{})
	burned := s.dns_draws_burned
	bank_burn(s, &first)
	testing.expect_value(t, s.dns_draws_burned, burned)
	next := [12]u16{200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211}
	assert(bank_refill(s, next[:]).kind == .None)
	wrapped, we := bank_reserve(s, 16)
	assert(we.kind == .None && wrapped.count == 16)

	for i in 0 ..< 16 {
		want := u16(112 + i) if i < 5 else u16(200 + i - 5)
		testing.expect_value(t, wrapped.values[i], want)
	}

	bank_burn(s, &wrapped)
	last, le := bank_reserve(s, 16)
	assert(le.kind == .None && last.count == 1)
	testing.expect_value(t, last.values[0], u16(211))
	bank_burn(s, &last)
	empty, ee := bank_reserve(s, 1)
	testing.expect(t, ee.kind == .Pending && empty == (DNS_ID_Block{}))
	testing.expect_value(t, f.calls, calls)
	testing.expect_value(t, s.dns_draws_reserved, u64(46))
	testing.expect_value(t, s.dns_draws_burned, u64(46))
	assert(network_dispose_prepared(s).kind == .None && runtime_async.destroy(&r).kind == .None)
	fmt.println(
		"DNS_BANK16 prepared_ids=17 known_refill_ids=29 ordered_wrap=true draws_reserved_burned=46 noalloc=true",
	)
}
@(test)
dns_bank_invalid_capacity_shapes_and_internal_aliases_preserve_sources :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	bootstrap_runtime(&r)
	f := Ownership_Fault {
		backing = context.allocator,
	}

	s := bank_prepare(&r, 17, {ownership_allocate, &f})
	before: [17]u16
	copy(before[:], s.dns_ids)
	head, count, reserved, burned := s.dns_head, s.dns_count, s.dns_draws_reserved, s.dns_draws_burned

	for maximum in ([5]int{0, -1, 17, min(int), max(int)}) {
		block, error := bank_reserve(s, maximum)
		testing.expect(t, error.kind == .Invalid_Config && block == (DNS_ID_Block{}))
	}

	source := [2]u16{10, 11}
	original := source
	testing.expect_value(t, bank_refill(s, source[:]).kind, .Capacity)
	testing.expect_value(t, source, original)
	aliases := [5]rawptr{s, raw_data(s.actors), raw_data(s.requests), raw_data(s.task_index), raw_data(s.dns_ids)}
	calls := f.calls

	for pointer in aliases {
		input := (cast([^]u16)pointer)[:1]
		testing.expect_value(t, bank_refill(s, input).kind, .Invalid_Config)
	}

	for length in ([3]int{-1, 1, 65537}) {
		malformed: []u16
		(cast(^mem.Raw_Slice)&malformed)^ = {
			data = nil,
			len  = length,
		}

		testing.expect_value(t, bank_refill(s, malformed).kind, .Invalid_Config)
	}

	testing.expect_value(t, s.dns_head, head)
	testing.expect_value(t, s.dns_count, count)
	testing.expect_value(t, s.dns_draws_reserved, reserved)
	testing.expect_value(t, s.dns_draws_burned, burned)
	testing.expect(t, bytes.equal(mem.slice_to_bytes(before[:]), mem.slice_to_bytes(s.dns_ids)))
	testing.expect_value(t, f.calls, calls)
	assert(bank_refill(s, nil).kind == .None)
	assert(network_dispose_prepared(s).kind == .None && runtime_async.destroy(&r).kind == .None)
	fmt.println("DNS_BANK16 atomic_rejection_cells=14 internal_aliases=5 sources_preserved=true")
}
@(test)
dns_bank_zero_capacity_and_saturating_scalar_accounting_are_literal :: proc(t: ^testing.T) {
	r: runtime_async.Runtime
	bootstrap_runtime(&r)
	zero := bank_prepare(&r, 0, context.allocator)
	testing.expect_value(t, len(zero.dns_ids), 0)
	assert(bank_refill(zero, nil).kind == .None)
	block, error := bank_reserve(zero, 1)
	testing.expect(t, error.kind == .Pending && block == (DNS_ID_Block{}))
	source := [1]u16{7}
	testing.expect_value(t, bank_refill(zero, source[:]).kind, .Capacity)
	testing.expect_value(t, source[0], u16(7))
	assert(network_dispose_prepared(zero).kind == .None)
	s := bank_prepare(&r, 1, context.allocator)
	// Local counter boundary injection, not billions of actual queries.
	s.dns_draws_reserved = max(u64) - 1
	s.dns_draws_burned = max(u64) - 1
	owned, cause := bank_reserve(s, 1)
	assert(cause.kind == .None)
	testing.expect_value(t, s.dns_draws_reserved, max(u64))
	bank_burn(s, &owned)
	testing.expect_value(t, s.dns_draws_burned, max(u64))
	assert(bank_refill(s, source[:]).kind == .None)
	owned, cause = bank_reserve(s, 1)
	assert(cause.kind == .None)
	bank_burn(s, &owned)
	testing.expect_value(t, s.dns_draws_reserved, max(u64))
	testing.expect_value(t, s.dns_draws_burned, max(u64))

	for invalid in ([3]int{-1, 17, max(int)}) {
		bad := DNS_ID_Block {
			count = invalid,
		}

		bank_burn(s, &bad)
		testing.expect_value(t, bad, DNS_ID_Block{})
		testing.expect_value(t, s.dns_draws_burned, max(u64))
	}

	assert(network_dispose_prepared(s).kind == .None && runtime_async.destroy(&r).kind == .None)
}

@(test)
session_invalid_actor_guards_preserve_response_ownership :: proc(t: ^testing.T) {
	response := surf.Response{status = 203}
	before := response

	testing.expect_value(t, network_assignment_finish(nil, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, response.status, before.status)
	testing.expect_value(t, network_session_resume(nil), .Done)
	testing.expect_value(t, network_session_cancel(nil), .Done)
	network_session_done(nil)

	actor := new(Session_Actor)
	defer free(actor)

	testing.expect_value(t, network_assignment_finish(actor, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, response.status, before.status)
	testing.expect_value(t, network_session_resume(actor), .Done)
	testing.expect_value(t, network_session_cancel(actor), .Done)
	network_session_done(actor)

	runtime: runtime_async.Runtime
	bootstrap_runtime(&runtime)

	state, error := network_prepare(&runtime, bootstrap_config(), context.allocator)
	assert(error.kind == .None)

	actor^ = state.actors[0] // A copied actor cannot acquire original-address ownership.

	snapshot := make([]u8, size_of(Session_Actor))
	defer delete(snapshot)
	copy(snapshot, (cast([^]u8)&state.actors[0])[:size_of(Session_Actor)])

	testing.expect_value(t, network_assignment_finish(actor, &response, {}).kind, .Invalid_State)
	testing.expect_value(t, network_session_resume(actor), .Done)
	network_session_done(actor)
	testing.expect(t, bytes.equal(snapshot, (cast([^]u8)&state.actors[0])[:size_of(Session_Actor)]))

	assert(network_dispose_prepared(state).kind == .None && runtime_async.destroy(&runtime).kind == .None)
}

@(test)
session_real_registered_cold_mailbox_cancel_has_no_io_and_drains_owners :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 5 * time.Second)

	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, rt.heap_allocator(), rt.heap_allocator())
	allocator := mem.tracking_allocator(&track)

	scope, se := scopes.create_root({bytes = 16 << 20, streams = 8, jobs = 8}, allocator)
	assert(se == .None)

	runtime: runtime_async.Runtime
	assert(runtime_async.init(&runtime, {workers = 1, task_capacity = 2, io_capacity = 0, allocator = allocator}).kind == .None)

	state, error := network_prepare(&runtime, bootstrap_config(scope), allocator)
	assert(error.kind == .None)

	state.coordinator.task = {
		data = &state.coordinator,
		resume = proc(_: rawptr) -> runtime_async.Resume_Result {
			return .Waiting
		},
		on_cancel = proc(data: rawptr) -> runtime_async.Resume_Result {
			c := cast(^Coordinator_State)data
			sync.lock(&c.owner.mu)
			c.done = true
			sync.unlock(&c.owner.mu)
			return .Done
		},
		on_done = proc(data: rawptr) {
			c := cast(^Coordinator_State)data
			network_task_done(c.owner, 0, true)
		},
	}

	actor := &state.actors[0]
	actor.task = {data = actor, resume = network_session_resume, on_cancel = network_session_cancel, on_done = network_session_done}

	for task in state.task_index {
		assert(network_state_retain(state))
		_ = task
	}

	sync.lock(&state.mu)
	state.registered_tasks = 2
	state.coordinator.registered = true
	actor.registered = true
	state.phase = .Published
	sync.unlock(&state.mu)

	assert(runtime_async.register_group(&runtime, state.task_index).kind == .None)

	request := bootstrap_queued(state, &runtime)
	assignment := bootstrap_dispatch(state, &runtime)

	sync.lock(&state.mu)
	actor.command = {assignment = assignment, pending = true, cancel = true}
	sync.unlock(&state.mu)

	assert(kernel_cancel(&state.kernel, request).kind == .None)
	assert(runtime_async.start(&runtime).kind == .None && signal.wake(actor.wake))

	completion: Completion
	for {
		found, valid := kernel_poll(&state.kernel)
		if valid {
			completion = found
			break
		}

		time.sleep(time.Millisecond)
	}

	testing.expect(t, completion.request == request && completion.error.phase == .Cancellation && completion.error.write_effect == .Not_Sent)
	assert(kernel_release(&state.kernel, request).kind == .None)

	for {
		sync.lock(&state.kernel.mu)
		free := state.kernel.sessions[0].state == .Free
		sync.unlock(&state.kernel.mu)

		if free {
			break
		}

		time.sleep(time.Millisecond)
	}

	testing.expect_value(t, bootstrap_usage(scope).used.streams, u64(0))

	sync.lock(&state.mu)
	state.phase = .Closing
	sync.unlock(&state.mu)

	assert(kernel_close(&state.kernel).kind == .None)

	runtime_async.shutdown(&runtime)
	assert(runtime_async.join(&runtime).kind == .None && runtime_async.destroy(&runtime).kind == .None)

	testing.expect(t, state.registered_tasks == 0 && state.runtime == nil && state.references == 1)

	sync.lock(&state.mu)
	state.base_owned = false
	sync.unlock(&state.mu)
	network_state_release(state)

	testing.expect_value(t, bootstrap_usage(scope).used, scopes.Usage{})
	scopes.release_scope(&scope)

	testing.expect(t, track.current_memory_allocated == 0 && len(track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&track)

	fmt.println("SESSION_ACTOR unit_cold_cancel=1 actual_runtime_group=true io_capacity=0 owners_drained=true public_client_init=0")
}
