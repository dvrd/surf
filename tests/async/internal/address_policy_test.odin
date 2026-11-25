package surf_async

import surf ".."
import runtime_async "shared:async"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

// The runner executes tests in parallel. Witnesses live on the calling stack
// and are passed through address_policy_data.

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
