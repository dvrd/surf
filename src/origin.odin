package surf

import "core:net"
import "core:strings"
import "core:time"
import "shared:async"

// One origin's async.Client. Origins with the same scheme, host and port share
// connections; a closing origin is never reused.
@(private)
Origin :: struct {
	client:    async.Client,
	s:         ^Client_State,
	host_buf:  [256]u8,
	// The host in lowercase, as SNI is sent.
	sni_buf:   [256]u8,
	host:      string,
	dial_host: string,
	port:      int,
	secure:    bool,
	decode:    bit_set[async.Coding],
	// The address policy refused the addresses of a dial.
	refused:   bool,
	// Exchanges on this origin.
	active:    int,
	idle_at:   async.Deadline,
	closing:   bool,
	done:      bool,
}

// waiting: every origin slot is taken; the request stays queued.
@(private)
origin_get :: proc(
	s: ^Client_State,
	u: async.Http_URL,
	decode: bit_set[async.Coding],
) -> (
	origin: ^Origin,
	waiting: bool,
	error: HTTP_Error,
) {
	for o in s.origins {
		if !o.closing &&
		   o.secure == u.secure &&
		   o.port == u.port &&
		   o.decode == decode &&
		   strings.equal_fold(o.host, u.host) {
			return o, false, {}
		}
	}

	if len(s.origins) >= s.capacities.origins {
		for o in s.origins {
			if !o.closing && o.active == 0 {
				origin_close(s, o)
				break
			}
		}
		return nil, true, {}
	}

	if len(u.host) > len(Origin{}.host_buf) {
		return nil, false, {kind = .Invalid_URL, phase = .Configuration, write_effect = .Not_Sent}
	}

	o, allocation := new(Origin, s.allocator)
	if allocation != nil {
		return nil, false, {kind = .Allocation_Failed, allocation = allocation, phase = .Admission, write_effect = .Not_Sent}
	}

	o.s = s
	copy(o.host_buf[:], u.host)
	o.host = string(o.host_buf[:len(u.host)])
	o.port, o.secure, o.decode = u.port, u.secure, decode
	o.dial_host = o.host

	if address, found := client_hosts_address(s, o.host, o.port); found {
		literal, e := strings.clone(net.address_to_string(address, context.temp_allocator), s.allocator)
		if e != nil {
			free(o, s.allocator)
			return nil, false, {kind = .Allocation_Failed, allocation = e, phase = .Admission, write_effect = .Not_Sent}
		}
		o.dial_host = literal
	}

	if o.dial_host == o.host && net.parse_address(o.host) == nil && len(client_name_servers(s)) == 0 {
		free(o, s.allocator)
		return nil, false, {kind = .Dial_Failed, phase = .DNS, write_effect = .Not_Sent}
	}

	if begun := async.client_begin(&o.client, &s.task, origin_config(s, o)); begun.kind != .None {
		origin_free(s, o)
		return nil, false, {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	if _, e := append(&s.origins, o); e != nil {
		async.client_destroy(&o.client)
		origin_free(s, o)
		return nil, false, {kind = .Allocation_Failed, allocation = e, phase = .Admission, write_effect = .Not_Sent}
	}

	return o, false, {}
}

@(private)
origin_config :: proc(s: ^Client_State, o: ^Origin) -> async.Client_Config {
	// surf applies Config.max_body_size itself, once the head and its status are
	// known.
	limit := i64(async.HTTP_MAX_BODY_SIZE)
	servers := client_name_servers(s)

	setup := s.config.setup_timeout
	if setup == 0 {
		setup = effective_timeout(s.config)
	}

	config := async.Client_Config {
		dial = {
			host = o.dial_host,
			port = o.port,
			nameservers = servers,
		},
		dial_timeout = setup,
		protocols = {.HTTP1, .H2},
		max_connections = s.capacities.connections_per_origin,
		http1 = {max_response_body_bytes = limit, decode = o.decode},
		http2 = {max_response_body_bytes = limit, decode = o.decode},
		allocator = s.allocator,
	}

	if s.config.address_policy != nil {
		config.dial.address_policy = origin_policy
		config.dial.policy_user = o
	}

	if o.secure {
		config.dial.tls = async.Dial_TLS {
			server_name        = origin_sni(o),
			roots              = client_roots(s),
			client_credentials = s.config.tls.client_credentials,
			session_cache      = s.config.tls.session_cache,
		}

		if origin_h3(s, o) {
			if pool := client_h3_pool(s); pool != nil {
				config.protocols += {.H3}
				config.h3_pool = pool
			}
		}
	}

	return config
}

@(private)
client_name_servers :: proc(s: ^Client_State) -> []net.Endpoint {
	if !s.resolver_ready {
		return nil
	}

	servers, _ := net.resolver_snapshot_name_servers(&s.resolver)

	return servers
}

// The address the hosts file gives a host name, IPv4 first, as a dial orders
// a DNS answer.
@(private)
client_hosts_address :: proc(s: ^Client_State, host: string, port: int) -> (net.Address, bool) {
	if !s.resolver_ready || net.parse_address(host) != nil {
		return nil, false
	}

	endpoints: [DNS_HOSTS_ENTRIES]net.Endpoint
	count, found, lookup := net.resolver_snapshot_lookup(&s.resolver, host, endpoints[:], port)

	if !found || lookup != nil || count == 0 {
		return nil, false
	}

	chosen := endpoints[0]

	for endpoint in endpoints[:count] {
		if _, v4 := endpoint.address.(net.IP4_Address); v4 {
			chosen = endpoint
			break
		}
	}

	return chosen.address, true
}

@(private)
origin_h3 :: proc(s: ^Client_State, o: ^Origin) -> bool {
	if o.decode != {} {
		return false
	}

	if s.config.http3 {
		return true
	}

	if s.config.alt_svc != nil {
		port, found := alt_svc_lookup(s.config.alt_svc, o.host, time.now(), o.port)
		return found && port == o.port
	}

	return false
}

@(private)
client_h3_pool :: proc(s: ^Client_State) -> ^async.H3_Pool {
	if s.h3_pool != nil {
		return s.h3_pool
	}

	if s.config.http3_pool != nil {
		s.h3_pool = s.config.http3_pool
		return s.h3_pool
	}

	pool, allocation := new(async.H3_Pool, s.allocator)
	if allocation != nil {
		return nil
	}

	config := async.H3_Pool_Config {
		qpack                   = s.config.http3_qpack,
		ecn                     = s.config.http3_ecn,
		max_response_body_bytes = async.HTTP_MAX_BODY_SIZE,
		allocator               = s.allocator,
	}

	if error := async.h3_pool_init(pool, config); error.kind != .None {
		free(pool, s.allocator)
		return nil
	}

	s.h3_pool, s.own_h3 = pool, true

	return pool
}

// The caller's policy sees the URL's host, also when the hosts file gave the
// address that is dialed.
@(private)
origin_policy :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	o := cast(^Origin)user
	config := o.s.config
	allowed := len(addresses) > 0 && config.address_policy(o.host, addresses, config.address_policy_data)

	if !allowed {
		o.refused = true
	}

	return allowed
}

@(private)
origin_close :: proc(s: ^Client_State, o: ^Origin) {
	if o.closing {
		return
	}

	o.closing = true
	_ = async.client_shutdown(&o.client, async.deadline_after(s.runtime, CLIENT_CLOSE_TIMEOUT))
}

// Resumes every origin's client, closes idle ones and frees closed ones.
@(private)
origins_resume :: proc(s: ^Client_State, active: int) -> (yield: bool) {
	for i := 0; i < len(s.origins); {
		o := s.origins[i]

		if !o.closing && o.active == 0 {
			if s.closing || o.idle_at == {} || async.sleep_until_earlier(s.runtime, o.idle_at).kind == .None {
				origin_close(s, o)
			}
		}

		switch async.client_resume(&o.client) {
		case .Yield:
			yield = true
		case .Done:
			o.done = true
		case .Waiting:
		}

		if o.done {
			async.client_destroy(&o.client)
			origin_free(s, o)
			ordered_remove(&s.origins, i)
			// A request may be waiting for this origin slot.
			yield = true
			continue
		}

		i += 1
	}

	return
}

@(private)
origin_free :: proc(s: ^Client_State, o: ^Origin) {
	if o.dial_host != o.host {
		delete(o.dial_host, s.allocator)
	}

	free(o, s.allocator)
}

@(private)
origin_sni :: proc(o: ^Origin) -> string {
	for i in 0 ..< len(o.host) {
		c := o.host[i]
		o.sni_buf[i] = c + 32 if c >= 'A' && c <= 'Z' else c
	}

	return string(o.sni_buf[:len(o.host)])
}

@(private)
client_roots :: proc(s: ^Client_State) -> ^async.Root_Pool {
	if s.config.tls.roots != nil {
		return s.config.tls.roots
	}

	if s.system_roots == nil {
		pool, allocation := new(async.Root_Pool, s.allocator)
		if allocation != nil {
			return nil
		}

		if async.root_pool_load_system(pool) != nil {
			async.root_pool_destroy(pool)
			free(pool, s.allocator)
			return nil
		}

		s.system_roots = pool
	}

	return s.system_roots
}
