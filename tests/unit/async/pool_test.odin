package surf_async

import rt "base:runtime"
import "core:crypto/x509"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:fmt"
import surf ".."
import runtime_async "shared:async"
import scopes "shared:async/sync/budget"
import "core:time"

Identity_Grant_Mode :: enum {
	Normal,
	Nil_Error,
	Grant_Error,
	Nil_Success,
	Short,
	Long,
	Misaligned,
}
Identity_Grant_Record :: struct {
	raw, reported: []u8,
}
Identity_Grant_Probe :: struct {
	mode:                              Identity_Grant_Mode,
	calls, fail_at, frees, live_bytes: int,
	records:                           [8]Identity_Grant_Record,
	profile_to_free:                   ^Profile,
	origin_to_free:                    ^Prepared_Origin,
}
identity_allocator :: proc(
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
	s := cast(^Identity_Grant_Probe)data
	backing := rt.heap_allocator()
	if mode == .Alloc || mode == .Alloc_Non_Zeroed {
		s.calls += 1
		selected := s.mode if s.calls == s.fail_at else Identity_Grant_Mode.Normal

		if selected == .Nil_Error {
			return nil, .Out_Of_Memory
		}

		if selected == .Nil_Success {
			return nil, nil
		}

		count := size

		if selected == .Short {
			count = max(0, size - 1)
		}

		if selected == .Long {
			count = size + 1
		}

		if selected == .Misaligned {
			count = size + 1
		}

		raw, cause := backing.procedure(backing.data, .Alloc, count, max(alignment, 8), nil, 0, location)
		assert(cause == nil && len(raw) == count)
		reported := raw

		if selected == .Misaligned {
			reported = raw[1:]
		}

		found := false

		for &record in s.records {
			if raw_data(record.raw) == nil {
				record = {
					raw      = raw,
					reported = reported,
				}

				found = true
				break
			}
		}

		assert(found)
		s.live_bytes += len(raw)

		if selected == .Grant_Error {
			return reported, .Out_Of_Memory
		}

		return reported, nil
	}
	if mode == .Free {
		for &record in s.records {
			if old_memory == raw_data(record.reported) && raw_data(record.raw) != nil {
				assert(old_size == len(record.reported))
				raw := record.raw
				record = {}
				s.frees += 1
				s.live_bytes -= len(raw)

				if s.profile_to_free != nil {
					owner := s.profile_to_free
					s.profile_to_free = nil
					assert(owner.self == nil && owner.owner_id == 0 && owner.storage == nil)
					free(owner, backing)
				}

				if s.origin_to_free != nil {
					owner := s.origin_to_free
					s.origin_to_free = nil
					assert(owner.storage == nil && owner.key.host == "" && owner.key.profile_id == 0)
					free(owner, backing)
				}

				return backing.procedure(backing.data, .Free, 0, max(alignment, 8), raw_data(raw), len(raw), location)
			}
		}

		assert(false, "unknown or duplicate physical free")
	}
	return backing.procedure(backing.data, mode, size, alignment, old_memory, old_size, location)
}
identity_backing :: proc(s: ^Identity_Grant_Probe) -> mem.Allocator {
	return {procedure = identity_allocator, data = s}
}
identity_test_offers: [1]string = {"http/1.1"}
identity_config :: proc() -> Normalized_Config {
	result, error := config_normalize(
		{
			http = {
				allow_http = true,
				tls = {server_name = "configured.example", alpn_protocols = identity_test_offers[:]},
			},
		},
	)
	assert(error.kind == .None)

	return result
}

@(test)
identity_profile_clones_descriptors_and_octets_but_borrows_certificates :: proc(t: ^testing.T) {
	arena_bytes: [2048]u8
	arena: mem.Arena
	mem.arena_init(&arena, arena_bytes[:])
	temporary := mem.arena_allocator(&arena)
	certificates: [2]x509.Certificate
	roots := make([]^x509.Certificate, 2, temporary)
	roots[0], roots[1] = &certificates[0], &certificates[1]
	offers := make([]string, 1, temporary)
	offers[0] = strings.clone("http/1.1", temporary)
	servers := make([]net.Endpoint, 1, temporary)
	servers[0] = {
		address = net.IP4_Address{127, 0, 0, 1},
		port    = 53,
	}

	config, error := config_normalize(
		{
			http = {
				allow_http = true,
				tls = {
					server_name = strings.clone("configured.example", temporary),
					alpn_protocols = offers,
					root_cas = roots,
				},
				resolver = {name_servers = servers},
			},
		},
	)
	testing.expect_value(t, error.kind, .None)
	probe: Identity_Grant_Probe
	profile: Profile
	testing.expect_value(t, profile_init(&profile, config, identity_backing(&probe)).kind, .None)
	testing.expect_value(t, probe.calls, 1)
	testing.expect(t, raw_data(profile.config.http.tls.root_cas) != raw_data(roots))
	testing.expect(t, raw_data(profile.config.http.tls.alpn_protocols) != raw_data(offers))
	testing.expect(t, raw_data(profile.config.http.resolver.name_servers) != raw_data(servers))
	testing.expect_value(
		t,
		uintptr(raw_data(profile.config.http.tls.root_cas)) % align_of(^x509.Certificate),
		uintptr(0),
	)
	testing.expect_value(t, uintptr(raw_data(profile.config.http.tls.alpn_protocols)) % align_of(string), uintptr(0))
	testing.expect_value(
		t,
		uintptr(raw_data(profile.config.http.resolver.name_servers)) % align_of(net.Endpoint),
		uintptr(0),
	)
	mem.arena_free_all(&arena)

	for &byte in arena_bytes {
		byte = 0xDD
	}

	testing.expect_value(t, profile.config.http.tls.server_name, "configured.example")
	testing.expect_value(t, profile.config.http.tls.alpn_protocols[0], "http/1.1")
	testing.expect_value(t, profile.config.http.resolver.name_servers[0].port, 53)
	testing.expect_value(t, profile.config.http.tls.root_cas[0], &certificates[0])
	testing.expect_value(t, profile.config.http.tls.root_cas[1], &certificates[1])
	before := profile.owner_id
	storage := raw_data(profile.storage)
	testing.expect_value(t, profile_init(&profile, config, identity_backing(&probe)).kind, .Invalid_State)
	testing.expect_value(t, profile.owner_id, before)
	testing.expect_value(t, raw_data(profile.storage), storage)
	profile_destroy(&profile)
	profile_destroy(&profile)
	testing.expect_value(t, probe.live_bytes, 0)
	testing.expect_value(t, probe.frees, 1)
	testing.expect_value(t, profile.owner_id, u64(0))
}

@(test)
identity_origins_follow_exact_profile_scheme_host_port_policy :: proc(t: ^testing.T) {
	profile: Profile
	testing.expect_value(t, profile_init(&profile, identity_config(), context.allocator).kind, .None)
	defer profile_destroy(&profile)
	pairs := [?]struct {
		a, b:  string,
		equal: bool,
	} {
		{"https://Example.COM/a", "HTTPS://example.com:443/b?q=1", true},
		{"http://Example.COM/", "http://example.com:80/x", true},
		{"https://example.com/", "http://example.com:443/", false},
		{"https://example.com/", "https://example.com:444/", false},
		{"https://a.example/", "https://b.example/", false},
		{"https://127.0.0.1/", "https://127.0.0.2/", false},
		{"https://[2001:db8::1]/", "https://[2001:db8::1]:443/x", true},
		{"https://[2001:db8::1]/", "https://[2001:0db8:0:0:0:0:0:1]/", false},
		{"https://[2001:DB8::1]/", "https://[2001:db8::1]/", false},
	}

	for pair in pairs {
		a, ea := origin_prepare(&profile, pair.a, context.allocator)
		b, eb := origin_prepare(&profile, pair.b, context.allocator)
		testing.expect_value(t, ea.kind, .None)
		testing.expect_value(t, eb.kind, .None)
		testing.expect_value(t, origin_equal(a.key, b.key), pair.equal)
		testing.expect_value(t, origin_equal(b.key, a.key), pair.equal)
		testing.expect_value(t, a.key.profile_id, profile.owner_id)
		origin_destroy(&a)
		origin_destroy(&b)
	}

	other: Profile
	testing.expect_value(t, profile_init(&other, identity_config(), context.allocator).kind, .None)
	a, _ := origin_prepare(&profile, "https://same.example/", context.allocator)
	b, _ := origin_prepare(&other, "https://same.example/", context.allocator)
	testing.expect(t, profile.owner_id != other.owner_id && !origin_equal(a.key, b.key))
	origin_destroy(&a)
	origin_destroy(&b)
	profile_destroy(&other)
	// URL storage is borrowed for the call only, then independently owned.
	input := strings.clone("https://MiXeD.example:8443/path", context.allocator)
	owned, error := origin_prepare(&profile, input, context.allocator)
	delete(input)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, owned.key.host, "mixed.example")
	testing.expect_value(t, owned.key.port, u16(8443))
	origin_destroy(&owned)
}

@(test)
identity_rejects_malformed_and_insecure_urls_before_allocation :: proc(t: ^testing.T) {
	config := identity_config()
	config.http.allow_http = false
	profile: Profile
	testing.expect_value(t, profile_init(&profile, config, context.allocator).kind, .None)
	defer profile_destroy(&profile)

	for url in ([?]string {
			"http://example.com/",
			"ftp://example.com/",
			"https:///",
			"https://a:0/",
			"https://a:65536/",
			"https://user@host/",
			"https://a/#fragment",
			"https://a/%Q0",
			"https://a\\b/",
			"https://[bad]/",
			"https://-bad/",
		}) {
		result, error := origin_prepare(&profile, url, mem.panic_allocator())
		testing.expect_value(t, error.kind, .Request_Error)
		testing.expect_value(t, result.key.profile_id, u64(0))
		testing.expect(t, result.storage == nil)
	}

	_, error := origin_prepare(nil, "https://example.com/", context.allocator)
	testing.expect_value(t, error.kind, .Invalid_State)
	alias := profile
	_, error = origin_prepare(&alias, "https://example.com/", context.allocator)
	testing.expect_value(t, error.kind, .Invalid_State)
	_, error = origin_prepare(&profile, "https://example.com/", {})
	testing.expect_value(t, error.kind, .Invalid_Config)
}

@(test)
identity_every_physical_constructor_grant_rolls_back :: proc(t: ^testing.T) {
	config := identity_config()
	baseline: Identity_Grant_Probe
	profile: Profile
	testing.expect_value(t, profile_init(&profile, config, identity_backing(&baseline)).kind, .None)
	profile_calls := baseline.calls
	profile_destroy(&profile)
	testing.expect_value(t, baseline.live_bytes, 0)
	testing.expect(t, profile_calls > 0)
	modes := [?]Identity_Grant_Mode{.Nil_Error, .Grant_Error, .Nil_Success, .Short, .Long, .Misaligned}

	for mode in modes {
		for point in 1 ..= profile_calls {
			probe := Identity_Grant_Probe {
				mode    = mode,
				fail_at = point,
			}

			destination: Profile
			error := profile_init(&destination, config, identity_backing(&probe))
			testing.expect_value(t, error.kind, .Allocation_Failed)
			testing.expect_value(t, error.http.kind, .Allocation_Failed)
			testing.expect(t, destination.self == nil)
			testing.expect_value(t, destination.owner_id, u64(0))
			testing.expect_value(t, probe.live_bytes, 0)
		}
	}

	testing.expect_value(t, profile_init(&profile, config, context.allocator).kind, .None)
	defer profile_destroy(&profile)
	origin_probe: Identity_Grant_Probe
	origin, error := origin_prepare(&profile, "https://example.com/", identity_backing(&origin_probe))
	testing.expect_value(t, error.kind, .None)
	origin_calls := origin_probe.calls
	origin_destroy(&origin)
	testing.expect_value(t, origin_probe.live_bytes, 0)
	testing.expect(t, origin_calls > 0)

	for mode in modes {
		for point in 1 ..= origin_calls {
			probe := Identity_Grant_Probe {
				mode    = mode,
				fail_at = point,
			}

			owner, cause := origin_prepare(&profile, "https://example.com/", identity_backing(&probe))

			if mode == .Misaligned {
				// Host bytes require alignment1: offset storage is valid, not a bad grant.
				testing.expect_value(t, cause.kind, .None)
				origin_destroy(&owner)
			} else {
				testing.expect_value(t, cause.kind, .Allocation_Failed)
				testing.expect(t, owner.storage == nil)
			}

			testing.expect_value(t, probe.live_bytes, 0)
		}
	}
}

Identity_Concurrent_Probe :: struct {
	identity: u64,
}
identity_thread :: proc(s: ^Identity_Concurrent_Probe) {
	p: Profile
	assert(profile_init(&p, identity_config(), rt.heap_allocator()).kind == .None)
	s.identity = p.owner_id
	profile_destroy(&p)
}
@(test)
identity_serials_are_unique_and_failed_constructors_publish_none :: proc(t: ^testing.T) {
	first: Profile
	testing.expect_value(t, profile_init(&first, identity_config(), context.allocator).kind, .None)
	old := first.owner_id
	profile_destroy(&first)
	failed: Profile
	probe := Identity_Grant_Probe {
		mode    = .Grant_Error,
		fail_at = 1,
	}

	testing.expect_value(
		t,
		profile_init(&failed, identity_config(), identity_backing(&probe)).kind,
		.Allocation_Failed,
	)
	testing.expect_value(t, failed.owner_id, u64(0))
	testing.expect_value(t, probe.live_bytes, 0)
	states: [16]Identity_Concurrent_Probe
	threads: [16]^thread.Thread

	for &state, i in states {
		threads[i] = thread.create_and_start_with_poly_data(&state, identity_thread)
		assert(threads[i] != nil)
	}

	for worker in threads {
		thread.join(worker)
		thread.destroy(worker)
	}

	for state, i in states {
		testing.expect(t, state.identity > old)

		for previous in states[:i] {
			testing.expect(t, previous.identity != state.identity)
		}
	}
}

@(test)
identity_physical_destructors_allow_owner_header_free :: proc(t: ^testing.T) {
	probe: Identity_Grant_Probe
	owner := new(Profile, rt.heap_allocator())
	testing.expect_value(t, profile_init(owner, identity_config(), identity_backing(&probe)).kind, .None)
	probe.profile_to_free = owner
	profile_destroy(owner) // Allocator frees the real header inside its callback.
	testing.expect(t, probe.profile_to_free == nil)
	testing.expect_value(t, probe.live_bytes, 0)
	profile: Profile
	testing.expect_value(t, profile_init(&profile, identity_config(), context.allocator).kind, .None)
	defer profile_destroy(&profile)
	origin, error := origin_prepare(&profile, "https://example.com/", identity_backing(&probe))
	testing.expect_value(t, error.kind, .None)
	header := new(Prepared_Origin, rt.heap_allocator())
	header^ = origin
	origin = {}
	probe.origin_to_free = header
	origin_destroy(header)
	testing.expect(t, probe.origin_to_free == nil)
	testing.expect_value(t, probe.live_bytes, 0)
}

@(test)
identity_empty_profile_and_exhaustion_are_transactional :: proc(t: ^testing.T) {
	config, error := config_normalize({})
	testing.expect_value(t, error.kind, .None)
	profile: Profile
	testing.expect_value(t, profile_init(&profile, config, mem.panic_allocator()).kind, .None)
	testing.expect(t, profile.owner_id != 0 && profile.storage == nil)
	profile_destroy(&profile)
	invalid := identity_config()
	invalid.request_timeout = 0
	probe: Identity_Grant_Probe
	testing.expect_value(t, profile_init(&profile, invalid, identity_backing(&probe)).kind, .Invalid_Config)
	testing.expect_value(t, probe.calls, 0)
	testing.expect(t, profile.self == nil && profile.owner_id == 0)
	invalid = identity_config()
	invalid.http.tls.alpn_protocols = {"h3"}
	testing.expect_value(t, profile_init(&profile, invalid, identity_backing(&probe)).kind, .Invalid_Config)
	testing.expect_value(t, probe.calls, 0)
	// Local-counter boundary probe avoids changing process identity allocation.
	// It does not claim to exhaust 2^64 actual Profile constructors.
	serial := max(u64)
	mu: sync.Mutex
	identity, ok := profile_identity_next(&serial, &mu)
	testing.expect(t, !ok)
	testing.expect_value(t, identity, u64(0))
	testing.expect_value(t, serial, max(u64))
	serial = max(u64) - 1
	identity, ok = profile_identity_next(&serial, &mu)
	testing.expect(t, ok)
	testing.expect_value(t, identity, max(u64))
	testing.expect_value(t, serial, max(u64))
	identity, ok = profile_identity_next(&serial, &mu)
	testing.expect(t, !ok)
	testing.expect_value(t, identity, u64(0))
	testing.expect_value(t, serial, max(u64))
}

policy_case_init :: proc(
	f: ^Pool_Case,
	caps: Capacities = {
		requests = 8,
		origins = 3,
		connections = 2,
		connections_per_origin = 1,
		waiters_per_origin = 2,
		dns_ids = 0,
		work_per_resume = 1,
	},
) {pool_case_init(f, caps, 100000, 200000)}
policy_origin :: proc(f: ^Pool_Case, url: string) -> Prepared_Origin {
	origin, error := origin_prepare(&f.profile, url, f.resources.allocator)
	assert(error.kind == .None)

	return origin
}
// Snapshot all Kernel bytes/arrays and owned origin/key/profile backing while
// the mutex is held. The selector has no ownership or mutation entitlement.
policy_select :: proc(
	t: ^testing.T,
	f: ^Pool_Case,
	key: Origin_Key,
	now: i64,
	allow_new: bool,
) -> (
	Pool_Selection,
	Client_Error,
) {
	k := &f.kernel
	sync.lock(&k.mu)
	defer sync.unlock(&k.mu)
	regions: [16][]u8
	regions[0] = mem.byte_slice(k, size_of(Kernel))
	regions[1] = mem.slice_to_bytes(k.requests)
	regions[2] = mem.slice_to_bytes(k.origins)
	regions[3] = mem.slice_to_bytes(k.sessions)
	regions[4] = mem.slice_to_bytes(k.request_free)
	regions[5] = mem.slice_to_bytes(k.origin_free)
	regions[6] = mem.slice_to_bytes(k.session_free)
	count := 7
	for origin in k.origins {
		regions[count] = origin.owner.storage
		count += 1
	}
	regions[count] = k.profile.storage
	count += 1
	regions[count] = transmute([]u8)key.host
	count += 1
	before: [16][16384]u8
	for region, i in regions[:count] {
		assert(len(region) <= len(before[i]))
		copy(before[i][:], region)
	}
	allocations, frees := f.track.total_allocation_count, f.track.total_free_count
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	selected, error := pool_select_locked(k, key, now, allow_new)
	context = previous
	for region, i in regions[:count] {
		testing.expect_value(t, mem.compare(before[i][:len(region)], region), 0)
	}
	testing.expect_value(t, f.track.total_allocation_count, allocations)
	testing.expect_value(t, f.track.total_free_count, frees)
	return selected, error
}
policy_claim :: proc(
	f: ^Pool_Case,
	p: Preparing_Request,
	url: string,
	allow_new: bool,
) -> (
	Pool_Reservation,
	Client_Error,
) {
	origin := policy_origin(f, url)
	defer origin_destroy(&origin)
	return pool_reserve_policy(&f.kernel, p, &origin, pool_case_time(f), allow_new)
}
policy_accept :: proc(f: ^Pool_Case, url: string, allow_new: bool) -> (Request_Handle, Pool_Reservation) {
	p := pool_case_prepare(f)
	claim, error := policy_claim(f, p, url, allow_new)
	assert(error.kind == .None)
	pool_case_commit(f, p, url)

	return p.request, claim
}
policy_await :: proc(f: ^Pool_Case, h: Request_Handle, awaiting: bool) {
	sync.lock(&f.kernel.mu)
	f.kernel.requests[h.slot - 1].stage = .Awaiting_DNS_IDs if awaiting else .Queued
	f.kernel.dispatch_dirty = true
	sync.unlock(&f.kernel.mu)
}
policy_no_dispatch :: proc(t: ^testing.T, f: ^Pool_Case) {
	for _ in 0 ..< 4 * (len(f.kernel.origins) + len(f.kernel.sessions) + 1) {
		assignment, used, error := pool_dispatch(&f.kernel, 1, pool_case_time(f))
		testing.expect_value(t, assignment, Assignment{})
		testing.expect(t, error.kind == .None || error.kind == .Pending)
		testing.expect(t, used >= 0 && used <= 1)

		if error.kind == .None && used == 0 {
			break
		}
	}
}

@(test)
policy_selector_is_pure_and_preserves_exact_old_callable :: proc(t: ^testing.T) {
	old: proc(_: ^Kernel, _: Preparing_Request, _: ^Prepared_Origin, _: i64) -> (Pool_Reservation, Client_Error) =
		pool_reserve
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	free_origin := f.kernel.origin_free[f.kernel.origin_free_count - 1]
	free_session := f.kernel.session_free[f.kernel.session_free_count - 1]
	selected, error := policy_select(t, &f, origin.key, 100, true)
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, selected.new_origin && selected.new_session && !selected.waiting)
	testing.expect_value(t, selected.origin.slot, free_origin)
	testing.expect_value(t, selected.session.slot, free_session)
	waiting, error2 := policy_select(t, &f, origin.key, 100, false)
	testing.expect_value(t, error2.kind, .None)
	testing.expect(t, waiting.new_origin && !waiting.new_session && waiting.waiting)
	testing.expect_value(t, waiting.session, Cell_Handle{})
	p := pool_case_prepare(&f)
	claim, cause := old(&f.kernel, p, &origin, pool_case_time(&f))
	testing.expect_value(t, cause.kind, .None)
	testing.expect_value(t, claim.session.slot, free_session)
	testing.expect_value(t, claim.waiting, false)
	pool_case_rollback(&f, p)
	fmt.println("POOL_POLICY pure_selection_and_old_callable=1")
}

@(test)
policy_wait_only_never_claims_free_and_rejection_preserves_origin :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.waiters_per_origin = 0
	f: Pool_Case
	policy_case_init(&f, caps)
	defer pool_case_destroy(&f)
	p := pool_case_prepare(&f)
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	pointer, size := raw_data(origin.storage), len(origin.storage)
	free_origins, free_sessions := f.kernel.origin_free_count, f.kernel.session_free_count
	result, cause := pool_reserve_policy(&f.kernel, p, &origin, pool_case_time(&f), false)
	testing.expect_value(t, cause.kind, .Capacity)
	testing.expect_value(t, result, Pool_Reservation{})
	testing.expect_value(t, raw_data(origin.storage), pointer)
	testing.expect_value(t, len(origin.storage), size)
	testing.expect_value(t, f.kernel.origin_free_count, free_origins)
	testing.expect_value(t, f.kernel.session_free_count, free_sessions)
	testing.expect_value(t, f.kernel.requests[p.request.slot - 1].origin, Cell_Handle{})
	pool_case_rollback(&f, p)
}

@(test)
policy_awaiting_dns_head_blocks_free_sessions_and_later_waiters :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	free := f.kernel.session_free_count
	head, head_claim := policy_accept(&f, "https://a.test", false)
	tail, tail_claim := policy_accept(&f, "https://a.test", false)
	testing.expect(t, head_claim.waiting && tail_claim.waiting)
	testing.expect_value(t, f.kernel.session_free_count, free)
	policy_await(&f, head, true)
	policy_no_dispatch(t, &f)
	testing.expect_value(t, f.kernel.requests[tail.slot - 1].state, .Queued)
	testing.expect_value(t, f.kernel.session_free_count, free)
	policy_await(&f, head, false)
	first := pool_case_dispatch(&f, head)
	pool_case_complete(&f, head)
	pool_case_idle(&f, first.session)
	second := pool_case_dispatch(&f, tail, true)
	pool_case_complete(&f, tail)
	pool_case_idle(&f, second.session)
}

@(test)
policy_idle_unparks_same_awaiting_head_in_fifo_order :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	f: Pool_Case
	policy_case_init(&f, caps)
	defer pool_case_destroy(&f)
	active, _ := pool_case_accept(&f, "https://a.test")
	assigned := pool_case_dispatch(&f, active)
	head, _ := policy_accept(&f, "https://a.test", false)
	tail, _ := policy_accept(&f, "https://a.test", false)
	policy_await(&f, head, true)
	pool_case_complete(&f, active)
	pool_case_idle(&f, assigned.session)
	first := pool_case_dispatch(&f, head, true)
	testing.expect_value(t, first.session, assigned.session)
	testing.expect_value(t, f.kernel.requests[head.slot - 1].stage, .Writing)
	testing.expect_value(t, f.kernel.requests[tail.slot - 1].state, .Queued)
	pool_case_complete(&f, head)
	pool_case_idle(&f, first.session)
	second := pool_case_dispatch(&f, tail, true)
	pool_case_complete(&f, tail)
	pool_case_idle(&f, second.session)
}

@(test)
policy_reserved_idle_can_bypass_ids_but_reserved_free_cannot :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test")
	policy_await(&f, request, true)
	policy_no_dispatch(t, &f)
	testing.expect_value(t, f.kernel.counters.reserved_connections, 1)
	policy_await(&f, request, false)
	first := pool_case_dispatch(&f, request)
	pool_case_complete(&f, request)
	pool_case_idle(&f, first.session)
	second, claim := policy_accept(&f, "https://a.test", false)
	testing.expect(t, !claim.waiting && claim.session == first.session)
	policy_await(&f, second, true)
	reused := pool_case_dispatch(&f, second, true)
	pool_case_complete(&f, second)
	pool_case_idle(&f, reused.session)
}

@(test)
policy_blocked_origin_does_not_stop_other_origin_work1 :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	blocked, blocked_claim := policy_accept(&f, "https://a.test", false)
	policy_await(&f, blocked, true)
	ready, _ := pool_case_accept(&f, "https://b.test")
	sync.lock(&f.kernel.mu)
	f.kernel.dispatch_cursor = blocked_claim.origin.slot - 1
	f.kernel.dispatch_origin = {}
	f.kernel.dispatch_remaining = 0
	f.kernel.dispatch_dirty = true
	sync.unlock(&f.kernel.mu)
	assigned := pool_case_dispatch(&f, ready)
	testing.expect_value(t, f.kernel.requests[blocked.slot - 1].state, .Queued)
	testing.expect_value(t, f.kernel.requests[blocked.slot - 1].session, Cell_Handle{})
	pool_case_complete(&f, ready)
	pool_case_idle(&f, assigned.session)
	pool_case_complete(&f, blocked)
}

@(test)
policy_selector_isolates_full_origin_and_zeroes_rejected_witness :: proc(t: ^testing.T) {
	f: Pool_Case
	policy_case_init(&f)
	defer pool_case_destroy(&f)
	request, claim := pool_case_accept(&f, "https://a.test")
	origin := policy_origin(&f, "https://a.test")
	defer origin_destroy(&origin)
	selected, error := policy_select(t, &f, origin.key, pool_case_time(&f), false)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, selected.origin, claim.origin)
	testing.expect(t, !selected.new_origin && selected.waiting)

	for field in 0 ..< 3 {
		key := origin.key

		switch field {
		case 0:
			key.secure = false; case 1:
			key.port = 8443; case 2:
			key.host = "b.test"
		}

		other, cause := policy_select(t, &f, key, pool_case_time(&f), false)
		testing.expect_value(t, cause.kind, .None)
		testing.expect(t, other.new_origin && other.origin != claim.origin)
	}

	wrong := origin.key
	wrong.profile_id += 1
	invalid, cause := policy_select(t, &f, wrong, pool_case_time(&f), true)
	testing.expect_value(t, cause.kind, .Invalid_Config)
	testing.expect_value(t, invalid, Pool_Selection{})
	pool_case_complete(&f, request)
}

Pool_Case :: struct {
	track:     mem.Tracking_Allocator,
	allocator: mem.Allocator,
	scope:     scopes.Scope,
	profile:   Profile,
	resources: Kernel_Resources,
	kernel:    Kernel,
	now:       i64,
}
pool_case_init :: proc(f: ^Pool_Case, capacities: Capacities, idle: time.Duration = 5, max_age: time.Duration = 20) {
	mem.tracking_allocator_init(&f.track, rt.heap_allocator(), rt.heap_allocator())
	f.allocator = mem.tracking_allocator(&f.track)
	scope, error := scopes.create_root({bytes = 64 << 20, streams = u64(capacities.requests)}, f.allocator)
	assert(error == .None)
	f.scope = scope
	config, cause := config_normalize(
		{http = {scope = scope}, capacities = capacities, idle_timeout = idle, max_age = max_age},
	)
	assert(cause.kind == .None)
	assert(profile_init(&f.profile, config, f.allocator).kind == .None)
	assert(resources_init(&f.resources, scope, f.allocator).kind == .None)
	assert(kernel_init(&f.kernel, &f.profile, &f.resources).kind == .None)
}
pool_case_time :: proc(f: ^Pool_Case, given: i64 = 0) -> i64 {
	now := given

	if now == 0 {
		now = 100 if f.now == 0 else min(f.now, max(i64) - 1) + 1
	}

	assert(now > 0 && now >= f.now)
	f.now = now

	return now
}
pool_case_clock :: proc(at: i64 = 101) -> runtime_async.Deadline {
	return {epoch = 77, at = at}
}
pool_case_prepare :: proc(f: ^Pool_Case) -> Preparing_Request {
	lease, error := resources_request_lease(&f.resources)
	assert(error.kind == .None)
	preparing, cause := kernel_reserve(&f.kernel, {epoch = 77, at = max(i64)}, &lease)
	assert(cause.kind == .None && lease == (scopes.Lease{}))

	return preparing
}
pool_case_claim :: proc(
	f: ^Pool_Case,
	p: Preparing_Request,
	url: string,
	now: i64 = 0,
	allocator: mem.Allocator = {},
) -> (
	Pool_Reservation,
	Client_Error,
) {
	at := pool_case_time(f, now)
	selected := allocator
	if selected.procedure == nil {
		selected = f.resources.allocator
	}
	origin, error := origin_prepare(&f.profile, url, selected)
	assert(error.kind == .None)
	pointer, size := raw_data(origin.storage), len(origin.storage)
	reservation, cause := pool_reserve(&f.kernel, p, &origin, at)
	if cause.kind != .None {
		assert(raw_data(origin.storage) == pointer && len(origin.storage) == size)
	}
	origin_destroy(&origin)
	return reservation, cause
}
pool_case_commit :: proc(f: ^Pool_Case, p: Preparing_Request, url: string, now: i64 = 0) {
	at := pool_case_time(f, now)
	input, error := request_clone({method = .GET, url = url}, f.resources.allocator)
	assert(error.kind == .None)
	assert(kernel_commit(&f.kernel, p, &input, pool_case_clock(at)).kind == .None && input.storage == nil)
}
pool_case_accept :: proc(f: ^Pool_Case, url: string, now: i64 = 0) -> (Request_Handle, Pool_Reservation) {
	p := pool_case_prepare(f)
	reservation, error := pool_case_claim(f, p, url, now)
	assert(error.kind == .None)
	pool_case_commit(f, p, url, now)

	return p.request, reservation
}
pool_case_dispose :: proc(f: ^Pool_Case, disposal: ^Request_Disposal) {
	ticket := disposal.origin.origin
	request_disposal_destroy(disposal)

	if ticket != (Cell_Handle{}) {
		assert(kernel_origin_cleanup_finish(&f.kernel, ticket).kind == .None)
	}
}
pool_case_finish :: proc(f: ^Pool_Case, request: Request_Handle, now: i64 = 0) {
	at := pool_case_time(f, now)

	for _ in 0 ..< 8 {
		disposal, done, error := kernel_cleanup_finish(&f.kernel, request, pool_case_clock(at))
		assert(error.kind == .None)
		pool_case_dispose(f, &disposal)

		if done {
			return
		}
	}

	assert(false, "cleanup did not finish")
}
pool_case_rollback :: proc(f: ^Pool_Case, p: Preparing_Request) {
	disposal, error := kernel_rollback(&f.kernel, p)
	assert(error.kind == .None)
	pool_case_dispose(f, &disposal)
	pool_case_finish(f, p.request)
}
pool_case_complete :: proc(f: ^Pool_Case, request: Request_Handle, now: i64 = 0) {
	response := surf.Response {
		status = 200,
	}

	disposal, error := kernel_begin_complete(&f.kernel, request, &response, {})
	assert(error.kind == .None)
	pool_case_dispose(f, &disposal)
	pool_case_finish(f, request, now)
	assert(kernel_release(&f.kernel, request).kind == .None)
}
pool_case_dispatch :: proc(f: ^Pool_Case, expected: Request_Handle, reused: bool = false, now: i64 = 0) -> Assignment {
	at := pool_case_time(f, now)
	limit := 4 * (len(f.kernel.requests) + len(f.kernel.origins) + len(f.kernel.sessions)) + 16

	for _ in 0 ..< limit {
		assignment, used, error := pool_dispatch(&f.kernel, 1, at)
		assert((error.kind == .None || error.kind == .Pending) && used >= 0 && used <= 1)

		if assignment.request == (Request_Handle{}) {
			continue
		}

		assert(error.kind == .None && assignment.request == expected)
		state := f.kernel.sessions[assignment.session.slot - 1].state
		assert(state == .Busy if reused else state == .Connecting)

		if !reused {
			assert(pool_session_state(&f.kernel, assignment.session, .Busy, at).kind == .None)
		}

		return assignment
	}

	assert(false, "work1 failed to dispatch eligible request")

	return {}
}
pool_case_idle :: proc(f: ^Pool_Case, session: Cell_Handle, now: i64 = 0) {
	assert(pool_session_state(&f.kernel, session, .Idle, pool_case_time(f, now)).kind == .None)
}
pool_case_retire :: proc(f: ^Pool_Case, session: Cell_Handle, now: i64 = 0) {
	assert(pool_session_state(&f.kernel, session, .Retiring, pool_case_time(f, now)).kind == .None)
	assert(pool_retire(&f.kernel, session).kind == .None)
}
pool_case_destroy :: proc(f: ^Pool_Case) {
	for slot, index in f.kernel.sessions {
		if slot.state == .Free || slot.state == .Retired {
			continue
		}

		assert(slot.request == (Request_Handle{}) && (slot.state == .Idle || slot.state == .Retiring))
		handle := Cell_Handle{u32(index + 1), slot.generation}

		if slot.state == .Idle {
			assert(pool_session_state(&f.kernel, handle, .Retiring, pool_case_time(f)).kind == .None)
		}

		assert(pool_retire(&f.kernel, handle).kind == .None)
	}

	assert(kernel_destroy(&f.kernel).kind == .None)
	profile_destroy(&f.profile)
	resources_destroy(&f.resources)
	usage, error := scopes.snapshot(f.scope)
	assert(error == .None && usage.used == (scopes.Usage{}))
	scopes.release_scope(&f.scope)
	assert(f.track.current_memory_allocated == 0 && len(f.track.bad_free_array) == 0)
	mem.tracking_allocator_destroy(&f.track)
}
pool_case_caps :: proc() -> Capacities {
	return {
		requests = 8,
		origins = 3,
		connections = 2,
		connections_per_origin = 1,
		waiters_per_origin = 2,
		dns_ids = 0,
		work_per_resume = 1,
	}
}

@(test)
pool_global_per_origin_origin_and_waiter_caps_are_real :: proc(t: ^testing.T) {
	f: Pool_Case
	pool_case_init(&f, pool_case_caps())
	defer pool_case_destroy(&f)
	a, a_claim := pool_case_accept(&f, "https://a.test")
	testing.expect(t, !a_claim.waiting && a_claim.session != (Cell_Handle{}))
	assigned_a := pool_case_dispatch(&f, a)
	b, b_claim := pool_case_accept(&f, "https://b.test")
	testing.expect(t, !b_claim.waiting && b_claim.session != a_claim.session)
	assigned_b := pool_case_dispatch(&f, b)
	waiting1, claim1 := pool_case_accept(&f, "https://a.test")
	waiting2, claim2 := pool_case_accept(&f, "https://a.test")
	testing.expect(
		t,
		claim1.waiting && claim2.waiting && claim1.session == (Cell_Handle{}) && claim2.session == (Cell_Handle{}),
	)
	p := pool_case_prepare(&f)
	_, cause := pool_case_claim(&f, p, "https://a.test")
	testing.expect_value(t, cause.kind, .Capacity)
	testing.expect_value(t, f.kernel.requests[p.request.slot - 1].state, .Preparing)
	pool_case_rollback(&f, p)
	pool_case_complete(&f, a)
	pool_case_idle(&f, assigned_a.session)
	first := pool_case_dispatch(&f, waiting1, true)
	pool_case_complete(&f, waiting1)
	pool_case_idle(&f, first.session)
	second := pool_case_dispatch(&f, waiting2, true)
	pool_case_complete(&f, waiting2)
	pool_case_idle(&f, second.session)
	pool_case_complete(&f, b)
	pool_case_idle(&f, assigned_b.session)
	// An exhausted origin table rejects a new key even with free connection cells.
	caps := pool_case_caps()
	caps.origins = 1
	caps.waiters_per_origin = 0
	isolated: Pool_Case
	pool_case_init(&isolated, caps)
	request, _ := pool_case_accept(&isolated, "https://a.test")
	session := pool_case_dispatch(&isolated, request)
	p = pool_case_prepare(&isolated)
	_, cause = pool_case_claim(&isolated, p, "https://b.test")
	testing.expect_value(t, cause.kind, .Capacity)
	pool_case_rollback(&isolated, p)
	pool_case_complete(&isolated, request)
	pool_case_idle(&isolated, session.session)
	pool_case_destroy(&isolated)
}

@(test)
pool_zero_waiter_requires_claim_and_rollback_restores_idle_or_free :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	caps.waiters_per_origin = 0
	f: Pool_Case
	pool_case_init(&f, caps)
	defer pool_case_destroy(&f)
	preparing := pool_case_prepare(&f)
	reservation, error := pool_case_claim(&f, preparing, "https://a.test")
	assert(error.kind == .None)
	testing.expect_value(t, f.kernel.sessions[reservation.session.slot - 1].state, .Reserved)
	pool_case_rollback(&f, preparing)
	testing.expect_value(t, f.kernel.sessions[reservation.session.slot - 1].state, .Free)
	request, _ := pool_case_accept(&f, "https://a.test")
	assignment := pool_case_dispatch(&f, request)
	denied := pool_case_prepare(&f)
	_, cause := pool_case_claim(&f, denied, "https://a.test")
	testing.expect_value(t, cause.kind, .Capacity)
	pool_case_rollback(&f, denied)
	pool_case_complete(&f, request)
	pool_case_idle(&f, assignment.session, 110)
	before := f.kernel.sessions[assignment.session.slot - 1]
	preparing = pool_case_prepare(&f)
	reservation, error = pool_case_claim(&f, preparing, "https://a.test", 111)
	assert(error.kind == .None)
	testing.expect(
		t,
		reservation.session == assignment.session &&
		f.kernel.sessions[assignment.session.slot - 1].reserved_from == .Idle,
	)
	pool_case_rollback(&f, preparing)
	after := f.kernel.sessions[assignment.session.slot - 1]
	testing.expect(
		t,
		after.state == .Idle &&
		after.generation == before.generation &&
		after.created_at == before.created_at &&
		after.idle_since == before.idle_since,
	)
}

@(test)
pool_retiring_keeps_capacity_and_retired_generations_never_reuse :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	caps.waiters_per_origin = 0
	f: Pool_Case
	pool_case_init(&f, caps)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test")
	assignment := pool_case_dispatch(&f, request)
	pool_case_complete(&f, request)
	pool_case_idle(&f, assignment.session)
	assert(pool_session_state(&f.kernel, assignment.session, .Retiring, 104).kind == .None)
	p := pool_case_prepare(&f)
	_, cause := pool_case_claim(&f, p, "https://b.test", 105)
	testing.expect_value(t, cause.kind, .Capacity)
	pool_case_rollback(&f, p)
	assert(pool_retire(&f.kernel, assignment.session).kind == .None)
	testing.expect(t, pool_retire(&f.kernel, assignment.session).kind != .None)
	request, _ = pool_case_accept(&f, "https://b.test", 106)
	next := pool_case_dispatch(&f, request, false, 107)
	testing.expect(
		t,
		next.session.slot == assignment.session.slot && next.session.generation != assignment.session.generation,
	)
	testing.expect(t, pool_session_state(&f.kernel, assignment.session, .Retiring, 107).kind != .None)
	pool_case_complete(&f, request, 108)
	pool_case_idle(&f, next.session, 109)
	// Explicit finite counter-boundary fixture on a real admitted/retired session;
	// no claim of executing max(u64) lifetimes.
	f.kernel.sessions[next.session.slot - 1].generation = max(u64)
	exhausted := Cell_Handle{next.session.slot, max(u64)}
	pool_case_retire(&f, exhausted, 110)
	testing.expect_value(t, f.kernel.sessions[exhausted.slot - 1].state, .Retired)
	p = pool_case_prepare(&f)
	_, cause = pool_case_claim(&f, p, "https://c.test", 111)
	testing.expect_value(t, cause.kind, .Capacity)
	pool_case_rollback(&f, p)
}

Pool_Free_Probe :: struct {
	backing: mem.Allocator,
	kernel:  ^Kernel,
	session: Cell_Handle,
	target:  rawptr,
	calls:   int,
	armed:   bool,
}
pool_probe_allocator :: proc(
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
	p := cast(^Pool_Free_Probe)data
	if mode == .Free && old_memory == p.target && p.armed {
		p.armed = false
		p.calls += 1
		assert(sync.try_lock(&p.kernel.mu))
		sync.unlock(&p.kernel.mu)
		assert(p.kernel.sessions[p.session.slot - 1].state == .Returning)
		assert(kernel_destroy(p.kernel).kind == .Pending)
	}
	return p.backing.procedure(p.backing.data, mode, size, alignment, old_memory, old_size, location)
}

@(test)
pool_origin_physical_free_is_unlocked_and_session_stays_returning :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	caps.waiters_per_origin = 0
	f: Pool_Case
	pool_case_init(&f, caps)
	defer pool_case_destroy(&f)
	p := pool_case_prepare(&f)
	probe := Pool_Free_Probe {
		backing = f.allocator,
		kernel  = &f.kernel,
	}

	origin, error := origin_prepare(&f.profile, "https://owned.test", {pool_probe_allocator, &probe})
	assert(error.kind == .None)
	probe.target = raw_data(origin.storage)
	reservation, cause := pool_reserve(&f.kernel, p, &origin, 100)
	assert(cause.kind == .None && origin.storage == nil)
	pool_case_commit(&f, p, "https://owned.test")
	assignment := pool_case_dispatch(&f, p.request)
	pool_case_complete(&f, p.request)
	pool_case_idle(&f, assignment.session)
	probe.session = reservation.session
	probe.armed = true
	pool_case_retire(&f, assignment.session)
	testing.expect_value(t, probe.calls, 1)
	testing.expect_value(t, f.kernel.counters.origins, 0)
}

@(test)
pool_state_guards_preserve_active_associations_until_completion :: proc(t: ^testing.T) {
	caps := pool_case_caps()
	caps.connections = 1
	caps.waiters_per_origin = 0
	f: Pool_Case
	pool_case_init(&f, caps, 1000, 10000)
	defer pool_case_destroy(&f)
	request, _ := pool_case_accept(&f, "https://a.test")
	assignment := pool_case_dispatch(&f, request)
	before := f.kernel.sessions[assignment.session.slot - 1]
	testing.expect_value(
		t,
		pool_session_state(&f.kernel, assignment.session, .Idle, pool_case_time(&f)).kind,
		.Pending,
	)
	testing.expect_value(t, pool_retire(&f.kernel, assignment.session).kind, .Pending)
	testing.expect_value(t, f.kernel.sessions[assignment.session.slot - 1], before)

	for invalid in ([4]Session_State{.Free, .Reserved, .Returning, .Retired}) {
		testing.expect(t, pool_session_state(&f.kernel, assignment.session, invalid, pool_case_time(&f)).kind != .None)
		testing.expect_value(t, f.kernel.sessions[assignment.session.slot - 1], before)
	}

	assert(pool_session_state(&f.kernel, assignment.session, .Retiring, pool_case_time(&f)).kind == .None)
	testing.expect_value(t, pool_retire(&f.kernel, assignment.session).kind, .Pending)
	testing.expect_value(t, f.kernel.sessions[assignment.session.slot - 1].request, request)
	pool_case_complete(&f, request)
	testing.expect_value(t, f.kernel.sessions[assignment.session.slot - 1].state, .Retiring)
	assert(pool_retire(&f.kernel, assignment.session).kind == .None)
}
