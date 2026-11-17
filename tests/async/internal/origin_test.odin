package surf_async

import rt "base:runtime"
import "core:crypto/x509"
import "core:mem"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"

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
