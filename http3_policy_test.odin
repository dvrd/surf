package surf

import http "../http"
import "core:crypto/tls"
import "core:fmt"
import "core:net"
import "core:os"
import "core:testing"
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
	request := http.Request{method = .POST, url = "https://127.0.0.1:9/saba"}
	_, error := execute(request, {http3 = true, timeout = 2 * time.Second})
	testing.expect_value(t, error.kind, .IO_Failed)
	testing.expect_value(t, error.phase, .Protocol)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
surf_http3_cleartext_refused :: proc(t: ^testing.T) {
	request := http.Request{method = .GET, url = "http://127.0.0.1:9/saba"}
	_, error := execute(request, {http3 = true, allow_http = true, timeout = 2 * time.Second})
	testing.expect_value(t, error.kind, .Insecure_URL)
	testing.expect_value(t, error.phase, .Configuration)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(test)
surf_http3_get_falls_back_once :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 10 * time.Second)
	request := http.Request{method = .GET, url = "https://127.0.0.1:9/saba"}
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
	testing.expect(t, alt_svc_note(&cache, "synthetic.invalid", "h3=\":9443\"; ma=60", true, true, now))
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
	testing.expect_value(t, literal.port, 9443)
	address, is_ip4 := literal.address.(net.IP4_Address)
	testing.expect(t, is_ip4 && address == net.IP4_Loopback)

	cache: Alt_Svc_Cache
	now := time.now()
	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9443\"; ma=60", true, true, now))
	port := http3_dial_port(&cache, "localhost", 8443, now)
	host, host_error := http3_resolve("localhost", port, time.time_add(now, time.Second), {})
	testing.expect_value(t, host_error.kind, .None)
	testing.expect_value(t, host.port, 9443)
	switch resolved in host.address {
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

	url := http.URL{host = "localhost", port = 9, target = "/", secure = true}
	_, dial_error := execute_http3(url, {method = .GET}, {}, time.time_add(time.now(), 2 * time.Second), context.allocator)
	testing.expect(t, dial_error.kind != .None)
	testing.expect_value(t, dial_error.write_effect, .Not_Sent)
	testing.expect(t, dial_error.phase != .DNS && dial_error.phase != .Configuration)
}

@(test)
surf_http3_peer_get :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 20 * time.Second)
	url_buf: [96]u8
	body_buf: [64]u8
	url, want, roots, ok := surf_peer_setup(t, false, url_buf[:], body_buf[:])
	if !ok do return
	defer surf_roots_free(roots)
	response, error := execute({method = .GET, url = url}, {http3 = true, timeout = 8 * time.Second, tls = {root_cas = roots.roots[:roots.count]}})
	defer response_destroy(&response)
	fmt.printf("surf-h3 get status %d err %v phase %v effect %v body %s\n", response.status, error.kind, error.phase, error.write_effect, string(response.body))
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
	if !ok do return
	defer surf_roots_free(roots)
	_, error := execute({method = .POST, url = url}, {http3 = true, timeout = 8 * time.Second, tls = {root_cas = roots.roots[:roots.count]}})
	fmt.printf("surf-h3 post phase %v effect %v kind %v\n", error.phase, error.write_effect, error.kind)
	testing.expect_value(t, error.kind, .IO_Failed)
	testing.expect_value(t, error.phase, .TLS)
	testing.expect_value(t, error.write_effect, .Not_Sent)
}

@(private)
surf_peer_setup :: proc(t: ^testing.T, bogus: bool, url_buf, body_buf: []u8) -> (url, body: string, roots: ^tls.Root_Pool, ok: bool) {
	port_buf: [32]u8
	cert_buf: [512]u8
	port_s := os.get_env_buf(port_buf[:], "H3_PEER_PORT")
	cert := os.get_env_buf(cert_buf[:], "H3_PEER_CERT")
	body = os.get_env_buf(body_buf, "H3_PEER_BODY")
	if len(port_s) == 0 || len(cert) == 0 || len(body) == 0 do return
	if bogus {
		cert = os.get_env_buf(cert_buf[:], "H3_BOGUS_CERT")
		if len(cert) == 0 do return
	}
	url = fmt.bprintf(url_buf, "https://127.0.0.1:%s/", port_s)
	if len(url) == 0 do return
	roots = new(tls.Root_Pool)
	load_error := tls.root_pool_load_file(roots, cert)
	testing.expect_value(t, load_error.kind, .None)
	if load_error.kind != .None {
		free(roots)
		roots = nil
		return
	}
	ok = true
	return
}

@(private)
surf_roots_free :: proc(pool: ^tls.Root_Pool) {
	if pool == nil do return
	tls.root_pool_destroy(pool)
	free(pool)
}
