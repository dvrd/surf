// Public Client pool, framing, and trust matrix.
// The peer is tests/testdata/pool101/peer.
package main

import support "../support"

import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

TCP_MODES :: [?]string{
	"framing", "framing-fragmented", "host-alias", "ports", "clients",
	"idle", "maxage", "stale", "partial", "separate", "peer-close",
}

TLS_MODES :: [?]string{"scheme", "trust", "alpn", "keyupdate", "keyupdate-inline", "wrong-host"}

FRAMING_PATHS :: [?]string{
	"/fixed", "/zero", "/head", "/204", "/304", "/chunked", "/interim", "/http10", "/post", "/close",
	"/http10-close", "/connection-close", "/eof", "/truncated", "/malformed", "/badchunk", "/101", "/surplus", "/last",
}

main :: proc() {
	g := support.begin("pool101")
	defer support.end(&g)
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/testdata/pool101/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/testdata/pool101", fixture_bin, true) {
		support.fail(&g, "fixture build")
	}
	cells := 0
	for transport in ([?]string{"tcp", "tls"}) {
		for mode in TCP_MODES {
			if reason := cell(&g, peer_bin, fixture_bin, transport, mode); reason != "" {
				support.fail(&g, reason)
			}
			cells += 1
		}
		if transport != "tls" {
			continue
		}
		for mode in TLS_MODES {
			if reason := cell(&g, peer_bin, fixture_bin, transport, mode); reason != "" {
				support.fail(&g, reason)
			}
			cells += 1
		}
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "pool cells passed")
}

cell :: proc(g: ^support.Gate, peer_bin, fixture_bin, transport, mode: string) -> string {
	support.note(g, fmt.tprintf("%s %s", transport, mode))
	dir := support.path(g, fmt.tprintf("%s-%s", transport, mode))
	defer delete(dir)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-mode", mode, "-dir", dir)
	if transport == "tls" {
		append(&command, "-tls")
	}
	peer, started := support.spawn(command[:], nil)
	defer support.stop(&peer)
	if !started {
		return "peer start"
	}
	endpoint, ready := support.first_line(&peer, 10 * time.Second)
	defer delete(endpoint)
	if !ready || !strings.has_prefix(endpoint, "127.0.0.1:") {
		fmt.eprintf("peer: %s\n", support.tail(&peer))
		return "readiness"
	}
	fixture_cmd := make([dynamic]string)
	defer delete(fixture_cmd)
	append(&fixture_cmd, fixture_bin, endpoint, mode, transport, dir)
	fixture, fix_started := support.spawn(fixture_cmd[:], nil)
	defer support.stop(&fixture)
	if !fix_started {
		return "fixture start"
	}
	if !support.reap(&fixture, 25 * time.Second) || fixture.code != 0 {
		fmt.eprintf("fixture: %s\n", support.tail(&fixture))
		return "fixture"
	}
	if !support.reap(&peer, 5 * time.Second) || peer.code != 0 {
		fmt.eprintf("peer: %s\n", support.tail(&peer))
		return "peer"
	}
	native, native_ok := support.only(support.stdout(&fixture))
	if !native_ok {
		return "native json"
	}
	defer json.destroy_value(native)
	oracle, oracle_ok := support.only(support.stdout(&peer))
	if !oracle_ok {
		return "peer json"
	}
	defer json.destroy_value(oracle)
	return verify(mode, transport == "tls", native, oracle)
}

verify :: proc(mode: string, encrypted: bool, native, peer: json.Value) -> string {
	if !support.is_true(native, "heap_zero") || !support.is_true(native, "scope_zero") || !support.is_true(native, "fd_zero") {
		return "cleanup"
	}
	events, events_ok := support.array_field(peer, "events")
	requests, requests_ok := support.int_field(peer, "requests")
	if !events_ok || !requests_ok || len(events) != requests {
		return "events"
	}
	for event in events {
		secure, secure_ok := support.bool_field(event, "secure")
		want := "http/1.1" if secure else ""
		if !secure_ok || !support.eq_string(event, "alpn", want) {
			return "alpn"
		}
	}
	if strings.has_prefix(mode, "framing") {
		if !support.eq_int(native, "completed", 19) || !support.eq_int(native, "framing_cases", 19) {
			return "framing count"
		}
		paths := FRAMING_PATHS
		if !support.field_strings(events, "path", paths[:]) {
			return "framing paths"
		}
		first, first_ok := support.int_field(events[0], "connection")
		if !first_ok {
			return "framing connection"
		}
		for i in 1 ..< 10 {
			id, id_ok := support.int_field(events[i], "connection")
			if !id_ok || id != first {
				return "framing reuse"
			}
		}
		for i in 10 ..< 19 {
			prev, prev_ok := support.int_field(events[i - 1], "connection")
			id, id_ok := support.int_field(events[i], "connection")
			if !prev_ok || !id_ok || id == prev {
				return "framing retire"
			}
		}
		if !support.eq_string(events[2], "method", "HEAD") || !support.eq_string(events[8], "method", "POST") || !support.eq_string(events[8], "body", "payload") {
			return "framing method"
		}
		return ""
	}
	if mode == "idle" || mode == "maxage" {
		timer, timer_ok := support.i64_field(native, "timer_ns")
		if !support.eq_int(native, "completed", 2) || !support.field_strings(events, "path", []string{"/A", "/B"}) {
			return "timer requests"
		}
		if same(events, 0, 1) || !timer_ok || timer < 0 || timer >= 1_000_000_000 {
			return "timer reuse"
		}
		return ""
	}
	if mode == "stale" || mode == "peer-close" || mode == "partial" || mode == "separate" || mode == "keyupdate" {
		if !support.eq_int(native, "completed", 3) || !support.eq_int(native, "failures", 1) {
			return "retirement count"
		}
		if !support.field_strings(events, "path", []string{"/A", "/C"}) || same(events, 0, 1) {
			return "retirement paths"
		}
		if mode == "keyupdate" && (!support.eq_int(peer, "key_updates", 1) || !support.eq_int(peer, "client_key_updates", 0)) {
			return "key update"
		}
		return ""
	}
	if mode == "keyupdate-inline" {
		if !support.eq_int(native, "completed", 2) || !support.field_strings(events, "path", []string{"/A", "/B"}) {
			return "inline requests"
		}
		if !same(events, 0, 1) || !support.eq_int(peer, "key_updates", 1) || !support.eq_int(peer, "client_key_updates", 1) {
			return "inline key update"
		}
		return ""
	}
	if mode == "host-alias" || mode == "ports" || mode == "scheme" || mode == "clients" {
		if !support.eq_int(native, "completed", 3) || !support.field_strings(events, "path", []string{"/A", "/B", "/C"}) {
			return "identity requests"
		}
		if !same(events, 0, 2) || same(events, 0, 1) {
			return "identity connection"
		}
		if mode == "host-alias" {
			want := [?]string{"a.pool.test", "b.pool.test", "a.pool.test"}
			for event, i in events {
				host, host_ok := support.string_field(event, "host")
				if !host_ok || !strings.equal_fold(hostname(host), want[i]) {
					return "hostname"
				}
				if encrypted && !support.eq_string(event, "sni", want[i]) {
					return "sni"
				}
			}
		}
		if mode == "ports" {
			if !same_host(events, 0, 2) || same_host(events, 0, 1) {
				return "port identity"
			}
		}
		if mode == "scheme" {
			want_secure := [?]bool{true, false, true}
			host0, host0_ok := support.string_field(events[0], "host")
			if !host0_ok {
				return "scheme"
			}
			for event, i in events {
				secure, secure_ok := support.bool_field(event, "secure")
				host, host_ok := support.string_field(event, "host")
				if !secure_ok || secure != want_secure[i] || !host_ok || host != host0 {
					return "scheme"
				}
			}
		}
		return ""
	}
	if mode == "trust" || mode == "wrong-host" || mode == "alpn" {
		want_completed := 2 if mode == "alpn" else 3
		if !support.eq_int(native, "completed", want_completed) {
			return "rejection count"
		}
		if !support.field_strings(events, "path", []string{"/A", "/C"}) || !same(events, 0, 1) {
			return "rejection paths"
		}
		if mode == "alpn" {
			if !support.eq_int(native, "rejected", 1) || !support.eq_int(peer, "connections", 1) {
				return "alpn rejection"
			}
		} else {
			errors, errors_ok := support.int_field(peer, "handshake_errors")
			if !support.eq_int(native, "failures", 1) || !errors_ok || errors < 1 || !support.eq_int(peer, "connections", 2) {
				return "handshake"
			}
		}
		return ""
	}
	return "mode"
}

same :: proc(events: json.Array, a, b: int) -> bool {
	left, left_ok := support.int_field(events[a], "connection")
	right, right_ok := support.int_field(events[b], "connection")
	return left_ok && right_ok && left == right
}

same_host :: proc(events: json.Array, a, b: int) -> bool {
	left, left_ok := support.string_field(events[a], "host")
	right, right_ok := support.string_field(events[b], "host")
	return left_ok && right_ok && left == right
}

hostname :: proc(host: string) -> string {
	if cut := strings.index(host, ":"); cut >= 0 {
		return host[:cut]
	}
	return host
}
