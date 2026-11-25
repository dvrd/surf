// Public Client redirect matrix. Units run once, then one cell per mode.
// The peer is tests/support/redirect/peer.

package main

import "support"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

// downgrade is TLS-only. The peer mode is "downgrade", not "tls-downgrade".
redirect_TCP_MODES :: [?]string{
	"get301", "get302", "get303", "get307", "get308",
	"head301", "head302", "head303", "head307", "head308",
	"post301", "post302", "post303", "post307", "post308",
	"disabled", "relative", "cross-public", "cross-auth", "cross-cookie", "cross-custom",
	"loop", "hopcap", "bodycap", "cutoff", "dns32", "cancel", "close", "handoff-cancel", "handoff-close",
}

redirect_UNIT_NAMES :: [?]string{
	"redirect28_public_config_and_prestart_handle_lifecycle",
	"network_schema_rejects_forged_normalization_and_invalid_redirect_policy",
}

run_redirect :: proc() {
	gate_label = "redirect"

	g := support.begin("redirect101")
	defer support.end(&g)
	units := redirect_UNIT_NAMES
	if !support.task_test(&g, "async", units[:], 2) {
		support.fail(&g, "units")
	}
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/support/redirect/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/support/redirect", fixture_bin, true) {
		support.fail(&g, "fixture build")
	}
	cells := 0
	for transport in ([?]string{"tcp", "tls"}) {
		for mode in redirect_TCP_MODES {
			if reason := redirect_cell(&g, peer_bin, fixture_bin, transport, mode); reason != "" {
				support.fail(&g, reason)
			}
			cells += 1
		}
		if transport != "tls" {
			continue
		}
		if reason := redirect_cell(&g, peer_bin, fixture_bin, transport, "downgrade"); reason != "" {
			support.fail(&g, reason)
		}
		cells += 1
	}
	if cells != 61 {
		support.fail(&g, "matrix")
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "redirect cells passed")
}

redirect_cell :: proc(g: ^support.Gate, peer_bin, fixture_bin, transport, mode: string) -> string {
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
	return redirect_verify(mode, transport == "tls", native, oracle)
}

redirect_verify :: proc(mode: string, encrypted: bool, native, peer: json.Value) -> string {
	if !support.eq_int(native, "completed", 1) || !support.eq_int(native, "workers", 1) {
		return "terminal"
	}
	if !support.is_true(native, "same_handle") || !support.is_true(native, "terminal_once") || !support.is_true(native, "cap_one") {
		return "handle"
	}
	if !support.is_true(native, "heap_zero") || !support.is_true(native, "scope_zero") || !support.is_true(native, "fd_zero") {
		return "cleanup"
	}
	if !support.eq_string(peer, "mode", mode) {
		return "peer mode"
	}
	if encrypted {
		if !support.is_true(peer, "tls") {
			return "peer tls"
		}
	} else if !support.is_false(peer, "tls") {
		return "peer tls"
	}
	events, events_ok := rows_or_empty(peer, "events")
	warmups, warmups_ok := rows_or_empty(peer, "warmups")
	if !events_ok || !warmups_ok {
		return "events"
	}
	warmup := encrypted && mode == "cutoff"
	if warmup {
		if !support.is_true(native, "warmup") {
			return "warmup witness"
		}
	} else if !support.is_false(native, "warmup") {
		return "warmup witness"
	}
	if warmup {
		if len(warmups) != 1 || len(events) == 0 {
			return "warmup"
		}
		w := warmups[0]
		if !support.eq_string(w, "method", "GET") || !support.eq_string(w, "path", "/warmup") || !support.eq_string(w, "body", "") {
			return "warmup request"
		}
		if !support.eq_int(w, "response_status", 200) || !support.gt_int(w, "response_bytes", 0) || !support.gt_int(w, "request_bytes", 0) {
			return "warmup response"
		}
		if !support.eq_string(w, "alpn", "http/1.1") || !support.eq_int(w, "negotiated_tls", 0x304) {
			return "warmup tls"
		}
		first, first_ok := support.int_field(events[0], "connection_id")
		warm_id, warm_ok := support.int_field(w, "connection_id")
		if !first_ok || !warm_ok || first != warm_id {
			return "warmup connection"
		}
	} else if len(warmups) != 0 {
		return "warmup"
	}
	expected := 2
	if single_wire(mode) {
		expected = 1
	}
	if mode == "loop" || mode == "hopcap" {
		expected = 6
	}
	if mode == "cutoff" {
		expected = len(events)
		if expected < 1 || expected > 3 {
			return "cutoff count"
		}
		if !support.eq_string(native, "error", "Deadline_Failed") || !support.eq_string(native, "phase", "Deadline") || !support.eq_int(native, "status", 302) {
			return "cutoff"
		}
		effect, effect_ok := support.string_field(native, "write_effect")
		elapsed, elapsed_ok := support.int_field(native, "elapsed_ms")
		if !effect_ok || (effect != "Unknown" && effect != "Response_Received") || !elapsed_ok || elapsed >= 350 {
			return "cutoff"
		}
		if !support.eq_int(events[0], "response_status", 302) || !support.gt_int(events[0], "response_bytes", 0) || !support.is_true(events[0], "old_stream_closed") {
			return "cutoff row"
		}
	}
	if len(events) != expected {
		return "wire count"
	}
	method := "GET"
	if strings.has_prefix(mode, "post") {
		method = "POST"
	} else if strings.has_prefix(mode, "head") {
		method = "HEAD"
	}
	body := ""
	if method == "POST" {
		body = "proof-body"
	}
	want_alpn := "http/1.1" if encrypted else ""
	want_tls := 0x304 if encrypted else 0
	ids: [8]int
	for event, i in events {
		order, order_ok := support.int_field(event, "order")
		id, id_ok := support.int_field(event, "connection_id")
		if !order_ok || order != i + 1 || !id_ok {
			return "order"
		}
		for prev in 0 ..< i {
			if ids[prev] == id {
				return "connection"
			}
		}
		ids[i] = id
		if !support.gt_int(event, "request_bytes", len(body)) {
			return "request bytes"
		}
		if !support.eq_string(event, "method", method) || !support.eq_string(event, "body", body) {
			return "method"
		}
		if !support.eq_string(event, "alpn", want_alpn) || !support.eq_int(event, "negotiated_tls", want_tls) {
			return "tls"
		}
		quiet := (mode == "cancel" || mode == "close" || mode == "cutoff") && order == expected
		if !quiet {
			if !support.gt_int(event, "response_bytes", 0) {
				return "response bytes"
			}
			status, status_ok := support.int_field(event, "response_status")
			if !status_ok {
				return "status"
			}
			if status != 200 && !support.is_true(event, "old_stream_closed") {
				return "keep-alive"
			}
		}
	}
	if strings.has_prefix(mode, "handoff-") && !support.is_true(native, "handoff_callback") {
		return "handoff"
	}
	if mode == "relative" {
		if expected < 2 || !support.eq_string(events[1], "path", "/final?proof=relative") {
			return "relative"
		}
	}
	if mode == "cross-public" {
		if expected < 2 {
			return "cross origin"
		}
		left, left_ok := support.string_field(events[0], "host")
		right, right_ok := support.string_field(events[1], "host")
		if !left_ok || !right_ok || left == right {
			return "cross origin"
		}
		headers, headers_ok := support.get(events[1], "headers")
		if !headers_ok {
			return "headers"
		}
		accept, accept_ok := support.array_field(headers, "Accept")
		if !accept_ok || !support.strings_equal(accept, []string{"text/plain"}) {
			return "headers"
		}
	}
	if mode == "dns32" {
		if !support.eq_int(native, "dns_ids_remaining", 32) {
			return "dns allowance"
		}
		names, names_ok := support.array_field(peer, "dns_names")
		want := [?]string{"one.redirect.test", "two.redirect.test"}
		if !names_ok || !support.same_strings(names, want[:]) {
			return "dns names"
		}
		if len(events) != 2 {
			return "dns order"
		}
		for event, i in events {
			host, host_ok := support.string_field(event, "host")
			if !host_ok || hostname(host) != want[i] {
				return "dns order"
			}
		}
	} else if !support.empty_or_null(peer, "dns_names") {
		return "dns names"
	}
	return ""
}

single_wire :: proc(mode: string) -> bool {
	switch mode {
	case "disabled", "bodycap", "downgrade", "cross-auth", "cross-cookie", "cross-custom", "handoff-cancel", "handoff-close", "post301", "post302", "post303", "head301", "head302", "head303":
		return true
	}
	return false
}

