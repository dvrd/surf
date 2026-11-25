// Held-phase cancel matrix. The peer is tests/testdata/cancel101/peer.
// Cases live in tests/testdata/cancel101/cases.json.
package main

import support "../support"

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

Case :: struct {
	name:               string,
	phase:              string,
	transport:          string,
	action:             string,
	layer:              string,
	expected_stage:     string,
	expected_terminal:  string,
	expected_runtime:   string,
}

main :: proc() {
	g := support.begin("cancel101")
	defer support.end(&g)
	cases, loaded := load_cases()
	if !loaded {
		support.fail(&g, "cases")
	}
	defer free_cases(&cases)
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/testdata/cancel101/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/testdata/cancel101", fixture_bin, true) {
		support.fail(&g, "fixture build")
	}
	for item in cases {
		if reason := cell(&g, peer_bin, fixture_bin, item); reason != "" {
			support.fail(&g, reason)
		}
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", len(cases))
	defer delete(text)
	support.passed(&g, text)
	fmt.println(len(cases), "cancel cells passed")
}

cell :: proc(g: ^support.Gate, peer_bin, fixture_bin: string, item: Case) -> string {
	support.note(g, item.name)
	dir := support.path(g, item.name)
	defer delete(dir)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-phase", item.phase, "-dir", dir)
	if item.transport == "tls" {
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
	append(&fixture_cmd, fixture_bin, endpoint, item.phase, item.transport, item.action, dir)
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
	return verify(item, native, oracle)
}

verify :: proc(item: Case, native, peer: json.Value) -> string {
	if item.layer == "runtime_connect_slot" {
		return verify_raw(item, native, peer)
	}
	if item.layer != "public_client" || !support.eq_string(native, "layer", "public_client") {
		return "layer"
	}
	encrypted := item.transport == "tls"
	if !support.eq_string(peer, "phase", item.phase) {
		return "peer case"
	}
	if encrypted && !support.is_true(peer, "tls") {
		return "peer case"
	}
	if !encrypted && !support.is_false(peer, "tls") {
		return "peer case"
	}
	if !support.eq_string(native, "expected_stage", item.expected_stage) || !support.eq_string(native, "observed_stage", item.expected_stage) {
		return "stage"
	}
	if !support.eq_string(native, "phase", item.expected_terminal) {
		return "terminal"
	}
	want_completed := 3 if item.phase == "queued" else 2
	if !support.eq_int(native, "completed", want_completed) {
		return "completed"
	}
	if !support.eq_int(native, "workers", 1) || !support.eq_int(native, "work_per_resume", 1) {
		return "workers"
	}
	facts := [?]string{"cheap_before_release", "terminal_once", "heap_zero", "scope_zero", "fd_zero"}
	for fact in facts {
		if !support.is_true(native, fact) {
			return fact
		}
	}
	if !support.is_true(peer, "cheap_before_release") {
		return "cheap"
	}
	events, events_ok := support.array_field(peer, "events")
	if !events_ok {
		return "events"
	}
	cheap := 0
	held := 0
	first_held: json.Value
	held_paths: [2]string
	for event in events {
		id, id_ok := support.int_field(event, "connection_id")
		if !id_ok {
			return "connection"
		}
		if id == 100 {
			cheap += 1
			if !support.eq_string(event, "path", "/cheap") || !support.gt_int(event, "response_bytes", 0) {
				return "cheap request"
			}
			continue
		}
		if held < 2 {
			path, _ := support.string_field(event, "path")
			held_paths[held] = path
		}
		if held == 0 {
			first_held = event
		}
		held += 1
		if item.phase == "tls" {
			hello, hello_ok := support.int_field(event, "clienthello_bytes")
			req, req_ok := support.int_field(event, "request_bytes")
			if !hello_ok || hello <= 5 || !req_ok || req != 0 {
				return "client hello"
			}
			continue
		}
		method := "POST" if item.phase == "write" else "GET"
		if !support.gt_int(event, "request_bytes", 0) || !support.eq_string(event, "method", method) {
			return "request"
		}
		want_alpn := "http/1.1" if encrypted else ""
		want_tls := 0x304 if encrypted else 0
		if !support.eq_string(event, "alpn", want_alpn) || !support.eq_int(event, "negotiated_tls", want_tls) {
			return "tls"
		}
	}
	if cheap != 1 {
		return "cheap count"
	}
	want_held := 1
	if item.phase == "dns" {
		want_held = 0
	} else if item.phase == "redirect" {
		want_held = 2
	}
	if held != want_held {
		return "held count"
	}
	if item.phase == "dns" {
		ids, ids_ok := support.array_field(peer, "dns_ids")
		remaining, rem_ok := support.int_field(native, "dns_ids_remaining")
		if !ids_ok || len(ids) == 0 || !rem_ok || remaining >= 64 {
			return "dns draw"
		}
		names, names_ok := support.array_field(peer, "dns_names")
		if !names_ok || len(names) == 0 {
			return "dns name"
		}
		for name in names {
			text, text_ok := name.(json.String)
			if !text_ok || string(text) != "held.cancel.test" {
				return "dns name"
			}
		}
		types, types_ok := support.array_field(peer, "dns_types")
		if !types_ok {
			return "dns type"
		}
		for item_type in types {
			n, n_ok := support.as_i64(item_type)
			if !n_ok || (n != 1 && n != 28) {
				return "dns type"
			}
		}
		sizes, sizes_ok := support.array_field(peer, "dns_bytes")
		if !sizes_ok {
			return "dns bytes"
		}
		for size in sizes {
			n, n_ok := support.as_i64(size)
			if !n_ok || n < 17 {
				return "dns bytes"
			}
		}
	} else {
		ids, ids_ok := support.array_field(peer, "dns_ids")
		if !ids_ok || len(ids) != 0 {
			return "dns"
		}
	}
	if item.phase == "write" {
		length, length_ok := support.int_field(first_held, "content_length")
		sent, sent_ok := support.int_field(first_held, "request_bytes")
		response, response_ok := support.int_field(first_held, "response_bytes")
		if !length_ok || length != 18 << 20 || !sent_ok || sent >= length || !response_ok || response != 0 {
			return "pending write"
		}
	}
	if item.phase == "body" || item.phase == "queued" {
		if !support.gt_int(first_held, "response_bytes", 0) {
			return "partial body"
		}
	}
	if item.phase == "redirect" {
		if held != 2 || held_paths[0] != "/held" || held_paths[1] != "/redirected" || !support.eq_int(native, "status", 307) {
			return "redirect"
		}
	}
	if item.phase == "body" {
		if !support.eq_int(native, "status", 200) || !support.eq_string(native, "write_effect", "Response_Received") {
			return "partial classification"
		}
	}
	if item.phase == "write" || item.phase == "header" || item.phase == "redirect" {
		if !support.eq_string(native, "write_effect", "Unknown") {
			return "write effect"
		}
	}
	if item.phase == "dns" || item.phase == "tls" || item.phase == "queued" {
		if !support.eq_string(native, "write_effect", "Not_Sent") {
			return "write effect"
		}
	}
	deadline := item.action == "total" || item.action == "setup" || item.action == "lifetime"
	if item.phase == "queued" && item.action == "lifetime" {
		deadline = false
	}
	if deadline {
		elapsed, elapsed_ok := support.f64_field(native, "elapsed_ms")
		if !support.eq_string(native, "error", "Deadline_Failed") || !support.eq_string(native, "phase", "Deadline") || !elapsed_ok || elapsed >= 2000 {
			return "deadline"
		}
	} else if !support.eq_string(native, "phase", "Cancellation") {
		return "cancellation"
	}
	return ""
}

verify_raw :: proc(item: Case, native, peer: json.Value) -> string {
	encrypted := item.transport == "tls"
	if !support.eq_string(native, "layer", "runtime_connect_slot") || !support.eq_string(native, "mode", item.action) {
		return "raw layer"
	}
	if encrypted && !support.is_true(native, "cheap_tls") {
		return "raw tls"
	}
	if !encrypted && !support.is_false(native, "cheap_tls") {
		return "raw tls"
	}
	if !support.eq_string(native, "error", item.expected_runtime) {
		return "runtime error"
	}
	if !support.eq_int(native, "workers", 1) || !support.eq_int(native, "client_completions", 1) || !support.eq_int(native, "owner_done_calls", 1) {
		return "workers"
	}
	facts := [?]string{
		"cheap_before_release",
		"peer_accepted",
		"connecting_slot_held",
		"external_socket_outside_client_cap",
		"scope_zero",
		"heap_zero",
		"fd_zero",
	}
	for fact in facts {
		if !support.is_true(native, fact) {
			return fact
		}
	}
	later := item.action == "later_finish"
	if support.is_true(native, "original_cutoff_retained") != later || support.is_true(native, "later_budget_rejected") != later {
		return "later budget"
	}
	if support.is_true(native, "earlier_budget_selected") != (item.action == "earlier_finish") {
		return "earlier budget"
	}
	if !support.eq_string(peer, "phase", "rawconnect") || !support.is_true(peer, "cheap_before_release") {
		return "raw peer"
	}
	if encrypted && !support.is_true(peer, "tls") {
		return "raw peer"
	}
	if !encrypted && !support.is_false(peer, "tls") {
		return "raw peer"
	}
	ids, ids_ok := support.array_field(peer, "dns_ids")
	if !ids_ok || len(ids) != 0 {
		return "raw dns"
	}
	events, events_ok := support.array_field(peer, "events")
	if !events_ok || len(events) != 2 {
		return "raw events"
	}
	raw: json.Value
	cheap: json.Value
	raw_n := 0
	cheap_n := 0
	for event in events {
		id, id_ok := support.int_field(event, "connection_id")
		if !id_ok {
			return "raw connection"
		}
		if id == 1 {
			raw = event
			raw_n += 1
		} else if id == 100 {
			cheap = event
			cheap_n += 1
		}
	}
	if raw_n != 1 || cheap_n != 1 {
		return "raw events"
	}
	if !support.eq_int(raw, "request_bytes", 0) || !support.eq_int(raw, "response_bytes", 0) || !support.eq_int(raw, "negotiated_tls", 0) || !support.eq_string(raw, "alpn", "") {
		return "raw socket"
	}
	if !support.eq_string(cheap, "method", "GET") || !support.eq_string(cheap, "path", "/cheap") || !support.gt_int(cheap, "response_bytes", 0) {
		return "cheap request"
	}
	want_alpn := "http/1.1" if encrypted else ""
	want_tls := 0x304 if encrypted else 0
	if !support.eq_string(cheap, "alpn", want_alpn) || !support.eq_int(cheap, "negotiated_tls", want_tls) {
		return "cheap tls"
	}
	return ""
}

load_cases :: proc() -> (cases: [dynamic]Case, ok: bool) {
	data, read_err := os.read_entire_file("tests/testdata/cancel101/cases.json", context.allocator)
	if read_err != nil {
		return
	}
	defer delete(data)
	root: json.Value
	if err := json.unmarshal(data, &root, .JSON); err != nil {
		return
	}
	defer json.destroy_value(root)
	if !support.eq_int(root, "workers", 1) || !support.eq_int(root, "work_per_resume", 1) || !support.eq_int(root, "expected_cases", 80) {
		return
	}
	items, items_ok := support.array_field(root, "cases")
	if !items_ok || len(items) != 80 {
		return
	}
	cases = make([dynamic]Case, 0, 80)
	public := 0
	raw := 0
	for item in items {
		row := Case{}
		cloned := false
		row.name, cloned = clone_field(item, "name")
		if !cloned {
			free_cases(&cases)
			return
		}
		row.phase, _ = clone_field(item, "phase")
		row.transport, _ = clone_field(item, "transport")
		row.action, _ = clone_field(item, "action")
		row.layer, _ = clone_field(item, "layer")
		row.expected_stage, _ = clone_field(item, "expected_stage")
		row.expected_terminal, _ = clone_field(item, "expected_terminal_phase")
		row.expected_runtime, _ = clone_field(item, "expected_runtime_error")
		want := fmt.tprintf("%s-%s-%s", row.phase, row.transport, row.action)
		if row.name != want {
			free_cases(&cases)
			return
		}
		if row.layer == "public_client" {
			class, _ := support.string_field(item, "class")
			if class != "held_phase" || row.expected_stage == "" || row.expected_terminal == "" {
				free_cases(&cases)
				return
			}
			public += 1
		} else if row.layer == "runtime_connect_slot" {
			class, _ := support.string_field(item, "class")
			if class != "accepted_connecting_boundary" || row.expected_runtime == "" {
				free_cases(&cases)
				return
			}
			raw += 1
		} else {
			free_cases(&cases)
			return
		}
		append(&cases, row)
	}
	if public != 68 || raw != 12 || !covers(cases[:]) {
		free_cases(&cases)
		return
	}
	return cases, true
}

covers :: proc(cases: []Case) -> bool {
	phases := [?]string{"dns", "tls", "write", "header", "body", "redirect", "queued"}
	actions := [?]string{"cancel", "total", "lifetime", "close", "shutdown"}
	raw_actions := [?]string{"release_success", "owner_cancel", "close_connect", "runtime_shutdown", "later_finish", "earlier_finish"}
	seen := 0
	for phase in phases {
		transports := [?]string{"tcp", "tls"}
		count := 2
		if phase == "tls" {
			count = 1
			transports[0] = "tls"
		}
		for t in 0 ..< count {
			for action in actions {
				if !has_case(cases, fmt.tprintf("%s-%s-%s", phase, transports[t], action)) {
					return false
				}
				seen += 1
			}
			if phase == "dns" || phase == "tls" {
				if !has_case(cases, fmt.tprintf("%s-%s-setup", phase, transports[t])) {
					return false
				}
				seen += 1
			}
		}
	}
	for transport in ([?]string{"tcp", "tls"}) {
		for action in raw_actions {
			if !has_case(cases, fmt.tprintf("rawconnect-%s-%s", transport, action)) {
				return false
			}
			seen += 1
		}
	}
	return seen == len(cases)
}

has_case :: proc(cases: []Case, name: string) -> bool {
	for item in cases {
		if item.name == name {
			return true
		}
	}
	return false
}

clone_field :: proc(value: json.Value, key: string) -> (string, bool) {
	text, ok := support.string_field(value, key)
	if !ok {
		return "", false
	}
	return strings.clone(text), true
}

free_cases :: proc(cases: ^[dynamic]Case) {
	for item in cases {
		delete(item.name)
		delete(item.phase)
		delete(item.transport)
		delete(item.action)
		delete(item.layer)
		delete(item.expected_stage)
		delete(item.expected_terminal)
		delete(item.expected_runtime)
	}
	delete(cases^)
}
