// Actor and runtime fixture. The peer ready line is JSON with tcp and dns
// endpoints; the summary is a later object on the same stdout.
// The peer is tests/support/session/peer.
package main

import support "../support"

import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

MODES :: [?]string{
	"healthy", "stale", "partial", "close", "setup-deadline", "body-deadline",
	"cancel-read", "cancel-mailbox", "uncertain", "one-worker", "lifetime", "reuse-waiter",
}

main :: proc() {
	g := support.begin("session_actor101")
	defer support.end(&g)
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/support/session/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/support/session", fixture_bin, true) {
		support.fail(&g, "fixture build")
	}
	cells := 0
	for transport in ([?]string{"tcp", "tls"}) {
		for mode in MODES {
			if reason := cell(&g, peer_bin, fixture_bin, transport, mode); reason != "" {
				support.fail(&g, reason)
			}
			cells += 1
		}
	}
	if cells != 24 {
		support.fail(&g, "matrix")
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "session actor cells passed")
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
	line, ready := support.first_line(&peer, 8 * time.Second)
	defer delete(line)
	if !ready {
		fmt.eprintf("peer: %s\n", support.tail(&peer))
		return "readiness"
	}
	ready_value: json.Value
	if json.unmarshal_string(line, &ready_value, .JSON) != nil {
		return "readiness"
	}
	defer json.destroy_value(ready_value)
	tcp, tcp_ok := support.string_field(ready_value, "tcp")
	dns, dns_ok := support.string_field(ready_value, "dns")
	if !support.eq_string(ready_value, "event", "ready") || !tcp_ok || !dns_ok {
		return "readiness"
	}
	if !strings.has_prefix(tcp, "127.0.0.1:") || !strings.has_prefix(dns, "127.0.0.1:") {
		return "readiness"
	}
	tcp_copy := strings.clone(tcp)
	defer delete(tcp_copy)
	dns_copy := strings.clone(dns)
	defer delete(dns_copy)
	fixture_cmd := make([dynamic]string)
	defer delete(fixture_cmd)
	append(&fixture_cmd, fixture_bin, tcp_copy, dns_copy, mode, transport, dir)
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
	native, native_ok := support.objects(support.stdout(&fixture))
	if !native_ok {
		return "native json"
	}
	defer support.release(&native)
	peer_rows, peer_ok := support.objects(support.stdout(&peer))
	if !peer_ok {
		return "peer json"
	}
	defer support.release(&peer_rows)
	oracle, oracle_ok := support.find_event(peer_rows[:], "summary")
	if !oracle_ok {
		return "peer summary"
	}
	return verify(mode, transport == "tls", native[:], oracle)
}

verify :: proc(mode: string, encrypted: bool, native: []json.Value, peer: json.Value) -> string {
	summary, summary_ok := support.find_event(native, "summary")
	cleanup, cleanup_ok := support.find_event(native, "cleanup")
	if !summary_ok || !cleanup_ok || !exact_cleanup(cleanup) {
		return "cleanup"
	}
	expected := 1
	if mode == "stale" || mode == "partial" || mode == "close" {
		expected = 3
	} else if mode == "healthy" || mode == "cancel-read" || mode == "one-worker" || mode == "reuse-waiter" {
		expected = 2
	}
	labels: [4]string
	count := 0
	for row in native {
		event, ok := support.string_field(row, "event")
		if !ok || event != "completion" {
			continue
		}
		label, label_ok := support.string_field(row, "label")
		if !label_ok || count == len(labels) {
			return "completion"
		}
		labels[count] = label
		count += 1
	}
	if count != expected || !support.eq_int(summary, "completed", expected) || !unique_labels(labels[:count]) {
		return "completion count"
	}
	if !support.is_true(summary, "fixture_controller") || !support.is_false(summary, "public_client_init") || !support.is_true(summary, "scope_zero") {
		return "fixture scope"
	}
	pin0, pin0_ok := support.i64_field(summary, "pin0")
	resumes0, resumes0_ok := support.i64_field(summary, "resumes0")
	if !pin0_ok || pin0 <= 0 || !resumes0_ok || resumes0 <= 0 || !support.is_false(summary, "fixture_prepin") {
		return "owner thread"
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
	facts, facts_ok := rows_or_empty(peer, "requests")
	events, events_ok := rows_or_empty(peer, "events")
	dns, dns_ok := rows_or_empty(peer, "dns")
	if !facts_ok || !events_ok || !dns_ok {
		return "peer lists"
	}
	if encrypted {
		for event in events {
			name, ok := support.string_field(event, "event")
			if !ok || name != "handshake" {
				continue
			}
			server, server_ok := support.string_field(event, "server_name")
			if !support.eq_int(event, "version", 772) || !support.eq_string(event, "alpn", "http/1.1") || !server_ok {
				return "handshake"
			}
			if server != "actor.test" && server != "cheap.actor.test" {
				return "sni"
			}
		}
	}
	if mode == "healthy" {
		if !support.is_true(summary, "old_cutoff_expired") || !support.is_true(summary, "late_response_survived_state_free") {
			return "retained owner"
		}
		if !support.field_strings(facts, "path", []string{"/A", "/B"}) || !support.eq_int(peer, "connections", 1) || len(dns) != 1 {
			return "connection"
		}
		a, a_ok := labeled(native, "A")
		b, b_ok := labeled(native, "B")
		if !a_ok || !b_ok || !same_connection(a, b) || !support.eq_string(b, "kind", "None") {
			return "generation"
		}
		if !cutoff_before(a, b) {
			return "budget"
		}
	} else if mode == "stale" || mode == "partial" || mode == "close" {
		if !support.is_true(summary, "old_cutoff_expired") {
			return "old cutoff"
		}
		b, b_ok := labeled(native, "B")
		kind, kind_ok := support.string_field(b, "kind")
		if !b_ok || !kind_ok || kind == "None" || !support.eq_string(b, "effect", "Not_Sent") {
			return "replay"
		}
		if !support.field_strings(facts, "path", []string{"/A", "/C"}) || !support.eq_int(peer, "connections", 2) {
			return "transport"
		}
		a, a_ok := labeled(native, "A")
		c, c_ok := labeled(native, "C")
		if !a_ok || !c_ok || !support.eq_string(c, "kind", "None") || same_connection(a, c) {
			return "fresh generation"
		}
		if mode == "stale" {
			helper, helper_ok := support.i64_field(summary, "fixture_helper_thread")
			if !support.eq_int(summary, "workers", 2) || !support.eq_int(summary, "fixture_helper_done", 1) || !helper_ok || helper <= 0 || helper == pin0 {
				return "workers"
			}
		}
		if mode == "partial" && !staged(events, encrypted) {
			return "staged"
		}
	} else if mode == "setup-deadline" {
		a, a_ok := labeled(native, "A")
		kind, kind_ok := support.string_field(a, "kind")
		if !a_ok || !support.eq_string(a, "phase", "Deadline") || !kind_ok || kind == "None" {
			return "setup cutoff"
		}
		if len(dns) < 1 || !has_event(events, "dns_reply") || !has_event(events, "server_record_held") {
			return "delayed dns"
		}
		if encrypted && (!support.eq_int(peer, "handshakes", 0) || len(facts) != 0 || !support.eq_string(a, "effect", "Not_Sent")) {
			return "tls cutoff"
		}
	} else if mode == "body-deadline" {
		a, a_ok := labeled(native, "A")
		if !a_ok || !support.eq_string(a, "phase", "Deadline") || !support.eq_int(a, "status", 200) || !support.eq_string(a, "effect", "Response_Received") {
			return "body cutoff"
		}
		if !has_event(events, "body_held") || len(dns) < 1 {
			return "body stages"
		}
	} else if mode == "lifetime" {
		a, a_ok := labeled(native, "A")
		if !a_ok || !support.eq_string(a, "phase", "Deadline") || !support.eq_int(a, "status", 200) || !support.eq_string(a, "effect", "Response_Received") {
			return "lifetime"
		}
		life, life_ok := support.i64_field(summary, "lifetime_cutoff")
		cut, cut_ok := support.i64_field(a, "cutoff")
		requested, requested_ok := support.i64_field(a, "requested_cutoff")
		if !life_ok || !cut_ok || !requested_ok || life != cut || cut >= requested {
			return "lifetime cap"
		}
		if !has_event(events, "body_held") {
			return "body boundary"
		}
	} else if mode == "reuse-waiter" {
		balance, balance_ok := support.find_event(native, "dns_balanced")
		if !balance_ok || !exact_keys(balance, 3) || !support.eq_int(balance, "reserved", 32) || !support.eq_int(balance, "burned", 32) {
			return "dns balance"
		}
		if !support.field_strings(facts, "path", []string{"/A", "/B"}) || !support.eq_int(peer, "connections", 1) || len(dns) != 1 {
			return "waiter"
		}
	} else if mode == "cancel-read" {
		a, a_ok := labeled(native, "A")
		b, b_ok := labeled(native, "B")
		if !a_ok || !b_ok || !support.eq_string(a, "phase", "Cancellation") || !support.eq_string(b, "kind", "None") {
			return "cancel"
		}
		if !support.eq_int(peer, "connections", 2) || !support.field_strings(facts, "path", []string{"/A", "/B"}) {
			return "cancel generation"
		}
	} else if mode == "cancel-mailbox" {
		a, a_ok := labeled(native, "A")
		if !a_ok || !support.eq_string(a, "phase", "Cancellation") || !support.eq_string(a, "effect", "Not_Sent") {
			return "mailbox"
		}
		if !support.eq_int(peer, "connections", 0) || len(facts) != 0 || len(dns) != 0 {
			return "mailbox setup"
		}
		draws, draws_ok := support.find_event(native, "mailbox_draws")
		burned, burned_ok := support.i64_field(draws, "burned")
		if !draws_ok || !exact_keys(draws, 3) || !support.eq_int(draws, "remaining", 0) || !burned_ok || burned < 16 {
			return "mailbox draws"
		}
	} else if mode == "uncertain" {
		a, a_ok := labeled(native, "A")
		kind, kind_ok := support.string_field(a, "kind")
		if !a_ok || !kind_ok || kind == "None" || !support.eq_string(a, "effect", "Unknown") {
			return "uncertain"
		}
		if !support.eq_int(peer, "connections", 1) || len(facts) != 1 || !support.eq_string(facts[0], "method", "POST") || !support.eq_int(facts[0], "body_bytes", 1) {
			return "uncertain write"
		}
		if !uncertain_reset(events) {
			return "cloned source"
		}
	} else if mode == "one-worker" {
		pin1, pin1_ok := support.i64_field(summary, "pin1")
		resumes1, resumes1_ok := support.i64_field(summary, "resumes1")
		if !support.eq_int(summary, "workers", 1) || !pin1_ok || pin0 != pin1 || !resumes1_ok || resumes1 <= 0 {
			return "worker"
		}
		if count != 2 || labels[0] != "B" || labels[1] != "A" {
			return "progress"
		}
		a, a_ok := labeled(native, "A")
		b, b_ok := labeled(native, "B")
		if !a_ok || !b_ok || !support.eq_string(a, "kind", "None") || !support.eq_string(b, "kind", "None") || !support.eq_int(peer, "connections", 2) {
			return "responses"
		}
		if !response_order(events) {
			return "peer progress"
		}
	} else {
		return "mode"
	}
	for row in native {
		event, ok := support.string_field(row, "event")
		if !ok || event != "completion" {
			continue
		}
		if support.eq_string(row, "phase", "Deadline") {
			completed, completed_ok := support.i64_field(row, "completed_at")
			cutoff, cutoff_ok := support.i64_field(row, "cutoff")
			if !completed_ok || !cutoff_ok || completed < cutoff {
				return "deadline witness"
			}
		}
		if support.eq_string(row, "kind", "None") {
			label, label_ok := support.string_field(row, "label")
			body, body_ok := support.i64_field(row, "body")
			if !label_ok || len(label) != 1 || !body_ok || body != i64(label[0]) || !support.eq_int(row, "status", 200) {
				return "response"
			}
		}
	}
	return ""
}

exact_cleanup :: proc(value: json.Value) -> bool {
	if !exact_keys(value, 3) || !support.eq_string(value, "event", "cleanup") || !support.is_true(value, "heap_zero") || !support.eq_int(value, "fd_delta", 0) {
		return false
	}
	return true
}

exact_keys :: proc(value: json.Value, n: int) -> bool {
	object, ok := value.(json.Object)
	return ok && len(object) == n
}

unique_labels :: proc(labels: []string) -> bool {
	for label, i in labels {
		for other, j in labels {
			if i != j && label == other {
				return false
			}
		}
	}
	return true
}

labeled :: proc(rows: []json.Value, label: string) -> (json.Value, bool) {
	found: json.Value
	count := 0
	for row in rows {
		event, ok := support.string_field(row, "event")
		if !ok || event != "completion" {
			continue
		}
		got, got_ok := support.string_field(row, "label")
		if !got_ok || got != label {
			continue
		}
		found = row
		count += 1
	}
	if count != 1 {
		return {}, false
	}
	return found, true
}

same_connection :: proc(a, b: json.Value) -> bool {
	left, left_ok := support.i64_field(a, "connection")
	right, right_ok := support.i64_field(b, "connection")
	return left_ok && right_ok && left == right
}

cutoff_before :: proc(a, b: json.Value) -> bool {
	left, left_ok := support.i64_field(a, "cutoff")
	right, right_ok := support.i64_field(b, "cutoff")
	return left_ok && right_ok && left < right
}

has_event :: proc(events: json.Array, name: string) -> bool {
	for event in events {
		got, ok := support.string_field(event, "event")
		if ok && got == name {
			return true
		}
	}
	return false
}

staged :: proc(events: json.Array, encrypted: bool) -> bool {
	kind := "partial_raw_staged"
	if encrypted {
		kind = "partial_record_staged"
	}
	found: json.Value
	count := 0
	for event in events {
		name, ok := support.string_field(event, "event")
		if !ok || name != kind {
			continue
		}
		found = event
		count += 1
	}
	if count != 1 || !support.eq_int(found, "bytes", 1) {
		return false
	}
	if encrypted && (!support.eq_int(found, "record_type", 23) || !support.gt_int(found, "full_bytes", 5)) {
		return false
	}
	return true
}

uncertain_reset :: proc(events: json.Array) -> bool {
	for event in events {
		name, ok := support.string_field(event, "event")
		if ok && name == "uncertain_post_reset" && support.eq_int(event, "body_first", 112) {
			return true
		}
	}
	return false
}

response_order :: proc(events: json.Array) -> bool {
	want := [?]string{"/B", "/A"}
	n := 0
	for event in events {
		name, ok := support.string_field(event, "event")
		if !ok || name != "response" {
			continue
		}
		path, path_ok := support.string_field(event, "path")
		if !path_ok || n >= len(want) || path != want[n] {
			return false
		}
		n += 1
	}
	return n == len(want)
}

rows_or_empty :: proc(value: json.Value, key: string) -> (items: json.Array, ok: bool) {
	field, exists := support.get(value, key)
	if !exists {
		return nil, true
	}
	if _, is_null := field.(json.Null); is_null {
		return nil, true
	}
	array, is_array := field.(json.Array)
	if !is_array {
		return nil, false
	}
	return array, true
}
