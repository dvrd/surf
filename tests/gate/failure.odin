// Allocation failures on the public Client across a POST and its redirect.
// The cell count comes from the baseline allocation census, not a fixed native
// total. The peer is tests/support/failure/peer.

package main

import "support"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

run_failure :: proc() {
	gate_label = "failure"

	g := support.begin("failure")
	defer support.end(&g)
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/support/failure/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/support/failure", fixture_bin, true) {
		support.fail(&g, "fixture build")
	}
	calls: int
	reason: string
	calls, reason = failure_cell(&g, peer_bin, fixture_bin, 0, 0)
	if reason != "" {
		support.fail(&g, reason)
	}
	if calls <= 0 {
		support.fail(&g, "census")
	}
	cells := 1
	// Each armed allocation fails, cancels its request, or releases it.
	modes := [?]int{1, 8, 10}
	for point in 1 ..= calls {
		for mode in modes {
			_, step := failure_cell(&g, peer_bin, fixture_bin, point, mode)
			if step != "" {
				support.fail(&g, step)
			}
			cells += 1
		}
	}
	// A close during an allocation lets the request in flight finish.
	_, step := failure_cell(&g, peer_bin, fixture_bin, 4, 9)
	if step != "" {
		support.fail(&g, step)
	}
	cells += 1
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "failure cells passed")
}

failure_cell :: proc(g: ^support.Gate, peer_bin, fixture_bin: string, point, mode: int) -> (calls: int, reason: string) {
	support.note(g, fmt.tprintf("p%d m%d", point, mode))
	dir := support.path(g, fmt.tprintf("p%d-m%d", point, mode))
	defer delete(dir)
	point_text := fmt.aprintf("%d", point)
	defer delete(point_text)
	mode_text := fmt.aprintf("%d", mode)
	defer delete(mode_text)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-dir", dir)
	peer, started := support.spawn(command[:], nil)
	defer support.stop(&peer)
	if !started {
		return 0, "peer start"
	}
	endpoint, ready := support.first_line(&peer, 10 * time.Second)
	defer delete(endpoint)
	if !ready || !strings.has_prefix(endpoint, "127.0.0.1:") {
		fmt.eprintf("peer: %s\n", support.tail(&peer))
		return 0, "readiness"
	}
	fixture_cmd := make([dynamic]string)
	defer delete(fixture_cmd)
	append(&fixture_cmd, fixture_bin, endpoint, dir, point_text, mode_text)
	fixture, fix_started := support.spawn(fixture_cmd[:], nil)
	defer support.stop(&fixture)
	if !fix_started {
		return 0, "fixture start"
	}
	if !support.reap(&fixture, 25 * time.Second) || fixture.code != 0 {
		fmt.eprintf("fixture: %s\n", support.tail(&fixture))
		return 0, "fixture"
	}
	if !support.reap(&peer, 5 * time.Second) || peer.code != 0 {
		fmt.eprintf("peer: %s\n", support.tail(&peer))
		return 0, "peer"
	}
	native, native_ok := support.only(support.stdout(&fixture))
	if !native_ok {
		return 0, "native json"
	}
	defer json.destroy_value(native)
	oracle, oracle_ok := support.only(support.stdout(&peer))
	if !oracle_ok {
		return 0, "peer json"
	}
	defer json.destroy_value(oracle)
	return failure_verify(mode, native, oracle)
}

failure_verify :: proc(mode: int, native, peer: json.Value) -> (calls: int, reason: string) {
	if !support.is_true(native, "header_freed") || !support.is_true(native, "heap_zero") || !support.is_true(native, "fd_zero") {
		return 0, "cleanup"
	}
	events, events_ok := support.array_field(peer, "events")
	if !events_ok {
		return 0, "events"
	}
	one := support.field_strings(events, "path", []string{"/A"})
	two := support.field_strings(events, "path", []string{"/A", "/final"})
	if !one && !two {
		return 0, "paths"
	}
	for event in events {
		if !support.eq_string(event, "body", "fixed-owned-payload") {
			return 0, "body"
		}
	}
	// A request cancelled or released during its redirect may leave the new
	// hop's connection open before any byte of the request went out.
	connections, connections_ok := support.int_field(peer, "connections")
	spare := 1 if mode == 8 || mode == 10 else 0
	if !connections_ok || connections < len(events) || connections > len(events) + spare || !distinct_connections(events) {
		return 0, "connections"
	}
	if mode == 0 {
		if !support.eq_string(native, "error", "None") || len(events) != 2 || !support.eq_int(native, "hits", 0) {
			return 0, "healthy"
		}
		return census(native)
	}
	if !support.eq_int(native, "hits", 1) {
		return 0, "injection"
	}
	switch mode {
	case 1:
		if !support.eq_string(native, "error", "Allocation_Failed") {
			return 0, "allocation"
		}
	case 8:
		cancelled := support.eq_string(native, "error", "IO_Failed") && support.eq_string(native, "phase", "Cancellation")
		finished := support.eq_string(native, "error", "None") && two
		// Point 4 waits on the network afterwards, so its cancel always lands
		// first. A later point may finish before the cancel does.
		point, _ := support.int_field(native, "point")
		if !cancelled && (point == 4 || !finished) {
			return 0, "cancellation"
		}
	case 9:
		if !support.eq_string(native, "error", "None") || !two {
			return 0, "close"
		}
	}
	return 0, ""
}

census :: proc(native: json.Value) -> (calls: int, reason: string) {
	n, calls_ok := support.int_field(native, "calls")
	sizes, sizes_ok := support.array_field(native, "sizes")
	alignments, alignments_ok := support.array_field(native, "alignments")
	if !calls_ok || !sizes_ok || !alignments_ok || n <= 0 || n != len(sizes) || n != len(alignments) {
		return 0, "census"
	}
	for item in alignments {
		alignment, alignment_ok := support.as_i64(item)
		if !alignment_ok || alignment < 1 || alignment & (alignment - 1) != 0 {
			return 0, "alignment"
		}
	}
	return n, ""
}

distinct_connections :: proc(events: json.Array) -> bool {
	ids: [8]int
	if len(events) > len(ids) {
		return false
	}
	for event, i in events {
		id, ok := support.int_field(event, "connection")
		if !ok {
			return false
		}
		for prev in 0 ..< i {
			if ids[prev] == id {
				return false
			}
		}
		ids[i] = id
	}
	return true
}
