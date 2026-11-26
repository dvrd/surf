// Streaming, upload, gzip, and redirect wire matrix.
// The peer is tests/support/stream/peer. Vet flags apply to the fixture only.

package main

import "support"
import "core:crypto/hash"
import "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

stream_Case :: struct {
	mode: string,
	size: int,
}

CASES :: [?]stream_Case{
	{"known", 32 << 20}, {"chunked", 32 << 20}, {"eof", 32 << 20},
	{"fragmented", 4096}, {"short-length", 65536},
	{"buffered-gzip", 65536}, {"buffered-short", 65536},
	{"allocation-engine", 2}, {"allocation-head-fields", 2},
	{"head-gzip", 12345}, {"no-content-gzip", 12345}, {"not-modified-gzip", 12345},
	{"coding-unsupported", 3}, {"coding-chain", 3}, {"coding-repeated", 3},
	{"chunk-invalid-size", 65536}, {"chunk-invalid-crlf", 65536},
	{"chunk-truncated", 65536}, {"chunk-missing-terminal", 65536},
	{"chunk-trailer-invalid", 65536}, {"conflicting-framing", 65536},
	{"credit", 131072}, {"late-head", 131072}, {"late-chunk", 131072},
	{"late-both", 131072}, {"timeout", 32 << 20}, {"cancel", 32 << 20},
	{"fairness", 32 << 20},
	{"upload", 4 << 20}, {"upload-backing", 3}, {"upload-empty", 4096},
	{"upload-oversize", 65536}, {"upload-overrun", 4096},
	{"upload-short", 131072}, {"upload-source-error", 131072},
	{"upload-source-error-blocked", 32 << 20},
	{"upload-cancel", 131072}, {"early-final", 32 << 20},
	{"early-final-prefix", 32 << 20}, {"early-final-blocked", 32 << 20},
	{"gzip", 4 << 20}, {"gzip-chunked", 4 << 20}, {"gzip-eof", 4 << 20},
	{"gzip-fragmented", 65536}, {"gzip-metadata", 65536},
	{"gzip-fhcrc", 65536}, {"gzip-fhcrc-invalid", 65536},
	{"gzip-crc", 65536}, {"gzip-crc-held", 65536}, {"gzip-size", 65536},
	{"gzip-truncated", 65536}, {"gzip-trailing", 65536},
	{"gzip-members", 65536}, {"gzip-encoded-exact", 65536},
	{"gzip-decoded-exact", 65536}, {"decoded-exact", 65536},
	{"gzip-encoded-limit", 65536}, {"gzip-decoded-limit", 65536},
	{"gzip-amplification", 4 << 20},
	{"encoded-limit", 65536}, {"decoded-limit", 65536},
	{"redirect", 2}, {"redirect-cross", 2}, {"redirect-cross-auth", 2}, {"redirect-loop", 2},
	{"redirect-malformed", 2}, {"redirect-gzip-invalid", 2},
	{"redirect-deadline", 2}, {"redirect-downgrade", 2},
}

HEX :: "0123456789abcdef"

// Two queued response chunks of at most 16 KiB each, plus allocator slack.
STREAM_BACKING_LIMIT :: 2 * 16384 + 4096

#assert(len(CASES) == 69)

run_stream :: proc() {
	gate_label = "stream"

	g := support.begin("stream")
	defer support.end(&g)
	peer_bin := support.path(&g, "peer")
	defer delete(peer_bin)
	fixture_bin := support.path(&g, "fixture")
	defer delete(fixture_bin)
	if !support.build(&g, "tests/support/stream/peer", peer_bin, false) {
		support.fail(&g, "peer build")
	}
	if !support.build(&g, "tests/support/stream", fixture_bin, true, "-vet", "-vet-packages:main") {
		support.fail(&g, "fixture build")
	}
	cells := 0
	for transport in ([?]string{"tcp", "tls"}) {
		for item in CASES {
			if item.mode == "redirect-downgrade" && transport != "tls" {
				continue
			}
			if strings.has_prefix(item.mode, "allocation-") && transport == "tls" {
				continue
			}
			if reason := stream_cell(&g, peer_bin, fixture_bin, transport, item.mode, item.size); reason != "" {
				support.fail(&g, reason)
			}
			cells += 1
		}
	}
	if cells != 135 {
		support.fail(&g, "matrix")
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "stream cells passed")
}

stream_cell :: proc(g: ^support.Gate, peer_bin, fixture_bin, transport, mode: string, size: int) -> string {
	support.note(g, fmt.tprintf("%s %s", transport, mode))
	dir := support.path(g, fmt.tprintf("%s-%s", transport, mode))
	defer delete(dir)
	size_text := fmt.aprintf("%d", size)
	defer delete(size_text)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, peer_bin, "-mode", mode, "-dir", dir, "-bytes", size_text)
	if transport == "tls" {
		append(&command, "-tls")
	}
	if mode == "known" || mode == "chunked" || mode == "eof" {
		append(&command, "-first-chunk-barrier")
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
	append(&fixture_cmd, fixture_bin, endpoint, mode, transport, dir, size_text)
	fixture, fix_started := support.spawn(fixture_cmd[:], nil)
	defer support.stop(&fixture)
	if !fix_started {
		return "fixture start"
	}
	long := (strings.has_prefix(mode, "gzip") && size >= 4 << 20 && mode != "gzip-amplification") || (mode == "fragmented" && transport == "tls")
	limit := 25 * time.Second
	if long {
		limit = 40 * time.Second
	}
	if !support.reap(&fixture, limit) || fixture.code != 0 {
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
	return validate(mode, size, transport == "tls", native, oracle)
}

validate :: proc(mode: string, size: int, encrypted: bool, native, peer: json.Value) -> string {
	if !support.eq_string(native, "mode", mode) || !support.eq_string(peer, "mode", mode) {
		return "case"
	}
	if encrypted {
		if !support.is_true(native, "tls") || !support.is_true(peer, "tls") || !support.eq_string(peer, "alpn", "http/1.1") {
			return "transport"
		}
	} else if !support.is_false(native, "tls") || !support.is_false(peer, "tls") || !support.eq_string(peer, "alpn", "") {
		return "transport"
	}
	if !support.is_true(native, "heap_zero") || !support.is_true(native, "fd_zero") {
		return "cleanup"
	}
	peak, peak_ok := support.i64_field(native, "peak_bytes")
	base, base_ok := support.i64_field(native, "baseline_bytes")
	if !peak_ok || !base_ok || peak > base + i64(4 << 20) {
		return "backing"
	}
	if !at_most(native, "max_response_backing", STREAM_BACKING_LIMIT) {
		return "bounds"
	}
	created, created_ok := support.int_field(native, "source_created")
	released, released_ok := support.int_field(native, "source_released")
	if !created_ok || !released_ok || created != released {
		return "source"
	}
	kind, kind_ok := support.string_field(native, "error_kind")
	if !kind_ok {
		return "error kind"
	}
	if mode == "upload-empty" || mode == "upload-oversize" || mode == "upload-overrun" {
		if !support.is_true(native, "occupied_preserved") || !support.gt_int(native, "source_rejected", 0) {
			return "rejected upload"
		}
	}
	if is_error(mode) {
		if !support.is_false(native, "ended") || kind == "" {
			return "typed failure"
		}
		return validate_error(mode, size, native, peer)
	}
	if !support.is_true(native, "ended") || kind != "" || !support.is_true(native, "head_received") {
		return "terminal"
	}
	if mode == "buffered-gzip" {
		if !support.eq_string(peer, "accept_encoding", "identity") {
			return "buffered identity"
		}
		if !same_int(native, "bytes", peer, "wire_body_bytes") || !same_string(native, "sha256", peer, "body_sha256") {
			return "buffered body"
		}
	} else if mode == "head-gzip" || mode == "no-content-gzip" || mode == "not-modified-gzip" {
		status := 200
		if mode == "no-content-gzip" {
			status = 204
		} else if mode == "not-modified-gzip" {
			status = 304
		}
		if !support.eq_int(native, "status", status) || !support.eq_int(native, "bytes", 0) || !support.eq_int(native, "chunks", 0) {
			return "bodyless"
		}
		if !support.eq_int(native, "wire_content_length", size) {
			return "bodyless wire"
		}
	} else if strings.has_prefix(mode, "upload") || strings.has_prefix(mode, "early-final") {
		if reason := validate_upload(mode, size, native, peer); reason != "" {
			return reason
		}
	} else if strings.has_prefix(mode, "redirect") {
		if !support.eq_int(native, "bytes", 2) || !support.eq_int(native, "status", 200) {
			return "redirect"
		}
		if !support.eq_int(peer, "requests", 2) || !support.is_true(peer, "intermediate_sent") || !support.is_true(native, "intermediate_hidden") {
			return "redirect hops"
		}
		if !same_string(native, "sha256", peer, "body_sha256") {
			return "redirect body"
		}
		if mode == "redirect-cross" && !support.is_true(peer, "authorization_gone") {
			return "authorization"
		}
	} else {
		if !support.eq_int(native, "bytes", size) || !same_string(native, "sha256", peer, "body_sha256") {
			return "body"
		}
		if mode == "known" || mode == "chunked" || mode == "eof" {
			if !support.is_true(peer, "first_chunk_barrier") || !support.is_true(native, "first_chunk_barrier") {
				return "barrier"
			}
		}
	}
	if mode == "credit" {
		if !support.is_true(native, "chunk_credit_held") || !support.is_true(native, "credit_reopened") {
			return "credit"
		}
	}
	if strings.has_prefix(mode, "late") {
		retained, retained_ok := support.i64_field(native, "retained_after_teardown_bytes")
		if !support.is_true(native, "late_owner") || !retained_ok || retained <= 0 {
			return "late owner"
		}
	}
	return ""
}

validate_error :: proc(mode: string, size: int, native, peer: json.Value) -> string {
	if detail, decoded := decoder_detail(mode); decoded {
		if !support.eq_string(native, "http_kind", "Content_Decoding_Failed") || !support.eq_string(native, "decoding", detail) {
			return "decoder"
		}
	}
	if mode == "gzip-crc-held" {
		retained, retained_ok := support.i64_field(native, "retained_after_teardown_bytes")
		if !support.is_true(native, "late_owner") || !retained_ok || retained <= 0 {
			return "checksum owner"
		}
	}
	if mode == "timeout" || mode == "redirect-deadline" {
		if !support.eq_string(native, "phase", "Deadline") {
			return "deadline"
		}
		if mode == "timeout" && !support.is_true(native, "deadline_without_poll") {
			return "deadline"
		}
		if mode == "redirect-deadline" {
			elapsed, elapsed_ok := support.i64_field(native, "elapsed_ns")
			if !elapsed_ok || elapsed < 200_000_000 || elapsed > 800_000_000 {
				return "redirect deadline"
			}
		}
	}
	if mode == "cancel" || mode == "upload-cancel" || mode == "fairness" {
		if !support.eq_string(native, "phase", "Cancellation") {
			return "cancellation"
		}
		if mode == "cancel" && !support.is_true(native, "cancel_without_poll") {
			return "cancellation"
		}
	}
	if mode == "upload-overrun" {
		if !support.eq_string(native, "http_kind", "Invalid_Config") || !support.eq_string(native, "phase", "Write") {
			return "overrun"
		}
		if !support.is_false(peer, "upload_complete") {
			return "overrun"
		}
	}
	if mode == "upload-source-error" || mode == "upload-source-error-blocked" {
		if !support.eq_string(native, "source_io", "Unexpected_EOF") || !support.eq_string(native, "phase", "Write") {
			return "source error"
		}
	}
	if mode == "upload-source-error-blocked" {
		stall, stall_ok := support.i64_field(native, "upload_stall_ns")
		blocked, blocked_ok := support.i64_field(native, "upload_blocked_after_bytes")
		done, done_ok := support.i64_field(native, "source_error_completed_ns")
		uploaded, uploaded_ok := support.i64_field(peer, "upload_bytes")
		if !stall_ok || stall < 100_000_000 || !blocked_ok || blocked <= 0 || !done_ok || done <= 0 || done >= 2_000_000_000 {
			return "upload stall"
		}
		if !uploaded_ok || uploaded >= i64(size) || !support.eq_int(peer, "requests", 1) || !support.is_false(native, "head_received") {
			return "upload stall"
		}
	}
	if mode == "fairness" {
		if !support.is_true(native, "cheap_before_release") || !support.is_true(peer, "cheap_before_release") || !support.eq_int(peer, "requests", 2) {
			return "fairness"
		}
	}
	if strings.has_prefix(mode, "allocation-") {
		// The engine fault is the dialed connection; the head fault is the
		// first allocation once the request is on the wire.
		point := 9
		if mode != "allocation-engine" {
			point = 1
		}
		sizes, sizes_ok := support.array_field(native, "allocation_sizes")
		if !support.eq_string(native, "http_kind", "Allocation_Failed") || !support.eq_int(native, "allocation_hits", 1) {
			return "allocation"
		}
		if !support.is_false(native, "head_received") || !support.eq_int(native, "bytes", 0) || !support.eq_int(native, "allocation_calls", point) {
			return "allocation"
		}
		if !sizes_ok || point - 1 >= len(sizes) {
			return "allocation"
		}
		n, n_ok := support.as_i64(sizes[point - 1])
		if !n_ok || n <= 0 {
			return "allocation"
		}
		want := 0
		if mode != "allocation-engine" {
			want = 1
		}
		if !support.eq_int(peer, "requests", want) {
			return "allocation boundary"
		}
	}
	if strings.has_prefix(mode, "coding-") {
		if !support.eq_string(native, "http_kind", "Unsupported_Content_Encoding") || !support.is_false(native, "head_received") {
			return "coding"
		}
	}
	if mode == "redirect-cross-auth" {
		if !support.eq_string(native, "http_kind", "Unsafe_Redirect") || !support.eq_int(native, "status", 302) {
			return "unsafe redirect"
		}
		if !support.eq_int(peer, "requests", 1) || !support.is_true(peer, "authorization_gone") {
			return "unsafe redirect"
		}
	}
	if strings.has_prefix(mode, "redirect") {
		if !support.is_false(native, "head_received") || !support.eq_int(native, "status", 302) {
			return "redirect failure"
		}
	}
	if mode == "gzip-decoded-limit" || mode == "gzip-amplification" {
		if !support.eq_string(native, "http_kind", "Body_Oversized") || !support.eq_string(native, "phase", "Body_Limit") {
			return "decoded limit"
		}
	}
	if mode == "gzip-amplification" {
		bytes, bytes_ok := support.i64_field(native, "bytes")
		if !bytes_ok || bytes > 65536 {
			return "amplification"
		}
	}
	if mode == "decoded-limit" || mode == "gzip-decoded-limit" || mode == "encoded-limit" {
		bytes, bytes_ok := support.i64_field(native, "bytes")
		if !bytes_ok || bytes > i64(size - 1) {
			return "limit"
		}
	}
	if mode == "gzip-encoded-limit" && !support.eq_int(native, "bytes", 0) {
		return "encoded limit"
	}
	return ""
}

validate_upload :: proc(mode: string, size: int, native, peer: json.Value) -> string {
	text := "ok"
	if strings.has_prefix(mode, "early-final") {
		text = "no!"
	}
	sum := digest(text)
	defer delete(sum)
	if !support.eq_int(native, "bytes", len(text)) || !support.eq_string(native, "sha256", sum) {
		return "upload response"
	}
	if strings.has_prefix(mode, "early-final") {
		uploaded, uploaded_ok := support.i64_field(peer, "upload_bytes")
		if !support.is_true(peer, "early_final") || !uploaded_ok || uploaded >= i64(size) || !support.eq_int(native, "status", 413) {
			return "early final"
		}
		if mode == "early-final-blocked" {
			blocked, blocked_ok := support.i64_field(native, "upload_blocked_after_bytes")
			stall, stall_ok := support.i64_field(native, "upload_stall_ns")
			if !blocked_ok || blocked <= 0 || !stall_ok || stall < 100_000_000 {
				return "early final block"
			}
		}
	} else {
		if !support.is_true(peer, "upload_complete") || !support.eq_int(peer, "upload_bytes", size) {
			return "upload bytes"
		}
		if !support.gt_int(native, "source_accepted", 0) {
			return "upload source"
		}
	}
	if mode == "upload-backing" {
		if !support.is_true(native, "credit_preserved") || !support.gt_int(native, "source_rejected", 0) {
			return "upload backing"
		}
	}
	return ""
}

is_error :: proc(mode: string) -> bool {
	switch mode {
	case "short-length", "buffered-short", "chunk-invalid-size", "chunk-invalid-crlf", "chunk-truncated",
	     "allocation-engine", "allocation-head-fields",
	     "chunk-missing-terminal", "chunk-trailer-invalid", "conflicting-framing",
	     "timeout", "cancel", "upload-short", "upload-source-error", "upload-cancel", "upload-overrun",
	     "upload-source-error-blocked", "fairness",
	     "gzip-fhcrc-invalid", "gzip-crc", "gzip-crc-held", "gzip-size", "gzip-truncated", "gzip-trailing",
	     "gzip-members", "gzip-encoded-limit", "gzip-decoded-limit", "gzip-amplification",
	     "encoded-limit", "decoded-limit", "redirect-loop", "redirect-malformed",
	     "coding-unsupported", "coding-chain", "coding-repeated",
	     "redirect-gzip-invalid", "redirect-deadline", "redirect-downgrade", "redirect-cross-auth":
		return true
	}
	return false
}

decoder_detail :: proc(mode: string) -> (string, bool) {
	switch mode {
	case "gzip-fhcrc-invalid", "gzip-crc", "gzip-crc-held":
		return "Checksum_Mismatch", true
	case "gzip-size":
		return "Size_Mismatch", true
	case "gzip-truncated":
		return "Truncated", true
	case "gzip-trailing":
		return "Trailing_Data", true
	case "gzip-members":
		return "Member_Limit", true
	}
	return "", false
}

at_most :: proc(value: json.Value, key: string, limit: int) -> bool {
	got, ok := support.int_field(value, key)
	return ok && got <= limit
}

same_int :: proc(left: json.Value, left_key: string, right: json.Value, right_key: string) -> bool {
	a, a_ok := support.i64_field(left, left_key)
	b, b_ok := support.i64_field(right, right_key)
	return a_ok && b_ok && a == b
}

same_string :: proc(left: json.Value, left_key: string, right: json.Value, right_key: string) -> bool {
	a, a_ok := support.string_field(left, left_key)
	b, b_ok := support.string_field(right, right_key)
	return a_ok && b_ok && a == b
}

digest :: proc(text: string) -> string {
	raw: [32]byte
	_ = hash.hash_string_to_buffer(.SHA256, text, raw[:])
	digits := HEX
	buf := make([]byte, 64)
	for b, i in raw {
		buf[i * 2] = digits[b >> 4]
		buf[i * 2 + 1] = digits[b & 15]
	}
	return string(buf)
}
