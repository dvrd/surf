package surf

import "core:math/rand"
import "core:strings"
import "core:testing"
import "shared:async"

// The runner seeds context.random_generator from t.seed and prints the seed, so
// a failure replays with -define:ODIN_TEST_RANDOM_SEED=n.
FUZZ_ROUNDS :: 20_000
FUZZ_INPUT_MAX :: 96

FUZZ_ALT_SVC_PIECES := []string {
	"h3=\"",
	"h3",
	"=",
	"\"",
	":",
	";",
	",",
	" ",
	"ma=",
	"ma",
	"h2=\":443\"",
	"clear",
	"persist=1",
	"0",
	"1",
	"9",
	"443",
	"65535",
	"65536",
	"99999999999999999999",
	"-",
	"\x00",
	"\xff",
}

FUZZ_PATH_PIECES := []string {
	"/",
	"/",
	"/",
	".",
	"..",
	"...",
	"a",
	"bc",
	"%2e",
	"%2F",
	"?",
	"=",
	"&",
	";",
	" ",
}

FUZZ_LOCATION_PIECES := []string {
	"/",
	"/",
	"//",
	".",
	"..",
	"a",
	"bc",
	"?",
	"#",
	":",
	"@",
	"[",
	"]",
	"%2e",
	"http",
	"https",
	"ftp",
	"://",
	"example.com",
	"localhost",
	":8443",
	":0",
	":99999",
	" ",
	"\\",
	"\r\n",
	"\x00",
	"\xff",
}

fuzz_input :: proc(buffer: []u8, pieces: []string) -> string {
	at := 0
	count := rand.int_max(12)

	for _ in 0 ..< count {
		piece := rand.choice(pieces)

		if at + len(piece) > len(buffer) {
			break
		}

		at += copy(buffer[at:], piece)
	}

	return cast(string)buffer[:at]
}

fuzz_path_has_dot_segment :: proc(target: string) -> bool {
	path := target

	if i := strings.index_byte(path, '?'); i >= 0 {
		path = path[:i]
	}

	for len(path) > 0 {
		end := len(path)

		if i := strings.index_byte(path, '/'); i >= 0 {
			end = i
		}

		segment := path[:end]

		if segment == "." || segment == ".." {
			return true
		}

		if end == len(path) {
			break
		}

		path = path[end + 1:]
	}

	return false
}

@(test)
fuzz_alt_svc_h3_stays_in_range :: proc(t: ^testing.T) {
	buffer: [FUZZ_INPUT_MAX]u8

	for _ in 0 ..< FUZZ_ROUNDS {
		value := fuzz_input(buffer[:], FUZZ_ALT_SVC_PIECES)
		port, ma, ok := alt_svc_h3(value)

		if ok {
			in_range := port >= 1 && port <= 65535 && ma >= 1 && ma <= ALT_SVC_MAX_AGE
			testing.expectf(t, in_range, "seed %v: %q gave port %v ma %v", t.seed, value, port, ma)
		} else {
			testing.expectf(t, port == 0, "seed %v: %q refused with port %v", t.seed, value, port)
		}

		if testing.failed(t) {
			return
		}
	}
}

@(test)
fuzz_redirect_path_normalize_removes_every_dot_segment :: proc(t: ^testing.T) {
	buffer: [FUZZ_INPUT_MAX]u8
	first: [FUZZ_INPUT_MAX]u8
	second: [FUZZ_INPUT_MAX]u8

	for _ in 0 ..< FUZZ_ROUNDS {
		buffer[0] = '/'
		target := cast(string)buffer[:1 + len(fuzz_input(buffer[1:], FUZZ_PATH_PIECES))]

		n := redirect_path_normalize(first[:], target)
		once := cast(string)first[:n]
		testing.expectf(t, n <= len(target), "seed %v: %q grew to %q", t.seed, target, once)
		testing.expectf(
			t,
			n > 0 && once[0] == '/',
			"seed %v: %q lost its root: %q",
			t.seed,
			target,
			once,
		)
		testing.expectf(
			t,
			!fuzz_path_has_dot_segment(once),
			"seed %v: %q kept a dot segment: %q",
			t.seed,
			target,
			once,
		)

		query := ""

		if i := strings.index_byte(target, '?'); i >= 0 {
			query = target[i:]
		}

		testing.expectf(
			t,
			strings.has_suffix(once, query),
			"seed %v: %q changed its query: %q",
			t.seed,
			target,
			once,
		)

		m := redirect_path_normalize(second[:], once)
		twice := cast(string)second[:m]
		testing.expectf(
			t,
			once == twice,
			"seed %v: %q is not stable: %q then %q",
			t.seed,
			target,
			once,
			twice,
		)

		if testing.failed(t) {
			return
		}
	}
}

@(test)
fuzz_redirect_url_resolves_to_a_normalized_url_or_refuses :: proc(t: ^testing.T) {
	bases := []string {
		"https://example.com",
		"https://example.com/",
		"https://example.com/a/b/c?x=1",
		"http://localhost:8080/a/",
		"https://[::1]:8443/a/../b?q",
	}
	buffer: [FUZZ_INPUT_MAX]u8

	for _ in 0 ..< FUZZ_ROUNDS {
		base_text := rand.choice(bases)
		base, be := async.http_url_parse(base_text)
		testing.expect(t, be.kind == .None)

		location := fuzz_input(buffer[:], FUZZ_LOCATION_PIECES)
		url, error := redirect_url(base, location, context.allocator)

		if error.kind != .None {
			testing.expectf(
				t,
				error.kind == .Invalid_Redirect && url == "",
				"seed %v: %q + %q failed with %v",
				t.seed,
				base_text,
				location,
				error.kind,
			)
		} else {
			parsed, pe := async.http_url_parse(url)
			testing.expectf(
				t,
				pe.kind == .None,
				"seed %v: %q + %q gave unparseable %q",
				t.seed,
				base_text,
				location,
				url,
			)
			testing.expectf(
				t,
				!fuzz_path_has_dot_segment(parsed.target),
				"seed %v: %q + %q kept a dot segment: %q",
				t.seed,
				base_text,
				location,
				url,
			)
			testing.expectf(
				t,
				len(url) <= async.HTTP_MAX_HEADER_SIZE,
				"seed %v: %q + %q is too long",
				t.seed,
				base_text,
				location,
			)
			delete(url, context.allocator)
		}

		if testing.failed(t) {
			return
		}
	}
}
