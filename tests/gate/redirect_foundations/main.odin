// Name-filtered private redirect tests. The names are read from the redirect
// unit file, then task test runs that list once.
package main

import support "../support"

import "core:fmt"
import "core:os"
import "core:strings"

SOURCES :: [?]string{
	"tests/unit/async/redirect_test.odin",
}

main :: proc() {
	g := support.begin("redirect_foundations101")
	defer support.end(&g)
	names := make([dynamic]string)
	defer {
		for name in names {
			delete(name)
		}
		delete(names)
	}
	for path in SOURCES {
		found, ok := discover(path)
		if !ok || len(found) == 0 {
			for name in found {
				delete(name)
			}
			delete(found)
			support.fail(&g, path)
		}
		for name in found {
			append(&names, name)
		}
		delete(found)
	}
	for name, i in names {
		for other, j in names {
			if i != j && name == other {
				support.fail(&g, "duplicate test")
			}
		}
	}
	if len(names) == 0 || !support.task_test(&g, "async", names[:], len(names), "-define:ODIN_TEST_LOG_STATE_CHANGES=true") {
		support.fail(&g, "units")
	}
	text := fmt.aprintf("{{\"passed\":true,\"tests\":%d}}\n", len(names))
	defer delete(text)
	support.passed(&g, text)
	fmt.println(len(names), "redirect foundation tests passed")
}

// @(test) is on its own line. The procedure name follows, then :: proc.
discover :: proc(path: string) -> (names: [dynamic]string, ok: bool) {
	data, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		return nil, false
	}
	defer delete(data)
	names = make([dynamic]string)
	rest := string(data)
	for len(rest) > 0 {
		at := strings.index(rest, "@(test)")
		if at < 0 {
			break
		}
		rest = rest[at + len("@(test)"):]
		for len(rest) > 0 && space(rest[0]) {
			rest = rest[1:]
		}
		end := 0
		for end < len(rest) && ident(rest[end]) {
			end += 1
		}
		if end == 0 {
			continue
		}
		name := rest[:end]
		rest = rest[end:]
		for len(rest) > 0 && space(rest[0]) {
			rest = rest[1:]
		}
		if !strings.has_prefix(rest, "::") {
			continue
		}
		rest = rest[2:]
		for len(rest) > 0 && space(rest[0]) {
			rest = rest[1:]
		}
		if !strings.has_prefix(rest, "proc") {
			continue
		}
		append(&names, strings.clone(name))
	}
	return names, true
}

space :: proc(c: byte) -> bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

ident :: proc(c: byte) -> bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
