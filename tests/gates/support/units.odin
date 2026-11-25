package support

import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

// Focused private tests. task test overlays tests/<package>/internal into the
// package before the compiler runs, which a direct odin test of src/ does not.
task_test :: proc(g: ^Gate, pkg: string, names: []string, expect: int, extra: ..string) -> bool {
	note(g, fmt.tprintf("units %s", pkg))
	base, env_error := os.environ(context.allocator)
	if env_error != nil {
		return false
	}
	env := make([dynamic]string, 0, len(base) + 2)
	defer {
		for item in env {
			delete(item)
		}
		delete(env)
	}
	for item in base {
		if strings.has_prefix(item, "ODIN=") || strings.has_prefix(item, "WEBTOOLS_SHARED=") {
			delete(item)
			continue
		}
		append(&env, item)
	}
	delete(base)
	append(&env, fmt.aprintf("ODIN=%s", g.compiler))
	append(&env, fmt.aprintf("WEBTOOLS_SHARED=%s", g.shared))
	joined, join_error := strings.join(names, ",")
	if join_error != nil {
		return false
	}
	defer delete(joined)
	names_flag := fmt.aprintf("-define:ODIN_TEST_NAMES=%s", joined)
	defer delete(names_flag)
	package_flag := fmt.aprintf("PACKAGE=%s", pkg)
	defer delete(package_flag)
	command := make([dynamic]string)
	defer delete(command)
	append(
		&command,
		"task",
		"test",
		"INTERNAL=1",
		package_flag,
		"--",
		"-define:ODIN_TEST_THREADS=1",
		"-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true",
		names_flag,
	)
	sanitize_flag := ""
	if g.sanitizer != "" && g.sanitizer != "none" {
		sanitize_flag = fmt.aprintf("-sanitize:%s", g.sanitizer)
		append(&command, sanitize_flag)
	}
	defer if sanitize_flag != "" {
		delete(sanitize_flag)
	}
	for flag in extra {
		append(&command, flag)
	}
	child, started := spawn(command[:], env[:])
	if !started {
		return false
	}
	child.out.limit = 16 << 20
	child.err.limit = 16 << 20
	defer stop(&child)
	if !reap(&child, 300 * time.Second) {
		fmt.eprintf("%s: units timed out\n%s\n%s\n", g.name, clip(stdout(&child)), clip(stderr(&child)))
		return false
	}
	text := stdout(&child)
	diag := stderr(&child)
	finished := false
	if expect == 1 {
		finished = strings.contains(text, "Finished 1 test in") || strings.contains(diag, "Finished 1 test in")
	} else {
		needle := fmt.tprintf("Finished %d tests in", expect)
		finished = strings.contains(text, needle) || strings.contains(diag, needle)
	}
	succeeded := strings.contains(text, "All tests were successful") || strings.contains(diag, "All tests were successful")
	missing := strings.contains(text, "No test found") || strings.contains(diag, "No test found") || strings.contains(text, "No tests to run") || strings.contains(diag, "No tests to run")
	named := true
	for name in names {
		if !strings.contains(text, name) && !strings.contains(diag, name) {
			named = false
			break
		}
	}
	if !finished || !succeeded || missing || !named || child.code != 0 {
		fmt.eprintf("%s: units exit %d\n%s\n%s\n", g.name, child.code, clip(text), clip(diag))
		return false
	}
	return true
}
