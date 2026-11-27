#+build linux, darwin, freebsd, openbsd, netbsd
package main

import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

// Acceptance gates. task gate stages shared:surf, then runs tests/gate with
// the compiler, that collection, and a report file filled in.
GATE_NAMES :: [?]string {
	"budgets",
	"cancel",
	"client",
	"concurrency",
	"consumer",
	"failure",
	"outcomes",
	"pool",
	"redirect",
	"setup",
	"stream",
	"uploads",
}

// Lines of a failed gate's log shown under its result.
FAILURE_TAIL :: 40

BOLD :: "1"
DIM :: "2"
RED :: "31"
GREEN :: "32"

gates_mode: bool
gate_selection: string
gate_verbose: bool
gate_color: bool

Gate_Result :: struct {
	name:    string,
	passed:  bool,
	status:  int,
	detail:  string,
	elapsed: time.Duration,
}

require_known_gate :: proc() {
	if gate_selection == "" || gate_selection == "all" {
		gate_selection = "all"
		return
	}

	for name in GATE_NAMES {
		if name == gate_selection {
			return
		}
	}

	say_err("Unknown gate %s\n", gate_selection)
	names: [dynamic]string
	for name in GATE_NAMES {
		append(&names, name)
	}

	say_err("names: %s\n", join_sep(names[:], " "))
	finish(2)
}

run_gates :: proc(staged: Staged) {
	binary := join(work_dir, "gate")
	build_log := join(work_dir, "gate-build.log")
	gate_color = use_color()
	say("%s\n", paint(DIM, "Building tests/gate"))
	build: [dynamic]string
	append(
		&build,
		staged.wrapper,
		"build",
		join(staged.repository, "tests/gate"),
		concat("-out:", binary),
	)
	spawn_grouped(build[:], staged.repository, "" if gate_verbose else build_log)
	status := wait_grouped("tests/gate")
	if status != 0 {
		say("%s  tests/gate did not build\n", paint(RED, "FAIL", true))
		show_tail(build_log, 0)
		finish(status)
	}

	names := selected_gates()
	width := 0
	for name in names {
		width = max(width, len(name))
	}

	say(
		"%s\n\n",
		paint(DIM, fmt.tprintf("Running %d gate%s", len(names), "" if len(names) == 1 else "s")),
	)
	results: [dynamic]Gate_Result
	started := time.tick_now()
	for name in names {
		stop_if_signaled()
		result := run_gate(binary, name, staged, width)
		append(&results, result)
	}

	summarize(results[:], time.tick_since(started))
}

run_gate :: proc(binary, name: string, staged: Staged, width: int) -> Gate_Result {
	report := join(work_dir, concat(name, ".json"))
	log := join(work_dir, concat(name, ".log"))
	command: [dynamic]string
	append(&command, binary, name)
	append(&command, "--odin", staged.wrapper)
	append(&command, "--shared", staged.shared)
	append(&command, "--report", report)

	if gate_verbose {
		say("%s\n", paint(BOLD, concat("── ", name)))
	} else {
		say("  %s  ", paint(BOLD, fmt.tprintf("%-*s", width, name)))
	}

	started := time.tick_now()
	spawn_grouped(command[:], staged.repository, "" if gate_verbose else log)
	status := wait_grouped(name)
	result := Gate_Result {
		name    = name,
		status  = status,
		elapsed = time.tick_since(started),
	}

	passed, detail := read_report(report)
	result.passed = status == 0 && passed
	result.detail = detail
	if !result.passed && status == 0 {
		result.detail = "no passing report"
	} else if status != 0 {
		result.detail = fmt.aprintf("exit %d", status)
	}

	if gate_verbose {
		say(
			"%s %s  %s  %s\n\n",
			paint(BOLD, concat("── ", name)),
			verdict(result.passed),
			result.detail,
			paint(DIM, seconds(result.elapsed)),
		)
	} else {
		say(
			"%s  %-28s %s\n",
			verdict(result.passed),
			result.detail,
			paint(DIM, seconds(result.elapsed)),
		)
	}

	if !result.passed && !gate_verbose {
		show_tail(log, FAILURE_TAIL)
	}

	return result
}

summarize :: proc(results: []Gate_Result, elapsed: time.Duration) {
	failed: [dynamic]string
	for result in results {
		if !result.passed {
			append(&failed, result.name)
		}
	}

	passed := len(results) - len(failed)
	passed_text := paint(GREEN, fmt.tprintf("%d passed", passed), passed > 0)
	failed_text := paint(RED, fmt.tprintf("%d failed", len(failed)), len(failed) > 0)
	if len(failed) == 0 {
		failed_text = paint(DIM, "0 failed")
	}

	say("\n%s, %s, %s\n", passed_text, failed_text, paint(DIM, seconds(elapsed)))
	if len(failed) == 0 {
		finish(0)
	}

	say("%s %s\n", paint(RED, "Failed:", true), join_sep(failed[:], " "))
	say("%s\n", paint(DIM, fmt.tprintf("Rerun one with: task gate GATE=%s VERBOSE=1", failed[0])))
	finish(1)
}

verdict :: proc(passed: bool) -> string {
	if passed {
		return paint(GREEN, "PASS", true)
	}

	return paint(RED, "FAIL", true)
}

// Color only reaches a terminal. NO_COLOR turns it off, and a pipe or a CI log
// gets plain text.
use_color :: proc() -> bool {
	if value, found := os.lookup_env("NO_COLOR", context.allocator); found && value != "" {
		return false
	}

	if value, found := os.lookup_env("TERM", context.allocator); found && value == "dumb" {
		return false
	}

	return bool(posix.isatty(posix.STDOUT_FILENO))
}

paint :: proc(code, text: string, bold := false) -> string {
	if !gate_color {
		return text
	}

	if bold {
		return fmt.aprintf("\x1b[1;%sm%s\x1b[0m", code, text)
	}

	return fmt.aprintf("\x1b[%sm%s\x1b[0m", code, text)
}

seconds :: proc(elapsed: time.Duration) -> string {
	return fmt.aprintf("%.1fs", time.duration_seconds(elapsed))
}

selected_gates :: proc() -> [dynamic]string {
	names: [dynamic]string
	if gate_selection == "all" {
		for name in GATE_NAMES {
			append(&names, name)
		}

		return names
	}

	append(&names, gate_selection)
	return names
}

// A report is one JSON object with "passed" and counts such as cells, tests,
// or checks. A count is a number or a list. It becomes the result line detail.
read_report :: proc(path: string) -> (passed: bool, detail: string) {
	if !os.exists(path) {
		return
	}

	text, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		return
	}

	value: json.Value
	if json.unmarshal(text, &value, .JSON) != nil {
		return false, "report is not JSON"
	}

	object, is_object := value.(json.Object)
	if !is_object {
		return false, "report is not an object"
	}

	flag, has_flag := object["passed"].(json.Boolean)
	passed = has_flag && bool(flag)
	parts: [dynamic]string
	for key in ([?]string{"cells", "tests", "units", "scenarios", "checks", "requests"}) {
		#partial switch count in object[key] {
		case json.Integer:
			append(&parts, fmt.aprintf("%d %s", count, key))
		case json.Array:
			append(&parts, fmt.aprintf("%d %s", len(count), key))
		}
	}

	detail = join_sep(parts[:], ", ")
	return
}

show_tail :: proc(path: string, limit: int) {
	text, err := os.read_entire_file(path, context.allocator)
	if err != nil || len(text) == 0 {
		say("      %s\n\n", paint(DIM, "(no output)"))
		return
	}

	lines := strings.split_lines(strings.trim_right(string(text), "\n"))
	first := 0
	if limit > 0 && len(lines) > limit {
		first = len(lines) - limit
		say("      %s\n", paint(DIM, fmt.tprintf("... %d earlier lines", first)))
	}

	for line in lines[first:] {
		say("      %s\n", line)
	}

	say("\n")
}
