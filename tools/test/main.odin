#+build linux, darwin, freebsd, openbsd, netbsd
package main

import "base:intrinsics"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"

work_dir: string
child_pid: posix.pid_t
caught_signal: i32

root: string
compiler: string
dependency_source: string
selected: string
internal_only: bool

main :: proc() {
	install_signals()
	load_environment()

	arguments := os.args[1:] if len(os.args) > 0 else []string{}
	odin_flags := parse_arguments(arguments)
	for argument in odin_flags {
		prefix := "-collection:shared="
		if strings.has_prefix(argument, prefix) {
			dependency_source = argument[len(prefix):]
		}
	}

	if !os.is_directory(join(root, "src")) {
		say_err("No src/ in %s\n", root)
		finish(2)
	}

	if !os.is_directory(dependency_source) {
		say_err("No shared collection at %s\n", dependency_source)
		finish(2)
	}
	dependency_source = physical_path(dependency_source)

	library := library_name()
	compiler = resolve_compiler(compiler)
	if gates_mode {
		require_known_gate()
	}

	make_work()

	suites: [dynamic]Suite
	if !gates_mode {
		suites = discover_suites(root)
		if len(suites) == 0 {
			say_err("No matching test suites\n")
			finish(2)
		}
	}

	staged := stage(library)
	if err := os.set_env("ODIN", staged.wrapper); err != nil {
		say_err("ODIN: %v\n", err)
		finish(1)
	}

	if gates_mode {
		run_gates(staged)
		finish(0)
	}

	flags := test_flags(staged.shared, odin_flags)
	run_suites(suites[:], staged.repository, flags[:])
	finish(0)
}

load_environment :: proc() {
	if value, found := os.lookup_env("SURF_ROOT", context.allocator); found && value != "" {
		root = value
	} else {
		cwd, err := os.get_working_directory(context.allocator)
		if err != nil {
			say_err("getcwd: %v\n", err)
			finish(1)
		}
		root = cwd
	}

	compiler = "odin"
	if value, found := os.lookup_env("SURF_ODIN", context.allocator); found && value != "" {
		compiler = value
	}

	if value, found := os.lookup_env("SURF_SHARED", context.allocator); found && value != "" {
		dependency_source = value
	} else {
		home := os.get_env("HOME", context.allocator)
		dependency_source = join(home, "dev/oss/Odin/shared")
	}

	selected = "all"
	if value, found := os.lookup_env("SURF_PACKAGE", context.allocator); found && value != "" {
		selected = value
	}

	gate_selection = "all"
	if value, found := os.lookup_env("SURF_GATE", context.allocator); found && value != "" {
		gate_selection = value
	}

	if value, found := os.lookup_env("SURF_GATE_VERBOSE", context.allocator); found {
		gate_verbose = value == "1" || value == "true"
	}

	if value, found := os.lookup_env("SURF_INTERNAL", context.allocator); found {
		internal_only = value == "1" || value == "true"
	}
}

parse_arguments :: proc(arguments: []string) -> []string {
	index := 0
	for index < len(arguments) {
		argument := arguments[index]
		switch argument {
		case "--odin":
			compiler = need_value(arguments, index, argument)
			index += 2
		case "--shared":
			dependency_source = need_value(arguments, index, argument)
			index += 2
		case "--package":
			selected = need_value(arguments, index, argument)
			index += 2
		case "--internal-only":
			internal_only = true
			index += 1
		case "--gates":
			gates_mode = true
			index += 1
		case "--":
			return arguments[index + 1:]
		case "--help", "-h":
			say(
				"Usage: task test [PACKAGE=owner] [INTERNAL=1] [ODIN=path] [SHARED=dir] -- [odin flags]\n",
			)
			say("       task gate [GATE=name] [VERBOSE=1] [ODIN=path] [SHARED=dir]\n")
			finish(0)
		case:
			return arguments[index:]
		}
	}
	return nil
}

need_value :: proc(arguments: []string, index: int, flag: string) -> string {
	if index + 1 >= len(arguments) {
		say_err("%s needs a value\n", flag)
		finish(2)
	}
	return arguments[index + 1]
}

test_flags :: proc(shared: string, odin_flags: []string) -> [dynamic]string {
	flags: [dynamic]string
	append(&flags, concat("-collection:shared=", shared))
	has_output := false
	for argument in odin_flags {
		if strings.has_prefix(argument, "-collection:shared=") {
			continue
		}

		if strings.has_prefix(argument, "-out:") {
			has_output = true
		}
		append(&flags, argument)
	}

	if !has_output {
		append(&flags, concat("-out:", work_dir, "/tests"))
	}
	return flags
}

run_suites :: proc(suites: []Suite, repository: string, flags: []string) {
	for suite in suites {
		stop_if_signaled()
		say("Testing %s\n", suite.relative)
		command: [dynamic]string
		append(&command, compiler, "test", suite_target(repository, suite))
		append(&command, ..flags)
		spawn_grouped(command[:], repository)
		status := wait_grouped(suite.relative)
		if status != 0 {
			finish(status)
		}
	}
}

make_work :: proc() {
	tmp, found := os.lookup_env("TMPDIR", context.allocator)
	if !found || tmp == "" {
		tmp = "/tmp"
	}
	tmp = strings.trim_right(tmp, "/")
	template := concat(tmp, "/odin-library-tests.XXXXXX")
	raw := make([]byte, len(template) + 1)
	copy(raw, template)
	made := posix.mkdtemp(raw_data(raw))
	if made == nil {
		say_err("mkdtemp: %s\n", string(posix.strerror()))
		finish(1)
	}
	work_dir = copy_string(string(made))
	work_dir = physical_path(work_dir)
}

install_signals :: proc() {
	action := posix.sigaction_t {
		sa_handler = handle_signal,
	}
	_ = posix.sigaction(.SIGINT, &action, nil)
	_ = posix.sigaction(.SIGHUP, &action, nil)
	_ = posix.sigaction(.SIGTERM, &action, nil)
}

handle_signal :: proc "c" (sig: posix.Signal) {
	intrinsics.atomic_store(&caught_signal, i32(sig))
}

signal_code :: proc() -> int {
	value := intrinsics.atomic_load(&caught_signal)
	if value == 0 {
		return 0
	}

	if posix.Signal(value) == .SIGINT {
		return 130
	}
	return 143
}

stop_if_signaled :: proc() {
	code := signal_code()
	if code != 0 {
		finish(code)
	}
}

// os.exit skips defers, so every exit goes through here while the temp tree exists.
finish :: proc(code: int) -> ! {
	if child_pid > 0 {
		signal_child(.SIGTERM)
		signal_child(.SIGKILL)
		reap_child()
	}

	if work_dir != "" {
		dir := work_dir
		work_dir = ""
		_ = os.set_working_directory("/")
		if err := os.remove_all(dir); err != nil {
			fmt.eprintf("%s: %v\n", dir, err)
		}
	}
	os.exit(code)
}

say :: proc(format: string, args: ..any) {
	fmt.printf(format, ..args)
	_ = os.flush(os.stdout)
}

say_err :: proc(format: string, args: ..any) {
	fmt.eprintf(format, ..args)
	_ = os.flush(os.stderr)
}

concat :: proc(parts: ..string) -> string {
	value, err := strings.concatenate(parts)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	return value
}

join :: proc(parts: ..string) -> string {
	value, err := os.join_path(parts, context.allocator)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	return value
}

copy_string :: proc(value: string) -> string {
	cloned, err := strings.clone(value)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	return cloned
}

join_sep :: proc(words: []string, sep: string) -> string {
	value, err := strings.join(words, sep, context.allocator)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	return value
}

replace_all :: proc(s, old, new: string) -> string {
	value, _ := strings.replace_all(s, old, new)
	return value
}
