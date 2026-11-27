// Shared process, build, and JSON helpers for the acceptance gates.
// The gates are one package main in the parent directory.
package support

import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

Gate :: struct {
	name:      string,
	compiler:  string,
	shared:    string,
	report:    string,
	sanitizer: string,
	root:      string,
}

begin :: proc(name: string) -> Gate {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	g := Gate {
		name      = name,
		sanitizer = "none",
	}
	for i in 1 ..< len(os.args) {
		arg := os.args[i]
		if i + 1 >= len(os.args) {
			break
		}
		next := os.args[i + 1]
		if arg == "--odin" {
			g.compiler = next
		} else if arg == "--shared" {
			g.shared = next
		} else if arg == "--report" {
			g.report = next
		} else if arg == "--sanitize" {
			g.sanitizer = next
		}
	}
	if g.compiler == "" || g.shared == "" || g.report == "" {
		fmt.eprintf(
			"%s: usage: --odin <compiler> --shared <collection> --report <path> [--sanitize address|thread|none]\n",
			name,
		)
		os.exit(2)
	}
	g.root = fmt.aprintf("/tmp/okami-%s-%d", name, posix.getpid())
	if err := os.make_directory_all(g.root, DIR_PERM); err != nil && err != .Exist {
		delete(g.root)
		g.root = ""
		fail(&g, "directory")
	}
	if !os.is_dir(g.root) {
		fail(&g, "directory")
	}
	return g
}

// os.exit skips defers, so callers that fail from main still need end.
end :: proc(g: ^Gate) {
	if g.root == "" {
		return
	}
	root := g.root
	g.root = ""
	_ = os.remove_all(root)
	delete(root)
}

fail :: proc(g: ^Gate, reason: string) {
	fmt.eprintf("%s: %s\n", g.name, reason)
	_ = os.flush(os.stderr)
	end(g)
	os.exit(1)
}

note :: proc(g: ^Gate, text: string) {
	fmt.eprintf("%s: %s\n", g.name, text)
	_ = os.flush(os.stderr)
}

path :: proc(g: ^Gate, name: string) -> string {
	return fmt.aprintf("%s/%s", g.root, name)
}

build :: proc(g: ^Gate, pkg, binary: string, sanitize: bool, extra: ..string) -> bool {
	note(g, fmt.tprintf("build %s", pkg))
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", g.shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(
		&command,
		g.compiler,
		"build",
		pkg,
		"-thread-count:1",
		"-warnings-as-errors",
		collection,
		out_flag,
	)
	sanitize_flag := ""
	if sanitize && g.sanitizer != "" && g.sanitizer != "none" {
		sanitize_flag = fmt.aprintf("-sanitize:%s", g.sanitizer)
		append(&command, sanitize_flag)
	}
	defer if sanitize_flag != "" {
		delete(sanitize_flag)
	}
	for flag in extra {
		append(&command, flag)
	}
	process, start_error := os.process_start(
		{command = command[:], stdout = os.stdout, stderr = os.stderr},
	)
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	if wait_error != nil {
		_ = os.process_kill(process)
		_, _ = os.process_wait(process, 2 * time.Second)
		return false
	}
	return state.exit_code == 0
}

passed :: proc(g: ^Gate, text: string) {
	if !ensure_parent(g.report) {
		fail(g, "report")
	}
	if os.write_entire_file(g.report, transmute([]u8)text, FILE_PERM) != nil {
		fail(g, "report")
	}
}

ensure_parent :: proc(path: string) -> bool {
	slash := strings.last_index(path, "/")
	if slash <= 0 {
		return true
	}
	parent := path[:slash]
	err := os.make_directory_all(parent, DIR_PERM)
	return err == nil || err == .Exist
}
