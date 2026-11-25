#+build linux, darwin, freebsd, openbsd, netbsd
package main

import "core:c"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sys/posix"

Suite :: struct {
	relative: string,
	private:  bool,
}

Staged :: struct {
	repository: string,
	shared:     string,
	wrapper:    string,
}

Escape :: struct {
	file:     string,
	resolved: string,
}

WRAPPER :: `if [[ "$*" == root && $# == 1 ]]; then printf '%s\n' "$staged_root"; exit; fi
args=()
for argument do
	case "$argument" in -collection:shared=*) ;; *) args+=("$argument") ;; esac
done
if [[ "${args[0]:-}" != version ]]; then args+=("-collection:shared=$staged_root/shared"); fi
exec "$compiler" "${args[@]}"
`

stage :: proc(library: string) -> Staged {
	repository := join(work_dir, "repository")
	copy_tree(root, repository)
	shared := join(work_dir, "shared")
	if err := os.make_directory_all(shared); err != nil {
		say_err("%s: %v\n", shared, err)
		finish(1)
	}
	force_symlink(join(repository, "src"), join(shared, library))
	// Internal tests copied into src #load ../tests/... . The compiler resolves
	// that path from the shared/<library> symlink, so ../tests is shared/tests.
	force_symlink(join(repository, "tests"), join(shared, "tests"))

	escapes := escaping_imports(join(repository, "src"), join(repository, "src"))
	more := escaping_imports(repository, join(repository, "tests"))
	append(&escapes, ..more[:])
	if len(escapes) > 0 {
		report_escapes(repository, escapes[:])
	}

	sdk := compiler_root()
	order := stage_dependencies(library, repository, shared, sdk)
	print_library(library, order[:])
	overlay_private(repository)
	link_sdk(sdk)
	wrapper := write_wrapper(compiler, work_dir)
	return {repository, shared, wrapper}
}

print_library :: proc(library: string, order: []string) {
	rest := " "
	if len(order) > 1 {
		rest = concat(" ", join_sep(order[1:], " "), " ")
	}
	say("Library %s from %s/src; dependencies from %s:%s\n", library, root, dependency_source, rest)
}

report_escapes :: proc(repository: string, escapes: []Escape) {
	prefix := concat(repository, "/")
	lines := make([dynamic]string, 0, len(escapes))
	for escape in escapes {
		file := replace_all(escape.file, prefix, "")
		resolved := replace_all(escape.resolved, prefix, "")
		append(&lines, concat(file, "\t", resolved))
	}
	say_err(
		"Relative imports leave the repository; use shared:<library> instead:\n%s\n",
		join_sep(lines[:], "\n"),
	)
	finish(2)
}

compiler_root :: proc() -> string {
	text, status := capture([]string{compiler, "root"})
	if status != 0 {
		finish(status)
	}
	sdk := strings.trim_space(text)
	if sdk == "" {
		say_err("odin root returned nothing\n")
		finish(1)
	}
	return sdk
}

stage_dependencies :: proc(library, repository, shared, sdk: string) -> [dynamic]string {
	repo := gather_shared({join(repository, "src"), join(repository, "tests")}, false)
	sdk_names := gather_shared({join(sdk, "core"), join(sdk, "vendor")}, true)
	pending: [dynamic]string
	append(&pending, ..repo[:])
	append(&pending, ..sdk_names[:])

	seen := make(map[string]bool)
	seen[library] = true
	order: [dynamic]string
	append(&order, library)

	for len(pending) > 0 {
		next: [dynamic]string
		for name in pending {
			stop_if_signaled()
			if name == "" || name in seen {
				continue
			}
			seen[name] = true
			append(&order, name)
			source := join(dependency_source, name)
			if !os.is_directory(source) {
				say_err("Missing dependency shared:%s in %s\n", name, dependency_source)
				finish(2)
			}
			dest := join(shared, name)
			copy_tree(source, dest)
			imported := gather_shared({dest}, false)
			append(&next, ..imported[:])
			for escape in escaping_imports(dest, dest) {
				if !strings.has_prefix(escape.resolved, concat(shared, "/")) {
					say_err("shared:%s imports outside the collection: %s\n", name, escape.resolved)
					finish(2)
				}
				top := escape.resolved[len(shared) + 1:]
				if slash := strings.index_byte(top, '/'); slash >= 0 {
					top = top[:slash]
				}
				append(&next, copy_string(top))
			}
		}
		pending = next
	}
	return order
}

link_sdk :: proc(sdk: string) {
	for name in ([]string{"base", "core", "vendor"}) {
		force_symlink(join(sdk, name), join(work_dir, name))
	}
}

write_wrapper :: proc(compiler_path, staged: string) -> string {
	body := concat(
		"#!/usr/bin/env bash\nset -euo pipefail\ncompiler=",
		bash_quote(compiler_path),
		"\nstaged_root=",
		bash_quote(staged),
		"\n",
		WRAPPER,
	)
	path := join(staged, "odin")
	if err := os.write_entire_file(path, body); err != nil {
		say_err("%s: %v\n", path, err)
		finish(1)
	}
	mode := os.Permissions_Read_All + os.Permissions_Execute_All + {.Write_User}
	if err := os.chmod(path, mode); err != nil {
		say_err("%s: %v\n", path, err)
		finish(1)
	}
	return path
}

bash_quote :: proc(value: string) -> string {
	if quote_safe(value) {
		return value
	}
	out: [dynamic]byte
	append(&out, '\'')
	for index := 0; index < len(value); index += 1 {
		if value[index] == '\'' {
			append(&out, '\'', '\\', '\'', '\'')
		} else {
			append(&out, value[index])
		}
	}
	append(&out, '\'')
	return string(out[:])
}

quote_safe :: proc(value: string) -> bool {
	if len(value) == 0 {
		return false
	}
	for index := 0; index < len(value); index += 1 {
		switch value[index] {
		case 'A' ..= 'Z', 'a' ..= 'z', '0' ..= '9', '/', '_', '.', ',', ':', '=', '@', '%', '+', '-':
		case:
			return false
		}
	}
	return true
}

library_name :: proc() -> string {
	if !os.exists(join(root, ".git")) {
		return copy_string(os.base(strings.trim_right(root, "/")))
	}
	text, status := capture([]string{"git", "-C", root, "rev-parse", "--git-common-dir"})
	if status != 0 {
		finish(status)
	}
	common := strings.trim_space(text)
	if !strings.has_prefix(common, "/") {
		common = join(root, common)
	}
	return copy_string(os.base(physical_path(os.dir(common))))
}

resolve_compiler :: proc(name: string) -> string {
	candidate := name
	if !strings.contains(name, "/") {
		if found, ok := lookup_executable(name); ok {
			candidate = found
		}
	}

	if !strings.has_prefix(candidate, "/") {
		cwd, err := os.get_working_directory(context.allocator)
		if err != nil {
			say_err("getcwd: %v\n", err)
			finish(1)
		}
		candidate = join(cwd, candidate)
	} else {
		candidate = clean_absolute(candidate)
	}

	if !os.is_directory(os.dir(candidate)) {
		say_err("cannot use compiler %s\n", name)
		finish(1)
	}
	return candidate
}

lookup_executable :: proc(name: string) -> (string, bool) {
	path_env := os.get_env("PATH", context.allocator)
	dirs, err := os.split_path_list(path_env, context.allocator)
	if err != nil {
		return "", false
	}
	for dir in dirs {
		candidate := join(dir, name)
		if executable(candidate) {
			return candidate, true
		}
	}
	return "", false
}

executable :: proc(path: string) -> bool {
	cpath, err := strings.clone_to_cstring(path, context.temp_allocator)
	if err != nil {
		return false
	}
	fd := posix.open(cpath, {.CLOEXEC, .EXEC})
	if fd == -1 {
		return false
	}
	posix.close(fd)
	return true
}

physical_path :: proc(path: string) -> string {
	cpath, err := strings.clone_to_cstring(path, context.temp_allocator)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	buf: [4096]byte
	resolved := posix.realpath(cpath, raw_data(buf[:]))
	if resolved == nil {
		say_err("%s: %s\n", path, string(posix.strerror()))
		finish(1)
	}
	return copy_string(string(resolved))
}

clean_absolute :: proc(path: string) -> string {
	cleaned, err := os.clean_path(path, context.allocator)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	return cleaned
}

discover_suites :: proc(tree: string) -> [dynamic]Suite {
	tests := join(tree, "tests")
	relatives: [dynamic]string
	if os.is_directory(tests) {
		walker := os.walker_create(tests)
		defer os.walker_destroy(&walker)
		for info in os.walker_walk(&walker) {
			if _, err := os.walker_error(&walker); err != nil {
				say_err("walk: %v\n", err)
				finish(1)
			}
			name := os.base(info.fullpath)
			if info.type == .Directory {
				if name == ".git" || name == "__pycache__" {
					os.walker_skip_dir(&walker)
				}
				continue
			}

			if info.type != .Regular || !strings.has_suffix(name, "_test.odin") {
				continue
			}
			relative := relative_to(tree, os.dir(info.fullpath))
			if relative != "" {
				append(&relatives, copy_string(relative))
			}
		}

		if _, err := os.walker_error(&walker); err != nil {
			say_err("walk: %v\n", err)
			finish(1)
		}
	}

	suites: [dynamic]Suite
	for relative in unique_sorted(relatives) {
		owner, private, ok := classify(relative)
		if !ok {
			continue
		}

		if selected != "all" && selected != owner {
			continue
		}

		if internal_only && !private {
			continue
		}
		append(&suites, Suite{relative, private})
	}
	return suites
}

classify :: proc(relative: string) -> (owner: string, private, ok: bool) {
	if relative == "tests/internal" {
		return ".", true, true
	}

	internal := "/internal"
	if strings.has_prefix(relative, "tests/") && strings.has_suffix(relative, internal) {
		start := len("tests/")
		end := len(relative) - len(internal)
		if end > start {
			return relative[start:end], true, true
		}
	}

	if relative == "tests" {
		return ".", false, true
	}

	if strings.has_prefix(relative, "tests/") {
		return relative[len("tests/"):], false, true
	}
	return "", false, false
}

suite_target :: proc(repository: string, suite: Suite) -> string {
	if !suite.private {
		return join(repository, suite.relative)
	}
	pkg := package_under_tests(suite.relative, "tests")
	if pkg == "" {
		return join(repository, "src")
	}
	return join(repository, "src", pkg)
}

overlay_private :: proc(repository: string) {
	tests := join(repository, "tests")
	if !os.is_directory(tests) {
		return
	}
	dirs := private_directories(tests)
	slice.sort(dirs[:])
	for directory in dirs {
		stop_if_signaled()
		pkg := package_under_tests(directory, tests)
		target := join(repository, "src")
		if pkg != "" {
			target = join(repository, "src", pkg)
		}

		if !os.is_directory(target) {
			prefix := concat(repository, "/")
			rel := directory
			if strings.has_prefix(directory, prefix) {
				rel = directory[len(prefix):]
			}
			say_err("Private tests %s have no package src/%s\n", rel, pkg)
			finish(2)
		}
		copy_odin_files(directory, target)
	}
}

private_directories :: proc(tests: string) -> [dynamic]string {
	dirs: [dynamic]string
	walker := os.walker_create(tests)
	defer os.walker_destroy(&walker)
	for info in os.walker_walk(&walker) {
		if _, err := os.walker_error(&walker); err != nil {
			say_err("walk: %v\n", err)
			finish(1)
		}

		if info.type != .Directory {
			continue
		}
		path := info.fullpath
		if path == concat(tests, "/internal") || nested_internal(tests, path) {
			append(&dirs, copy_string(path))
		}
	}
	return dirs
}

// macOS find -path treats * as matching slashes, so tests/*/internal is every
// nested internal directory, not only a single path component.
nested_internal :: proc(tests, path: string) -> bool {
	prefix := concat(tests, "/")
	if !strings.has_prefix(path, prefix) || !strings.has_suffix(path, "/internal") {
		return false
	}
	return len(path) > len(prefix) + len("internal")
}

package_under_tests :: proc(path, tests_prefix: string) -> string {
	rest := path
	marker := concat(tests_prefix, "/")
	if path == tests_prefix {
		rest = ""
	} else if strings.has_prefix(path, marker) {
		rest = path[len(tests_prefix):]
	}

	if strings.has_suffix(rest, "internal") {
		rest = rest[:len(rest) - len("internal")]
	}
	rest = strings.trim_left(rest, "/")
	rest = strings.trim_right(rest, "/")
	return rest
}

copy_odin_files :: proc(directory, target: string) {
	entries, err := os.read_all_directory_by_path(directory, context.allocator)
	if err != nil {
		say_err("%s: %v\n", directory, err)
		finish(1)
	}
	defer os.file_info_slice_delete(entries, context.allocator)

	for entry in entries {
		if !strings.has_suffix(entry.name, ".odin") || entry.type == .Directory {
			continue
		}

		if !os.is_file(entry.fullpath) {
			continue
		}
		dest := join(target, entry.name)
		if copy_err := os.copy_file(dest, entry.fullpath); copy_err != nil {
			say_err("%s: %v\n", dest, copy_err)
			finish(1)
		}
	}
}

copy_tree :: proc(source, target: string) {
	// Collection entries are symlinks. The walker reports the real path, so a
	// relative slice against the link path matches nothing and the copy is empty.
	source := physical_path(source)
	if err := os.make_directory_all(target); err != nil {
		say_err("%s: %v\n", target, err)
		finish(1)
	}

	if os.exists(join(source, ".git")) {
		copy_git(source, target)
		return
	}
	copy_plain(source, target)
}

copy_git :: proc(source, target: string) {
	text, status := capture([]string{
		"git", "-C", source, "ls-files", "--cached", "--others", "--exclude-standard", "-z",
	})
	if status != 0 {
		finish(status)
	}
	start := 0
	data := text
	for index := 0; index <= len(data); index += 1 {
		if index == len(data) || data[index] == 0 {
			if index > start {
				stop_if_signaled()
				copy_tracked(source, target, data[start:index])
			}
			start = index + 1
		}
	}
}

copy_tracked :: proc(source, target, relative: string) {
	if relative == "" {
		return
	}
	src := join(source, relative)
	if !os.is_file(src) {
		return
	}
	dest := join(target, relative)
	info, err := os.lstat(src, context.allocator)
	if err != nil {
		say_err("%s: %v\n", src, err)
		finish(1)
	}
	kind := info.type
	os.file_info_delete(info, context.allocator)
	if kind == .Symlink {
		copy_symlink(src, dest)
		return
	}
	copy_regular(src, dest)
}

copy_plain :: proc(source, target: string) {
	walker := os.walker_create(source)
	defer os.walker_destroy(&walker)
	for info in os.walker_walk(&walker) {
		if _, err := os.walker_error(&walker); err != nil {
			say_err("walk: %v\n", err)
			finish(1)
		}
		name := os.base(info.fullpath)
		if info.type == .Directory {
			if name == "__pycache__" || (len(name) > 0 && name[0] == '.') {
				os.walker_skip_dir(&walker)
			}
			continue
		}

		if info.type != .Regular || (len(name) > 0 && name[0] == '.') {
			continue
		}
		relative := relative_to(source, info.fullpath)
		if relative == "" {
			continue
		}
		stop_if_signaled()
		copy_regular(info.fullpath, join(target, relative))
	}
}

copy_regular :: proc(src, dest: string) {
	ensure_parent(dest)
	if err := os.copy_file(dest, src); err != nil {
		say_err("%s: %v\n", dest, err)
		finish(1)
	}
}

copy_symlink :: proc(src, dest: string) {
	ensure_parent(dest)
	text := read_link(src)
	old, old_err := strings.clone_to_cstring(text, context.temp_allocator)
	path, path_err := strings.clone_to_cstring(dest, context.temp_allocator)
	if old_err != nil || path_err != nil {
		say_err("out of memory\n")
		finish(1)
	}

	if posix.symlink(old, path) != .OK {
		say_err("symlink %s: %s\n", dest, string(posix.strerror()))
		finish(1)
	}
}

read_link :: proc(path: string) -> string {
	cpath, err := strings.clone_to_cstring(path, context.temp_allocator)
	if err != nil {
		say_err("out of memory\n")
		finish(1)
	}
	size := 128
	for size <= 1 << 20 {
		buf := make([]byte, size)
		n := posix.readlink(cpath, raw_data(buf), c.size_t(size))
		if n < 0 {
			say_err("%s: %s\n", path, string(posix.strerror()))
			finish(1)
		}

		if int(n) < size {
			return copy_string(string(buf[:n]))
		}
		size *= 2
	}
	say_err("%s: symbolic link is too long\n", path)
	finish(1)
}

ensure_parent :: proc(path: string) {
	parent := os.dir(path)
	if parent == "" || parent == "." {
		return
	}

	// make_directory_all reports Exist when the directory is already there.
	if os.is_directory(parent) {
		return
	}

	if err := os.make_directory_all(parent); err != nil {
		say_err("%s: %v\n", parent, err)
		finish(1)
	}
}

force_symlink :: proc(target, link_path: string) {
	old, old_err := strings.clone_to_cstring(target, context.temp_allocator)
	path, path_err := strings.clone_to_cstring(link_path, context.temp_allocator)
	if old_err != nil || path_err != nil {
		say_err("out of memory\n")
		finish(1)
	}

	if posix.symlink(old, path) != .OK {
		say_err("symlink %s: %s\n", link_path, string(posix.strerror()))
		finish(1)
	}
}

relative_to :: proc(root_path, full: string) -> string {
	if !strings.has_prefix(full, root_path) || len(full) <= len(root_path) || full[len(root_path)] != '/' {
		return ""
	}
	return full[len(root_path) + 1:]
}

gather_shared :: proc(roots: []string, skip_tests: bool) -> [dynamic]string {
	names: [dynamic]string
	for root_path in roots {
		if !os.is_directory(root_path) {
			continue
		}
		for file in odin_files(root_path, skip_tests) {
			stop_if_signaled()
			scan_shared_file(file, &names)
		}
	}
	return unique_sorted(names)
}

escaping_imports :: proc(tree, scan: string) -> [dynamic]Escape {
	escapes: [dynamic]Escape
	if !os.is_directory(scan) {
		return escapes
	}
	for file in odin_files(scan, false) {
		stop_if_signaled()
		scan_escape_file(file, tree, &escapes)
	}
	return escapes
}

odin_files :: proc(root_path: string, skip_tests: bool) -> [dynamic]string {
	files: [dynamic]string
	walker := os.walker_create(root_path)
	defer os.walker_destroy(&walker)
	for info in os.walker_walk(&walker) {
		if _, err := os.walker_error(&walker); err != nil {
			say_err("walk: %v\n", err)
			finish(1)
		}
		name := os.base(info.fullpath)
		if info.type == .Directory {
			if skip_tests && name == "tests" {
				os.walker_skip_dir(&walker)
			}
			continue
		}

		if info.type != .Regular || !strings.has_suffix(name, ".odin") {
			continue
		}

		if skip_tests && strings.has_suffix(name, "_test.odin") {
			continue
		}
		append(&files, copy_string(info.fullpath))
	}
	return files
}

scan_shared_file :: proc(path: string, names: ^[dynamic]string) {
	data, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		say_err("%s: %v\n", path, err)
		finish(1)
	}
	defer delete(data)
	text := string(data)
	start := 0
	for index := 0; index <= len(text); index += 1 {
		if index == len(text) || text[index] == '\n' {
			scan_shared_line(text[start:index], names)
			start = index + 1
		}
	}
}

scan_escape_file :: proc(path, tree: string, escapes: ^[dynamic]Escape) {
	data, err := os.read_entire_file(path, context.allocator)
	if err != nil {
		say_err("%s: %v\n", path, err)
		finish(1)
	}
	defer delete(data)
	text := string(data)
	start := 0
	for index := 0; index <= len(text); index += 1 {
		if index == len(text) || text[index] == '\n' {
			scan_escape_line(text[start:index], path, tree, escapes)
			start = index + 1
		}
	}
}

scan_shared_line :: proc(line: string, names: ^[dynamic]string) {
	key := "\"shared:"
	index := 0
	for index < len(line) {
		if !has_at(line, index, key) {
			index += 1
			continue
		}
		start := index + len(key)
		end := start
		for end < len(line) && is_ident(line[end]) {
			end += 1
		}

		if end > start {
			append(names, copy_string(line[start:end]))
		}
		index = end if end > index else index + 1
	}
}

scan_escape_line :: proc(line, file, tree: string, escapes: ^[dynamic]Escape) {
	index := 0
	for index < len(line) {
		if !has_at(line, index, "import") {
			index += 1
			continue
		}
		path, used, ok := relative_import(line[index + len("import"):])
		if !ok {
			index += 1
			continue
		}
		resolved := join(os.dir(file), path)
		if resolved != tree && !strings.has_prefix(resolved, concat(tree, "/")) {
			append(escapes, Escape{file, resolved})
		}
		index += len("import") + used
	}
}

relative_import :: proc(rest: string) -> (path: string, used: int, ok: bool) {
	spaces := count_spaces(rest)
	if spaces == 0 {
		return
	}
	after := rest[spaces:]
	if _, ident_len, has_ident := take_ident(after); has_ident {
		more := count_spaces(after[ident_len:])
		if more > 0 {
			if quoted, quoted_len, quoted_ok := take_quoted_rel(after[ident_len + more:]); quoted_ok {
				return quoted, spaces + ident_len + more + quoted_len, true
			}
		}
	}

	if quoted, quoted_len, quoted_ok := take_quoted_rel(after); quoted_ok {
		return quoted, spaces + quoted_len, true
	}
	return
}

take_quoted_rel :: proc(value: string) -> (path: string, used: int, ok: bool) {
	if len(value) < 4 || value[0] != '"' {
		return
	}
	body := value[1:]
	prefix: int
	if strings.has_prefix(body, "../") {
		prefix = 3
	} else if strings.has_prefix(body, "./") {
		prefix = 2
	} else {
		return
	}
	for index := prefix; index < len(body); index += 1 {
		if body[index] == '"' {
			return body[:index], index + 2, true
		}
	}
	return
}

take_ident :: proc(value: string) -> (text: string, used: int, ok: bool) {
	if len(value) == 0 || !is_ident(value[0]) {
		return
	}
	end := 1
	for end < len(value) && is_ident(value[end]) {
		end += 1
	}
	return value[:end], end, true
}

count_spaces :: proc(value: string) -> int {
	count := 0
	for count < len(value) && value[count] == ' ' {
		count += 1
	}
	return count
}

has_at :: proc(value: string, index: int, needle: string) -> bool {
	if index < 0 || index + len(needle) > len(value) {
		return false
	}
	return value[index:index + len(needle)] == needle
}

is_ident :: proc(char: byte) -> bool {
	switch char {
	case 'A' ..= 'Z', 'a' ..= 'z', '0' ..= '9', '_':
		return true
	}
	return false
}

unique_sorted :: proc(names: [dynamic]string) -> [dynamic]string {
	if len(names) == 0 {
		return names
	}
	slice.sort(names[:])
	out: [dynamic]string
	append(&out, names[0])
	for index := 1; index < len(names); index += 1 {
		if names[index] != names[index - 1] {
			append(&out, names[index])
		}
	}
	return out
}
