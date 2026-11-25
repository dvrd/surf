package main

import "../support/loopback"
import "support"
import "core:c"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

read_some :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if encrypted {
		n, status := loopback.tls_read(conn, dst)
		if status == .Ok {
			return n, nil
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		return 0, .Connection_Closed
	}
	return net.recv_tcp(fd, dst)
}

write_all :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, text: string) -> bool {
	if encrypted {
		return loopback.tls_write(conn, transmute([]u8)text)
	}
	return loopback.write_full(fd, transmute([]u8)text)
}

port_of :: proc(socket: net.TCP_Socket) -> int {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return int(endpoint.port)
}

join :: proc(dir, name: string) -> string {
	return fmt.aprintf("%s/%s", dir, name)
}

Capture :: struct {
	file: ^os.File,
	buf:  [dynamic]u8,
	eof:  bool,
}

Session :: struct {
	transport:     string,
	mode:          string,
	peer:          os.Process,
	fixture:       os.Process,
	peer_live:     bool,
	fixture_live:  bool,
	out_r:         ^os.File,
	out_w:         ^os.File,
	err_r:         ^os.File,
	err_w:         ^os.File,
	fix_r:         ^os.File,
	fix_w:         ^os.File,
	fix_err_r:     ^os.File,
	fix_err_w:     ^os.File,
	peer_out:      Capture,
	peer_err:      Capture,
	fixture_out:   Capture,
	fixture_err:   Capture,
}

session_cleanup :: proc(s: ^Session) {
	if s.peer_live {
		_ = os.process_kill(s.peer)
		_, _ = os.process_wait(s.peer, 2 * time.Second)
		s.peer_live = false
	}
	if s.fixture_live {
		_ = os.process_kill(s.fixture)
		_, _ = os.process_wait(s.fixture, 2 * time.Second)
		s.fixture_live = false
	}
	close_file(&s.out_r)
	close_file(&s.out_w)
	close_file(&s.err_r)
	close_file(&s.err_w)
	close_file(&s.fix_r)
	close_file(&s.fix_w)
	close_file(&s.fix_err_r)
	close_file(&s.fix_err_w)
}

wait_line :: proc(process: os.Process, out, err: ^Capture, live: ^bool, dest: []u8, limit: time.Duration) -> int {
	deadline := time.time_add(time.now(), limit)
	for {
		pump(out)
		pump(err)
		at := line_end(out.buf[:])
		if at >= 0 {
			n := at
			if n > 0 && out.buf[n - 1] == '\r' {
				n -= 1
			}
			if n > len(dest) {
				n = len(dest)
			}
			copy(dest, out.buf[:n])
			return n
		}
		_, wait_error := os.process_wait(process, 0)
		if wait_error == nil {
			live^ = false
			finish(out, err)
			return -1
		}
		if wait_error != .Timeout || time.diff(time.now(), deadline) <= 0 {
			return 0
		}
		time.sleep(2 * time.Millisecond)
	}
}

wait_proc :: proc(process: os.Process, out, err: ^Capture, live: ^bool, limit: time.Duration) -> (os.Process_State, bool) {
	deadline := time.time_add(time.now(), limit)
	for {
		pump(out)
		pump(err)
		state, wait_error := os.process_wait(process, 0)
		if wait_error == nil {
			live^ = false
			finish(out, err)
			return state, true
		}
		if wait_error != .Timeout || time.diff(time.now(), deadline) <= 0 {
			return {}, false
		}
		time.sleep(2 * time.Millisecond)
	}
}

finish :: proc(out, err: ^Capture) {
	for _ in 0 ..< 100 {
		before := len(out.buf) + len(err.buf)
		out_eof := out.eof
		err_eof := err.eof
		pump(out)
		pump(err)
		if out.eof && err.eof {
			return
		}
		if len(out.buf) + len(err.buf) == before && out.eof == out_eof && err.eof == err_eof {
			time.sleep(2 * time.Millisecond)
		}
	}
}

pump :: proc(c: ^Capture) {
	if c.eof || c.file == nil {
		return
	}
	ok, err := os.pipe_has_data(c.file)
	if err == .Broken_Pipe {
		c.eof = true
		return
	}
	if err != nil || !ok {
		return
	}
	scratch: [1024]u8
	n, read_err := os.read(c.file, scratch[:])
	if n > 0 {
		if len(c.buf) < 1 << 20 {
			append(&c.buf, ..scratch[:n])
		}
		return
	}
	if read_err != nil || n == 0 {
		c.eof = true
	}
}

line_end :: proc(buf: []u8) -> int {
	for i in 0 ..< len(buf) {
		if buf[i] == '\n' {
			return i
		}
	}
	return -1
}

field_at :: proc(text, key: string) -> (string, bool) {
	for i in 0 ..< len(text) {
		if text[i] != '"' || i + len(key) + 2 >= len(text) {
			continue
		}
		if text[i + 1:i + 1 + len(key)] != key || text[i + 1 + len(key)] != '"' {
			continue
		}
		j := i + len(key) + 2
		for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
			j += 1
		}
		if j >= len(text) || text[j] != ':' {
			continue
		}
		j += 1
		for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
			j += 1
		}
		if j >= len(text) {
			return "", false
		}
		if text[j] == '"' {
			start := j + 1
			k := start
			for k < len(text) && text[k] != '"' {
				k += 1
			}
			return text[start:k], true
		}
		start := j
		k := start
		for k < len(text) && text[k] != ',' && text[k] != '}' && text[k] != '\n' && text[k] != ' ' {
			k += 1
		}
		return text[start:k], k > start
	}
	return "", false
}

field_string :: proc(text, key: string) -> (string, bool) {
	return field_at(text, key)
}

field_bool :: proc(text, key: string) -> (bool, bool) {
	value, ok := field_at(text, key)
	if !ok || (value != "true" && value != "false") {
		return false, false
	}
	return value == "true", true
}

field_int :: proc(text, key: string) -> (int, bool) {
	value, ok := field_at(text, key)
	if !ok {
		return 0, false
	}
	return strconv.parse_int(value)
}

field_true :: proc(text, key: string) -> bool {
	value, ok := field_bool(text, key)
	return ok && value
}

build :: proc(compiler, shared, pkg, binary, sanitizer: string) -> bool {
	fmt.eprintf("%s: build %s\n", gate_label, pkg)
	_ = os.flush(os.stderr)
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, compiler, "build", pkg, "-thread-count:1", "-warnings-as-errors", collection, out_flag)
	sanitize := ""
	if sanitizer != "" && sanitizer != "none" {
		sanitize = fmt.aprintf("-sanitize:%s", sanitizer)
		append(&command, sanitize)
	}
	defer if sanitize != "" {
		delete(sanitize)
	}
	process, start_error := os.process_start({command = command[:], stdout = os.stdout, stderr = os.stderr})
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	return wait_error == nil && state.exit_code == 0
}

parse_args :: proc() -> (compiler, shared, report, sanitizer: string) {
	sanitizer = "none"
	for i in 1 ..< len(os.args) {
		arg := os.args[i]
		if i + 1 >= len(os.args) {
			break
		}
		next := os.args[i + 1]
		if arg == "--odin" {
			compiler = next
		} else if arg == "--shared" {
			shared = next
		} else if arg == "--report" {
			report = next
		} else if arg == "--sanitize" {
			sanitizer = next
		}
	}
	if compiler == "" || shared == "" || report == "" {
		fail("usage: --odin <compiler> --shared <collection> --report <path> [--sanitize address|none]")
	}
	return
}

close_file :: proc(file: ^^os.File) {
	if file^ == nil {
		return
	}
	_ = os.close(file^)
	file^ = nil
}

clip :: proc(text: string) -> string {
	if len(text) <= 800 {
		return text
	}
	return text[len(text) - 800:]
}

Job :: struct {
	listener:  net.TCP_Socket,
	encrypted: bool,
}

Conn :: struct {
	fd:        net.TCP_Socket,
	encrypted: bool,
}

plain_thread: ^thread.Thread
secure_thread: ^thread.Thread

document :: proc(text: string) -> (string, bool) {
	start := -1
	for i in 0 ..< len(text) {
		if text[i] == '{' {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	depth := 0
	in_string := false
	escape := false
	for i in start ..< len(text) {
		c := text[i]
		if in_string {
			if escape {
				escape = false
				continue
			}
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				in_string = false
			}
			continue
		}
		if c == '"' {
			in_string = true
			continue
		}
		if c == '{' {
			depth += 1
		} else if c == '}' {
			depth -= 1
			if depth == 0 {
				return text[start:i + 1], true
			}
		}
	}
	return "", false
}

reserve_refused :: proc() -> posix.FD {
	fd := posix.socket(.INET, .STREAM)
	if fd < 0 {
		fail("reserve")
	}
	addr: posix.sockaddr_in
	addr.sin_len = c.uint8_t(size_of(addr))
	addr.sin_family = .INET
	addr.sin_port = 0
	addr.sin_addr.s_addr = 0x7f000001
	if posix.bind(fd, (^posix.sockaddr)(&addr), posix.socklen_t(size_of(addr))) != .OK {
		posix.close(fd)
		fail("reserve bind")
	}
	return fd
}

refused_port_of :: proc(fd: posix.FD) -> int {
	addr: posix.sockaddr_in
	n := posix.socklen_t(size_of(addr))
	if posix.getsockname(fd, (^posix.sockaddr)(&addr), &n) != .OK {
		fail("reserve name")
	}
	return int(addr.sin_port)
}

hostname :: proc(host: string) -> string {
	if cut := strings.index(host, ":"); cut >= 0 {
		return host[:cut]
	}
	return host
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

