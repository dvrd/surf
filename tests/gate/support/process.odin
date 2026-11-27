package support

import "core:os"
import "core:strings"
import "core:time"

Capture :: struct {
	file:  ^os.File,
	buf:   [dynamic]u8,
	eof:   bool,
	limit: int,
}

Child :: struct {
	process: os.Process,
	live:    bool,
	code:    int,
	out:     Capture,
	err:     Capture,
	out_r:   ^os.File,
	out_w:   ^os.File,
	err_r:   ^os.File,
	err_w:   ^os.File,
}

spawn :: proc(command: []string, env: []string = nil) -> (child: Child, ok: bool) {
	child.out.buf = make([dynamic]u8, 0, 4096)
	child.err.buf = make([dynamic]u8, 0, 1024)
	child.out.limit = 1 << 20
	child.err.limit = 1 << 20
	read_out, write_out, pipe_err := os.pipe()
	if pipe_err != nil {
		discard(&child)
		return
	}
	child.out_r = read_out
	child.out_w = write_out
	read_err, write_err, pipe_err2 := os.pipe()
	if pipe_err2 != nil {
		close_file(&child.out_r)
		close_file(&child.out_w)
		discard(&child)
		return
	}
	child.err_r = read_err
	child.err_w = write_err
	process, start_error := os.process_start(
		{command = command, env = env, stdout = child.out_w, stderr = child.err_w},
	)
	close_file(&child.out_w)
	close_file(&child.err_w)
	if start_error != nil {
		close_file(&child.out_r)
		close_file(&child.err_r)
		discard(&child)
		return
	}
	child.process = process
	child.live = true
	child.out.file = child.out_r
	child.err.file = child.err_r
	return child, true
}

stop :: proc(child: ^Child) {
	if child.live {
		_ = os.process_kill(child.process)
		_, _ = os.process_wait(child.process, 2 * time.Second)
		child.live = false
	}
	close_file(&child.out_r)
	close_file(&child.out_w)
	close_file(&child.err_r)
	close_file(&child.err_w)
	discard(child)
}

stdout :: proc(child: ^Child) -> string {
	return string(child.out.buf[:])
}

stderr :: proc(child: ^Child) -> string {
	return string(child.err.buf[:])
}

tail :: proc(child: ^Child) -> string {
	return clip(stderr(child))
}

clip :: proc(text: string) -> string {
	if len(text) <= 800 {
		return text
	}
	return text[len(text) - 800:]
}

first_line :: proc(child: ^Child, limit: time.Duration) -> (line: string, ok: bool) {
	deadline := time.time_add(time.now(), limit)
	for {
		pump(&child.out)
		pump(&child.err)
		if got, found := take_line(&child.out); found {
			return got, true
		}
		if !child.live {
			return "", false
		}
		state, wait_error := os.process_wait(child.process, 0)
		if wait_error == nil {
			child.live = false
			child.code = state.exit_code
			finish(&child.out, &child.err)
			if got, found := take_line(&child.out); found {
				return got, true
			}
			return "", false
		}
		if wait_error != .Timeout || time.diff(time.now(), deadline) <= 0 {
			return "", false
		}
		time.sleep(2 * time.Millisecond)
	}
}

reap :: proc(child: ^Child, limit: time.Duration) -> bool {
	if !child.live {
		finish(&child.out, &child.err)
		return true
	}
	deadline := time.time_add(time.now(), limit)
	for {
		pump(&child.out)
		pump(&child.err)
		state, wait_error := os.process_wait(child.process, 0)
		if wait_error == nil {
			child.live = false
			child.code = state.exit_code
			finish(&child.out, &child.err)
			return true
		}
		if wait_error != .Timeout || time.diff(time.now(), deadline) <= 0 {
			return false
		}
		time.sleep(2 * time.Millisecond)
	}
}

take_line :: proc(out: ^Capture) -> (line: string, ok: bool) {
	at := line_end(out.buf[:])
	if at < 0 {
		return "", false
	}
	n := at
	if n > 0 && out.buf[n - 1] == '\r' {
		n -= 1
	}
	return strings.clone(string(out.buf[:n])), true
}

pump :: proc(c: ^Capture) {
	if c.eof || c.file == nil {
		return
	}
	ready, err := os.pipe_has_data(c.file)
	if err == .Broken_Pipe {
		c.eof = true
		return
	}
	if err != nil || !ready {
		return
	}
	scratch: [1024]u8
	n, read_err := os.read(c.file, scratch[:])
	if n > 0 {
		limit := c.limit
		if limit <= 0 {
			limit = 1 << 20
		}
		if len(c.buf) < limit {
			room := limit - len(c.buf)
			if room > n {
				room = n
			}
			append(&c.buf, ..scratch[:room])
		}
		return
	}
	if read_err != nil || n == 0 {
		c.eof = true
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

line_end :: proc(buf: []u8) -> int {
	for i in 0 ..< len(buf) {
		if buf[i] == '\n' {
			return i
		}
	}
	return -1
}

close_file :: proc(file: ^^os.File) {
	if file^ == nil {
		return
	}
	_ = os.close(file^)
	file^ = nil
}

discard :: proc(child: ^Child) {
	delete(child.out.buf)
	delete(child.err.buf)
	child.out.buf = nil
	child.err.buf = nil
	child.out.file = nil
	child.err.file = nil
}
