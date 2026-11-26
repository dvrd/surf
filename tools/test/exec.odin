#+build linux, darwin, freebsd, openbsd, netbsd
package main

import "core:c"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

SUITE_TIMEOUT :: 300 * time.Second
TERM_GRACE :: 5 * time.Second
POLL :: 250 * time.Millisecond

// Darwin rejects setpgid after a successful exec, and odin test spawns the
// suite binary. The group has to exist before exec or a timeout cannot reach
// that child. process_wait also retries EINTR, so the suite is polled with
// waitpid and the signal flag is observed between polls.
spawn_grouped :: proc(command: []string, working_dir: string, log: string = "") {
	if len(command) == 0 {
		say_err("empty command\n")
		finish(1)
	}

	argv := make([]cstring, len(command) + 1)
	for part, index in command {
		text, err := strings.clone_to_cstring(part)
		if err != nil {
			say_err("out of memory\n")
			finish(1)
		}
		argv[index] = text
	}

	cwd: cstring
	if working_dir != "" {
		text, err := strings.clone_to_cstring(working_dir)
		if err != nil {
			say_err("out of memory\n")
			finish(1)
		}
		cwd = text
	}

	// The child takes the log as stdout and stderr, so both keep their order in one file.
	output := posix.FD(-1)
	if log != "" {
		path, err := strings.clone_to_cstring(log)
		if err != nil {
			say_err("out of memory\n")
			finish(1)
		}

		output = posix.open(path, {.WRONLY, .CREAT, .TRUNC, .CLOEXEC}, {.IRUSR, .IWUSR})
		delete(path)
		if output == -1 {
			say_err("%s: %s\n", log, string(posix.strerror()))
			finish(1)
		}
	}

	ends: [2]posix.FD
	if posix.pipe(&ends) != .OK {
		say_err("pipe: %s\n", string(posix.strerror()))
		finish(1)
	}

	if posix.fcntl(ends[0], .SETFD, i32(posix.FD_CLOEXEC)) == -1 ||
	   posix.fcntl(ends[1], .SETFD, i32(posix.FD_CLOEXEC)) == -1 {
		posix.close(ends[0])
		posix.close(ends[1])
		say_err("fcntl: %s\n", string(posix.strerror()))
		finish(1)
	}

	switch pid := posix.fork(); pid {
	case -1:
		posix.close(ends[0])
		posix.close(ends[1])
		say_err("fork: %s\n", string(posix.strerror()))
		finish(1)
	case 0:
		posix.close(ends[0])
		if posix.setpgid(0, 0) != .OK {
			child_fail(ends[1])
		}
		null := posix.open("/dev/null", {})
		if null == -1 {
			child_fail(ends[1])
		}

		if posix.dup2(null, posix.STDIN_FILENO) == -1 {
			child_fail(ends[1])
		}

		if null != posix.STDIN_FILENO {
			posix.close(null)
		}

		if output != -1 {
			if posix.dup2(output, posix.STDOUT_FILENO) == -1 || posix.dup2(output, posix.STDERR_FILENO) == -1 {
				child_fail(ends[1])
			}
		}

		if cwd != nil && posix.chdir(cwd) != .OK {
			child_fail(ends[1])
		}
		_ = posix.execve(argv[0], raw_data(argv), posix.environ)
		child_fail(ends[1])
	case:
		for text in argv[:len(command)] {
			delete(text)
		}
		delete(argv)
		if cwd != nil {
			delete(cwd)
		}

		if output != -1 {
			posix.close(output)
		}

		child_pid = pid
		_ = posix.setpgid(pid, pid)
		posix.close(ends[1])
		errno_byte: u8
		read_count := -1
		for {
			n := posix.read(ends[0], &errno_byte, 1)
			if n == -1 && posix.errno() == .EINTR {
				continue
			}
			read_count = int(n)
			break
		}
		posix.close(ends[0])
		if read_count < 0 {
			say_err("exec: %s\n", string(posix.strerror()))
			finish(1)
		}

		// EOF means the child exec'd and CLOEXEC closed the pipe.
		if read_count == 0 {
			return
		}
		reap_child()
		say_err("%s: %s\n", command[0], string(posix.strerror(posix.Errno(errno_byte))))
		finish(1)
	}
}

child_fail :: proc "contextless" (fd: posix.FD) -> ! {
	code := u8(posix.errno())
	posix.write(fd, &code, 1)
	posix._exit(126)
}

wait_grouped :: proc(relative: string) -> int {
	started := time.tick_now()
	term_sent := false
	term_at: time.Tick
	for {
		code := signal_code()
		if code != 0 {
			finish(code)
		}

		status: c.int
		w := posix.waitpid(child_pid, &status, {.NOHANG})
		if w == -1 {
			if posix.errno() == .EINTR {
				continue
			}
			say_err("wait: %s\n", string(posix.strerror()))
			finish(1)
		}

		if w == child_pid {
			child_pid = 0
			return status_code(status)
		}

		elapsed := time.tick_since(started)
		if !term_sent && elapsed >= SUITE_TIMEOUT {
			say_err("Test timeout: %s\n", relative)
			signal_child(.SIGTERM)
			term_sent = true
			term_at = time.tick_now()
		} else if term_sent && time.tick_since(term_at) >= TERM_GRACE {
			signal_child(.SIGKILL)
		}
		time.sleep(POLL)
	}
}

signal_child :: proc(sig: posix.Signal) {
	if child_pid <= 0 {
		return
	}

	if posix.killpg(child_pid, sig) != .OK {
		_ = posix.kill(child_pid, sig)
	}
}

reap_child :: proc() {
	if child_pid <= 0 {
		return
	}
	pid := child_pid
	status: c.int
	for {
		w := posix.waitpid(pid, &status, {})
		if w == -1 && posix.errno() == .EINTR {
			continue
		}
		break
	}
	child_pid = 0
}

status_code :: proc(status: c.int) -> int {
	if posix.WIFSIGNALED(status) {
		return 128 + int(posix.WTERMSIG(status))
	}

	if posix.WIFEXITED(status) {
		return int(posix.WEXITSTATUS(status))
	}
	return 1
}

capture :: proc(command: []string) -> (text: string, status: int) {
	read_end, write_end, pipe_err := os.pipe()
	if pipe_err != nil {
		say_err("pipe: %v\n", pipe_err)
		finish(1)
	}

	process, start_err := os.process_start({
		command = command,
		stdout = write_end,
		stderr = os.stderr,
	})
	os.close(write_end)
	if start_err != nil {
		os.close(read_end)
		say_err("%s: %v\n", command[0], start_err)
		finish(1)
	}

	data: [dynamic]u8
	buf: [4096]u8
	for {
		n, read_err := os.read(read_end, buf[:])
		if n > 0 {
			append(&data, ..buf[:n])
		}

		if read_err != nil {
			break
		}
	}
	os.close(read_end)

	state, wait_err := os.process_wait(process)
	if wait_err != nil {
		say_err("%s: %v\n", command[0], wait_err)
		finish(1)
	}

	status = state.exit_code
	if state.signal != 0 {
		status = 128 + state.signal
	}
	text = copy_string(strings.trim_right(string(data[:]), "\r\n"))
	delete(data)
	return
}
