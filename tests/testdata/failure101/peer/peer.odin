// Plain HTTP/1 peer for the allocation-failure matrix. One request per
// accepted connection. /A waits until dir/release exists, then answers 307
// Location: /dir/../final. /final answers 200 with the body "response" and a
// fixed X-Connection of 2. dir/done closes the listener; the process then
// prints one JSON object and exits.
package main

import loopback "../../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

Event :: struct {
	connection: int,
	path:       [256]u8,
	path_n:     int,
	body:       [1024]u8,
	body_n:     int,
}

Job :: struct {
	fd: net.TCP_Socket,
	id: int,
}

listener: net.TCP_Socket
listener_mu: sync.Mutex
listener_open: bool
directory: string
events: [4]Event
event_n: int
event_mu: sync.Mutex

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	directory = flag_dir()
	// make_directory_all rejects a path that already exists. MkdirAll does not.
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
	socket, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fail("listen")
	}
	listener = socket
	listener_open = true
	endpoint, endpoint_error := net.bound_endpoint(listener)
	if endpoint_error != nil {
		fail("bound")
	}
	emit_line(fmt.tprintf("127.0.0.1:%d", endpoint.port))
	if thread.create_and_start_with_poly_data(nil, watch, self_cleanup = true) == nil {
		fail("watch")
	}

	workers: [4]^thread.Thread
	worker_n := 0
	connections := 0
	for {
		fd, _, accept_error := net.accept_tcp(listener)
		if accept_error != nil {
			break
		}
		connections += 1
		if connections > 4 {
			net.close(fd)
			fail("connection bound")
		}
		_ = net.set_option(fd, .TCP_Nodelay, true)
		_ = net.set_option(fd, .Send_Timeout, 10 * time.Second)
		_ = net.set_option(fd, .Receive_Timeout, 10 * time.Second)
		job := new(Job)
		job.fd = fd
		job.id = connections
		worker := thread.create_and_start_with_poly_data(job, serve)
		if worker == nil {
			net.close(fd)
			free(job)
			fail("thread")
		}
		workers[worker_n] = worker
		worker_n += 1
	}
	for i in 0 ..< worker_n {
		thread.destroy(workers[i])
	}
	shutdown_listener()
	emit_json(connections)
}

flag_dir :: proc() -> string {
	args := os.args
	for i in 1 ..< len(args) {
		if args[i] == "-dir" && i + 1 < len(args) {
			return args[i + 1]
		}
	}
	fail("directory required")
	return ""
}

watch :: proc(_: rawptr) {
	deadline := time.time_add(time.now(), 15 * time.Second)
	name: [1024]u8
	path := child(name[:], "done")
	for time.diff(deadline, time.now()) <= 0 {
		if os.exists(path) {
			shutdown_listener()
			return
		}
		time.sleep(time.Millisecond)
	}
	shutdown_listener()
}

shutdown_listener :: proc() {
	sync.lock(&listener_mu)
	defer sync.unlock(&listener_mu)
	if listener_open {
		listener_open = false
		net.close(listener)
	}
}

serve :: proc(job: ^Job) {
	defer free(job)
	defer net.close(job.fd)
	buf: [2048]u8
	n := 0
	head: loopback.Head
	for {
		parsed, complete, overflow, ok := loopback.take_request(buf[:n], 1024)
		if !ok {
			if overflow {
				fail("body bound")
			}
			fail("request")
		}
		if complete {
			head = parsed
			break
		}
		if n == len(buf) {
			fail("request")
		}
		got, err := net.recv_tcp(job.fd, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
	if len(head.path) > len(events[0].path) || len(head.body) > len(events[0].body) {
		fail("body bound")
	}
	sync.lock(&event_mu)
	slot := &events[event_n]
	slot.connection = job.id
	slot.path_n = copy(slot.path[:], head.path)
	slot.body_n = copy(slot.body[:], head.body)
	event_n += 1
	sync.unlock(&event_mu)

	path := string(slot.path[:slot.path_n])
	if path == "/A" {
		if !write_file("A.received", "ready") {
			fail("marker")
		}
		if !wait_file("release", 8 * time.Second) {
			fail("release timeout")
		}
		write_all(job.fd, "HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 0\r\nLocation: /dir/../final\r\n\r\n")
	} else if path == "/final" {
		write_all(job.fd, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Connection: 2\r\nConnection: close\r\n\r\nresponse")
	} else {
		fail("unexpected request")
	}
}

write_all :: proc(fd: net.TCP_Socket, text: string) {
	rest := transmute([]u8)text
	for len(rest) > 0 {
		n, err := net.send_tcp(fd, rest)
		if n > 0 {
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
}

write_file :: proc(name, text: string) -> bool {
	buf: [1024]u8
	path := child(buf[:], name)
	return os.write_entire_file(path, text, FILE_PERM) == nil
}

wait_file :: proc(name: string, limit: time.Duration) -> bool {
	buf: [1024]u8
	path := child(buf[:], name)
	deadline := time.time_add(time.now(), limit)
	for time.diff(deadline, time.now()) <= 0 {
		if os.exists(path) {
			return true
		}
		time.sleep(time.Millisecond)
	}
	return false
}

child :: proc(buf: []u8, name: string) -> string {
	if len(directory) + 1 + len(name) > len(buf) {
		fail("path")
	}
	n := copy(buf, directory)
	buf[n] = '/'
	n += 1
	n += copy(buf[n:], name)
	return string(buf[:n])
}

emit_line :: proc(text: string) {
	_, _ = os.write(os.stdout, transmute([]u8)text)
	newline := [1]u8{'\n'}
	_, _ = os.write(os.stdout, newline[:])
	_ = os.flush(os.stdout)
}

emit_json :: proc(connections: int) {
	fmt.fprintf(os.stdout, `{{"connections":%d,"events":[`, connections)
	sync.lock(&event_mu)
	for i in 0 ..< event_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		ev := &events[i]
		fmt.fprintf(os.stdout, `{{"connection":%d,"path":"`, ev.connection)
		write_escaped(string(ev.path[:ev.path_n]))
		fmt.fprint(os.stdout, `","body":"`)
		write_escaped(string(ev.body[:ev.body_n]))
		fmt.fprint(os.stdout, `"}`)
	}
	sync.unlock(&event_mu)
	fmt.fprint(os.stdout, "]}\n")
	_ = os.flush(os.stdout)
}

write_escaped :: proc(text: string) {
	for i in 0 ..< len(text) {
		c := text[i]
		if c == '"' || c == '\\' {
			pair := [2]u8{'\\', c}
			_, _ = os.write(os.stdout, pair[:])
		} else if c < 0x20 {
			hex := [6]u8{'\\', 'u', '0', '0', HEX[c >> 4], HEX[c & 0x0f]}
			_, _ = os.write(os.stdout, hex[:])
		} else {
			_, _ = os.write(os.stdout, transmute([]u8)text[i:i + 1])
		}
	}
}

HEX := [16]u8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

fail :: proc(reason: string) {
	fmt.eprintf("failure101: %s\n", reason)
	os.exit(1)
}
