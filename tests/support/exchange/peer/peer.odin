// HTTP/1 peer and TLS 1.3 record oracle for the exchange matrix. The
// handshake is tests/support/loopback. Manual records and KeyUpdate use the
// application secrets from that handshake.
package main

import loopback "../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:sys/posix"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

Stream :: struct {
	fd:        net.TCP_Socket,
	conn:      loopback.Conn,
	encrypted: bool,
	pending:   [8192]u8,
	n:         int,
	closed:    bool,
}

directory: string
mode: string
encrypted: bool

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	parse_flags()
	ensure_dir()
	if encrypted {
		dns := [1]string{"localhost"}
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "localhost", dns[:], nil) {
			fail("certificate")
		}
	}
	defer loopback.identity_clear()
	listener := listen()
	defer shutdown(listener)
	endpoint := bound(listener)
	emit_line(fmt.bprintf(line_buf[:], "127.0.0.1:%d", endpoint.port))
	fd, _, accept_error := net.accept_tcp(listener)
	if accept_error != nil {
		fail("accept")
	}
	stream := Stream{fd = fd, encrypted = encrypted, conn = {fd = fd}}
	defer close_stream(&stream)
	arm(&stream)
	if encrypted {
		if !loopback.handshake(&stream.conn, .HTTP1) {
			fail(stream.conn.reason if stream.conn.reason != "" else "handshake")
		}
	}
	head, got := read_request(&stream, 1 << 20)
	if !got || head.path != "/A" {
		fail("first request is not A")
	}
	body_n := len(head.body)
	response_buf: [128]u8
	response_n := copy(response_buf[:], "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: A\r\n\r\nA")
	manual := false
	if mode == "keyupdate-inline" {
		if !encrypted || !loopback.server_key_update(&stream.conn) {
			fail("key update")
		}
		manual = true
	}
	if mode == "same-read" {
		response_n += copy(response_buf[response_n:], "OLD")
	}
	response := string(response_buf[:response_n])
	if mode == "fragmented" {
		for i in 0 ..< len(response) {
			if !send(&stream, manual, response[i:i + 1]) {
				fail("write")
			}
		}
	} else if !send(&stream, manual, response) {
		fail("write")
	}
	switch mode {
	case "separate", "partial", "keyupdate":
		if !wait_file("A.done", 10 * time.Second) {
			fail("fixture coordination timeout")
		}
		if mode == "keyupdate" {
			if !encrypted || !loopback.server_key_update(&stream.conn) {
				fail("key update")
			}
			manual = true
		} else if encrypted {
			wire: [64]u8
			n := loopback.seal_wire(&stream.conn, wire[:], transmute([]u8)string("OLD"), 23)
			if n < 3 {
				fail("record")
			}
			limit := n if mode == "separate" else 3
			if !loopback.write_full(stream.fd, wire[:limit]) {
				fail("write")
			}
		} else if !write_raw(&stream, "OLD") {
			fail("write")
		}
	case "close":
		if !wait_file("A.done", 10 * time.Second) {
			fail("fixture coordination timeout")
		}
		net.close(stream.fd)
		stream.closed = true
	}
	if !write_marker("staged", mode) {
		fail("staged")
	}
	requests := 1
	if mode == "healthy" || mode == "fragmented" || mode == "keyupdate-inline" {
		consume(&stream, head.consumed)
		second, again := read_request(&stream, 1 << 20)
		if !again || second.path != "/B" {
			fail("second request not B")
		}
		requests = 2
		if !send(&stream, manual, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: B\r\n\r\nB") {
			fail("write")
		}
	} else {
		one: [1]u8
		n, _ := read_some(&stream, one[:])
		if n != 0 {
			fail("retired stream accepted B bytes")
		}
	}
	emit_result(&stream.conn, requests, body_n, manual)
}

parse_flags :: proc() {
	mode = "healthy"
	for i in 1 ..< len(os.args) {
		arg := os.args[i]
		if arg == "-tls" {
			encrypted = true
		} else if arg == "-mode" && i + 1 < len(os.args) {
			mode = os.args[i + 1]
		} else if arg == "-dir" && i + 1 < len(os.args) {
			directory = os.args[i + 1]
		}
	}
	if directory == "" {
		fail("directory required")
	}
}

emit_result :: proc(conn: ^loopback.Conn, requests, body_n: int, manual: bool) {
	manual_report := manual || mode == "partial" || mode == "separate"
	fmt.fprintf(os.stdout, `{{"mode":"%s","tls":%t,"requests":%d,"first_body_bytes":%d,"application_records":%d,"manual_rfc8446":%t,"key_updates":%d,"client_key_updates":%d,"manual_sequences":[`, mode, encrypted, requests, body_n, conn.app_records, manual_report, conn.updates, conn.client_updates)
	for i in 0 ..< conn.manual_n {
		if i > 0 {
			fmt.fprint(os.stdout, ",")
		}
		fmt.fprintf(os.stdout, "%d", int(conn.manual_seq[i]))
	}
	fmt.fprint(os.stdout, "]}\n")
	_ = os.flush(os.stdout)
}

read_request :: proc(stream: ^Stream, body_cap: int) -> (head: loopback.Head, ok: bool) {
	for {
		parsed, complete, overflow, valid := loopback.take_request(stream.pending[:stream.n], body_cap)
		if !valid || overflow {
			return {}, false
		}
		if complete {
			return parsed, true
		}
		if stream.n == len(stream.pending) {
			return {}, false
		}
		got, err := read_some(stream, stream.pending[stream.n:])
		if got > 0 {
			stream.n += got
			continue
		}
		if err == .Interrupted {
			continue
		}
		return {}, false
	}
}

consume :: proc(stream: ^Stream, n: int) {
	copy(stream.pending[:], stream.pending[n:stream.n])
	stream.n -= n
}

send :: proc(stream: ^Stream, manual: bool, text: string) -> bool {
	if manual {
		wire: [1024]u8
		n := loopback.seal_wire(&stream.conn, wire[:], transmute([]u8)text, 23)
		if n < 0 {
			return false
		}
		return loopback.write_full(stream.fd, wire[:n])
	}
	if stream.encrypted {
		return loopback.tls_write(&stream.conn, transmute([]u8)text)
	}
	return write_raw(stream, text)
}

read_some :: proc(stream: ^Stream, dst: []u8) -> (int, net.TCP_Recv_Error) {
	if stream.encrypted {
		n, status := loopback.tls_read(&stream.conn, dst)
		if status == .Ok {
			return n, nil
		}
		if status == .Timeout {
			return 0, .Timeout
		}
		return 0, .Connection_Closed
	}
	return net.recv_tcp(stream.fd, dst)
}

write_raw :: proc(stream: ^Stream, text: string) -> bool {
	rest := transmute([]u8)text
	for len(rest) > 0 {
		n, err := net.send_tcp(stream.fd, rest)
		if n > 0 {
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return false
	}
	return true
}

arm :: proc(stream: ^Stream) {
	_ = net.set_option(stream.fd, .TCP_Nodelay, true)
	_ = net.set_option(stream.fd, .Send_Timeout, 12 * time.Second)
	_ = net.set_option(stream.fd, .Receive_Timeout, 12 * time.Second)
}

close_stream :: proc(stream: ^Stream) {
	loopback.conn_wipe(&stream.conn)
	if !stream.closed {
		net.close(stream.fd)
		stream.closed = true
	}
}

listen :: proc() -> net.TCP_Socket {
	socket, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	return socket
}

bound :: proc(socket: net.TCP_Socket) -> net.Endpoint {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return endpoint
}

shutdown :: proc(socket: net.TCP_Socket) {
	net.close(socket)
}

ensure_dir :: proc() {
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	if !os.is_dir(directory) {
		fail("directory")
	}
}

write_marker :: proc(name, text: string) -> bool {
	buf: [1024]u8
	return os.write_entire_file(child(buf[:], name), text, FILE_PERM) == nil
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

line_buf: [64]u8

fail :: proc(reason: string) {
	fmt.eprintf("exchange101: %s\n", reason)
	os.exit(1)
}
