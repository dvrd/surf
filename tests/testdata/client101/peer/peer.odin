// HTTP/1 peer and TLS 1.3 record oracle for the client matrix. The handshake
// is tests/loopback. Manual records, partial ciphertext, and KeyUpdate use
// the application secrets from that handshake.
package main

import loopback "../../../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:thread"
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
held_alpn: string
alpn_buf: [32]u8

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	parse_flags()
	ensure_dir()
	if encrypted {
		dns := [1]string{"localhost"}
		raw := [4]u8{127, 0, 0, 1}
		ips := [1][]u8{raw[:]}
		root: [1024]u8
		if !loopback.mint_p256(child(root[:], "root.pem"), "localhost", dns[:], ips[:]) {
			fail("certificate")
		}
	}
	defer loopback.identity_clear()
	listener := listen()
	defer shutdown(listener)
	if mode == "progress" {
		run_progress(listener)
		return
	}
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
		if string(stream.conn.alpn[:stream.conn.alpn_n]) != "http/1.1" {
			fail("HTTP1 ALPN")
		}
	}
	head, got := read_request(&stream, 1 << 20)
	if !got {
		fail("first request")
	}
	if head.path != "/A" || head.method != "POST" || string(head.body) != "copied-body" {
		fail("caller inputs were not cloned")
	}
	copy_header, found := loopback.header_value(head.headers, "x-copy")
	host, host_found := loopback.header_value(head.headers, "host")
	if !found || copy_header != "original" || !host_found || !strings.has_prefix(host, "127.0.0.1:") {
		fail("caller inputs were not cloned")
	}
	body_n := len(head.body)
	method := "POST"
	path := "/A"
	copy_value := "original"
	if mode == "healthy" || mode == "fragmented" {
		if !wait_file("input-mutated", 10 * time.Second) {
			fail("fixture coordination timeout")
		}
	}
	response_buf: [160]u8
	response_n := copy(response_buf[:], "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: A\r\nX-Connection: 1\r\n\r\nA")
	manual := false
	if mode == "keyupdate-inline" {
		if !encrypted {
			fail("TLS required")
		}
		if !loopback.server_key_update(&stream.conn) {
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
		if !send(&stream, manual, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: B\r\nX-Connection: 1\r\n\r\nB") {
			fail("write")
		}
	} else {
		one: [1]u8
		n, _ := read_some(&stream, one[:])
		if n != 0 {
			fail("retired stream accepted B bytes")
		}
	}
	alpn := ""
	if encrypted {
		alpn = string(stream.conn.alpn[:stream.conn.alpn_n])
	}
	emit_result(&stream.conn, alpn, requests, body_n, method, copy_value, path, manual)
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

run_progress :: proc(held: net.TCP_Socket) {
	cheap := listen()
	defer shutdown(cheap)
	cheap_ep := bound(cheap)
	held_ep := bound(held)
	file: [64]u8
	text := fmt.bprintf(file[:], "127.0.0.1:%d", cheap_ep.port)
	if !write_marker("cheap.endpoint", text) {
		fail("cheap endpoint")
	}
	emit_line(fmt.bprintf(line_buf[:], "127.0.0.1:%d", held_ep.port))
	held_box := new(net.TCP_Socket)
	cheap_box := new(net.TCP_Socket)
	held_box^ = held
	cheap_box^ = cheap
	held_thread := thread.create_and_start_with_poly_data(held_box, serve_held)
	cheap_thread := thread.create_and_start_with_poly_data(cheap_box, serve_cheap)
	if held_thread == nil || cheap_thread == nil {
		fail("thread")
	}
	thread.destroy(held_thread)
	thread.destroy(cheap_thread)
	alpn := held_alpn
	fmt.fprintf(os.stdout, `{{"mode":"progress","tls":%t,"alpn":"`, encrypted)
	write_escaped(alpn)
	fmt.fprint(os.stdout, `","requests":2,"held_body":true,"cheap_before_release":true,"named_requests":0}` + "\n")
	_ = os.flush(os.stdout)
}

serve_held :: proc(box: ^net.TCP_Socket) {
	listener := box^
	free(box)
	fd, _, accept_error := net.accept_tcp(listener)
	if accept_error != nil {
		fail("held accept")
	}
	stream := Stream{fd = fd, encrypted = encrypted, conn = {fd = fd}}
	defer close_stream(&stream)
	arm(&stream)
	if encrypted {
		if !loopback.handshake(&stream.conn, .HTTP1) {
			fail("held handshake")
		}
		alpn := string(stream.conn.alpn[:stream.conn.alpn_n])
		if alpn != "http/1.1" {
			fail("held HTTP1 ALPN")
		}
		held_alpn = string(alpn_buf[:copy(alpn_buf[:], alpn)])
	}
	head, got := read_request(&stream, 1024)
	if !got || head.path != "/hold" {
		fail("hold route")
	}
	if !send(&stream, false, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Connection: held\r\n\r\nhe") {
		fail("held write")
	}
	if !write_marker("held", "body") {
		fail("held marker")
	}
	if !wait_file("release", 10 * time.Second) {
		fail("fixture coordination timeout")
	}
	_ = send(&stream, false, "ld")
}

serve_cheap :: proc(box: ^net.TCP_Socket) {
	listener := box^
	free(box)
	fd, _, accept_error := net.accept_tcp(listener)
	if accept_error != nil {
		fail("cheap accept")
	}
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 12 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 12 * time.Second)
	stream := Stream{fd = fd}
	head, got := read_request(&stream, 1024)
	if !got || head.path != "/cheap" {
		fail("cheap route")
	}
	marker: [1024]u8
	if os.exists(child(marker[:], "release")) {
		fail("cheap happened after held release")
	}
	if !write_raw(&stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Connection: cheap\r\n\r\nok") {
		fail("cheap write")
	}
}

emit_result :: proc(conn: ^loopback.Conn, alpn: string, requests, body_n: int, method, copy_header, path: string, manual: bool) {
	manual_report := manual || mode == "partial" || mode == "separate"
	fmt.fprintf(os.stdout, `{{"mode":"%s","tls":%t,"alpn":"`, mode, encrypted)
	write_escaped(alpn)
	fmt.fprintf(os.stdout, `","requests":%d,"first_body_bytes":%d,"first_method":"`, requests, body_n)
	write_escaped(method)
	fmt.fprint(os.stdout, `","first_copy_header":"`)
	write_escaped(copy_header)
	fmt.fprint(os.stdout, `","first_path":"`)
	write_escaped(path)
	fmt.fprintf(os.stdout, `","application_records":%d,"manual_rfc8446":%t,"key_updates":%d,"client_key_updates":%d,"manual_sequences":[`, conn.app_records, manual_report, conn.updates, conn.client_updates)
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

write_escaped :: proc(text: string) {
	for i in 0 ..< len(text) {
		c := text[i]
		if c == '"' || c == '\\' {
			pair := [2]u8{'\\', c}
			_, _ = os.write(os.stdout, pair[:])
		} else {
			_, _ = os.write(os.stdout, transmute([]u8)text[i:i + 1])
		}
	}
}

line_buf: [64]u8

fail :: proc(reason: string) {
	fmt.eprintf("client101: %s\n", reason)
	os.exit(1)
}
