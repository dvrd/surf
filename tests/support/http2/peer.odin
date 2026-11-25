// Loopback peer for the surf HTTP client. TLS 1.3 is tests/support/loopback: the leaf
// at ../credentials is Ed25519, and the core server engine only signs
// P-256 and RSA. HTTP/2 sessions are libnghttp2, in this process only.
package main

import loopback "../loopback"

import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

emit_mu: sync.Mutex


main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	mode := mode_arg()
	if !loopback.load_identity() {
		fail("identity")
	}
	defer loopback.identity_clear()

	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fail("listen")
	}
	defer net.close(listener)
	endpoint, endpoint_error := net.bound_endpoint(listener)
	if endpoint_error != nil {
		fail("bound")
	}
	emit_ready(endpoint.port)

	for {
		fd, _, accept_error := net.accept_tcp(listener)
		if accept_error != nil {
			continue
		}
		_ = net.set_option(fd, .TCP_Nodelay, true)
		_ = net.set_option(fd, .Send_Timeout, 30 * time.Second)
		loopback.set_recv_timeout(fd, 10 * time.Second)
		job := new(Job)
		job.fd = fd
		job.mode = mode
		if thread.create_and_start_with_poly_data(job, serve, self_cleanup = true) == nil {
			net.close(fd)
			free(job)
		}
	}
}

Job :: struct {
	fd:   net.TCP_Socket,
	mode: loopback.Mode,
}

serve :: proc(job: ^Job) {
	defer free(job)
	defer net.close(job.fd)
	conn := loopback.Conn{fd = job.fd}
	defer loopback.conn_wipe(&conn)
	if !loopback.handshake(&conn, job.mode) {
		if conn.reason != "" {
			fmt.eprintf("handshake: %s\n", conn.reason)
		}
		return
	}
	emit_conn(string(conn.alpn[:conn.alpn_n]))
	switch job.mode {
	case .H2:
		serve_h2(&conn)
	case .HTTP1, .HTTP1_NoALPN:
		serve_http1(&conn)
	case .GoAway:
		serve_goaway(&conn)
	}
}

mode_arg :: proc() -> loopback.Mode {
	args := os.args
	name := "h2"
	for i in 1 ..< len(args) {
		if args[i] == "-mode" && i + 1 < len(args) {
			name = args[i + 1]
		}
	}
	switch name {
	case "h2":
		return .H2
	case "http1":
		return .HTTP1
	case "http1-noalpn":
		return .HTTP1_NoALPN
	case "goaway":
		return .GoAway
	}
	fail("mode")
	return .H2
}


fail :: proc(reason: string) {
	buf: [160]u8
	emit(fmt.bprintf(buf[:], `{{"event":"error","error":"%s"}}`, reason))
	os.exit(1)
}

emit :: proc(text: string) {
	sync.lock(&emit_mu)
	_, _ = os.write(os.stdout, transmute([]u8)text)
	newline := [1]u8{'\n'}
	_, _ = os.write(os.stdout, newline[:])
	_ = os.flush(os.stdout)
	sync.unlock(&emit_mu)
}

emit_ready :: proc(port: int) {
	buf: [80]u8
	emit(fmt.bprintf(buf[:], `{{"event":"ready","port":%d}}`, port))
}

emit_conn :: proc(alpn: string) {
	buf: [80]u8
	emit(fmt.bprintf(buf[:], `{{"event":"conn","alpn":"%s"}}`, alpn))
}

emit_request :: proc(path: string) {
	buf: [600]u8
	emit(fmt.bprintf(buf[:], `{{"event":"request","path":"%s"}}`, path))
}

emit_goaway :: proc(headers: int) {
	buf: [80]u8
	emit(fmt.bprintf(buf[:], `{{"event":"goaway","headers":%d}}`, headers))
}


serve_http1 :: proc(conn: ^loopback.Conn) {
	pending: [8 * 1024]u8
	n := 0
	for {
		header_end := -1
		for {
			text := string(pending[:n])
			at := strings.index(text, "\r\n\r\n")
			if at >= 0 {
				header_end = at
				break
			}
			if n == len(pending) {
				return
			}
			got, status := loopback.tls_read(conn, pending[n:])
			if status != .Ok || got == 0 {
				return
			}
			n += got
		}
		head := string(pending[:header_end])
		rest := pending[header_end + 4:n]
		line, headers, _ := cut(head, "\r\n")
		method, request_rest, _ := cut(line, " ")
		target, _, _ := cut(request_rest, " ")
		path, query := split_target(target)
		body_n := content_length(headers)
		if body_n < 0 || body_n > 4096 {
			return
		}
		body: [4096]u8
		have := copy(body[:], rest)
		need := body_n
		if have > need {
			have = need
		}
		for have < need {
			got, status := loopback.tls_read(conn, body[have:need])
			if status != .Ok || got == 0 {
				return
			}
			have += got
		}
		extra := 0
		if len(rest) > body_n {
			extra = len(rest) - body_n
			copy(pending[:], rest[body_n:])
		}
		n = extra
		emit_request(path)
		switch path {
		case "/reset":
			return
		case "/stall", "/cancel":
			time.sleep(8 * time.Second)
			if !http1_write(conn, "late") {
				return
			}
		case "/blob":
			count, ok := blob_count(query)
			if !ok || !http1_blob(conn, count) {
				return
			}
		case "/buffered-headers":
			text := buffered_text("HTTP/1.1", method, headers, string(body[:body_n]))
			defer delete(text)
			if !http1_write(conn, text) {
				return
			}
		case:
			if !http1_write(conn, path) {
				return
			}
		}
	}
}

cut :: proc(s, sep: string) -> (string, string, bool) {
	at := strings.index(s, sep)
	if at < 0 {
		return s, "", false
	}
	return s[:at], s[at + len(sep):], true
}

split_target :: proc(target: string) -> (path, query: string) {
	at := strings.index(target, "?")
	if at < 0 {
		return target, ""
	}
	return target[:at], target[at + 1:]
}

content_length :: proc(headers: string) -> int {
	rest := headers
	for len(rest) > 0 {
		line: string
		line, rest, _ = cut(rest, "\r\n")
		name, value, ok := cut(line, ":")
		if !ok || !ascii_equal(name, "content-length") {
			continue
		}
		value = strings.trim_space(value)
		n, parsed := strconv.parse_int(value)
		if !parsed || n < 0 {
			return -1
		}
		return n
	}
	return 0
}

ascii_equal :: proc(got, want: string) -> bool {
	if len(got) != len(want) {
		return false
	}
	for b, i in got {
		c := b
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != rune(want[i]) {
			return false
		}
	}
	return true
}

header_get :: proc(headers, name: string) -> string {
	rest := headers
	for len(rest) > 0 {
		line: string
		line, rest, _ = cut(rest, "\r\n")
		field, value, ok := cut(line, ":")
		if ok && ascii_equal(field, name) {
			return strings.trim_space(value)
		}
	}
	return ""
}

header_join :: proc(headers, name: string) -> string {
	out: [512]u8
	n := 0
	rest := headers
	for len(rest) > 0 {
		line: string
		line, rest, _ = cut(rest, "\r\n")
		field, value, ok := cut(line, ":")
		if !ok || !ascii_equal(field, name) {
			continue
		}
		value = strings.trim_space(value)
		if n > 0 && n < len(out) {
			out[n] = ','
			n += 1
		}
		n += copy(out[n:], value)
	}
	return strings.clone(string(out[:n]))
}

blob_count :: proc(query: string) -> (int, bool) {
	rest := query
	for len(rest) > 0 {
		pair: string
		pair, rest, _ = cut(rest, "&")
		name, value, ok := cut(pair, "=")
		if !ok || name != "n" {
			continue
		}
		n, parsed := strconv.parse_int(value)
		if !parsed {
			return 0, true
		}
		if n < 0 || n > 1 << 20 {
			return 0, false
		}
		return n, true
	}
	return 0, true
}

http1_write :: proc(conn: ^loopback.Conn, body: string) -> bool {
	head: [128]u8
	written := fmt.bprintf(head[:], "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", len(body))
	return loopback.tls_write(conn, transmute([]u8)written) && loopback.tls_write(conn, transmute([]u8)body)
}

http1_blob :: proc(conn: ^loopback.Conn, count: int) -> bool {
	head: [128]u8
	written := fmt.bprintf(head[:], "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", count)
	if !loopback.tls_write(conn, transmute([]u8)written) {
		return false
	}
	chunk: [4096]u8
	for &b in chunk {
		b = 'a'
	}
	left := count
	for left > 0 {
		take := min(left, len(chunk))
		if !loopback.tls_write(conn, chunk[:take]) {
			return false
		}
		left -= take
	}
	return true
}

buffered_text :: proc(proto, method, headers, body: string) -> string {
	review := header_join(headers, "x-review")
	defer delete(review)
	return fmt.aprintf(
		"%s|%s|%s|%s|%s|%s|%s",
		proto,
		method,
		header_get(headers, "authorization"),
		header_get(headers, "cookie"),
		header_get(headers, "content-type"),
		review,
		body,
	)
}

serve_goaway :: proc(conn: ^loopback.Conn) {
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	buf: [64 * 1024]u8
	n := 0
	for strings.index(string(buf[:n]), preface) < 0 {
		if n == len(buf) {
			return
		}
		got, status := loopback.tls_read(conn, buf[n:])
		if status != .Ok || got == 0 {
			return
		}
		n += got
	}
	// Empty SETTINGS, SETTINGS ACK, GOAWAY with a zero last-stream and error.
	frames := [?]u8 {
		0, 0, 0, 4, 0, 0, 0, 0, 0,
		0, 0, 0, 4, 1, 0, 0, 0, 0,
		0, 0, 8, 7, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	if !loopback.tls_write(conn, frames[:]) {
		return
	}
	loopback.set_recv_timeout(conn.fd, time.Second)
	for {
		got, status := loopback.tls_read(conn, buf[n:])
		if got > 0 {
			n += got
			continue
		}
		if status == .Timeout || status == .Closed {
			break
		}
		break
	}
	at := strings.index(string(buf[:n]), preface)
	rest := buf[at + len(preface):n]
	headers := 0
	for len(rest) >= 9 {
		length := int(rest[0]) << 16 | int(rest[1]) << 8 | int(rest[2])
		if len(rest) < 9 + length {
			break
		}
		if rest[3] == 1 {
			headers += 1
		}
		rest = rest[9 + length:]
	}
	emit_goaway(headers)
}
