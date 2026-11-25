// Loopback TLS peer for the surf async WebSocket client. RFC 6455 over TLS 1.3.
// The leaf is Ed25519, so the handshake is tests/support/loopback rather than the core
// server engine. This peer does not negotiate HTTP/2 or QUIC.
package main

import loopback "../loopback"
import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	if !loopback.load_identity() {
		fmt.eprintf("identity\n")
		os.exit(1)
	}
	defer loopback.identity_clear()

	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_error != nil {
		fmt.eprintf("listen\n")
		os.exit(1)
	}
	defer net.close(listener)
	endpoint, endpoint_error := net.bound_endpoint(listener)
	if endpoint_error != nil {
		fmt.eprintf("bound\n")
		os.exit(1)
	}
	fmt.println(endpoint.port)
	_ = os.flush(os.stdout)

	for i in 0 ..< 2 {
		fd, _, accept_error := net.accept_tcp(listener)
		if accept_error != nil {
			fmt.eprintf("accept\n")
			return
		}
		handle(fd, i == 0)
	}
}

handle :: proc(fd: net.TCP_Socket, echo: bool) {
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Send_Timeout, 15 * time.Second)
	loopback.set_recv_timeout(fd, 15 * time.Second)
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	if !loopback.handshake(&conn, .HTTP1_NoALPN) {
		return
	}
	if !echo {
		return
	}
	header_buf: [8192]u8
	header_n, header_ok := read_header(&conn, header_buf[:])
	if !header_ok {
		return
	}
	header := string(header_buf[:header_n])
	key := header_value(header, "Sec-WebSocket-Key")
	if key == "" {
		fmt.eprintf("missing key\n")
		return
	}
	protocol := ""
	if strings.contains(header, "Sec-WebSocket-Protocol: chat") {
		protocol = "chat"
	}
	accept := accept_key(key)
	defer delete(accept)
	if !write_switching(&conn, accept, protocol) {
		fmt.eprintf("101\n")
		return
	}
	payload: [4096]u8
	n, ok := read_text(&conn, payload[:])
	if !ok {
		fmt.eprintf("read\n")
		return
	}
	if !write_fragments(&conn, payload[:n]) {
		fmt.eprintf("echo\n")
		return
	}
	close_body := [2]u8{0x03, 0xe8}
	if !write_frame(&conn, true, 8, close_body[:]) {
		fmt.eprintf("close\n")
		return
	}
	discard: [256]u8
	for {
		got, status := loopback.tls_read(&conn, discard[:])
		if status != .Ok || got == 0 {
			return
		}
	}
}

read_header :: proc(conn: ^loopback.Conn, buf: []u8) -> (int, bool) {
	n := 0
	for n < len(buf) {
		got, status := loopback.tls_read(conn, buf[n:])
		if got > 0 {
			n += got
			text := string(buf[:n])
			if strings.contains(text, "\r\n\r\n") {
				return n, true
			}
		}
		if status != .Ok || got == 0 {
			fmt.eprintf("header\n")
			return 0, false
		}
	}
	fmt.eprintf("header\n")
	return 0, false
}

header_value :: proc(header, name: string) -> string {
	needle: [80]u8
	n := copy(needle[:], name)
	if n + 2 > len(needle) {
		return ""
	}
	n += copy(needle[n:], ": ")
	at := strings.index(header, string(needle[:n]))
	if at < 0 {
		return ""
	}
	rest := header[at + len(name) + 2:]
	end := strings.index(rest, "\r\n")
	if end < 0 {
		return ""
	}
	return strings.trim_space(rest[:end])
}

accept_key :: proc(key: string) -> string {
	raw: [160]u8
	n := copy(raw[:], key)
	n += copy(raw[n:], "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, raw[:n])
	digest: [sha1.DIGEST_SIZE]u8
	sha1.final(&ctx, digest[:])
	encoded, _ := base64.encode(digest[:])
	return encoded
}

write_switching :: proc(conn: ^loopback.Conn, accept, protocol: string) -> bool {
	buf: [384]u8
	text: string
	if protocol != "" {
		text = fmt.bprintf(
			buf[:],
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: %s\r\n\r\n",
			accept,
			protocol,
		)
	} else {
		text = fmt.bprintf(
			buf[:],
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			accept,
		)
	}
	return loopback.tls_write(conn, transmute([]u8)text)
}

read_text :: proc(conn: ^loopback.Conn, dst: []u8) -> (int, bool) {
	n := 0
	saw := false
	frame: [4096]u8
	for {
		opcode, count, fin, ok := read_frame(conn, frame[:])
		if !ok {
			return 0, false
		}
		switch opcode {
		case 1:
			if saw || n + count > len(dst) {
				return 0, false
			}
			saw = true
			n += copy(dst[n:], frame[:count])
		case 0:
			if !saw || n + count > len(dst) {
				return 0, false
			}
			n += copy(dst[n:], frame[:count])
		case 8:
			return 0, false
		case 9, 10:
			continue
		case:
			return 0, false
		}
		if saw && fin {
			return n, true
		}
	}
}

read_frame :: proc(conn: ^loopback.Conn, dst: []u8) -> (opcode: u8, n: int, fin, ok: bool) {
	hdr: [2]u8
	if !fill(conn, hdr[:]) {
		return
	}
	fin = hdr[0] & 0x80 != 0
	opcode = hdr[0] & 0x0f
	if hdr[1] & 0x80 == 0 {
		return
	}
	length := int(hdr[1] & 0x7f)
	if length == 126 {
		ext: [2]u8
		if !fill(conn, ext[:]) {
			return
		}
		length = int(ext[0]) << 8 | int(ext[1])
	} else if length == 127 {
		return
	}
	if length > len(dst) {
		return
	}
	mask: [4]u8
	if !fill(conn, mask[:]) || (length > 0 && !fill(conn, dst[:length])) {
		return
	}
	for i in 0 ..< length {
		dst[i] ~= mask[i % 4]
	}
	return opcode, length, fin, true
}

write_fragments :: proc(conn: ^loopback.Conn, payload: []u8) -> bool {
	if len(payload) == 0 {
		return write_frame(conn, true, 1, payload)
	}
	at := 0
	for at < len(payload) {
		step := min(4, len(payload) - at)
		opcode: u8 = 0
		if at == 0 {
			opcode = 1
		}
		fin := at + step == len(payload)
		if !write_frame(conn, fin, opcode, payload[at:][:step]) {
			return false
		}
		at += step
	}
	return true
}

write_frame :: proc(conn: ^loopback.Conn, fin: bool, opcode: u8, payload: []u8) -> bool {
	if len(payload) > 125 {
		return false
	}
	frame: [128]u8
	frame[0] = opcode
	if fin {
		frame[0] |= 0x80
	}
	frame[1] = u8(len(payload))
	copy(frame[2:], payload)
	for b in frame[:2 + len(payload)] {
		one := [1]u8{b}
		if !loopback.tls_write(conn, one[:]) {
			return false
		}
		time.sleep(time.Millisecond)
	}
	return true
}

fill :: proc(conn: ^loopback.Conn, dst: []u8) -> bool {
	at := 0
	for at < len(dst) {
		n, status := loopback.tls_read(conn, dst[at:])
		if n > 0 {
			at += n
			continue
		}
		if status != .Ok {
			return false
		}
		return false
	}
	return true
}
