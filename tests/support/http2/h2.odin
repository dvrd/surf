package main

import loopback "../loopback"

import "base:runtime"
import "core:c"
import "core:fmt"
import "core:mem"
import "core:strings"
import "core:time"

@(extra_linker_flags = "-L/opt/homebrew/lib")
foreign import nghttp2 "system:nghttp2"

Frame_Hd :: struct {
	length:    c.size_t,
	stream_id: i32,
	type:      u8,
	flags:     u8,
	reserved:  u8,
}

NV :: struct {
	name:     [^]u8,
	value:    [^]u8,
	namelen:  c.size_t,
	valuelen: c.size_t,
	flags:    u8,
}

Settings_Entry :: struct {
	settings_id: i32,
	value:       u32,
}

Data_Read :: proc "c" (
	session: rawptr,
	stream_id: i32,
	buf: [^]u8,
	length: c.size_t,
	data_flags: ^u32,
	source: rawptr,
	user_data: rawptr,
) -> c.ptrdiff_t

Frame_Recv :: proc "c" (session: rawptr, frame: rawptr, user_data: rawptr) -> c.int
Header_Recv :: proc "c" (
	session: rawptr,
	frame: rawptr,
	name: [^]u8,
	namelen: c.size_t,
	value: [^]u8,
	valuelen: c.size_t,
	flags: u8,
	user_data: rawptr,
) -> c.int
Data_Recv :: proc "c" (
	session: rawptr,
	flags: u8,
	stream_id: i32,
	data: [^]u8,
	length: c.size_t,
	user_data: rawptr,
) -> c.int
Stream_Close :: proc "c" (
	session: rawptr,
	stream_id: i32,
	error_code: u32,
	user_data: rawptr,
) -> c.int

Data_Provider :: struct {
	source:        rawptr,
	read_callback: Data_Read,
}

@(default_calling_convention = "c")
foreign nghttp2 {
	nghttp2_session_callbacks_new :: proc(callbacks: ^rawptr) -> c.int ---
	nghttp2_session_callbacks_del :: proc(callbacks: rawptr) ---
	nghttp2_session_callbacks_set_on_frame_recv_callback :: proc(callbacks: rawptr, cb: Frame_Recv) ---
	nghttp2_session_callbacks_set_on_header_callback :: proc(callbacks: rawptr, cb: Header_Recv) ---
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback :: proc(callbacks: rawptr, cb: Data_Recv) ---
	nghttp2_session_callbacks_set_on_stream_close_callback :: proc(callbacks: rawptr, cb: Stream_Close) ---
	nghttp2_session_server_new2 :: proc(session: ^rawptr, callbacks: rawptr, user_data: rawptr, option: rawptr) -> c.int ---
	nghttp2_session_del :: proc(session: rawptr) ---
	nghttp2_session_mem_recv2 :: proc(session: rawptr, data: [^]u8, length: c.size_t) -> c.ptrdiff_t ---
	nghttp2_session_mem_send2 :: proc(session: rawptr, data: ^[^]u8) -> c.ptrdiff_t ---
	nghttp2_submit_settings :: proc(session: rawptr, flags: u8, iv: [^]Settings_Entry, niv: c.size_t) -> c.int ---
	nghttp2_submit_response2 :: proc(session: rawptr, stream_id: i32, nva: [^]NV, nvlen: c.size_t, provider: ^Data_Provider) -> c.int ---
	nghttp2_submit_rst_stream :: proc(session: rawptr, flags: u8, stream_id: i32, error_code: u32) -> c.int ---
}

DATA_FLAG_EOF :: u32(0x01)
HEADERS :: u8(0x01)
DATA :: u8(0x00)
END_STREAM :: u8(0x01)
INTERNAL_ERROR :: u32(0x02)

Stream :: struct {
	id:              i32,
	live:            bool,
	logged:          bool,
	responded:       bool,
	stall:           bool,
	stall_at:        time.Time,
	blob:            bool,
	method:          [16]u8,
	method_n:        int,
	path:            [512]u8,
	path_n:          int,
	authorization:   [256]u8,
	authorization_n: int,
	cookie:          [256]u8,
	cookie_n:        int,
	content_type:    [128]u8,
	content_type_n:  int,
	review:          [512]u8,
	review_n:        int,
	body:            [4096]u8,
	body_n:          int,
	reply:           [1024]u8,
	reply_n:         int,
	reply_at:        int,
	blob_n:          int,
	blob_sent:       int,
}

H2 :: struct {
	conn:    ^loopback.Conn,
	session: rawptr,
	streams: [32]Stream,
	waiting: bool,
}

serve_h2 :: proc(conn: ^loopback.Conn) {
	h := H2 {
		conn = conn,
	}
	callbacks: rawptr
	if nghttp2_session_callbacks_new(&callbacks) != 0 {
		return
	}
	nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame)
	nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header)
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data)
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_close)
	if nghttp2_session_server_new2(&h.session, callbacks, &h, nil) != 0 {
		nghttp2_session_callbacks_del(callbacks)
		return
	}
	nghttp2_session_callbacks_del(callbacks)
	defer nghttp2_session_del(h.session)
	push: [1]Settings_Entry
	push[0] = {
		settings_id = 0x02,
		value       = 0,
	}
	_ = nghttp2_submit_settings(h.session, 0, &push[0], 1)

	for {
		if !h2_send(&h) {
			return
		}
		if h2_release_stalls(&h) {
			continue
		}
		timeout := 60 * time.Second
		if h.waiting {
			timeout = 50 * time.Millisecond
		}
		loopback.set_recv_timeout(conn.fd, timeout)
		buf: [16 * 1024]u8
		n, status := loopback.tls_read(conn, buf[:])
		if n > 0 {
			if !h2_recv(&h, buf[:n]) {
				return
			}
			continue
		}
		if status == .Timeout {
			continue
		}
		return
	}
}

h2_send :: proc(h: ^H2) -> bool {
	for {
		data: [^]u8
		n := nghttp2_session_mem_send2(h.session, &data)
		if n < 0 {
			return false
		}
		if n == 0 {
			return true
		}
		if !loopback.tls_write(h.conn, mem.byte_slice(data, n)) {
			return false
		}
	}
}

h2_recv :: proc(h: ^H2, data: []u8) -> bool {
	off := 0
	for off < len(data) {
		remain := len(data) - off
		n := nghttp2_session_mem_recv2(h.session, &data[off], c.size_t(remain))
		if n < 0 {
			return false
		}
		if n == 0 {
			return false
		}
		off += int(n)
	}
	return true
}

h2_release_stalls :: proc(h: ^H2) -> bool {
	now := time.now()
	released := false
	waiting := false
	for &stream in h.streams {
		if !stream.live || !stream.stall || stream.responded {
			continue
		}
		if time.diff(stream.stall_at, now) >= 0 {
			h2_respond(h, &stream)
			released = true
		} else {
			waiting = true
		}
	}
	h.waiting = waiting
	return released
}

h2_find :: proc(h: ^H2, id: i32) -> ^Stream {
	for &stream in h.streams {
		if stream.live && stream.id == id {
			return &stream
		}
	}
	return nil
}

h2_open :: proc(h: ^H2, id: i32) -> ^Stream {
	if found := h2_find(h, id); found != nil {
		return found
	}
	for &stream in h.streams {
		if !stream.live {
			stream = Stream {
				id   = id,
				live = true,
			}
			return &stream
		}
	}
	return nil
}

h2_on_header :: proc "c" (
	session: rawptr,
	frame: rawptr,
	name: [^]u8,
	namelen: c.size_t,
	value: [^]u8,
	valuelen: c.size_t,
	flags: u8,
	user_data: rawptr,
) -> c.int {
	context = runtime.default_context()
	h := cast(^H2)user_data
	hd := cast(^Frame_Hd)frame
	if hd.stream_id == 0 {
		return 0
	}
	stream := h2_open(h, hd.stream_id)
	if stream == nil {
		return 0
	}
	field := string(mem.byte_slice(name, namelen))
	text := mem.byte_slice(value, valuelen)
	switch field {
	case ":method":
		stream.method_n = copy(stream.method[:], text)
	case ":path":
		stream.path_n = copy(stream.path[:], text)
	case "authorization":
		if stream.authorization_n == 0 {
			stream.authorization_n = copy(stream.authorization[:], text)
		}
	case "cookie":
		if stream.cookie_n == 0 {
			stream.cookie_n = copy(stream.cookie[:], text)
		}
	case "content-type":
		if stream.content_type_n == 0 {
			stream.content_type_n = copy(stream.content_type[:], text)
		}
	case "x-review":
		if stream.review_n > 0 && stream.review_n < len(stream.review) {
			stream.review[stream.review_n] = ','
			stream.review_n += 1
		}
		stream.review_n += copy(stream.review[stream.review_n:], text)
	}
	return 0
}

h2_on_data :: proc "c" (
	session: rawptr,
	flags: u8,
	stream_id: i32,
	data: [^]u8,
	length: c.size_t,
	user_data: rawptr,
) -> c.int {
	context = runtime.default_context()
	h := cast(^H2)user_data
	stream := h2_find(h, stream_id)
	if stream == nil || stream.body_n == len(stream.body) {
		return 0
	}
	room := len(stream.body) - stream.body_n
	n := min(room, int(length))
	copy(stream.body[stream.body_n:], mem.byte_slice(data, n))
	stream.body_n += n
	return 0
}

h2_on_frame :: proc "c" (session: rawptr, frame: rawptr, user_data: rawptr) -> c.int {
	context = runtime.default_context()
	h := cast(^H2)user_data
	hd := cast(^Frame_Hd)frame
	if hd.stream_id == 0 {
		return 0
	}
	stream := h2_find(h, hd.stream_id)
	if stream == nil {
		return 0
	}
	if hd.type == HEADERS && !stream.logged {
		stream.logged = true
		emit_request(h2_path(stream))
	}
	ended := hd.flags & END_STREAM != 0 && (hd.type == HEADERS || hd.type == DATA)
	if ended {
		h2_respond(h, stream)
	}
	return 0
}

h2_on_close :: proc "c" (
	session: rawptr,
	stream_id: i32,
	error_code: u32,
	user_data: rawptr,
) -> c.int {
	context = runtime.default_context()
	h := cast(^H2)user_data
	if stream := h2_find(h, stream_id); stream != nil {
		stream.live = false
	}
	return 0
}

h2_path :: proc(stream: ^Stream) -> string {
	path := string(stream.path[:stream.path_n])
	if at := strings.index(path, "?"); at >= 0 {
		return path[:at]
	}
	return path
}

h2_respond :: proc(h: ^H2, stream: ^Stream) {
	if stream.responded || !stream.live {
		return
	}
	path := h2_path(stream)
	query := ""
	full := string(stream.path[:stream.path_n])
	if at := strings.index(full, "?"); at >= 0 {
		query = full[at + 1:]
	}
	switch path {
	case "/reset":
		stream.responded = true
		_ = nghttp2_submit_rst_stream(h.session, 0, stream.id, INTERNAL_ERROR)
		return
	case "/stall", "/cancel":
		if stream.reply_n == 0 && stream.stall && time.diff(stream.stall_at, time.now()) < 0 {
			return
		}
		if stream.reply_n == 0 && !stream.stall {
			stream.stall = true
			stream.stall_at = time.time_add(time.now(), 8 * time.Second)
			h.waiting = true
			return
		}
		stream.reply_n = copy(stream.reply[:], "late")
	case "/blob":
		count, ok := blob_count(query)
		if !ok {
			stream.reply_n = copy(stream.reply[:], "bad")
			break
		}
		stream.blob = count > 0
		stream.blob_n = count
	case "/buffered-headers":
		written := fmt.bprintf(
			stream.reply[:],
			"HTTP/2.0|%s|%s|%s|%s|%s|%s",
			string(stream.method[:stream.method_n]),
			string(stream.authorization[:stream.authorization_n]),
			string(stream.cookie[:stream.cookie_n]),
			string(stream.content_type[:stream.content_type_n]),
			string(stream.review[:stream.review_n]),
			string(stream.body[:stream.body_n]),
		)
		stream.reply_n = len(written)
	case:
		stream.reply_n = copy(stream.reply[:], path)
	}
	stream.responded = true
	stream.stall = false
	h2_submit(h, stream)
}

h2_submit :: proc(h: ^H2, stream: ^Stream) {
	name := ":status"
	value := "200"
	if string(stream.reply[:stream.reply_n]) == "bad" {
		value = "400"
	}
	nv := NV {
		name     = cast([^]u8)raw_data(name),
		value    = cast([^]u8)raw_data(value),
		namelen  = c.size_t(len(name)),
		valuelen = c.size_t(len(value)),
	}
	provider: Data_Provider
	prd: ^Data_Provider
	if stream.blob || stream.reply_n > 0 {
		provider.read_callback = h2_read
		prd = &provider
	}
	_ = nghttp2_submit_response2(h.session, stream.id, &nv, 1, prd)
}

h2_read :: proc "c" (
	session: rawptr,
	stream_id: i32,
	buf: [^]u8,
	length: c.size_t,
	data_flags: ^u32,
	source: rawptr,
	user_data: rawptr,
) -> c.ptrdiff_t {
	context = runtime.default_context()
	h := cast(^H2)user_data
	stream := h2_find(h, stream_id)
	if stream == nil {
		return -902
	}
	if stream.blob {
		left := stream.blob_n - stream.blob_sent
		if left <= 0 {
			data_flags^ |= DATA_FLAG_EOF
			return 0
		}
		n := min(int(length), left)
		for i in 0 ..< n {
			buf[i] = 'a'
		}
		stream.blob_sent += n
		if stream.blob_sent == stream.blob_n {
			data_flags^ |= DATA_FLAG_EOF
		}
		return c.ptrdiff_t(n)
	}
	left := stream.reply_n - stream.reply_at
	n := min(int(length), left)
	if n > 0 {
		mem.copy(buf, &stream.reply[stream.reply_at], n)
	}
	stream.reply_at += n
	if stream.reply_at >= stream.reply_n {
		data_flags^ |= DATA_FLAG_EOF
	}
	return c.ptrdiff_t(n)
}
