// Buffered adapter against an in-process HTTP/1 peer. TLS is 1.3 only;
// tests/support/loopback does not serve TLS 1.2, so that legacy cell is omitted.

package main

import "../support/loopback"
import "support"
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

compatibility_Wire :: enum {
	Required,
	Forbidden,
	Optional,
}

Payload :: enum {
	Standard,
	Empty,
	Exact,
	Oversize,
}

Request :: struct {
	name:      string,
	method:    string,
	target:    string,
	body:      string,
	file:      bool,
	size:      int,
	timeout:   int,
	encrypted: bool,
	ca:        string,
	custom_ca: bool,
	headers:   []string,
	wire:      compatibility_Wire,
}

compatibility_Record :: struct {
	method:  string,
	target:  string,
	secure:  bool,
	headers: [dynamic]string,
	body:    [dynamic]u8,
}

Hit :: struct {
	present: bool,
	method:  string,
	target:  string,
	secure:  bool,
	headers: [dynamic]string,
	body:    [dynamic]u8,
}

PROXY_KEYS :: [?]string{
	"http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy",
}

plain_job: Job
secure_job: Job
listeners_open: bool
plain_port: int
secure_port: int
cert_path: string
body_path: string
handlers: int
cells: int
server_error: string
state_mu: sync.Mutex
records: [dynamic]compatibility_Record

run_compatibility :: proc() {
	gate_label = "compatibility"

	g := support.begin("compatibility")
	defer support.end(&g)
	defer free_records()
	defer loopback.identity_clear()
	defer stop_servers()
	cert_path = support.path(&g, "ca.pem")
	defer delete(cert_path)
	body_path = support.path(&g, "body")
	defer delete(body_path)
	missing_path := support.path(&g, "missing.pem")
	defer delete(missing_path)
	if os.write_entire_file(body_path, transmute([]u8)string("file-extra"), support.FILE_PERM) != nil {
		abort(&g, "body file")
	}
	dns := [1]string{"localhost"}
	raw := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{raw[:]}
	if !loopback.mint_p256(cert_path, "localhost", dns[:], ips[:]) {
		abort(&g, "certificate")
	}
	binary := support.path(&g, "fixture")
	defer delete(binary)
	if !support.build(&g, "tests/support/compatibility", binary, true) {
		abort(&g, "fixture build")
	}
	if !start_servers() {
		abort(&g, "listen")
	}
	env := proxy_env()
	if env == nil {
		abort(&g, "environment")
	}
	defer {
		for item in env {
			delete(item)
		}
		delete(env)
	}
	for method in ([?]string{"GET", "get", "POST", "PUT", "DELETE", "PATCH", "PROPFIND", "HEAD"}) {
		req := base_request(fmt.tprintf("method-%s", method), method)
		must(&g, binary, env[:], req)
	}
	for method in ([?]string{"PUT", "POST", "DELETE", "PROPFIND"}) {
		req := base_request(fmt.tprintf("file-%s", method), method)
		req.file = true
		must(&g, binary, env[:], req)
	}
	zero := base_request("file-zero", "PUT")
	zero.file = true
	zero.size = 0
	must(&g, binary, env[:], zero)
	short := base_request("file-short", "PUT")
	short.file = true
	short.size = 20
	must(&g, binary, env[:], short)
	{
		headers := [?]string{
			"Host: override.test", "X-Duplicate: one", "X-Duplicate: two",
			"Accept:", "X-Suppress:", "X-Empty;", "bare",
		}
		req := base_request("headers", "GET")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	{
		headers := [?]string{"Host:"}
		req := base_request("host-suppress", "POST")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	{
		headers := [?]string{"Host: first.test", "Host: second.test"}
		req := base_request("host-duplicate", "POST")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	{
		headers := [?]string{"Content-Type:"}
		req := base_request("type-suppress", "POST")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	{
		headers := [?]string{"Content-Type;"}
		req := base_request("type-empty", "POST")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	{
		headers := [?]string{"Content-Length: 4"}
		req := base_request("length-override", "POST")
		req.headers = headers[:]
		must(&g, binary, env[:], req)
	}
	for method in ([?]string{"PUT", "POST"}) {
		req := base_request(fmt.tprintf("empty-%s", method), method)
		req.body = "empty"
		must(&g, binary, env[:], req)
	}
	for target in ([?]string{"/a/../b/%2f?q=%2B&empty=", "/a/./b//c", "/a/./b//c#fragment", "?query=only"}) {
		req := base_request(fmt.tprintf("path-%s", target), "GET")
		req.target = target
		if strings.contains(target, "#fragment") {
			req.wire = .Optional
		}
		must(&g, binary, env[:], req)
	}
	for target in ([?]string{
		"/exact", "/oversize", "/chunked", "/eof", "/empty", "/status",
		"/truncated", "/redirect", "/reset", "/malformed", "/slow", "/head-wait",
	}) {
		method := "POST"
		if target == "/head-wait" {
			method = "HEAD"
		}
		req := base_request(fmt.tprintf("response-%s", target), method)
		req.target = target
		if target == "/slow" || target == "/head-wait" {
			req.timeout = 100
		}
		must(&g, binary, env[:], req)
	}
	tls_case := base_request("tls-1.3", "GET")
	tls_case.encrypted = true
	must(&g, binary, env[:], tls_case)
	missing := base_request("ca-missing", "GET")
	missing.encrypted = true
	missing.custom_ca = true
	missing.ca = missing_path
	missing.wire = .Forbidden
	must(&g, binary, env[:], missing)
	malformed := base_request("ca-malformed", "GET")
	malformed.encrypted = true
	malformed.custom_ca = true
	malformed.ca = body_path
	malformed.wire = .Forbidden
	must(&g, binary, env[:], malformed)
	if server_error != "" {
		abort(&g, server_error)
	}
	if cells != 41 {
		abort(&g, "matrix")
	}
	text := fmt.aprintf("{{\"passed\":true,\"cells\":%d}}\n", cells)
	defer delete(text)
	support.passed(&g, text)
	fmt.println(cells, "compatibility cells passed")
}

must :: proc(g: ^support.Gate, binary: string, env: []string, req: Request) {
	if reason := run_case(g, binary, env, req); reason != "" {
		abort(g, fmt.tprintf("%s: %s", req.name, reason))
	}
	cells += 1
}

run_case :: proc(g: ^support.Gate, binary: string, env: []string, req: Request) -> string {
	support.note(g, req.name)
	native, hit, reason := execute(binary, env, req)
	defer json.destroy_value(native)
	if reason != "" {
		return reason
	}
	if specific := expect_case(req, native, hit); specific != "" {
		return specific
	}
	return general(native, hit)
}

execute :: proc(binary: string, env: []string, req: Request) -> (native: json.Value, hit: Hit, reason: string) {
	scheme := "http"
	port := plain_port
	ca := ""
	if req.encrypted {
		scheme = "https"
		port = secure_port
		ca = cert_path
		if req.custom_ca {
			ca = req.ca
		}
	}
	url := fmt.aprintf("%s://127.0.0.1:%d%s", scheme, port, req.target)
	defer delete(url)
	size_text := fmt.aprintf("%d", req.size)
	defer delete(size_text)
	timeout_text := fmt.aprintf("%d", req.timeout)
	defer delete(timeout_text)
	file_arg := "-"
	if req.file {
		file_arg = body_path
	}
	command := make([dynamic]string)
	defer delete(command)
	append(&command, binary, req.method, url, ca, file_arg, size_text, timeout_text, req.body, scheme)
	for header in req.headers {
		append(&command, header)
	}
	before := record_count()
	child, started := support.spawn(command[:], env)
	defer support.stop(&child)
	if !started {
		return {}, {}, "fixture start"
	}
	if !support.reap(&child, 8 * time.Second) || child.code != 0 {
		fmt.eprintf("fixture: %s\n", support.tail(&child))
		return {}, {}, "fixture"
	}
	if strings.contains(support.stderr(&child), "Sanitizer") {
		return {}, {}, "sanitizer"
	}
	parsed, parsed_ok := support.only(support.stdout(&child))
	if !parsed_ok {
		return {}, {}, "json"
	}
	if req.wire == .Required {
		deadline := time.time_add(time.now(), 200 * time.Millisecond)
		for record_count() == before && time.diff(time.now(), deadline) > 0 {
			time.sleep(2 * time.Millisecond)
		}
	}
	added, got := snapshot(before)
	if added < 0 || added > 1 {
		json.destroy_value(parsed)
		return {}, {}, "wire"
	}
	if req.wire == .Required && added != 1 {
		json.destroy_value(parsed)
		return {}, {}, "wire"
	}
	if req.wire == .Forbidden && added != 0 {
		json.destroy_value(parsed)
		return {}, {}, "wire"
	}
	return parsed, got, ""
}

expect_case :: proc(req: Request, native: json.Value, hit: Hit) -> string {
	if strings.has_prefix(req.name, "method-") {
		want := ""
		if req.method == "PUT" || req.method == "POST" {
			want = "body"
		}
		if !support.is_true(native, "transport_ok") || !hit.present || hit.method != req.method || !body_is(hit.body, want) {
			return "method"
		}
	}
	if strings.has_prefix(req.name, "file-") && req.name != "file-zero" && req.name != "file-short" {
		if !support.is_true(native, "transport_ok") || !support.eq_int(native, "file_position", 4) || !hit.present || !body_is(hit.body, "file") {
			return "file"
		}
	}
	if req.name == "file-zero" {
		if !support.is_true(native, "transport_ok") || !support.eq_int(native, "file_position", 0) || !hit.present || len(hit.body) != 0 {
			return "file zero"
		}
	}
	if req.name == "file-short" {
		if support.is_true(native, "transport_ok") || !support.eq_int(native, "file_position", 10) {
			return "file short"
		}
		if !support.eq_string(native, "phase", "Write") || !support.eq_string(native, "effect", "Unknown") {
			return "file short"
		}
	}
	if req.name == "headers" {
		want := [?]string{"Host: override.test", "X-Duplicate: one", "X-Duplicate: two", "X-Empty:"}
		if !hit.present || !headers_match(hit.headers, want[:]) {
			return "headers"
		}
	}
	if strings.has_prefix(req.name, "response-") {
		return expect_response(req, native)
	}
	if req.name == "tls-1.3" {
		if !support.is_true(native, "transport_ok") || !support.eq_int(native, "status", 200) || !hit.present || !hit.secure {
			return "tls"
		}
	}
	if strings.has_prefix(req.name, "ca-") {
		if support.is_true(native, "transport_ok") || hit.present {
			return "ca"
		}
		if !support.eq_string(native, "phase", "TLS") || !support.eq_string(native, "effect", "Not_Sent") {
			return "ca"
		}
	}
	return ""
}

expect_response :: proc(req: Request, native: json.Value) -> string {
	ok := false
	status := 0
	length := 0
	switch req.target {
	case "/exact":
		ok, status, length = true, 200, 65536
	case "/oversize":
		ok, status, length = false, 200, 0
	case "/chunked":
		ok, status, length = true, 200, 4
	case "/eof":
		ok, status, length = true, 200, 4
	case "/empty":
		ok, status, length = true, 200, 0
	case "/status":
		ok, status, length = true, 503, 4
	case "/truncated":
		ok, status, length = false, 503, 0
	case "/redirect":
		ok, status, length = true, 307, 0
	case "/reset", "/malformed", "/slow":
		ok, status, length = false, 0, 0
	case "/head-wait":
		ok, status, length = false, 200, 0
	case:
		return "response"
	}
	transport := support.is_true(native, "transport_ok")
	if transport != ok || !support.eq_int(native, "status", status) || !support.eq_int(native, "length", length) {
		return "response"
	}
	if !transport {
		got, got_ok := support.int_field(native, "status")
		if got_ok && got != 0 {
			if !support.eq_string(native, "effect", "Response_Received") || !support.eq_int(native, "error_status", got) {
				return "effect"
			}
		}
	}
	if req.target == "/slow" || req.target == "/head-wait" {
		elapsed, elapsed_ok := support.f64_field(native, "elapsed_ms")
		if !support.eq_string(native, "phase", "Deadline") || !elapsed_ok || elapsed < 50 || elapsed >= 1000 {
			return "deadline"
		}
	}
	return ""
}

general :: proc(native: json.Value, hit: Hit) -> string {
	if !support.is_true(native, "all_r") {
		return "all_r"
	}
	if support.is_true(native, "transport_ok") {
		status, status_ok := support.int_field(native, "status")
		if !support.eq_int(native, "provider_code", 0) || !support.eq_string(native, "kind", "None") || !status_ok {
			return "success"
		}
		if status >= 200 && status < 300 {
			if !support.is_true(native, "ok") {
				return "ok"
			}
		} else if !support.is_false(native, "ok") {
			return "ok"
		}
	}
	if hit.present && (hit.target == "/must-not-follow" || strings.has_prefix(hit.target, "/must-not-follow")) {
		return "followed"
	}
	return ""
}

base_request :: proc(name, method: string) -> Request {
	req: Request
	req.name = name
	req.method = method
	req.target = "/ordinary"
	req.body = "body"
	req.size = 4
	req.timeout = 1500
	req.wire = .Required
	return req
}

abort :: proc(g: ^support.Gate, reason: string) {
	stop_servers()
	loopback.identity_clear()
	support.fail(g, reason)
}

proxy_env :: proc() -> [dynamic]string {
	base, env_err := os.environ(context.allocator)
	if env_err != nil {
		return nil
	}
	env := make([dynamic]string, 0, len(base) + len(PROXY_KEYS))
	for item in base {
		if proxy_key(item) {
			delete(item)
			continue
		}
		append(&env, item)
	}
	delete(base)
	for key in PROXY_KEYS {
		value := "http://127.0.0.1:1"
		if key == "NO_PROXY" || key == "no_proxy" {
			value = ""
		}
		append(&env, fmt.aprintf("%s=%s", key, value))
	}
	return env
}

proxy_key :: proc(item: string) -> bool {
	for key in PROXY_KEYS {
		if strings.has_prefix(item, fmt.tprintf("%s=", key)) {
			return true
		}
	}
	return false
}

start_servers :: proc() -> bool {
	plain, plain_err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if plain_err != nil {
		return false
	}
	secure, secure_err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if secure_err != nil {
		net.close(plain)
		return false
	}
	plain_job = Job{listener = plain}
	secure_job = Job{listener = secure, encrypted = true}
	listeners_open = true
	plain_port = compatibility_port_of(plain)
	secure_port = compatibility_port_of(secure)
	if plain_port <= 0 || secure_port <= 0 {
		stop_servers()
		return false
	}
	plain_thread = thread.create_and_start_with_poly_data(&plain_job, compatibility_serve)
	secure_thread = thread.create_and_start_with_poly_data(&secure_job, compatibility_serve)
	if plain_thread == nil || secure_thread == nil {
		stop_servers()
		return false
	}
	return true
}

stop_servers :: proc() {
	if listeners_open {
		listeners_open = false
		net.close(plain_job.listener)
		net.close(secure_job.listener)
	}
	if plain_thread != nil {
		thread.join(plain_thread)
		thread.destroy(plain_thread)
		plain_thread = nil
	}
	if secure_thread != nil {
		thread.join(secure_thread)
		thread.destroy(secure_thread)
		secure_thread = nil
	}
	deadline := time.time_add(time.now(), 2 * time.Second)
	for {
		sync.lock(&state_mu)
		left := handlers
		sync.unlock(&state_mu)
		if left == 0 || time.diff(time.now(), deadline) <= 0 {
			return
		}
		time.sleep(2 * time.Millisecond)
	}
}

compatibility_serve :: proc(job: ^Job) {
	for {
		fd, _, err := net.accept_tcp(job.listener)
		if err != nil {
			return
		}
		box := new(Conn)
		box.fd = fd
		box.encrypted = job.encrypted
		sync.lock(&state_mu)
		handlers += 1
		sync.unlock(&state_mu)
		if thread.create_and_start_with_poly_data(box, compatibility_handle_conn, self_cleanup = true) == nil {
			free(box)
			net.close(fd)
			finish_handler()
		}
	}
}

compatibility_handle_conn :: proc(box: ^Conn) {
	fd := box.fd
	encrypted := box.encrypted
	free(box)
	compatibility_handle(fd, encrypted)
	finish_handler()
}

finish_handler :: proc() {
	sync.lock(&state_mu)
	handlers -= 1
	sync.unlock(&state_mu)
}

compatibility_handle :: proc(fd: net.TCP_Socket, encrypted: bool) {
	defer net.close(fd)
	_ = net.set_option(fd, .TCP_Nodelay, true)
	_ = net.set_option(fd, .Receive_Timeout, 3 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 3 * time.Second)
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	if encrypted {
		if !loopback.handshake(&conn, .HTTP1) {
			return
		}
	}
	buf := make([]u8, 131072)
	defer delete(buf)
	n := 0
	for !compatibility_bytes_contains(buf[:n], "\r\n\r\n") {
		if n == len(buf) {
			note_error("request cap")
			return
		}
		got, stop := read_more(fd, &conn, encrypted, buf[n:])
		if stop {
			return
		}
		n += got
	}
	head_at := compatibility_bytes_index(buf[:n], "\r\n\r\n")
	head := string(buf[:head_at])
	body := buf[head_at + 4:n]
	lines := make([dynamic]string)
	defer delete(lines)
	split_lines(head, &lines)
	if len(lines) == 0 {
		note_error("request")
		return
	}
	method, target, _, parts_ok := request_parts(lines[0])
	if !parts_ok {
		note_error("request line")
		return
	}
	length, found, valid := compatibility_content_length(head)
	if found && !valid {
		note_error("content-length")
		return
	}
	if len(lines) > 1 && wants_continue(lines[1:]) {
		if !write_text(fd, &conn, encrypted, "HTTP/1.1 100 Continue\r\n\r\n") {
			return
		}
	}
	for len(body) < length {
		if n == len(buf) {
			break
		}
		got, stop := read_more(fd, &conn, encrypted, buf[n:])
		if stop {
			break
		}
		n += got
		body = buf[head_at + 4:n]
	}
	header_lines := lines[1:] if len(lines) > 1 else []string{}
	record_request(method, target, header_lines, body, encrypted)
	respond(fd, &conn, encrypted, target)
}

record_request :: proc(method, target: string, headers: []string, body: []u8, secure: bool) {
	rec: compatibility_Record
	rec.method = strings.clone(method)
	rec.target = strings.clone(target)
	rec.secure = secure
	rec.headers = make([dynamic]string, 0, len(headers))
	for line in headers {
		append(&rec.headers, strings.clone(line))
	}
	rec.body = make([dynamic]u8, len(body))
	copy(rec.body[:], body)
	sync.lock(&state_mu)
	append(&records, rec)
	sync.unlock(&state_mu)
}

respond :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, target: string) {
	if strings.has_prefix(target, "/reset") {
		return
	}
	if strings.has_prefix(target, "/slow") || strings.has_prefix(target, "/head-wait") {
		if strings.has_prefix(target, "/head-wait") {
			_ = write_text(fd, conn, encrypted, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
		}
		time.sleep(350 * time.Millisecond)
		return
	}
	if strings.has_prefix(target, "/malformed") {
		_ = write_text(fd, conn, encrypted, "HTTP/1.1 bad status\r\n\r\n")
		return
	}
	if strings.has_prefix(target, "/chunked") {
		_ = write_text(fd, conn, encrypted, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nRRRR\r\n0\r\n\r\n")
		return
	}
	if strings.has_prefix(target, "/eof") {
		_ = write_text(fd, conn, encrypted, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nRRRR")
		return
	}
	if strings.has_prefix(target, "/truncated") {
		_ = write_text(fd, conn, encrypted, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\n\r\nR")
		return
	}
	status := "200 OK"
	extra := ""
	kind := Payload.Standard
	if strings.has_prefix(target, "/redirect") {
		status = "307 Temporary Redirect"
		extra = "Location: /must-not-follow\r\n"
		kind = .Empty
	} else if strings.has_prefix(target, "/status") {
		status = "503 Service Unavailable"
	} else if strings.has_prefix(target, "/empty") {
		kind = .Empty
	} else if strings.has_prefix(target, "/exact") {
		kind = .Exact
	} else if strings.has_prefix(target, "/oversize") {
		kind = .Oversize
	}
	compatibility_write_payload(fd, conn, encrypted, status, extra, kind)
}

compatibility_write_payload :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, status, extra: string, kind: Payload) {
	n := 4
	if kind == .Empty {
		n = 0
	} else if kind == .Exact {
		n = 65536
	} else if kind == .Oversize {
		n = 65537
	}
	head := fmt.aprintf("HTTP/1.1 %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n", status, extra, n)
	defer delete(head)
	if !write_text(fd, conn, encrypted, head) {
		return
	}
	if n == 0 {
		return
	}
	if kind == .Standard {
		_ = write_text(fd, conn, encrypted, "RRRR")
		return
	}
	chunk: [4096]u8
	for &b in chunk {
		b = 'R'
	}
	left := n
	for left > 0 {
		take := left if left < len(chunk) else len(chunk)
		if !write_bytes(fd, conn, encrypted, chunk[:take]) {
			return
		}
		left -= take
	}
}

write_text :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, text: string) -> bool {
	return write_bytes(fd, conn, encrypted, transmute([]u8)text)
}

write_bytes :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, src: []u8) -> bool {
	if encrypted {
		return loopback.tls_write(conn, src)
	}
	return loopback.write_full(fd, src)
}

read_more :: proc(fd: net.TCP_Socket, conn: ^loopback.Conn, encrypted: bool, dst: []u8) -> (int, bool) {
	for {
		got, err := read_some(fd, conn, encrypted, dst)
		if got > 0 {
			return got, false
		}
		if err == .Interrupted {
			continue
		}
		return 0, true
	}
}

compatibility_content_length :: proc(head: string) -> (length: int, found, valid: bool) {
	rest := head
	for len(rest) > 0 {
		cut := strings.index(rest, "\r\n")
		line := rest if cut < 0 else rest[:cut]
		if cut < 0 {
			rest = ""
		} else {
			rest = rest[cut + 2:]
		}
		if len(line) >= len("content-length:") && strings.equal_fold(line[:len("content-length:")], "content-length:") {
			value := strings.trim_space(line[len("content-length:"):])
			parsed, parsed_ok := strconv.parse_int(value)
			return parsed, true, parsed_ok
		}
	}
	return 0, false, true
}

request_parts :: proc(line: string) -> (method, target, version: string, ok: bool) {
	first := strings.index(line, " ")
	if first <= 0 {
		return
	}
	rest := line[first + 1:]
	second := strings.index(rest, " ")
	if second <= 0 {
		return
	}
	tail := rest[second + 1:]
	if strings.contains(tail, " ") {
		return
	}
	return line[:first], rest[:second], tail, true
}

wants_continue :: proc(lines: []string) -> bool {
	for line in lines {
		if strings.equal_fold(line, "expect: 100-continue") {
			return true
		}
	}
	return false
}

split_lines :: proc(head: string, lines: ^[dynamic]string) {
	rest := head
	for len(rest) > 0 {
		cut := strings.index(rest, "\r\n")
		line := rest if cut < 0 else rest[:cut]
		if cut < 0 {
			rest = ""
		} else {
			rest = rest[cut + 2:]
		}
		append(lines, line)
	}
}

record_count :: proc() -> int {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	return len(records)
}

snapshot :: proc(before: int) -> (added: int, hit: Hit) {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	added = len(records) - before
	if added != 1 {
		return
	}
	rec := records[before]
	hit.present = true
	hit.method = rec.method
	hit.target = rec.target
	hit.secure = rec.secure
	hit.headers = rec.headers
	hit.body = rec.body
	return
}

note_error :: proc(text: string) {
	sync.lock(&state_mu)
	defer sync.unlock(&state_mu)
	if server_error == "" {
		server_error = strings.clone(text)
	}
}

free_records :: proc() {
	for &rec in records {
		delete(rec.method)
		delete(rec.target)
		for line in rec.headers {
			delete(line)
		}
		delete(rec.headers)
		delete(rec.body)
	}
	delete(records)
	if server_error != "" {
		delete(server_error)
		server_error = ""
	}
}

body_is :: proc(body: [dynamic]u8, text: string) -> bool {
	if len(body) != len(text) {
		return false
	}
	for b, i in body {
		if b != text[i] {
			return false
		}
	}
	return true
}

headers_match :: proc(got: [dynamic]string, want: []string) -> bool {
	if len(got) != len(want) {
		return false
	}
	for item, i in got {
		if item != want[i] {
			return false
		}
	}
	return true
}

compatibility_port_of :: proc(socket: net.TCP_Socket) -> int {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		return 0
	}
	return int(endpoint.port)
}

compatibility_bytes_contains :: proc(buf: []u8, needle: string) -> bool {
	return compatibility_bytes_index(buf, needle) >= 0
}

compatibility_bytes_index :: proc(buf: []u8, needle: string) -> int {
	if len(needle) == 0 || len(buf) < len(needle) {
		return -1
	}
	for i in 0 ..= len(buf) - len(needle) {
		match := true
		for j in 0 ..< len(needle) {
			if buf[i + j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
