// Owned stand-ins for the setup matrix. TLS 1.3 is tests/loopback. The
// refused port is bound and not listening. Silent connections stay open
// on their own threads so the accept loop can take the next attempt.
package main

import loopback "../../loopback"

import "core:c"
import "core:fmt"
import "core:net"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:thread"
import "core:time"

DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

Dns :: struct {
	socket:   net.UDP_Socket,
	mu:       sync.Mutex,
	requests: int,
	answer:   bool,
	delay:    time.Duration,
	stop:     bool,
}

handshake_mu: sync.Mutex

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	compiler, shared, report_path, sanitizer := parse_args()
	root := fmt.aprintf("/tmp/okami-setup-%d", posix.getpid())
	defer delete(root)
	if err := os.make_directory_all(root, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	cert := join(root, "root.pem")
	defer delete(cert)
	dns_names := [1]string{"localhost"}
	raw := [4]u8{127, 0, 0, 1}
	ips := [1][]u8{raw[:]}
	if !loopback.mint_p256(cert, "localhost", dns_names[:], ips[:]) {
		fail("certificate")
	}
	defer loopback.identity_clear()
	binary := join(root, "checks")
	defer delete(binary)
	if !build(compiler, shared, binary, sanitizer) {
		fail("build")
	}

	dns := start_dns()
	run_mode(binary, "dns", port_of(dns.socket), cert, "")
	run_mode(binary, "surf-dns", port_of(dns.socket), cert, "")
	if dns_count(dns) != 16 {
		fail(fmt.tprintf("dns requests %d", dns_count(dns)))
	}
	set_answer(dns, true, 0)
	run_mode(binary, "resolve", port_of(dns.socket), cert, "")
	if dns_count(dns) != 24 {
		fail(fmt.tprintf("resolve requests %d", dns_count(dns)))
	}
	run_mode(binary, "dns-tiny", port_of(dns.socket), cert, "")
	set_answer(dns, true, 25 * time.Millisecond)
	silent := listen_tcp(0)
	silent_thread := thread.create_and_start_with_poly_data(silent, serve_silent)
	if silent_thread == nil {
		fail("thread")
	}
	run_mode(binary, "tls-dns", port_of(silent), cert, fmt.tprintf("%d", port_of(dns.socket)))
	stop_tcp(silent, silent_thread)
	stop_dns(dns)

	send_listener := listen_tcp(0)
	send_thread := thread.create_and_start_with_poly_data(send_listener, serve_send)
	if send_thread == nil {
		fail("thread")
	}
	run_mode(binary, "connect", port_of(send_listener), cert, "")
	stop_tcp(send_listener, send_thread)

	refused := reserve_refused()
	run_mode(binary, "refuse", refused_port_of(refused), cert, "")
	posix.close(refused)

	held := listen_tcp(0)
	held_thread := thread.create_and_start_with_poly_data(held, serve_silent)
	if held_thread == nil {
		fail("thread")
	}
	held_modes := [?]string{"tls", "tls-setup", "tls-handshake"}
	for mode in held_modes {
		run_mode(binary, mode, port_of(held), cert, "")
	}
	stop_tcp(held, held_thread)

	secure := listen_tcp(0)
	secure_thread := thread.create_and_start_with_poly_data(secure, serve_tls)
	if secure_thread == nil {
		fail("thread")
	}
	secure_modes := [?]string{"tls-finished", "tls-clear", "tls-finished-configured", "tls-clear-configured"}
	for mode in secure_modes {
		run_mode(binary, mode, port_of(secure), cert, "")
	}
	stop_tcp(secure, secure_thread)

	completed := 14
	if saturate_backlog(binary, cert) {
		completed += 1
	}
	text := fmt.aprintf("{{\"passed\":true,\"scenarios\":%d}}\n", completed)
	defer delete(text)
	if os.write_entire_file(report_path, transmute([]u8)text, FILE_PERM) != nil {
		fail("report")
	}
	fmt.printf("%d bounded setup scenarios passed\n", completed)
}

start_dns :: proc() -> ^Dns {
	socket, err := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if err != nil {
		fail("dns listen")
	}
	_ = net.set_option(socket, .Receive_Timeout, 200 * time.Millisecond)
	dns := new(Dns)
	dns.socket = socket
	worker := thread.create_and_start_with_poly_data(dns, dns_loop)
	if worker == nil {
		fail("dns thread")
	}
	dns_thread = worker
	return dns
}

dns_thread: ^thread.Thread

dns_loop :: proc(dns: ^Dns) {
	query: [512]u8
	for {
		if dns_stopped(dns) {
			return
		}
		n, from, err := net.recv_udp(dns.socket, query[:])
		if err == .Timeout || err == .Would_Block || err == .Interrupted {
			continue
		}
		if err != nil || n < 12 || n > len(query) {
			if err != nil {
				return
			}
			continue
		}
		sync.lock(&dns.mu)
		dns.requests += 1
		answer := dns.answer
		delay := dns.delay
		sync.unlock(&dns.mu)
		if !answer {
			continue
		}
		if delay > 0 {
			time.sleep(delay)
		}
		reply: [528]u8
		if n + 16 > len(reply) {
			continue
		}
		copy(reply[:], query[:n])
		reply[2] = 0x81
		reply[3] = 0x80
		reply[4] = 0
		reply[5] = 1
		reply[6] = 0
		reply[7] = 1
		reply[8] = 0
		reply[9] = 0
		reply[10] = 0
		reply[11] = 0
		at := n
		reply[at] = 0xc0
		reply[at + 1] = 0x0c
		reply[at + 2] = 0
		reply[at + 3] = 1
		reply[at + 4] = 0
		reply[at + 5] = 1
		reply[at + 6] = 0
		reply[at + 7] = 0
		reply[at + 8] = 0
		reply[at + 9] = 1
		reply[at + 10] = 0
		reply[at + 11] = 4
		reply[at + 12] = 127
		reply[at + 13] = 0
		reply[at + 14] = 0
		reply[at + 15] = 1
		_, _ = net.send_udp(dns.socket, reply[:n + 16], from)
	}
}

dns_count :: proc(dns: ^Dns) -> int {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)
	return dns.requests
}

dns_stopped :: proc(dns: ^Dns) -> bool {
	sync.lock(&dns.mu)
	defer sync.unlock(&dns.mu)
	return dns.stop
}

set_answer :: proc(dns: ^Dns, answer: bool, delay: time.Duration) {
	sync.lock(&dns.mu)
	dns.answer = answer
	dns.delay = delay
	sync.unlock(&dns.mu)
}

stop_dns :: proc(dns: ^Dns) {
	sync.lock(&dns.mu)
	dns.stop = true
	sync.unlock(&dns.mu)
	net.close(dns.socket)
	if dns_thread != nil {
		thread.join(dns_thread)
		thread.destroy(dns_thread)
		dns_thread = nil
	}
	free(dns)
}

serve_silent :: proc(listener: net.TCP_Socket) {
	for {
		fd, _, err := net.accept_tcp(listener)
		if err != nil {
			return
		}
		worker := thread.create_and_start_with_poly_data(fd, hold_silent, self_cleanup = true)
		if worker == nil {
			net.close(fd)
		}
	}
}

hold_silent :: proc(fd: net.TCP_Socket) {
	defer net.close(fd)
	_ = net.set_option(fd, .Receive_Timeout, 2 * time.Second)
	buf: [4096]u8
	_, _ = net.recv_tcp(fd, buf[:])
	time.sleep(500 * time.Millisecond)
}

serve_send :: proc(listener: net.TCP_Socket) {
	for {
		fd, _, err := net.accept_tcp(listener)
		if err != nil {
			return
		}
		worker := thread.create_and_start_with_poly_data(fd, hold_send, self_cleanup = true)
		if worker == nil {
			net.close(fd)
		}
	}
}

hold_send :: proc(fd: net.TCP_Socket) {
	defer net.close(fd)
	time.sleep(10 * time.Millisecond)
	_ = loopback.write_full(fd, []u8{'x'})
}

serve_tls :: proc(listener: net.TCP_Socket) {
	for {
		fd, _, err := net.accept_tcp(listener)
		if err != nil {
			return
		}
		worker := thread.create_and_start_with_poly_data(fd, hold_tls, self_cleanup = true)
		if worker == nil {
			net.close(fd)
		}
	}
}

hold_tls :: proc(fd: net.TCP_Socket) {
	defer net.close(fd)
	_ = net.set_option(fd, .Receive_Timeout, 2 * time.Second)
	_ = net.set_option(fd, .Send_Timeout, 2 * time.Second)
	conn := loopback.Conn{fd = fd}
	defer loopback.conn_wipe(&conn)
	// One handshake at a time. The identity key is process-global.
	sync.lock(&handshake_mu)
	_ = loopback.handshake(&conn, .HTTP1)
	sync.unlock(&handshake_mu)
}

listen_tcp :: proc(backlog: int) -> net.TCP_Socket {
	endpoint := net.Endpoint{address = net.IP4_Loopback, port = 0}
	socket: net.TCP_Socket
	err: net.Network_Error
	if backlog > 0 {
		socket, err = net.listen_tcp(endpoint, backlog)
	} else {
		socket, err = net.listen_tcp(endpoint)
	}
	if err != nil {
		fail("listen")
	}
	return socket
}

stop_tcp :: proc(listener: net.TCP_Socket, worker: ^thread.Thread) {
	net.close(listener)
	if worker != nil {
		thread.join(worker)
		thread.destroy(worker)
	}
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

saturate_backlog :: proc(binary, cert: string) -> bool {
	listener := listen_tcp(1)
	defer net.close(listener)
	endpoint := port_of(listener)
	held: [32]net.TCP_Socket
	count := 0
	full := false
	for _ in 0 ..< 32 {
		socket, err := net.dial_tcp_until(
			{address = net.IP4_Address{127, 0, 0, 1}, port = endpoint},
			time.time_add(time.now(), 30 * time.Millisecond),
		)
		if err == nil {
			held[count] = socket
			count += 1
			continue
		}
		full = true
		break
	}
	defer for socket in held[:count] {
		net.close(socket)
	}
	if !full {
		fmt.eprintln("SKIP backlog: could not saturate owned queue")
		return false
	}
	run_mode(binary, "backlog", endpoint, cert, "")
	return true
}

run_mode :: proc(binary, mode: string, port: int, cert, extra: string) {
	command := make([dynamic]string)
	defer delete(command)
	append(&command, binary, mode, fmt.tprintf("%d", port), cert)
	if extra != "" {
		append(&command, extra)
	}
	fmt.eprintf("setup: %s\n", mode)
	_ = os.flush(os.stderr)
	process, start_error := os.process_start({command = command[:], stdout = os.stdout, stderr = os.stderr})
	if start_error != nil {
		fail(mode)
	}
	state, wait_error := os.process_wait(process, 15 * time.Second)
	if wait_error != nil || state.exit_code != 0 {
		fail(mode)
	}
}

build :: proc(compiler, shared, binary, sanitizer: string) -> bool {
	out_flag := fmt.aprintf("-out:%s", binary)
	defer delete(out_flag)
	collection := fmt.aprintf("-collection:shared=%s", shared)
	defer delete(collection)
	command := make([dynamic]string)
	defer delete(command)
	append(&command, compiler, "build", "tests/testdata/setup", "-thread-count:1", "-warnings-as-errors", collection, out_flag)
	if sanitizer != "" && sanitizer != "none" {
		append(&command, fmt.aprintf("-sanitize:%s", sanitizer))
	}
	process, start_error := os.process_start({command = command[:], stdout = os.stdout, stderr = os.stderr})
	if start_error != nil {
		return false
	}
	state, wait_error := os.process_wait(process, 180 * time.Second)
	return wait_error == nil && state.exit_code == 0
}

port_of :: proc(socket: net.Any_Socket) -> int {
	endpoint, err := net.bound_endpoint(socket)
	if err != nil {
		fail("bound")
	}
	return int(endpoint.port)
}

join :: proc(dir, name: string) -> string {
	return fmt.aprintf("%s/%s", dir, name)
}

parse_args :: proc() -> (compiler, shared, report, sanitizer: string) {
	sanitizer = "address"
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

fail :: proc(reason: string) {
	fmt.eprintf("setup: %s\n", reason)
	_ = os.flush(os.stderr)
	os.exit(1)
}
