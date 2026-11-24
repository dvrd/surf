package loopback

import "core:crypto"
import "core:crypto/aead"
import "core:crypto/ecdh"
import "core:crypto/ecdsa"
import "core:crypto/ed25519"
import "core:crypto/hash"
import "core:crypto/hkdf"
import "core:crypto/hmac"
import "core:encoding/pem"
import "core:net"
import "core:os"
import "core:time"

Mode :: enum {
	H2,
	HTTP1,
	HTTP1_NoALPN,
	GoAway,
}

Read_Status :: enum {
	Ok,
	Timeout,
	Closed,
	Failed,
}

Conn :: struct {
	fd:         net.TCP_Socket,
	in_key:     [16]u8,
	out_key:    [16]u8,
	in_iv:      [12]u8,
	out_iv:     [12]u8,
	in_seq:     u64,
	out_seq:    u64,
	// Application traffic secrets. The record oracle reads these; handshake
	// keys are never stored here.
	client_secret: [32]u8,
	server_secret: [32]u8,
	app_records:   int,
	updates:       int,
	client_updates: int,
	manual_seq:    [8]u64,
	manual_n:      int,
	plain:      [18 * 1024]u8,
	plain_at:   int,
	plain_n:    int,
	alpn:       [32]u8,
	alpn_n:     int,
	sni:        [256]u8,
	sni_n:      int,
	reason:     string,
}

Hello :: struct {
	session:     [32]u8,
	session_n:   int,
	share:       [32]u8,
	share_ok:    bool,
	tls13:       bool,
	ed25519:     bool,
	p256:        bool,
	aes128:      bool,
	alpn:        [8][32]u8,
	alpn_len:    [8]int,
	alpn_count:  int,
	sni:         [256]u8,
	sni_n:       int,
}

Signer :: enum {
	Ed25519,
	P256,
}

peer_cert: [4096]u8
peer_cert_n: int
peer_key: ed25519.Private_Key
peer_p256: ecdsa.Private_Key
peer_signer: Signer

CERT_VERIFY_CONTEXT :: [98]u8 {
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	// "TLS 1.3, server CertificateVerify\0"
	0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c,
	0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66,
	0x79, 0x00,
}

load_identity :: proc() -> bool {
	cert_pem, cert_error := os.read_entire_file("../testdata/credentials/leaf.pem", context.allocator)
	if cert_error != nil {
		return false
	}
	defer delete(cert_pem)
	key_pem, key_error := os.read_entire_file("../testdata/credentials/key.pem", context.allocator)
	if key_error != nil {
		return false
	}
	defer delete(key_pem)
	block, _, decode_error := pem.decode(cert_pem)
	if decode_error != nil || block == nil || len(block.data) > len(peer_cert) {
		return false
	}
	peer_cert_n = copy(peer_cert[:], block.data[:])
	pem.block_delete(block)
	key_block, _, key_decode := pem.decode(key_pem)
	if key_decode != nil || key_block == nil {
		return false
	}
	defer pem.block_delete(key_block)
	seed, ok := ed25519_seed(key_block.data[:])
	if !ok || !ed25519.private_key_set_bytes(&peer_key, seed[:]) {
		return false
	}
	peer_signer = .Ed25519
	return peer_cert_n > 0
}

// PKCS#8 Ed25519: OCTET STRING wrapping a 32-byte seed.
ed25519_seed :: proc(der: []u8) -> (seed: [32]u8, ok: bool) {
	for i in 0 ..< len(der) - 34 {
		if der[i] == 0x04 && der[i + 1] == 0x22 && der[i + 2] == 0x04 && der[i + 3] == 0x20 {
			copy(seed[:], der[i + 4:][:32])
			return seed, true
		}
	}
	return
}

set_recv_timeout :: proc(fd: net.TCP_Socket, timeout: time.Duration) {
	_ = net.set_option(fd, .Receive_Timeout, timeout)
}

read_full :: proc(fd: net.TCP_Socket, dst: []u8) -> Read_Status {
	at := 0
	for at < len(dst) {
		n, err := net.recv_tcp(fd, dst[at:])
		if n > 0 {
			at += n
			continue
		}
		if err == .Interrupted {
			continue
		}
		if err == .Timeout || err == .Would_Block {
			if at == 0 {
				return .Timeout
			}
			continue
		}
		if err == nil || err == .Connection_Closed {
			return .Closed
		}
		return .Failed
	}
	return .Ok
}

write_full :: proc(fd: net.TCP_Socket, src: []u8) -> bool {
	at := 0
	for at < len(src) {
		n, err := net.send_tcp(fd, src[at:])
		if n > 0 {
			at += n
			continue
		}
		if err == .Interrupted {
			continue
		}
		return false
	}
	return true
}

write_record :: proc(fd: net.TCP_Socket, kind: u8, version: u16, body: []u8) -> bool {
	header: [5]u8
	header[0] = kind
	header[1] = u8(version >> 8)
	header[2] = u8(version)
	header[3] = u8(len(body) >> 8)
	header[4] = u8(len(body))
	return write_full(fd, header[:]) && write_full(fd, body)
}

read_record :: proc(fd: net.TCP_Socket, dst: []u8) -> (kind: u8, body: []u8, status: Read_Status) {
	header: [5]u8
	if status = read_full(fd, header[:]); status != .Ok {
		return 0, nil, status
	}
	length := int(header[3]) << 8 | int(header[4])
	if length > len(dst) {
		return 0, nil, .Failed
	}
	if status = read_full(fd, dst[:length]); status != .Ok {
		return 0, nil, status
	}
	return header[0], dst[:length], .Ok
}

// ServerHello, then the compatibility ChangeCipherSpec, then one handshake
// record carrying EncryptedExtensions through Finished. Finished ends that
// record: the client rejects a key change in the middle of a record.
handshake :: proc(conn: ^Conn, mode: Mode) -> bool {
	storage: [12 * 1024]u8
	kind, body, status := read_record(conn.fd, storage[:])
	if status != .Ok || kind != 22 {
		conn.reason = "client hello record"
		return false
	}
	hello_msg := body
	for len(hello_msg) < 4 || len(hello_msg) < 4 + u24(hello_msg[1:]) {
		kind, body, status = read_record(conn.fd, storage[len(hello_msg):])
		if status != .Ok || kind != 22 {
			conn.reason = "client hello fragment"
			return false
		}
		hello_msg = storage[:len(hello_msg) + len(body)]
	}
	if len(hello_msg) != 4 + u24(hello_msg[1:]) || hello_msg[0] != 1 {
		conn.reason = "client hello bounds"
		return false
	}
	hello, parsed := parse_hello(hello_msg)
	if !parsed {
		conn.reason = "client hello parse"
		return false
	}
	if !hello.tls13 {
		conn.reason = "client hello version"
		return false
	}
	if !hello.aes128 {
		conn.reason = "client hello cipher"
		return false
	}
	if !hello.share_ok {
		conn.reason = "client hello share"
		return false
	}
	if !scheme_offered(&hello) {
		conn.reason = "client hello scheme p256" if peer_signer == .P256 else "client hello scheme ed25519"
		return false
	}
	selected := select_alpn(mode, &hello)
	if selected == "" && alpn_required(mode, &hello) {
		conn.reason = "alpn"
		return false
	}

	priv: ecdh.Private_Key
	defer ecdh.private_key_clear(&priv)
	if !ecdh.private_key_generate(&priv, .X25519) {
		conn.reason = "x25519"
		return false
	}
	public: [32]u8
	ecdh.private_key_public_bytes(&priv, public[:])
	peer: ecdh.Public_Key
	defer ecdh.public_key_clear(&peer)
	shared: [32]u8
	defer crypto.zero_explicit(&shared, size_of(shared))
	if !ecdh.public_key_set_bytes(&peer, .X25519, hello.share[:]) || !ecdh.ecdh(&priv, &peer, shared[:]) {
		conn.reason = "ecdh"
		return false
	}

	server_hello: [128]u8
	random: [32]u8
	crypto.rand_bytes(random[:])
	hello_n := write_server_hello(server_hello[:], hello.session[:hello.session_n], public[:], random[:])
	if !write_record(conn.fd, 22, 0x0303, server_hello[:hello_n]) {
		conn.reason = "server hello write"
		return false
	}
	if !write_record(conn.fd, 20, 0x0303, []u8{1}) {
		conn.reason = "ccs"
		return false
	}

	transcript: hash.Context
	hash.init(&transcript, .SHA256)
	hash.update(&transcript, hello_msg)
	hash.update(&transcript, server_hello[:hello_n])
	digest: [32]u8
	hash.final(&transcript, digest[:], true)

	client_hs, server_hs: [32]u8
	defer crypto.zero_explicit(&client_hs, size_of(client_hs))
	defer crypto.zero_explicit(&server_hs, size_of(server_hs))
	if !traffic_secrets(shared[:], digest[:], &client_hs, &server_hs) {
		conn.reason = "handshake secrets"
		return false
	}
	install(&conn.out_key, &conn.out_iv, server_hs[:])
	install(&conn.in_key, &conn.in_iv, client_hs[:])
	conn.out_seq = 0
	conn.in_seq = 0

	flight: [4096]u8
	at := 0
	ee := write_extensions(flight[at:], selected)
	hash.update(&transcript, flight[at:][:ee])
	at += ee
	cert := write_certificate(flight[at:])
	if cert < 0 {
		conn.reason = "certificate"
		return false
	}
	hash.update(&transcript, flight[at:][:cert])
	at += cert
	hash.final(&transcript, digest[:], true)
	verify := write_certificate_verify(flight[at:], digest[:])
	if verify < 0 {
		conn.reason = "certificate verify"
		return false
	}
	hash.update(&transcript, flight[at:][:verify])
	at += verify
	hash.final(&transcript, digest[:], true)
	finished := write_finished(flight[at:], server_hs[:], digest[:])
	hash.update(&transcript, flight[at:][:finished])
	at += finished
	if !seal(conn, 22, flight[:at]) {
		conn.reason = "flight"
		return false
	}

	client_finished: [64]u8
	got := 0
	for {
		if conn.plain_at >= conn.plain_n {
			inner_kind, _, opened := open_handshake(conn)
			if !opened || inner_kind != 22 {
				conn.reason = "client finished"
				return false
			}
		}
		need := len(client_finished)
		if got >= 4 {
			need = 4 + u24(client_finished[1:])
			if need < 4 || need > len(client_finished) {
				conn.reason = "client finished length"
				return false
			}
		}
		take := min(need - got, conn.plain_n - conn.plain_at)
		copy(client_finished[got:], conn.plain[conn.plain_at:][:take])
		conn.plain_at += take
		got += take
		if got >= 4 && got >= 4 + u24(client_finished[1:]) {
			break
		}
	}
	// Application secrets cover the transcript through server Finished.
	hash.final(&transcript, digest[:], true)
	if client_finished[0] != 20 || got != 36 || !finished_ok(client_hs[:], digest[:], client_finished[4:36]) {
		conn.reason = "finished mac"
		return false
	}
	client_ap, server_ap: [32]u8
	defer crypto.zero_explicit(&client_ap, size_of(client_ap))
	defer crypto.zero_explicit(&server_ap, size_of(server_ap))
	if !application_secrets(shared[:], digest[:], &client_ap, &server_ap) {
		conn.reason = "application secrets"
		return false
	}
	install(&conn.out_key, &conn.out_iv, server_ap[:])
	install(&conn.in_key, &conn.in_iv, client_ap[:])
	copy(conn.server_secret[:], server_ap[:])
	copy(conn.client_secret[:], client_ap[:])
	conn.out_seq = 0
	conn.in_seq = 0
	conn.alpn_n = copy(conn.alpn[:], selected)
	conn.sni_n = copy(conn.sni[:], hello.sni[:hello.sni_n])
	set_recv_timeout(conn.fd, 60 * time.Second)
	return true
}

u24 :: proc(b: []u8) -> int {
	return int(b[0]) << 16 | int(b[1]) << 8 | int(b[2])
}

put16 :: proc(dst: []u8, at: ^int, value: int) {
	dst[at^] = u8(value >> 8)
	dst[at^ + 1] = u8(value)
	at^ += 2
}

put24 :: proc(dst: []u8, at: int) {
	n := at - 4
	dst[1] = u8(n >> 16)
	dst[2] = u8(n >> 8)
	dst[3] = u8(n)
}

parse_hello :: proc(msg: []u8) -> (hello: Hello, ok: bool) {
	if len(msg) < 44 || msg[0] != 1 {
		return
	}
	at := 38
	session_n := int(msg[at])
	at += 1
	if session_n > 32 || at + session_n + 2 > len(msg) {
		return
	}
	copy(hello.session[:], msg[at:][:session_n])
	hello.session_n = session_n
	at += session_n
	suites_n := int(msg[at]) << 8 | int(msg[at + 1])
	at += 2
	if suites_n < 2 || suites_n % 2 != 0 || at + suites_n + 1 > len(msg) {
		return
	}
	for i := 0; i < suites_n; i += 2 {
		if int(msg[at + i]) << 8 | int(msg[at + i + 1]) == 0x1301 {
			hello.aes128 = true
		}
	}
	at += suites_n
	methods_n := int(msg[at])
	at += 1 + methods_n
	if at + 2 > len(msg) {
		return
	}
	ext_n := int(msg[at]) << 8 | int(msg[at + 1])
	at += 2
	if at + ext_n != len(msg) {
		return
	}
	end := at + ext_n
	for at + 4 <= end {
		kind := int(msg[at]) << 8 | int(msg[at + 1])
		size := int(msg[at + 2]) << 8 | int(msg[at + 3])
		at += 4
		if size > end - at {
			return
		}
		data := msg[at:][:size]
		at += size
		switch kind {
		case 0x0000:
			if len(data) >= 5 {
				list := int(data[0]) << 8 | int(data[1])
				name_n := int(data[3]) << 8 | int(data[4])
				if data[2] == 0 && list == len(data) - 2 && name_n == list - 3 && name_n <= len(hello.sni) && 5 + name_n <= len(data) {
					copy(hello.sni[:], data[5:][:name_n])
					hello.sni_n = name_n
				}
			}
		case 0x002b:
			if len(data) < 1 || int(data[0]) != len(data) - 1 {
				return
			}
			for i := 1; i + 1 < len(data); i += 2 {
				if int(data[i]) << 8 | int(data[i + 1]) == 0x0304 {
					hello.tls13 = true
				}
			}
		case 0x0033:
			if len(data) < 2 {
				return
			}
			shares := int(data[0]) << 8 | int(data[1])
			if shares != len(data) - 2 {
				return
			}
			pos := 2
			for pos + 4 <= len(data) {
				group := int(data[pos]) << 8 | int(data[pos + 1])
				key_n := int(data[pos + 2]) << 8 | int(data[pos + 3])
				pos += 4
				if key_n > len(data) - pos {
					return
				}
				if group == 0x001d && key_n == 32 {
					copy(hello.share[:], data[pos:][:32])
					hello.share_ok = true
				}
				pos += key_n
			}
		case 0x000d:
			if len(data) < 2 {
				return
			}
			list := int(data[0]) << 8 | int(data[1])
			if list != len(data) - 2 {
				return
			}
			for i := 2; i + 1 < len(data); i += 2 {
				scheme := int(data[i]) << 8 | int(data[i + 1])
				if scheme == 0x0807 {
					hello.ed25519 = true
				} else if scheme == 0x0403 {
					hello.p256 = true
				}
			}
		case 0x0010:
			if len(data) < 2 {
				return
			}
			list := int(data[0]) << 8 | int(data[1])
			if list != len(data) - 2 {
				return
			}
			pos := 2
			for pos < len(data) && hello.alpn_count < len(hello.alpn) {
				name_n := int(data[pos])
				pos += 1
				if name_n > len(data) - pos || name_n > len(hello.alpn[0]) {
					return
				}
				slot := hello.alpn_count
				copy(hello.alpn[slot][:], data[pos:][:name_n])
				hello.alpn_len[slot] = name_n
				hello.alpn_count += 1
				pos += name_n
			}
		}
	}
	return hello, true
}

preference :: proc(mode: Mode) -> string {
	switch mode {
	case .H2, .GoAway:
		return "h2"
	case .HTTP1:
		return "http/1.1"
	case .HTTP1_NoALPN:
		return ""
	}
	return ""
}

select_alpn :: proc(mode: Mode, hello: ^Hello) -> string {
	want := preference(mode)
	if want == "" {
		return ""
	}
	for i in 0 ..< hello.alpn_count {
		if string(hello.alpn[i][:hello.alpn_len[i]]) == want {
			return want
		}
	}
	return ""
}

alpn_required :: proc(mode: Mode, hello: ^Hello) -> bool {
	return preference(mode) != "" && hello.alpn_count > 0
}

write_server_hello :: proc(dst, session, public, random: []u8) -> int {
	at := 4
	put16(dst, &at, 0x0303)
	copy(dst[at:], random)
	at += 32
	dst[at] = u8(len(session))
	at += 1
	copy(dst[at:], session)
	at += len(session)
	put16(dst, &at, 0x1301)
	dst[at] = 0
	at += 1
	put16(dst, &at, 14 + len(public))
	put16(dst, &at, 43)
	put16(dst, &at, 2)
	put16(dst, &at, 0x0304)
	put16(dst, &at, 51)
	put16(dst, &at, 4 + len(public))
	put16(dst, &at, 0x001d)
	put16(dst, &at, len(public))
	copy(dst[at:], public)
	at += len(public)
	dst[0] = 2
	put24(dst, at)
	return at
}

write_extensions :: proc(dst: []u8, alpn: string) -> int {
	at := 6
	if alpn != "" {
		put16(dst, &at, 0x0010)
		put16(dst, &at, 3 + len(alpn))
		put16(dst, &at, 1 + len(alpn))
		dst[at] = u8(len(alpn))
		at += 1
		copy(dst[at:], alpn)
		at += len(alpn)
	}
	body := at - 4
	dst[0] = 8
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	ext_n := at - 6
	dst[4] = u8(ext_n >> 8)
	dst[5] = u8(ext_n)
	return at
}

write_certificate :: proc(dst: []u8) -> int {
	der := peer_cert[:peer_cert_n]
	// context, list length, cert length, der, empty extensions.
	body := 1 + 3 + 3 + len(der) + 2
	if 4 + body > len(dst) {
		return -1
	}
	dst[0] = 11
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	dst[4] = 0
	list := 3 + len(der) + 2
	dst[5] = u8(list >> 16)
	dst[6] = u8(list >> 8)
	dst[7] = u8(list)
	dst[8] = u8(len(der) >> 16)
	dst[9] = u8(len(der) >> 8)
	dst[10] = u8(len(der))
	copy(dst[11:], der)
	at := 11 + len(der)
	dst[at] = 0
	dst[at + 1] = 0
	return at + 2
}

scheme_offered :: proc(hello: ^Hello) -> bool {
	switch peer_signer {
	case .Ed25519:
		return hello.ed25519
	case .P256:
		return hello.p256
	}
	return false
}

write_certificate_verify :: proc(dst: []u8, transcript: []u8) -> int {
	message: [160]u8
	prefix := CERT_VERIFY_CONTEXT
	copy(message[:], prefix[:])
	signed := message[:len(prefix) + len(transcript)]
	copy(signed, prefix[:])
	copy(signed[len(prefix):], transcript)
	if peer_signer == .P256 {
		sig, ok := ecdsa.sign_asn1(&peer_p256, .SHA256, signed, context.allocator)
		if !ok {
			return -1
		}
		defer delete(sig)
		return write_verify(dst, 0x0403, sig)
	}
	raw: [ed25519.SIGNATURE_SIZE]u8
	ed25519.sign(&peer_key, signed, raw[:])
	return write_verify(dst, 0x0807, raw[:])
}

write_verify :: proc(dst: []u8, scheme: int, sig: []u8) -> int {
	body := 2 + 2 + len(sig)
	if len(sig) > 0xffff || 4 + body > len(dst) {
		return -1
	}
	dst[0] = 15
	dst[1] = u8(body >> 16)
	dst[2] = u8(body >> 8)
	dst[3] = u8(body)
	dst[4] = u8(scheme >> 8)
	dst[5] = u8(scheme)
	dst[6] = u8(len(sig) >> 8)
	dst[7] = u8(len(sig))
	copy(dst[8:], sig)
	return 8 + len(sig)
}

write_finished :: proc(dst: []u8, secret, transcript: []u8) -> int {
	verify: [32]u8
	finished_hmac(secret, transcript, verify[:])
	dst[0] = 20
	dst[1] = 0
	dst[2] = 0
	dst[3] = 32
	copy(dst[4:], verify[:])
	return 36
}

finished_hmac :: proc(secret, transcript, dst: []u8) {
	key: [32]u8
	defer crypto.zero_explicit(&key, size_of(key))
	expand_label(secret, "finished", nil, key[:])
	hmac.sum(.SHA256, dst, transcript, key[:])
}

finished_ok :: proc(secret, transcript, verify: []u8) -> bool {
	want: [32]u8
	finished_hmac(secret, transcript, want[:])
	same := true
	for b, i in want {
		same = same && b == verify[i]
	}
	return same && len(verify) == 32
}

empty_hash :: proc() -> [32]u8 {
	out: [32]u8
	ctx: hash.Context
	hash.init(&ctx, .SHA256)
	hash.final(&ctx, out[:])
	return out
}

expand_label :: proc(secret: []u8, label: string, hashed: []u8, dst: []u8) {
	info: [128]u8
	n := 0
	info[n] = u8(len(dst) >> 8)
	info[n + 1] = u8(len(dst))
	n += 2
	info[n] = u8(6 + len(label))
	n += 1
	n += copy(info[n:], "tls13 ")
	n += copy(info[n:], label)
	info[n] = u8(len(hashed))
	n += 1
	n += copy(info[n:], hashed)
	hkdf.expand(.SHA256, secret, info[:n], dst)
}

derive :: proc(secret: []u8, label: string, transcript, dst: []u8) {
	expand_label(secret, label, transcript, dst)
}

traffic_secrets :: proc(shared, transcript: []u8, client, server: ^[32]u8) -> bool {
	zeros: [32]u8
	early: [32]u8
	stage: [32]u8
	hs: [32]u8
	defer crypto.zero_explicit(&early, size_of(early))
	defer crypto.zero_explicit(&stage, size_of(stage))
	defer crypto.zero_explicit(&hs, size_of(hs))
	hkdf.extract(.SHA256, zeros[:], zeros[:], early[:])
	empty := empty_hash()
	derive(early[:], "derived", empty[:], stage[:])
	hkdf.extract(.SHA256, stage[:], shared, hs[:])
	derive(hs[:], "c hs traffic", transcript, client[:])
	derive(hs[:], "s hs traffic", transcript, server[:])
	return true
}

application_secrets :: proc(shared, transcript: []u8, client, server: ^[32]u8) -> bool {
	// Recompute the handshake secret, then the master secret. The transcript
	// here runs through server Finished.
	zeros: [32]u8
	early, stage, hs, master: [32]u8
	defer crypto.zero_explicit(&early, size_of(early))
	defer crypto.zero_explicit(&stage, size_of(stage))
	defer crypto.zero_explicit(&hs, size_of(hs))
	defer crypto.zero_explicit(&master, size_of(master))
	hkdf.extract(.SHA256, zeros[:], zeros[:], early[:])
	empty := empty_hash()
	derive(early[:], "derived", empty[:], stage[:])
	hkdf.extract(.SHA256, stage[:], shared, hs[:])
	derive(hs[:], "derived", empty[:], stage[:])
	hkdf.extract(.SHA256, stage[:], zeros[:], master[:])
	derive(master[:], "c ap traffic", transcript, client[:])
	derive(master[:], "s ap traffic", transcript, server[:])
	return true
}

install :: proc(key: ^[16]u8, iv: ^[12]u8, secret: []u8) {
	expand_label(secret, "key", nil, key[:])
	expand_label(secret, "iv", nil, iv[:])
}

nonce_of :: proc(iv: [12]u8, seq: u64) -> [12]u8 {
	nonce := iv
	rest := seq
	for i in 0 ..< 8 {
		nonce[11 - i] ~= u8(rest)
		rest >>= 8
	}
	return nonce
}

seal :: proc(conn: ^Conn, kind: u8, body: []u8) -> bool {
	if len(body) + 1 > 16 * 1024 {
		return false
	}
	inner: [16 * 1024]u8
	cipher: [16 * 1024]u8
	copy(inner[:], body)
	inner[len(body)] = kind
	inner_n := len(body) + 1
	wire_n := inner_n + 16
	header: [5]u8
	header[0] = 23
	header[1] = 3
	header[2] = 3
	header[3] = u8(wire_n >> 8)
	header[4] = u8(wire_n)
	tag: [16]u8
	nonce := nonce_of(conn.out_iv, conn.out_seq)
	aead.seal_oneshot(.AES_GCM_128, cipher[:inner_n], tag[:], conn.out_key[:], nonce[:], header[:], inner[:inner_n])
	conn.out_seq += 1
	return write_full(conn.fd, header[:]) && write_full(conn.fd, cipher[:inner_n]) && write_full(conn.fd, tag[:])
}

// seal_wire builds one TLS record and advances the send sequence without
// writing it. The sequence used is recorded for the oracle. dst receives
// header || ciphertext || tag.
seal_wire :: proc(conn: ^Conn, dst: []u8, body: []u8, kind: u8) -> int {
	if len(body) + 1 > 16 * 1024 || conn.manual_n >= len(conn.manual_seq) {
		return -1
	}
	inner_n := len(body) + 1
	total := 5 + inner_n + 16
	if len(dst) < total {
		return -1
	}
	conn.manual_seq[conn.manual_n] = conn.out_seq
	conn.manual_n += 1
	inner: [16 * 1024]u8
	copy(inner[:], body)
	inner[len(body)] = kind
	dst[0] = 23
	dst[1] = 3
	dst[2] = 3
	dst[3] = u8((inner_n + 16) >> 8)
	dst[4] = u8(inner_n + 16)
	tag := dst[5 + inner_n:][:16]
	nonce := nonce_of(conn.out_iv, conn.out_seq)
	aead.seal_oneshot(.AES_GCM_128, dst[5:][:inner_n], tag, conn.out_key[:], nonce[:], dst[:5], inner[:inner_n])
	conn.out_seq += 1
	return total
}

// server_key_update sends one KeyUpdate requesting an update, then rotates
// the server application secret and resets the send sequence.
server_key_update :: proc(conn: ^Conn) -> bool {
	message := [5]u8{24, 0, 0, 1, 1}
	wire: [32]u8
	n := seal_wire(conn, wire[:], message[:], 22)
	if n < 0 || !write_full(conn.fd, wire[:n]) {
		return false
	}
	rotate_secret(&conn.server_secret, &conn.out_key, &conn.out_iv, &conn.out_seq)
	conn.updates += 1
	return true
}

rotate_secret :: proc(secret: ^[32]u8, key: ^[16]u8, iv: ^[12]u8, seq: ^u64) {
	next: [32]u8
	defer crypto.zero_explicit(&next, size_of(next))
	expand_label(secret[:], "traffic upd", nil, next[:])
	copy(secret[:], next[:])
	install(key, iv, secret[:])
	seq^ = 0
}

open_record :: proc(conn: ^Conn) -> (kind: u8, body: []u8, status: Read_Status) {
	wire: [5 + 16 * 1024 + 1 + 16]u8
	header_kind, payload, rec := read_record(conn.fd, wire[:])
	if rec != .Ok {
		return 0, nil, rec
	}
	if header_kind == 20 {
		return 20, nil, .Ok
	}
	if header_kind != 23 || len(payload) < 16 {
		return 0, nil, .Failed
	}
	header: [5]u8
	header[0] = 23
	header[1] = 3
	header[2] = 3
	header[3] = u8(len(payload) >> 8)
	header[4] = u8(len(payload))
	cipher_n := len(payload) - 16
	opened: [16 * 1024 + 1]u8
	nonce := nonce_of(conn.in_iv, conn.in_seq)
	if !aead.open_oneshot(.AES_GCM_128, opened[:cipher_n], conn.in_key[:], nonce[:], header[:], payload[:cipher_n], payload[cipher_n:]) {
		return 0, nil, .Failed
	}
	conn.in_seq += 1
	end := cipher_n
	for end > 0 && opened[end - 1] == 0 {
		end -= 1
	}
	if end == 0 {
		return 0, nil, .Failed
	}
	kind = opened[end - 1]
	n := copy(conn.plain[:], opened[:end - 1])
	conn.plain_at = 0
	conn.plain_n = n
	return kind, conn.plain[:n], .Ok
}

open_handshake :: proc(conn: ^Conn) -> (kind: u8, body: []u8, ok: bool) {
	for {
		kind, body, status := open_record(conn)
		if status != .Ok {
			return 0, nil, false
		}
		if kind == 20 {
			continue
		}
		return kind, body, true
	}
}

tls_read :: proc(conn: ^Conn, dst: []u8) -> (int, Read_Status) {
	if len(dst) == 0 {
		return 0, .Ok
	}
	for conn.plain_at >= conn.plain_n {
		kind, _, status := open_record(conn)
		if status != .Ok {
			return 0, status
		}
		// A client KeyUpdate is a handshake record inside application keys.
		// Consume it and rotate the read secret. Do not surface it as HTTP.
		if kind == 22 && conn.plain_n >= 4 && conn.plain[0] == 24 {
			rotate_secret(&conn.client_secret, &conn.in_key, &conn.in_iv, &conn.in_seq)
			conn.client_updates += 1
			conn.plain_at = conn.plain_n
			continue
		}
		if kind != 23 {
			return 0, .Failed
		}
		if conn.plain_n == 0 {
			continue
		}
	}
	n := copy(dst, conn.plain[conn.plain_at:conn.plain_n])
	conn.plain_at += n
	return n, .Ok
}

tls_write :: proc(conn: ^Conn, src: []u8) -> bool {
	at := 0
	for at < len(src) {
		n := min(len(src) - at, 16 * 1024 - 1)
		if !seal(conn, 23, src[at:][:n]) {
			return false
		}
		conn.app_records += 1
		at += n
	}
	return true
}

identity_clear :: proc() {
	ed25519.private_key_clear(&peer_key)
	ecdsa.private_key_clear(&peer_p256)
	peer_signer = .Ed25519
	peer_cert_n = 0
}

conn_wipe :: proc(conn: ^Conn) {
	crypto.zero_explicit(&conn.in_key, size_of(conn.in_key))
	crypto.zero_explicit(&conn.out_key, size_of(conn.out_key))
	crypto.zero_explicit(&conn.in_iv, size_of(conn.in_iv))
	crypto.zero_explicit(&conn.out_iv, size_of(conn.out_iv))
	crypto.zero_explicit(&conn.client_secret, size_of(conn.client_secret))
	crypto.zero_explicit(&conn.server_secret, size_of(conn.server_secret))
}
