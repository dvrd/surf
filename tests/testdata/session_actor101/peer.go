// Owned independent Actor18 peer. Standard Go TLS/HTTP codecs; no native SDK.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type requestFact struct {
	Connection int    `json:"connection"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	BodyBytes  int64  `json:"body_bytes"`
	AtNS       int64  `json:"at_ns"`
}
type peer struct {
	mu                      sync.Mutex
	start                   time.Time
	mode, dir               string
	encrypted               bool
	connections, handshakes int
	requests                []requestFact
	dns                     []map[string]any
	events                  []map[string]any
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func (p *peer) event(kind string, fields map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fields["event"] = kind
	fields["at_ns"] = time.Since(p.start).Nanoseconds()
	p.events = append(p.events, fields)
	must(json.NewEncoder(os.Stdout).Encode(fields))
}
func (p *peer) mark(name string) { must(os.WriteFile(filepath.Join(p.dir, name), []byte(name), 0600)) }
func (p *peer) wait(name string, timeout time.Duration) bool {
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		if _, e := os.Stat(filepath.Join(p.dir, name)); e == nil {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}
func (p *peer) certificate() *tls.Config {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1801), Subject: pkix.Name{CommonName: "actor.test"}, DNSNames: []string{"actor.test", "cheap.actor.test", "stall.actor.test"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(e)
	must(os.WriteFile(filepath.Join(p.dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, NextProtos: []string{"http/1.1"}}
}

// Delays only independently observed raw record writes; it never parses TLS
// plaintext, edits SDK state, or produces fake handshake completion.
type recordConn struct {
	net.Conn
	p                         *peer
	id                        int
	handshakeDelayed, partial bool
	mu                        sync.Mutex
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	partial := c.partial
	c.partial = false
	delay := !c.handshakeDelayed && (c.p.mode == "setup-deadline" || c.p.mode == "body-deadline")
	if delay {
		c.handshakeDelayed = true
	}
	c.mu.Unlock()
	if delay {
		c.p.event("server_record_held", map[string]any{"connection": c.id, "bytes": len(b), "record_type": int(b[0])})
		if c.p.mode == "body-deadline" {
			time.Sleep(80 * time.Millisecond)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if partial && len(b) > 1 {
		n, e := c.Conn.Write(b[:1])
		if e != nil {
			return n, e
		}
		c.p.event("partial_record_staged", map[string]any{"connection": c.id, "bytes": n, "record_type": int(b[0]), "full_bytes": len(b)})
		c.p.mark("staged")
		time.Sleep(500 * time.Millisecond)
		rest, e := c.Conn.Write(b[1:])
		return n + rest, e
	}
	return c.Conn.Write(b)
}
func (p *peer) serve(raw net.Conn, id int, config *tls.Config) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	records := &recordConn{Conn: raw, p: p, id: id}
	var conn net.Conn = records
	if p.encrypted {
		secure := tls.Server(records, config)
		if e := secure.Handshake(); e != nil {
			p.event("handshake_error", map[string]any{"connection": id, "error": e.Error()})
			return
		}
		cs := secure.ConnectionState()
		p.mu.Lock()
		p.handshakes++
		p.mu.Unlock()
		p.event("handshake", map[string]any{"connection": id, "version": cs.Version, "cipher": cs.CipherSuite, "alpn": cs.NegotiatedProtocol, "server_name": cs.ServerName})
		conn = secure
	}
	reader := bufio.NewReader(conn)
	for {
		request, e := http.ReadRequest(reader)
		if e != nil {
			p.event("read_terminal", map[string]any{"connection": id, "error": e.Error()})
			return
		}
		fact := requestFact{Connection: id, Path: request.URL.Path, Method: request.Method, AtNS: time.Since(p.start).Nanoseconds()}
		p.event("request_head", map[string]any{"connection": id, "path": fact.Path, "method": fact.Method, "content_length": request.ContentLength})
		if p.mode == "uncertain" && fact.Method == "POST" {
			var one [1]byte
			n, _ := io.ReadFull(request.Body, one[:])
			fact.BodyBytes = int64(n)
			p.mu.Lock()
			p.requests = append(p.requests, fact)
			p.mu.Unlock()
			p.event("uncertain_post_reset", map[string]any{"connection": id, "body_bytes": n, "body_first": int(one[0])})
			p.mark("uncertain")
			if tcp, ok := raw.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			return
		}
		fact.BodyBytes, e = io.Copy(io.Discard, io.LimitReader(request.Body, 2<<20))
		if e != nil {
			p.event("body_error", map[string]any{"connection": id, "error": e.Error()})
			return
		}
		must(request.Body.Close())
		p.mu.Lock()
		p.requests = append(p.requests, fact)
		p.mu.Unlock()
		body := "A"
		if request.URL.Path == "/B" {
			body = "B"
		}
		if request.URL.Path == "/C" {
			body = "C"
		}
		head := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Connection: %d\r\nConnection: keep-alive\r\n\r\n", id))
		if _, e = conn.Write(head); e != nil {
			p.event("write_error", map[string]any{"connection": id, "error": e.Error()})
			return
		}
		if request.URL.Path == "/A" && (p.mode == "body-deadline" || p.mode == "cancel-read" || p.mode == "one-worker" || p.mode == "lifetime" || p.mode == "reuse-waiter") {
			p.event("body_held", map[string]any{"connection": id})
			p.mark("A.stalled")
			delay := 600 * time.Millisecond
			if p.mode == "body-deadline" {
				delay = 300 * time.Millisecond
			}
			if p.mode == "reuse-waiter" {
				if !p.wait("releaseA", 5*time.Second) {
					panic("releaseA timeout")
				}
			} else {
				time.Sleep(delay)
			}
		}
		if request.Method != "HEAD" {
			if _, e = conn.Write([]byte(body)); e != nil {
				p.event("write_error", map[string]any{"connection": id, "error": e.Error()})
				return
			}
		}
		p.event("response", map[string]any{"connection": id, "path": fact.Path, "body": body})
		if request.URL.Path == "/A" && (p.mode == "stale" || p.mode == "partial" || p.mode == "close") {
			if !p.wait("A.done", 5*time.Second) {
				p.event("coordination_timeout", map[string]any{"connection": id})
				return
			}
			if p.mode == "close" {
				p.event("stale_close", map[string]any{"connection": id})
				p.mark("staged")
				return
			}
			if p.mode == "partial" && p.encrypted {
				records.mu.Lock()
				records.partial = true
				records.mu.Unlock()
			}
			if p.mode == "partial" && !p.encrypted {
				_, e = conn.Write([]byte{'O'})
				p.event("partial_raw_staged", map[string]any{"connection": id, "bytes": 1})
				p.mark("staged")
			} else {
				_, e = conn.Write([]byte("OLD"))
				if p.mode != "partial" {
					p.mark("staged")
				}
			}
			if e != nil {
				p.event("stale_write_error", map[string]any{"connection": id, "error": e.Error()})
			}
		}
	}
}
func dnsQuestion(wire []byte) (string, uint16, int, error) {
	if len(wire) < 12 || binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return "", 0, 0, fmt.Errorf("invalid DNS header")
	}
	at := 12
	name := ""
	for {
		if at >= len(wire) {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		n := int(wire[at])
		at++
		if n == 0 {
			break
		}
		if n > 63 || at+n > len(wire) {
			return "", 0, 0, fmt.Errorf("invalid DNS label")
		}
		if name != "" {
			name += "."
		}
		name += string(wire[at : at+n])
		at += n
	}
	if at+4 != len(wire) {
		return "", 0, 0, fmt.Errorf("unexpected DNS tail")
	}
	return name, binary.BigEndian.Uint16(wire[at : at+2]), at + 4, nil
}
func (p *peer) dnsServe(socket *net.UDPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 4096)
	for {
		n, source, e := socket.ReadFromUDP(buf)
		if e != nil {
			return
		}
		wire := append([]byte(nil), buf[:n]...)
		name, qtype, end, e := dnsQuestion(wire)
		must(e)
		fact := map[string]any{"name": name, "type": qtype, "id": binary.BigEndian.Uint16(wire[:2]), "at_ns": time.Since(p.start).Nanoseconds()}
		p.mu.Lock()
		p.dns = append(p.dns, fact)
		p.mu.Unlock()
		p.event("dns_query", fact)
		p.mark("DNS.seen")
		if p.mode == "setup-deadline" {
			time.Sleep(150 * time.Millisecond)
		} else if p.mode == "body-deadline" {
			time.Sleep(80 * time.Millisecond)
		}
		reply := append([]byte(nil), wire[:end]...)
		binary.BigEndian.PutUint16(reply[2:4], 0x8180)
		if qtype == 1 {
			binary.BigEndian.PutUint16(reply[6:8], 1)
			reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
		}
		_, e = socket.WriteToUDP(reply, source)
		if e != nil {
			return
		}
		p.event("dns_reply", map[string]any{"name": name, "type": qtype})
	}
}
func main() {
	mode := flag.String("mode", "healthy", "owned schedule")
	encrypted := flag.Bool("tls", false, "TLS13")
	dir := flag.String("dir", "", "fixture directory")
	flag.Parse()
	must(os.MkdirAll(*dir, 0700))
	p := &peer{start: time.Now(), mode: *mode, dir: *dir, encrypted: *encrypted}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	dns, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(e)
	var config *tls.Config
	if p.encrypted {
		config = p.certificate()
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "ready", "tcp": listener.Addr().String(), "dns": dns.LocalAddr().String(), "mode": p.mode, "tls": p.encrypted, "go": runtime.Version()}))
	var wg sync.WaitGroup
	wg.Add(1)
	go p.dnsServe(dns, &wg)
	done := make(chan struct{})
	go func() { defer close(done); p.wait("finish", 15*time.Second); listener.Close(); dns.Close() }()
	for {
		conn, e := listener.Accept()
		if e != nil {
			break
		}
		p.mu.Lock()
		p.connections++
		id := p.connections
		p.mu.Unlock()
		p.event("accept", map[string]any{"connection": id})
		wg.Add(1)
		go func() { defer wg.Done(); p.serve(conn, id, config) }()
	}
	<-done
	wg.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "summary", "mode": p.mode, "tls": p.encrypted, "connections": p.connections, "handshakes": p.handshakes, "requests": p.requests, "dns": p.dns, "events": p.events}))
}
