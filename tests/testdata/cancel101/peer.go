// Literal owned phase barriers; only Go net/http parses HTTP requests.
package main

import (
	"bufio"
	"bytes"
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
	"strings"
	"sync"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func waitFile(path string) {
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		if _, e := os.Stat(path); e == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	panic("barrier timeout " + path)
}
func mark(dir, name string) { must(os.WriteFile(filepath.Join(dir, name), []byte(name), 0600)) }

type observation struct {
	ID            int    `json:"connection_id"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	RequestBytes  int    `json:"request_bytes"`
	ContentLength int64  `json:"content_length"`
	ALPN          string `json:"alpn"`
	TLS           uint16 `json:"negotiated_tls"`
	ClientHello   int    `json:"clienthello_bytes"`
	ResponseBytes int    `json:"response_bytes"`
}

func main() {
	phase := flag.String("phase", "body", "held phase")
	encrypted := flag.Bool("tls", false, "TLS held connection")
	dir := flag.String("dir", "", "barriers")
	flag.Parse()
	switch *phase {
	case "dns", "tls", "write", "header", "body", "redirect", "queued", "rawconnect":
	default:
		panic("unsupported owned phase")
	}
	must(os.MkdirAll(*dir, 0700))
	var mu sync.Mutex
	events := []observation{}
	dnsIDs := []uint16{}
	dnsNames := []string{}
	dnsTypes := []uint16{}
	dnsBytes := []int{}
	cheapBeforeRelease := false
	var config *tls.Config
	if *encrypted {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(e)
		cert := &x509.Certificate{SerialNumber: big.NewInt(130), Subject: pkix.Name{CommonName: "cancel101"}, DNSNames: []string{"held.cancel.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		must(e)
		must(os.WriteFile(filepath.Join(*dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		config = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	}
	dns, e := net.ListenPacket("udp4", "127.0.0.1:0")
	must(e)
	defer dns.Close()
	must(os.WriteFile(filepath.Join(*dir, "dns.endpoint"), []byte(dns.LocalAddr().String()), 0600))
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		var b [4096]byte
		for {
			n, _, e := dns.ReadFrom(b[:])
			if e != nil {
				return
			}
			if n < 17 {
				panic("DNS question too short")
			}
			at := 12
			labels := []string{}
			for {
				if at >= n {
					panic("DNS label bound")
				}
				length := int(b[at])
				at++
				if length == 0 {
					break
				}
				if length > 63 || at+length > n {
					panic("DNS label shape")
				}
				labels = append(labels, string(b[at:at+length]))
				at += length
			}
			if at+4 > n {
				panic("DNS question tail")
			}
			name := strings.Join(labels, ".")
			typ := binary.BigEndian.Uint16(b[at : at+2])
			if name != "held.cancel.test" || (typ != 1 && typ != 28) {
				panic("unexpected named query")
			}
			mu.Lock()
			dnsNames = append(dnsNames, name)
			dnsTypes = append(dnsTypes, typ)
			dnsBytes = append(dnsBytes, n)
			dnsIDs = append(dnsIDs, binary.BigEndian.Uint16(b[:2]))
			mu.Unlock()
			if *phase != "dns" {
				panic("unexpected external DNS")
			}
			mark(*dir, "held")
		}
	}()
	cheap, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	defer cheap.Close()
	must(os.WriteFile(filepath.Join(*dir, "cheap.endpoint"), []byte(cheap.Addr().String()), 0600))
	cheapDone := make(chan struct{})
	cheapServe := func() {
		defer close(cheapDone)
		conn, e := cheap.Accept()
		must(e)
		defer conn.Close()
		must(conn.SetDeadline(time.Now().Add(12 * time.Second)))
		var cheapStream net.Conn = conn
		cheapALPN := ""
		cheapVersion := uint16(0)
		if *phase == "rawconnect" && *encrypted {
			secure := tls.Server(conn, config)
			must(secure.Handshake())
			cheapStream = secure
			cheapALPN = secure.ConnectionState().NegotiatedProtocol
			cheapVersion = secure.ConnectionState().Version
		}
		var captured bytes.Buffer
		r, e := httpRead(cheapStream, &captured)
		must(e)
		if r.method != "GET" || r.path != "/cheap" || r.length != 0 {
			panic("cheap request")
		}
		if _, e := os.Stat(filepath.Join(*dir, "release")); e == nil {
			panic("cheap completed after held release")
		}
		n, e := io.WriteString(cheapStream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		must(e)
		mu.Lock()
		cheapBeforeRelease = true
		events = append(events, observation{ID: 100, ALPN: cheapALPN, TLS: cheapVersion, Method: r.method, Path: r.path, RequestBytes: captured.Len(), ResponseBytes: n})
		mu.Unlock()
	}
	held, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	defer held.Close()
	heldAddr := held.Addr().String()

	go cheapServe()
	heldDone := make(chan struct{})
	go func() {
		defer close(heldDone)
		if *phase == "dns" {
			waitFile(filepath.Join(*dir, "done"))
			return
		}
		limit := 1
		if *phase == "redirect" {
			limit = 2
		}
		for id := 1; id <= limit; id++ {
			conn, e := held.Accept()
			must(e)
			must(conn.SetDeadline(time.Now().Add(12 * time.Second)))
			if *phase == "write" {
				must(conn.(*net.TCPConn).SetReadBuffer(1024))
			}
			var stream net.Conn = conn
			obs := observation{ID: id}
			if *phase == "rawconnect" {
				mark(*dir, "held")
				waitFile(filepath.Join(*dir, "done"))
				var one [1]byte
				n, e := conn.Read(one[:])
				if n != 0 || e == nil {
					panic("raw Connecting slot sent unexpected application bytes")
				}
				obs.RequestBytes = n
				mu.Lock()
				events = append(events, obs)
				mu.Unlock()
				conn.Close()
				return
			}
			if *phase == "tls" {
				var head [5]byte
				_, e = io.ReadFull(conn, head[:])
				must(e)
				if head[0] != 22 {
					panic("not ClientHello TLS record")
				}
				length := int(binary.BigEndian.Uint16(head[3:]))
				if length < 4 || length > 16384 {
					panic("hello bound")
				}
				body := make([]byte, length)
				_, e = io.ReadFull(conn, body)
				must(e)
				if body[0] != 1 {
					panic("not ClientHello message")
				}
				obs.ClientHello = length + 5
			} else {
				if config != nil {
					secure := tls.Server(conn, config)
					must(secure.Handshake())
					stream = secure
					obs.ALPN = secure.ConnectionState().NegotiatedProtocol
					obs.TLS = secure.ConnectionState().Version
				}
				var captured bytes.Buffer
				r, e := httpRead(stream, &captured)
				must(e)
				obs.Method = r.method
				obs.Path = r.path
				obs.ContentLength = r.length
				obs.RequestBytes = captured.Len()
				if r.path != "/held" && r.path != "/redirected" {
					panic("held path")
				}
				if *phase == "write" && r.length < 16<<20 {
					panic("write fixture not large")
				}
				if *phase == "redirect" && id == 1 {
					n, e := io.WriteString(stream, "HTTP/1.1 307 Redirect\r\nLocation: /redirected\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
					must(e)
					obs.ResponseBytes = n
					mu.Lock()
					events = append(events, obs)
					mu.Unlock()
					var b [1]byte
					n, e = stream.Read(b[:])
					if n != 0 || e == nil {
						panic("old redirect stream replay or no close")
					}
					conn.Close()
					continue
				}
				if *phase == "body" || *phase == "queued" {
					n, e := io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhe")
					must(e)
					obs.ResponseBytes = n
				}
			}
			mu.Lock()
			events = append(events, obs)
			mu.Unlock()
			mark(*dir, "held")
			waitFile(filepath.Join(*dir, "done"))
			conn.Close()
		}
	}()
	fmt.Println(heldAddr)
	waitFile(filepath.Join(*dir, "done"))
	mark(*dir, "release")
	dns.Close()
	if held != nil {
		held.Close()
	}
	cheap.Close()
	<-dnsDone
	<-heldDone
	<-cheapDone
	mu.Lock()
	defer mu.Unlock()
	out, e := json.Marshal(map[string]any{"phase": *phase, "tls": *encrypted, "events": events, "dns_ids": dnsIDs, "dns_names": dnsNames, "dns_types": dnsTypes, "dns_bytes": dnsBytes, "cheap_before_release": cheapBeforeRelease})
	must(e)
	fmt.Println(string(out))
}

// Go's parser, through a bounded header reader, supplies independent semantics.
type request struct {
	method, path string
	length       int64
}

func httpRead(conn net.Conn, capture io.Writer) (request, error) {
	r, e := http.ReadRequest(bufio.NewReader(io.TeeReader(conn, capture)))
	if e != nil {
		return request{}, e
	}
	return request{r.Method, r.URL.RequestURI(), r.ContentLength}, nil
}
