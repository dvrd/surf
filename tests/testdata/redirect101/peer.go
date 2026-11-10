// Owned literal HTTP peer. Request parsing is Go's independent net/http parser.
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
	"strconv"
	"strings"
	"sync"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}

type event struct {
	ID           int         `json:"connection_id"`
	Order        int         `json:"order"`
	Method       string      `json:"method"`
	Host         string      `json:"host"`
	Path         string      `json:"path"`
	Body         string      `json:"body"`
	ALPN         string      `json:"alpn"`
	TLS          uint16      `json:"negotiated_tls"`
	Bytes        int         `json:"response_bytes"`
	RequestBytes int         `json:"request_bytes"`
	Headers      http.Header `json:"headers"`
	OldClosed    bool        `json:"old_stream_closed"`
	Status       int         `json:"response_status"`
}

func main() {
	mode := flag.String("mode", "get301", "case")
	encrypted := flag.Bool("tls", false, "TLS13")
	dir := flag.String("dir", "", "barriers")
	flag.Parse()
	must(os.MkdirAll(*dir, 0700))
	first, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	defer first.Close()
	other, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	defer other.Close()
	var config *tls.Config
	if *encrypted {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(e)
		cert := &x509.Certificate{SerialNumber: big.NewInt(128), Subject: pkix.Name{CommonName: "redirect101"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"one.redirect.test", "two.redirect.test", "three.redirect.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		must(e)
		must(os.WriteFile(filepath.Join(*dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		config = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	}
	must(os.WriteFile(filepath.Join(*dir, "other.endpoint"), []byte(other.Addr().String()), 0600))
	dns, e := net.ListenPacket("udp4", "127.0.0.1:0")
	must(e)
	defer dns.Close()
	must(os.WriteFile(filepath.Join(*dir, "dns.endpoint"), []byte(dns.LocalAddr().String()), 0600))
	var mu sync.Mutex
	var acceptors, handlers sync.WaitGroup
	var rows []event
	var names []string
	nextID := 0
	go func() {
		var b [4096]byte
		for {
			n, addr, e := dns.ReadFrom(b[:])
			if e != nil {
				return
			}
			if n < 17 {
				panic("short DNS")
			}
			end := 12
			var labels []string
			for b[end] != 0 {
				l := int(b[end])
				end++
				if end+l >= n {
					panic("DNS bounds")
				}
				labels = append(labels, string(b[end:end+l]))
				end += l
			}
			end++
			if end+4 > n {
				panic("DNS question")
			}
			name := strings.Join(labels, ".")
			typ := binary.BigEndian.Uint16(b[end : end+2])
			questionEnd := end + 4
			mu.Lock()
			names = append(names, name)
			mu.Unlock()
			reply := append([]byte{}, b[:questionEnd]...)
			reply[2] = 0x81
			reply[3] = 0x80
			reply[6] = 0
			reply[7] = 0
			if typ == 1 {
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
			}
			_, e = dns.WriteTo(reply, addr)
			must(e)
		}
	}()
	serve := func(l net.Listener) {
		defer acceptors.Done()
		for {
			conn, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			nextID++
			id := nextID
			mu.Unlock()
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				must(conn.SetDeadline(time.Now().Add(12 * time.Second)))
				var stream net.Conn = conn
				alpn := ""
				version := uint16(0)
				if config != nil {
					t := tls.Server(conn, config)
					if e := t.Handshake(); e != nil {
						return
					}
					stream = t
					alpn = t.ConnectionState().NegotiatedProtocol
					version = t.ConnectionState().Version
					if alpn != "http/1.1" {
						panic("ALPN")
					}
				}
				var captured bytes.Buffer
				r, e := http.ReadRequest(bufio.NewReader(io.TeeReader(stream, &captured)))
				if e != nil {
					return
				}
				body, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				must(e)
				must(r.Body.Close())
				mu.Lock()
				order := len(rows) + 1
				rows = append(rows, event{ID: id, Order: order, Method: r.Method, Host: r.Host, Path: r.URL.RequestURI(), Body: string(body), ALPN: alpn, TLS: version, RequestBytes: captured.Len(), Headers: r.Header.Clone()})
				mu.Unlock()
				status := 302
				for _, s := range []string{"301", "302", "303", "307", "308"} {
					if strings.HasSuffix(*mode, s) {
						status, _ = strconv.Atoi(s)
					}
				}
				target := "/final"
				scheme := "http"
				if *encrypted {
					scheme = "https"
				}
				if strings.HasPrefix(*mode, "cross-") {
					target = scheme + "://" + other.Addr().String() + "/final"
				}
				if *mode == "downgrade" {
					target = "http://" + other.Addr().String() + "/final"
				}
				if *mode == "relative" {
					target = "../final?proof=relative"
				}
				if *mode == "loop" {
					target = r.URL.RequestURI()
				}
				if *mode == "hopcap" {
					target = "/hop/" + strconv.Itoa(order)
				}
				if *mode == "dns32" {
					host := "two.redirect.test"
					if order > 1 {
						host = "three.redirect.test"
					}
					_, port, _ := net.SplitHostPort(first.Addr().String())
					target = scheme + "://" + net.JoinHostPort(host, port) + "/start"
				}
				final := strings.HasPrefix(r.URL.Path, "/final")
				if *mode == "cutoff" {
					time.Sleep(80 * time.Millisecond)
					final = order >= 3
					target = "/hop/" + strconv.Itoa(order)
				}
				if *mode == "cancel" || *mode == "close" {
					final = order == 2
					if final {
						must(os.WriteFile(filepath.Join(*dir, "target-held"), []byte("headers"), 0600))
						for {
							if _, e := os.Stat(filepath.Join(*dir, "done")); e == nil {
								return
							}
							time.Sleep(time.Millisecond)
						}
					}
				}
				payload := "intermediate"
				if *mode == "bodycap" {
					payload = strings.Repeat("x", 65)
				}
				wire := ""
				if final {
					wire = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
					if r.Method != "HEAD" {
						wire += "final"
					}
				} else {
					wire = fmt.Sprintf("HTTP/1.1 %d Redirect\r\nLocation: %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", status, target, len(payload))
					if r.Method != "HEAD" {
						wire += payload
					}
				}
				n, e := io.WriteString(stream, wire)
				if e != nil && *mode != "cutoff" {
					panic(e)
				}
				mu.Lock()
				rows[order-1].Bytes = n
				rows[order-1].Status = status
				if final {
					rows[order-1].Status = 200
				}
				mu.Unlock()
				if !final {
					var one [1]byte
					count, err := stream.Read(one[:])
					if count != 0 {
						panic("redirect old stream received replay bytes")
					}
					if err == nil {
						panic("redirect old stream did not terminate")
					}
					if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
						panic("redirect old stream was not physically closed")
					}
					mu.Lock()
					rows[order-1].OldClosed = true
					mu.Unlock()
				}
			}()
		}
	}
	acceptors.Add(2)
	go serve(first)
	go serve(other)
	fmt.Println(first.Addr().String())
	until := time.Now().Add(18 * time.Second)
	for {
		if _, e := os.Stat(filepath.Join(*dir, "done")); e == nil {
			break
		}
		if time.Now().After(until) {
			panic("native completion timeout")
		}
		time.Sleep(time.Millisecond)
	}
	first.Close()
	other.Close()
	dns.Close()
	acceptors.Wait()
	drained := make(chan struct{})
	go func() { handlers.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		panic("peer handlers failed to drain")
	}
	mu.Lock()
	defer mu.Unlock()
	out, e := json.Marshal(map[string]any{"mode": *mode, "tls": *encrypted, "events": rows, "dns_names": names})
	must(e)
	fmt.Println(string(out))
}
