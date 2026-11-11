// Loopback peer for the surf HTTP client. Stdlib only. No network installs.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	mode := flag.String("mode", "h2", "h2, http1, http1-noalpn, goaway")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(
		"../../../async/connection/tests/testdata/peer/credentials/leaf.pem",
		"../../../async/connection/tests/testdata/peer/credentials/key.pem",
	)
	if err != nil {
		fail(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
		},
	}
	switch *mode {
	case "h2":
		cfg.NextProtos = []string{"h2"}
		serve(cfg, true, false)
	case "http1":
		cfg.NextProtos = []string{"http/1.1"}
		serve(cfg, false, false)
	case "http1-noalpn":
		serve(cfg, false, true)
	case "goaway":
		cfg.NextProtos = []string{"h2"}
		goaway(cfg)
	default:
		fail(os.ErrInvalid)
	}
}

func serve(cfg *tls.Config, h2 bool, omitALPN bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	tlsLn := tls.NewListener(ln, cfg)
	protocols := new(http.Protocols)
	server := &http.Server{Handler: http.HandlerFunc(route), ConnState: connState}
	if h2 {
		protocols.SetHTTP2(true)
		server.Protocols = protocols
	} else {
		protocols.SetHTTP1(true)
		server.Protocols = protocols
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		if omitALPN {
			cfg.NextProtos = nil
		}
	}
	emit(map[string]any{"event": "ready", "port": port})
	if err := server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
		fail(err)
	}
}

func connState(c net.Conn, state http.ConnState) {
	if state != http.StateNew {
		return
	}
	alpn := ""
	if tc, ok := c.(*tls.Conn); ok {
		alpn = tc.ConnectionState().NegotiatedProtocol
	}
	emit(map[string]any{"event": "conn", "alpn": alpn})
}

func route(w http.ResponseWriter, r *http.Request) {
	emit(map[string]any{"event": "request", "path": r.URL.Path})
	switch r.URL.Path {
	case "/buffered-headers":
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, strings.Join([]string{r.Proto, r.Method,
			r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Header.Get("Content-Type"),
			strings.Join(r.Header.Values("X-Review"), ","), string(body)}, "|"))
	case "/blob":
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 0 || n > 1<<20 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = 'a'
		}
		flusher, _ := w.(http.Flusher)
		left := n
		for left > 0 {
			chunk := buf
			if left < len(chunk) {
				chunk = buf[:left]
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			left -= len(chunk)
		}
	case "/reset":
		panic(http.ErrAbortHandler)
	case "/stall", "/cancel":
		time.Sleep(8 * time.Second)
		_, _ = io.WriteString(w, "late")
	default:
		_, _ = io.WriteString(w, r.URL.Path)
	}
}

func goaway(cfg *tls.Config) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		fail(err)
	}
	defer ln.Close()
	emit(map[string]any{"event": "ready", "port": ln.Addr().(*net.TCPAddr).Port})
	conn, err := ln.Accept()
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for !bytes.Contains(buf, preface) {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			fail(readErr)
		}
		if len(buf) > 1<<16 {
			fail(os.ErrInvalid)
		}
	}
	flight := append(frame(4, 0, nil), frame(4, 1, nil)...)
	flight = append(flight, frame(7, 0, make([]byte, 8))...)
	if _, err := conn.Write(flight); err != nil {
		fail(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	at := bytes.Index(buf, preface)
	rest := buf[at+len(preface):]
	headers := 0
	for len(rest) >= 9 {
		length := int(rest[0])<<16 | int(rest[1])<<8 | int(rest[2])
		if length < 0 || len(rest) < 9+length {
			break
		}
		if rest[3] == 1 {
			headers++
		}
		rest = rest[9+length:]
	}
	emit(map[string]any{"event": "goaway", "headers": headers})
}

func frame(kind, flags byte, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	n := len(payload)
	out[0] = byte(n >> 16)
	out[1] = byte(n >> 8)
	out[2] = byte(n)
	out[3] = kind
	out[4] = flags
	copy(out[9:], payload)
	return out
}

func emit(v map[string]any) {
	_ = json.NewEncoder(os.Stdout).Encode(v)
	_ = os.Stdout.Sync()
}

func fail(err error) {
	emit(map[string]any{"event": "error", "error": err.Error()})
	os.Exit(1)
}
