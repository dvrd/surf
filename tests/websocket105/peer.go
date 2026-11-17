// Loopback TLS peer for the surf async WebSocket client. Speaks RFC 6455 over
// TLS 1.3. It does not negotiate HTTP/2 or QUIC.
package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	cert, err := tls.LoadX509KeyPair(
		"../../../async/tests/connection/testdata/peer/credentials/leaf.pem",
		"../../../async/tests/connection/testdata/peer/credentials/key.pem",
	)
	if err != nil {
		panic(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println(ln.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	for i := 0; i < 2; i++ {
		raw, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept", err)
			return
		}
		handle(raw, cfg, i == 0)
	}
}

func handle(raw net.Conn, cfg *tls.Config, echo bool) {
	defer func() { _ = recover() }()
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Server(raw, cfg)
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		if echo {
			fmt.Fprintln(os.Stderr, "handshake", err)
		}
		return
	}
	if !echo {
		return
	}
	header, err := readHeader(conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "header", err)
		return
	}
	key := headerValue(header, "Sec-WebSocket-Key")
	if key == "" {
		fmt.Fprintln(os.Stderr, "missing key")
		return
	}
	protocol := ""
	if strings.Contains(header, "Sec-WebSocket-Protocol: chat") {
		protocol = "chat"
	}
	if _, err = conn.Write([]byte(switching(key, protocol))); err != nil {
		fmt.Fprintln(os.Stderr, "101", err)
		return
	}
	payload, err := readText(conn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read", err)
		return
	}
	if err = writeFragments(conn, payload); err != nil {
		fmt.Fprintln(os.Stderr, "echo", err)
		return
	}
	if err = writeFrame(conn, true, 8, []byte{0x03, 0xe8}); err != nil {
		fmt.Fprintln(os.Stderr, "close", err)
		return
	}
	discard := make([]byte, 256)
	for {
		if _, err = conn.Read(discard); err != nil {
			return
		}
	}
}

func readHeader(r io.Reader) (string, error) {
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 256)
	for len(buf) < 8192 {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if strings.Contains(string(buf), "\r\n\r\n") {
				return string(buf), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
	return "", io.ErrShortBuffer
}

func headerValue(header, name string) string {
	at := strings.Index(header, name+": ")
	if at < 0 {
		return ""
	}
	rest := header[at+len(name)+2:]
	end := strings.Index(rest, "\r\n")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}

func switching(key, protocol string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	body := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n"
	if protocol != "" {
		body += "Sec-WebSocket-Protocol: " + protocol + "\r\n"
	}
	return body + "\r\n"
}

func readText(r io.Reader) ([]byte, error) {
	var out []byte
	saw := false
	for {
		opcode, payload, fin, err := readFrame(r)
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 1:
			if saw {
				return nil, io.ErrUnexpectedEOF
			}
			saw = true
			out = append(out, payload...)
		case 0:
			if !saw {
				return nil, io.ErrUnexpectedEOF
			}
			out = append(out, payload...)
		case 8:
			return nil, io.EOF
		case 9, 10:
			continue
		default:
			return nil, io.ErrUnexpectedEOF
		}
		if saw && fin && opcode != 9 && opcode != 10 {
			if opcode == 0 || opcode == 1 {
				return out, nil
			}
		}
	}
}

func readFrame(r io.Reader) (opcode byte, payload []byte, fin bool, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0f
	if hdr[1]&0x80 == 0 {
		err = io.ErrUnexpectedEOF
		return
	}
	ln := int(hdr[1] & 0x7f)
	switch ln {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		ln = int(ext[0])<<8 | int(ext[1])
	case 127:
		err = io.ErrShortBuffer
		return
	}
	mask := make([]byte, 4)
	if _, err = io.ReadFull(r, mask); err != nil {
		return
	}
	payload = make([]byte, ln)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

func writeFragments(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return writeFrame(w, true, 1, payload)
	}
	for at := 0; at < len(payload); {
		step := 4
		if step > len(payload)-at {
			step = len(payload) - at
		}
		opcode := byte(0)
		if at == 0 {
			opcode = 1
		}
		fin := at+step == len(payload)
		if err := writeFrame(w, fin, opcode, payload[at:at+step]); err != nil {
			return err
		}
		at += step
	}
	return nil
}

func writeFrame(w io.Writer, fin bool, opcode byte, payload []byte) error {
	frame := make([]byte, 2+len(payload))
	frame[0] = opcode
	if fin {
		frame[0] |= 0x80
	}
	frame[1] = byte(len(payload))
	copy(frame[2:], payload)
	for _, b := range frame {
		if _, err := w.Write([]byte{b}); err != nil {
			return err
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}
