package loopback

import "core:strconv"
import "core:strings"

// One HTTP/1 request. method, path, target, and body alias `pending` and die
// with it. body_cap is the most body bytes a caller will keep: a larger
// Content-Length is reported as overflow once that many bytes plus one are
// buffered, so a hostile length cannot force a full read.
Head :: struct {
	method:   string,
	path:     string,
	target:   string,
	headers:  string, // request line and fields, aliasing pending
	body:     []u8,
	consumed: int,
}

take_request :: proc(pending: []u8, body_cap: int) -> (head: Head, complete, overflow, ok: bool) {
	if body_cap < 0 {
		return {}, false, false, false
	}
	text := string(pending)
	split := strings.index(text, "\r\n\r\n")
	if split < 0 {
		return {}, false, false, true
	}
	headers := text[:split]
	line_end := strings.index(headers, "\r\n")
	line := headers if line_end < 0 else headers[:line_end]
	method, target, _, parsed := request_line(line)
	if !parsed {
		return {}, true, false, false
	}
	length, length_ok := content_length(headers)
	if !length_ok || length < 0 {
		return {}, true, false, false
	}
	body_at := split + 4
	if length > body_cap {
		need := body_at + body_cap + 1
		if len(pending) < need {
			return {}, false, false, true
		}
		return {}, true, true, false
	}
	if len(pending) < body_at + length {
		return {}, false, false, true
	}
	head.method = method
	head.target = target
	head.headers = headers
	head.path = target
	if query := strings.index(target, "?"); query >= 0 {
		head.path = target[:query]
	}
	head.body = pending[body_at:][:length]
	head.consumed = body_at + length
	return head, true, false, true
}

request_line :: proc(line: string) -> (method, target, version: string, ok: bool) {
	first := strings.index(line, " ")
	if first <= 0 {
		return
	}
	second := strings.index(line[first + 1:], " ")
	if second <= 0 {
		return
	}
	second += first + 1
	method = line[:first]
	target = line[first + 1:second]
	version = line[second + 1:]
	if len(target) == 0 || len(version) == 0 {
		return
	}
	return method, target, version, true
}

header_value :: proc(headers, name: string) -> (value: string, found: bool) {
	rest := headers
	if cut := strings.index(rest, "\r\n"); cut >= 0 {
		rest = rest[cut + 2:]
	}
	for len(rest) > 0 {
		line := rest
		if cut := strings.index(rest, "\r\n"); cut >= 0 {
			line = rest[:cut]
			rest = rest[cut + 2:]
		} else {
			rest = ""
		}
		colon := strings.index(line, ":")
		if colon <= 0 {
			continue
		}
		if !strings.equal_fold(strings.trim_space(line[:colon]), name) {
			continue
		}
		return strings.trim_space(line[colon + 1:]), true
	}
	return "", false
}

content_length :: proc(headers: string) -> (length: int, ok: bool) {
	rest := headers
	if cut := strings.index(rest, "\r\n"); cut >= 0 {
		rest = rest[cut + 2:]
	}
	seen := false
	for len(rest) > 0 {
		line := rest
		if cut := strings.index(rest, "\r\n"); cut >= 0 {
			line = rest[:cut]
			rest = rest[cut + 2:]
		} else {
			rest = ""
		}
		colon := strings.index(line, ":")
		if colon <= 0 {
			continue
		}
		if !strings.equal_fold(strings.trim_space(line[:colon]), "content-length") {
			continue
		}
		value := strings.trim_space(line[colon + 1:])
		parsed, valid := strconv.parse_int(value, 10)
		if !valid || parsed < 0 {
			return 0, false
		}
		if seen && parsed != length {
			return 0, false
		}
		length = parsed
		seen = true
	}
	return length, true
}
