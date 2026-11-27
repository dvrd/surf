package surf

import "core:mem"
import "core:net"
import "core:strings"
import "shared:async"

// The URL the response at status redirects current to, allocated with allocator.
redirect_next :: proc(
	status: int,
	headers: []async.Http_Header,
	current: async.Http_Request,
	u: async.Http_URL,
	config: Config,
	redirects: int,
	allocator: mem.Allocator,
) -> (
	string,
	HTTP_Error,
) {
	if redirects >= config.max_redirects {
		return "", {kind = .Redirect_Limit}
	}

	if current.method != .GET && status != 307 && status != 308 {
		return "", {kind = .Unsafe_Redirect}
	}

	location: string
	locations := 0
	for h in headers {
		if strings.equal_fold(h.name, "Location") {
			if locations == 0 {
				location = h.value
			}
			locations += 1
		}
	}

	if locations != 1 {
		return "", {kind = .Invalid_Redirect}
	}

	new_url, resolve_err := redirect_url(u, location, allocator)
	if resolve_err.kind != .None {
		return "", resolve_err
	}

	new_parsed, parse_err := async.http_url_parse(new_url)
	if parse_err.kind != .None {
		delete(new_url, allocator)
		return "", {kind = .Invalid_Redirect}
	}

	if u.secure && !new_parsed.secure || !new_parsed.secure && !config.allow_http {
		delete(new_url, allocator)
		return "", {kind = .Insecure_URL}
	}

	if !redirect_origin_safe(current, u, new_parsed) {
		delete(new_url, allocator)
		return "", {kind = .Unsafe_Redirect}
	}

	// A name is checked after the next hop resolves. An IP literal is already
	// the address that would be dialed, so refuse it before following the hop.
	if config.address_policy != nil {
		if literal := net.parse_address(new_parsed.host); literal != nil {
			endpoint := net.Endpoint {
				address = literal,
				port    = new_parsed.port,
			}
			if rejected := address_policy_check(config, new_parsed.host, []net.Endpoint{endpoint});
			   rejected.kind != .None {
				delete(new_url, allocator)
				return "", rejected
			}
		}
	}
	return new_url, {}
}

redirect_origin_safe :: proc(request: async.Http_Request, previous, next: async.Http_URL) -> bool {
	cross_origin :=
		previous.secure != next.secure ||
		previous.port != next.port ||
		!strings.equal_fold(previous.host, next.host)

	if !cross_origin {
		return true
	}

	// Only a GET with public media headers may cross origins automatically.
	if request.method != .GET {
		return false
	}

	for header in request.headers {
		safe := false

		for name in ([?]string{"Accept", "Content-Type", "Origin", "User-Agent"}) {
			if strings.equal_fold(header.name, name) {
				safe = true
			}
		}

		if !safe {
			return false
		}
	}

	return true
}


// Resolve absolute, network-path, root-relative, query-only and relative paths.
// Dot segments are removed without decoding percent escapes (RFC3986 section5).
redirect_url :: proc(
	base: async.Http_URL,
	location: string,
	allocator: mem.Allocator,
) -> (
	string,
	HTTP_Error,
) {
	if len(location) == 0 || len(location) > async.HTTP_MAX_HEADER_SIZE {
		return "", {kind = .Invalid_Redirect}
	}

	parts: [5]string
	count := redirect_parts(base, location, &parts)

	size := 0
	for p in parts[:count] {
		size += len(p)
	}

	if size > async.HTTP_MAX_HEADER_SIZE {
		return "", {kind = .Invalid_Redirect}
	}

	storage, ae := make([]u8, size, allocator)

	if ae != nil {
		return "", {kind = .Allocation_Failed, allocation = ae}
	}

	at := 0
	for p in parts[:count] {
		at += copy(storage[at:], transmute([]u8)p)
	}
	parsed, pe := async.http_url_parse(cast(string)storage)

	if pe.kind != .None {
		delete(storage, allocator)
		return "", {kind = .Invalid_Redirect}
	}

	if parsed.target == "" || parsed.target[0] == '?' {
		return cast(string)storage, {}
	}

	normalized: [async.HTTP_MAX_HEADER_SIZE]u8
	n := redirect_path_normalize(normalized[:], parsed.target)
	prefix_size := len(storage) - len(parsed.target)
	copy(storage[prefix_size:], normalized[:n])
	// Return an allocation of exact length so deletion always frees the base.
	if n == len(parsed.target) {
		return cast(string)storage, {}
	}

	result, ae2 := make([]u8, prefix_size + n, allocator)

	if ae2 != nil {
		delete(storage, allocator)
		return "", {kind = .Allocation_Failed, allocation = ae2}
	}

	copy(result, storage[:prefix_size + n])
	delete(storage, allocator)

	return cast(string)result, {}
}

redirect_parts :: proc(base: async.Http_URL, location: string, parts: ^[5]string) -> int {
	assert(len(location) > 0 && len(location) <= async.HTTP_MAX_HEADER_SIZE)
	count := 0
	scheme_end := strings.index_byte(location, ':')
	path_end := len(location)

	if i := strings.index_any(location, "/?"); i >= 0 {
		path_end = i
	}

	if scheme_end >= 0 && scheme_end < path_end {
		parts[0], count = location, 1
	} else if strings.has_prefix(location, "//") {
		parts[0], parts[1], parts[2], count = base.scheme, ":", location, 3
	} else if location[0] == '/' {
		parts[0], parts[1], parts[2], parts[3], count =
			base.scheme, "://", base.authority, location, 4
	} else if location[0] == '?' {
		target := base.target
		if target == "" || target[0] == '?' {
			target = "/"
		}

		if i := strings.index_byte(target, '?'); i >= 0 {
			target = target[:i]
		}

		parts[0], parts[1], parts[2], parts[3], parts[4], count =
			base.scheme, "://", base.authority, target, location, 5
	} else {
		// RFC3986 relative path merging; normalize dot segments below.
		target := base.target

		if i := strings.index_byte(target, '?'); i >= 0 {
			target = target[:i]
		}

		if target == "" {
			target = "/"
		}

		last := strings.last_index_byte(target, '/')
		target = target[:last + 1]
		parts[0], parts[1], parts[2], parts[3], parts[4], count =
			base.scheme, "://", base.authority, target, location, 5
	}

	return count
}

redirect_path_normalize :: proc(dst: []u8, target: string) -> int {
	path, query := target, ""

	if i := strings.index_byte(path, '?'); i >= 0 {
		path, query = path[:i], path[i:]
	}

	at := 0

	for len(path) > 0 {
		if strings.has_prefix(path, "../") {
			path = path[3:]
			continue
		}

		if strings.has_prefix(path, "./") {
			path = path[2:]
			continue
		}

		if strings.has_prefix(path, "/./") {
			path = path[2:]
			continue
		}

		if path == "/." {
			path = "/"
			continue
		}

		if strings.has_prefix(path, "/../") || path == "/.." {
			if path == "/.." {
				path = "/"
			} else {
				path = path[3:]
			}

			if i := strings.last_index_byte(cast(string)dst[:at], '/'); i >= 0 {
				at = i
			} else {
				at = 0
			}

			continue
		}

		if path == "." || path == ".." {
			break
		}

		end := len(path)
		start := 0
		if path[0] == '/' {
			start = 1
		}

		if i := strings.index_byte(path[start:], '/'); i >= 0 {
			end = start + i
		}

		at += copy(dst[at:], transmute([]u8)path[:end])
		path = path[end:]
	}

	at += copy(dst[at:], transmute([]u8)query)

	return at
}

