package surf

import "core:io"
import "core:mem"
import "core:net"
import "core:strings"
import "core:time"
import "shared:async"

HTTP_Error :: struct {
	kind:          HTTP_Error_Kind,
	transport:     net.Network_Error,
	network:       net.Network_Error,
	tls_error:     TLS_Failure,
	allocation:    mem.Allocator_Error,
	phase:         HTTP_Phase,
	write_effect:  HTTP_Write_Effect,
	// Last validated HTTP status, including failures while reading its body.
	status:        int,
	// Numeric external-provider code only; native paths leave it zero.
	provider_code: int,
	// Source-stream failure during a request upload; no path/body is retained.
	source_io:     io.Error,
	// Exact scope admission cause; allocator-enforced byte failures retain the
	// standard Allocation_Failed kind without guessing a concurrent cause.
	budget:        Budget_Failure,
	decoding:      Decode_Failure,
}

// Return false to refuse every address. user is Config.address_policy_data.
Address_Policy :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool

// Everything is borrowed for as long as a request or Client uses the Config.
TLS_Config :: struct {
	// Nil trusts the platform's roots.
	roots:              ^Trust_Roots,
	client_credentials: ^Client_Credentials,
	session_cache:      ^TLS_Session_Cache,
}

Config :: struct {
	// The server name always comes from the request URL.
	tls:                 TLS_Config,
	// Zero selects 8 MiB. All responses, including redirect bodies, are bounded.
	max_body_size:       int,
	// Zero disables automatic redirects; maximum 5. POST follows only 307/308.
	max_redirects:       int,
	// Zero selects 30s for the entire setup/I/O/redirect budget.
	timeout:             time.Duration,
	allow_http:          bool,
	// Zero uses the remaining total budget. A positive value bounds DNS+TCP+TLS
	// together for each new connection, always capped by the total deadline.
	setup_timeout:       time.Duration,
	// Empty name_servers reads the system resolver configuration.
	resolver:            net.Resolver_Options,
	// Nil allows every resolved address. Called with the URL host, the exact
	// endpoints about to be dialed, and address_policy_data, after DNS or an IP
	// literal is known and before any socket is opened. Each redirect hop is
	// checked the same way. A redirect to an IP literal is refused before that
	// hop is followed. Return false to refuse the whole set. Host and addresses
	// are valid only for the call. address_policy_data is borrowed for every
	// check this config performs. A pooled connection that is reused is not
	// resolved or passed through this policy again.
	address_policy:      Address_Policy,
	address_policy_data: rawptr,
	// Zero preserves unmanaged compatibility. Host supplies an operation Scope
	// below its connection/global hierarchy.
	scope:               async.Budget_Scope,
	// Trusted coverage for a caller arena whose BOTH backings are charged.
	// This reference does not extend the arena/storage lifetime.
	allocator_scope:     async.Budget_Scope,
	// Explicit HTTP/3. Default off. Cleartext is refused. A GET or HEAD without a
	// body falls back to TCP once when nothing reached the wire.
	http3:               bool,
	http3_qpack:         HTTP3_Qpack,
	http3_ecn:           bool,
	// Written only after an authenticated TLS response. Nil disables discovery.
	// An advertisement for the origin's own port turns HTTP/3 on for it.
	alt_svc:             ^Alt_Svc_Cache,
	// Nil gives each Client its own pool. Borrowed; must outlive every Client
	// that uses it.
	http3_pool:          ^HTTP3_Pool,
}

// Owns header strings/body. Do not copy and destroy twice. Destroy on success;
// errors return an empty response. Content-Encoding is not decompressed.
Response :: struct {
	trailers:         []Header,
	trailer_storage:  []u8,
	status:           int,
	headers:          []Header,
	body:             []u8,
	allocator:        mem.Allocator,
	header_storage:   []u8,
	body_storage:     [dynamic]u8,
	_allocator_scope: async.Budget_Scope,
}

response_destroy :: proc(response: ^Response) {
	if response == nil {
		return
	}

	old := response^
	response^ = {}

	if old.allocator.procedure != nil {
		delete(old.trailers, old.allocator)
		delete(old.trailer_storage, old.allocator)
		delete(old.headers, old.allocator)
		delete(old.header_storage, old.allocator)
		delete(old.body_storage)
	}

	async.budget_release_scope(&old._allocator_scope)
}

response_header :: proc(response: ^Response, name: string) -> (string, bool) {
	if response == nil {
		return "", false
	}

	for h in response.headers {
		if strings.equal_fold(h.name, name) {
			return h.value, true
		}
	}

	return "", false
}

response_trailer :: proc(response: ^Response, name: string) -> (string, bool) {
	if response == nil {
		return "", false
	}

	for h in response.trailers {
		if strings.equal_fold(h.name, name) {
			return h.value, true
		}
	}

	return "", false
}

config_validate :: proc(c: Config) -> HTTP_Error {
	if c.max_body_size < 0 ||
	   c.max_body_size > async.HTTP_MAX_BODY_SIZE ||
	   c.max_redirects < 0 ||
	   c.max_redirects > async.HTTP_MAX_REDIRECTS ||
	   c.timeout < 0 ||
	   c.setup_timeout < 0 ||
	   c.http3_qpack.blocked_streams < 0 ||
	   len(c.resolver.name_servers) > DNS_MAX_NAME_SERVERS {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	return {}
}

effective_timeout :: proc(c: Config) -> time.Duration {
	if c.timeout == 0 {
		return 30 * time.Second
	}

	return c.timeout
}

effective_body_limit :: proc(c: Config) -> int {
	if c.max_body_size == 0 {
		return async.HTTP_DEFAULT_MAX_BODY_SIZE
	}

	return c.max_body_size
}

http_protocol_error :: proc(error: async.Http_Error) -> HTTP_Error {
	return {kind = http_error_kind(error.kind), allocation = error.allocation, phase = .Protocol}
}

// Moves the response's complete body allocation into a separately releasable
// owner. Headers remain with response; response_destroy stays safe afterward.
// The allocator backing body_storage must survive until the chunk is released.
// Borrowed/manually constructed bodies are rejected without changing response.
response_take_body :: proc(response: ^Response) -> (Body_Chunk, Body_Chunk_Error) {
	if response == nil ||
	   len(response.body) != len(response.body_storage) ||
	   raw_data(response.body) != raw_data(response.body_storage) {
		return {}, {kind = .Invalid_Input}
	}

	owned, error := async.owned_take_dynamic(&response.body_storage)
	if error.kind != .None {
		return {}, body_chunk_error(error)
	}

	response.body = nil

	return body_chunk_from(owned), {}
}

// Host, Connection, Content-Length, Transfer-Encoding, Accept-Encoding,
// Expect, Upgrade, Trailer, and TE. A request that carries one is rejected
// with .Reserved_Header before a socket is opened.
header_reserved :: proc(name: string) -> bool {
	reserved := [?]string {
		"host",
		"connection",
		"content-length",
		"transfer-encoding",
		"accept-encoding",
		"expect",
		"upgrade",
		"trailer",
		"te",
	}

	for r in reserved {
		if strings.equal_fold(name, r) {
			return true
		}
	}

	return false
}

// Failure categories preserve observable distinctions without storing URLs,
// headers, tokens or response bodies. Unknown means the provider cannot say.
HTTP_Phase :: enum {
	Unknown,
	Configuration,
	DNS,
	Connect,
	TLS,
	Write,
	Read,
	Protocol,
	Body_Limit,
	Deadline,
	Cancellation,
	Admission,
	Decode,
}

// Unknown is deliberately the zero value: a zero/named legacy aggregate must
// never become evidence that replaying a non-idempotent operation is safe.
HTTP_Write_Effect :: enum {
	Unknown,
	Not_Sent,
	Response_Received,
}
