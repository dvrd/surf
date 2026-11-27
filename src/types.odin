package surf

// surf's own vocabulary. Every type a caller builds or reads is defined here,
// so a change in shared:async changes surf's conversions, not its callers.
// The conversions below are exhaustive switches: a new async value fails
// surf's build instead of passing through unnamed.

import "core:io"
import "core:mem"
import "core:net"
import "shared:async"

Method :: enum {
	GET,
	POST,
	PATCH,
	HEAD,
	PUT,
	DELETE,
	OPTIONS,
}

Header :: struct {
	name, value: string,
}

// Strings and body are borrowed for the duration of the call that takes the
// request.
Request :: struct {
	method:   Method,
	url:      string,
	headers:  []Header,
	trailers: []Header,
	body:     []u8,
}

HTTP_Error_Kind :: enum {
	None,
	Invalid_URL,
	Insecure_URL,
	Invalid_Config,
	Invalid_Method,
	Invalid_Header,
	Reserved_Header,
	Header_Incomplete,
	Header_Oversized,
	Header_Limit,
	Invalid_Status,
	Conflicting_Framing,
	Unsupported_Transfer_Encoding,
	Invalid_Content_Length,
	Invalid_Chunk,
	Invalid_Trailer,
	Body_Oversized,
	Unexpected_EOF,
	No_Progress,
	Destination_Undersized,
	Overlapping_Buffers,
	Allocation_Failed,
	Dial_Failed,
	TLS_Failed,
	IO_Failed,
	Deadline_Failed,
	Redirect_Limit,
	Invalid_Redirect,
	Unsafe_Redirect,
	Too_Many_Informational,
	Unsupported_Content_Encoding,
	Content_Decoding_Failed,
	// Resolved addresses were refused before a socket was opened.
	Address_Rejected,
}

// Why TLS failed: a local cause, a system cause, or the alert that ended the
// handshake or the connection.
TLS_Failure :: enum {
	None,
	// The configuration: roots, credentials, server name, a call out of order.
	Invalid_Config,
	Invalid_State,
	Invalid_Trust_Roots,
	Invalid_Server_Name,
	Credential_Failed,
	Client_Certificate_Unsupported,
	Nonblocking_Socket,
	Deadline_Unsupported,
	// The system could not supply randomness, the clock or a key share.
	Entropy_Unavailable,
	Clock_Unavailable,
	Key_Share_Failed,
	Cancelled,
	Limit_Exceeded,
	Early_Data_Rejected,
	Address_Refused,
	Name_Resolution_Failed,
	// Alerts (RFC 8446 section 6).
	Close_Notify,
	Unexpected_Message,
	Bad_Record_Mac,
	Record_Overflow,
	Handshake_Failure,
	Bad_Certificate,
	Unsupported_Certificate,
	Certificate_Revoked,
	Certificate_Expired,
	Certificate_Unknown,
	Illegal_Parameter,
	Unknown_CA,
	Access_Denied,
	Decode_Error,
	Decrypt_Error,
	Protocol_Version,
	Insufficient_Security,
	Internal_Error,
	Inappropriate_Fallback,
	User_Canceled,
	Missing_Extension,
	Unsupported_Extension,
	Unrecognized_Name,
	Bad_Certificate_Status_Response,
	Unknown_PSK_Identity,
	Certificate_Required,
	General_Alert,
	No_Application_Protocol,
	// The socket under TLS failed; HTTP_Error.transport holds the cause.
	Transport,
	Allocation_Failed,
}

// Why a budget refused an operation.
Budget_Failure :: enum {
	None,
	Invalid_Config,
	Invalid_Handle,
	Limit_Exceeded,
	Closed,
	Depth_Exceeded,
	Allocation_Failed,
	Foreign_Root,
	Overflow,
}

// Why a response body could not be decoded.
Decode_Failure :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Overlapping_Buffers,
	Malformed,
	Truncated,
	Checksum_Mismatch,
	Size_Mismatch,
	Encoded_Limit,
	Decoded_Limit,
	Metadata_Limit,
	Member_Limit,
	Trailing_Data,
	Allocation_Failed,
	Memory_Limit,
}

// Zero selects the QPACK defaults.
HTTP3_Qpack :: struct {
	table_capacity:  u32,
	blocked_streams: int,
}

// ---- TLS resources ----

// Trusted roots. Never copy or move it after loading; destroy it after every
// Config that borrows it.
Trust_Roots :: struct {
	_pool: async.Root_Pool,
}

Trust_Roots_Error :: enum {
	None,
	// Already loaded, or nil.
	Invalid_State,
	// Unreadable, not PEM, no certificate, or a certificate that cannot be used.
	Invalid_Roots,
	// The bundle or its certificate count is over the limit.
	Limit_Exceeded,
	Allocation_Failed,
}

// A client certificate chain and its private key.
Client_Credentials :: struct {
	_store: ^async.Credential_Store,
}

Credentials_Error :: enum {
	None,
	Invalid_Config,
	Invalid_Input,
	Invalid_Store,
	Invalid_Lease,
	Allocation_Failed,
	Closed,
	Empty,
	Busy,
	Capacity,
	Failed,
}

// Resumable TLS sessions. The zero value is empty and ready.
TLS_Session_Cache :: struct {
	_cache: async.Session_Cache,
}

// HTTP/3 connections shared by Clients. Never copy or move it between
// http3_pool_init and http3_pool_destroy.
HTTP3_Pool :: struct {
	_pool: async.H3_Pool,
}

trust_roots_load_file :: proc(roots: ^Trust_Roots, path: string) -> Trust_Roots_Error {
	if roots == nil {
		return .Invalid_State
	}

	return trust_roots_error(async.root_pool_load_file(&roots._pool, path))
}

// PEM certificates in data.
trust_roots_parse :: proc(roots: ^Trust_Roots, data: []u8, allocator := context.allocator) -> Trust_Roots_Error {
	if roots == nil {
		return .Invalid_State
	}

	return trust_roots_error(async.root_pool_parse(&roots._pool, data, allocator))
}

// The platform's trust store.
trust_roots_load_system :: proc(roots: ^Trust_Roots) -> Trust_Roots_Error {
	if roots == nil {
		return .Invalid_State
	}

	return trust_roots_error(async.root_pool_load_system(&roots._pool))
}

trust_roots_destroy :: proc(roots: ^Trust_Roots) {
	if roots != nil {
		async.root_pool_destroy(&roots._pool)
	}
}

// The number of certificates loaded.
trust_roots_count :: proc(roots: ^Trust_Roots) -> int {
	if roots == nil {
		return 0
	}

	return roots._pool.count
}

client_credentials_from_pem :: proc(
	chain_pem, key_pem: []u8,
	allocator := context.allocator,
) -> (
	Client_Credentials,
	Credentials_Error,
) {
	store, error := async.credential_store_from_pem(chain_pem, key_pem, allocator)
	if error.kind != .None {
		return {}, credentials_error(error)
	}

	return {_store = store}, .None
}

client_credentials_destroy :: proc(credentials: ^Client_Credentials) -> Credentials_Error {
	if credentials == nil || credentials._store == nil {
		return .None
	}

	error := async.credential_store_destroy(credentials._store)
	credentials._store = nil

	return credentials_error(error)
}

// lanes is the QUIC connections kept at once, 1 to 32; zero selects the
// default. allocator must be usable from every worker that runs a Client on
// the pool.
http3_pool_init :: proc(
	pool: ^HTTP3_Pool,
	lanes := 0,
	qpack := HTTP3_Qpack{},
	ecn := false,
	allocator := context.allocator,
) -> bool {
	if pool == nil {
		return false
	}

	config := async.H3_Pool_Config {
		max_lanes               = lanes,
		qpack                   = http3_qpack(qpack),
		ecn                     = ecn,
		max_response_body_bytes = async.HTTP_MAX_BODY_SIZE,
		allocator               = allocator,
	}

	return async.h3_pool_init(&pool._pool, config).kind == .None
}

http3_pool_destroy :: proc(pool: ^HTTP3_Pool) -> bool {
	if pool == nil {
		return false
	}

	return async.h3_pool_destroy(&pool._pool).kind == .None
}

// ---- body chunks ----

// A body buffer that owns its storage: data is the payload. Release it once,
// with body_chunk_release, unless a client call took it.
Body_Chunk :: struct {
	data:   []u8,
	_owned: async.Owned_Chunk,
}

Body_Chunk_Error_Kind :: enum {
	None,
	Invalid_Input,
	Limit_Exceeded,
	Allocation_Failed,
}

Body_Chunk_Error :: struct {
	kind:       Body_Chunk_Error_Kind,
	allocation: mem.Allocator_Error,
}

// A chunk holding a copy of data, refused when data is longer than limit.
body_chunk_copy :: proc(data: []u8, limit: int, allocator := context.allocator) -> (Body_Chunk, Body_Chunk_Error) {
	owned, error := async.owned_copy_bounded(data, limit, allocator)
	if error.kind != .None {
		return {}, body_chunk_error(error)
	}

	return body_chunk_from(owned), {}
}

body_chunk_release :: proc(chunk: ^Body_Chunk) {
	if chunk == nil {
		return
	}

	async.owned_destroy(&chunk._owned)
	chunk^ = {}
}

// True while the chunk owns storage that holds data.
body_chunk_valid :: proc(chunk: ^Body_Chunk) -> bool {
	return chunk != nil && async.owned_valid(&chunk._owned)
}

body_chunk_from :: proc(owned: async.Owned_Chunk) -> Body_Chunk {
	return {data = owned.data, _owned = owned}
}

body_chunk_error :: proc(error: async.Owned_Error) -> Body_Chunk_Error {
	kind: Body_Chunk_Error_Kind

	switch error.kind {
	case .None:
		kind = .None
	case .Invalid_Input:
		kind = .Invalid_Input
	case .Limit_Exceeded:
		kind = .Limit_Exceeded
	case .Allocation_Failed:
		kind = .Allocation_Failed
	}

	return {kind = kind, allocation = error.allocation}
}

// ---- conversions to async ----

#assert(size_of(Header) == size_of(async.Http_Header))
#assert(offset_of(Header, name) == offset_of(async.Http_Header, name))
#assert(offset_of(Header, value) == offset_of(async.Http_Header, value))

headers_async :: proc(headers: []Header) -> []async.Http_Header {
	return transmute([]async.Http_Header)headers
}

headers_from_async :: proc(headers: []async.Http_Header) -> []Header {
	return transmute([]Header)headers
}

method_async :: proc(method: Method) -> async.Http_Method {
	switch method {
	case .GET:
		return .GET
	case .POST:
		return .POST
	case .PATCH:
		return .PATCH
	case .HEAD:
		return .HEAD
	case .PUT:
		return .PUT
	case .DELETE:
		return .DELETE
	case .OPTIONS:
		return .OPTIONS
	}

	return .GET
}

method_from_async :: proc(method: async.Http_Method) -> Method {
	switch method {
	case .GET:
		return .GET
	case .POST:
		return .POST
	case .PATCH:
		return .PATCH
	case .HEAD:
		return .HEAD
	case .PUT:
		return .PUT
	case .DELETE:
		return .DELETE
	case .OPTIONS:
		return .OPTIONS
	}

	return .GET
}

request_async :: proc(request: Request) -> async.Http_Request {
	return {
		method = method_async(request.method),
		url = request.url,
		headers = headers_async(request.headers),
		trailers = headers_async(request.trailers),
		body = request.body,
	}
}

http3_qpack :: proc(qpack: HTTP3_Qpack) -> async.H3_Qpack_Config {
	return {table_capacity = qpack.table_capacity, blocked_streams = qpack.blocked_streams}
}

// ---- conversions from async ----

http_error_kind :: proc(kind: async.Http_Error_Kind) -> HTTP_Error_Kind {
	switch kind {
	case .None:
		return .None
	case .Invalid_URL:
		return .Invalid_URL
	case .Insecure_URL:
		return .Insecure_URL
	case .Invalid_Config:
		return .Invalid_Config
	case .Invalid_Method:
		return .Invalid_Method
	case .Invalid_Header:
		return .Invalid_Header
	case .Reserved_Header:
		return .Reserved_Header
	case .Header_Incomplete:
		return .Header_Incomplete
	case .Header_Oversized:
		return .Header_Oversized
	case .Header_Limit:
		return .Header_Limit
	case .Invalid_Status:
		return .Invalid_Status
	case .Conflicting_Framing:
		return .Conflicting_Framing
	case .Unsupported_Transfer_Encoding:
		return .Unsupported_Transfer_Encoding
	case .Invalid_Content_Length:
		return .Invalid_Content_Length
	case .Invalid_Chunk:
		return .Invalid_Chunk
	case .Invalid_Trailer:
		return .Invalid_Trailer
	case .Body_Oversized:
		return .Body_Oversized
	case .Unexpected_EOF:
		return .Unexpected_EOF
	case .No_Progress:
		return .No_Progress
	case .Destination_Undersized:
		return .Destination_Undersized
	case .Overlapping_Buffers:
		return .Overlapping_Buffers
	case .Allocation_Failed:
		return .Allocation_Failed
	case .Dial_Failed:
		return .Dial_Failed
	case .TLS_Failed:
		return .TLS_Failed
	case .IO_Failed:
		return .IO_Failed
	case .Deadline_Failed:
		return .Deadline_Failed
	case .Redirect_Limit:
		return .Redirect_Limit
	case .Invalid_Redirect:
		return .Invalid_Redirect
	case .Unsafe_Redirect:
		return .Unsafe_Redirect
	case .Too_Many_Informational:
		return .Too_Many_Informational
	case .Unsupported_Content_Encoding:
		return .Unsupported_Content_Encoding
	case .Content_Decoding_Failed:
		return .Content_Decoding_Failed
	case .Address_Rejected:
		return .Address_Rejected
	}

	return .IO_Failed
}

// The TLS failure, and the socket error under it when there was one.
tls_failure :: proc(error: async.TLS_Error) -> (TLS_Failure, net.Network_Error) {
	switch cause in error {
	case mem.Allocator_Error:
		return .Allocation_Failed, nil
	case io.Error:
		return .Transport, nil
	case net.TCP_Send_Error:
		return .Transport, cause
	case net.TCP_Recv_Error:
		return .Transport, cause
	case net.Dial_Error:
		return .Transport, cause
	case async.TLS_General_Error:
		return tls_general_failure(cause), nil
	case async.TLS_Protocol_Error:
		return tls_alert_failure(cause), nil
	}

	return .None, nil
}

tls_general_failure :: proc(error: async.TLS_General_Error) -> TLS_Failure {
	switch error {
	case .Nonblocking_Socket:
		return .Nonblocking_Socket
	case .Invalid_SNI_Hostname:
		return .Invalid_Server_Name
	case .Failed_Key_Share_Generation:
		return .Key_Share_Failed
	case .Unsupported_Client_Certificate_Requested:
		return .Client_Certificate_Unsupported
	case .Invalid_State:
		return .Invalid_State
	case .Invalid_Config:
		return .Invalid_Config
	case .Invalid_Trust_Roots:
		return .Invalid_Trust_Roots
	case .Name_Resolution_Failed:
		return .Name_Resolution_Failed
	case .Cancelled:
		return .Cancelled
	case .Deadline_Unsupported:
		return .Deadline_Unsupported
	case .Limit_Exceeded:
		return .Limit_Exceeded
	case .Entropy_Unavailable:
		return .Entropy_Unavailable
	case .Clock_Unavailable:
		return .Clock_Unavailable
	case .Early_Data_Rejected:
		return .Early_Data_Rejected
	case .Credential_Failed:
		return .Credential_Failed
	case .Address_Refused:
		return .Address_Refused
	}

	return .Invalid_State
}

tls_alert_failure :: proc(alert: async.TLS_Protocol_Error) -> TLS_Failure {
	switch alert {
	case .None:
		return .None
	case .Close_Notify:
		return .Close_Notify
	case .Unexpected_Message:
		return .Unexpected_Message
	case .Bad_Record_Mac:
		return .Bad_Record_Mac
	case .Record_Overflow:
		return .Record_Overflow
	case .Handshake_Failure:
		return .Handshake_Failure
	case .Bad_Certificate:
		return .Bad_Certificate
	case .Unsupported_Certificate:
		return .Unsupported_Certificate
	case .Certificate_Revoked:
		return .Certificate_Revoked
	case .Certificate_Expired:
		return .Certificate_Expired
	case .Certificate_Unknown:
		return .Certificate_Unknown
	case .Illegal_Parameter:
		return .Illegal_Parameter
	case .Unknown_Ca:
		return .Unknown_CA
	case .Access_Denied:
		return .Access_Denied
	case .Decode_Error:
		return .Decode_Error
	case .Decrypt_Error:
		return .Decrypt_Error
	case .Protocol_Version:
		return .Protocol_Version
	case .Insufficient_Security:
		return .Insufficient_Security
	case .Internal_Error:
		return .Internal_Error
	case .Inappropriate_Fallback:
		return .Inappropriate_Fallback
	case .User_Canceled:
		return .User_Canceled
	case .Missing_Extension:
		return .Missing_Extension
	case .Unsupported_Extension:
		return .Unsupported_Extension
	case .Unrecognized_Name:
		return .Unrecognized_Name
	case .Bad_Certificate_Status_Response:
		return .Bad_Certificate_Status_Response
	case .Unknown_Psk_Identity:
		return .Unknown_PSK_Identity
	case .Certificate_Required:
		return .Certificate_Required
	case .General_Error:
		return .General_Alert
	case .No_Application_Protocol:
		return .No_Application_Protocol
	}

	return .General_Alert
}

budget_failure :: proc(error: async.Budget_Error) -> Budget_Failure {
	switch error {
	case .None:
		return .None
	case .Invalid_Config:
		return .Invalid_Config
	case .Invalid_Handle:
		return .Invalid_Handle
	case .Limit_Exceeded:
		return .Limit_Exceeded
	case .Closed:
		return .Closed
	case .Depth_Exceeded:
		return .Depth_Exceeded
	case .Allocation_Failed:
		return .Allocation_Failed
	case .Foreign_Root:
		return .Foreign_Root
	case .Overflow:
		return .Overflow
	}

	return .Invalid_Handle
}

decode_failure :: proc(error: async.Coding_Decode_Error) -> Decode_Failure {
	switch error {
	case .None:
		return .None
	case .Invalid_State:
		return .Invalid_State
	case .Invalid_Config:
		return .Invalid_Config
	case .Overlapping_Buffers:
		return .Overlapping_Buffers
	case .Malformed:
		return .Malformed
	case .Truncated:
		return .Truncated
	case .Checksum_Mismatch:
		return .Checksum_Mismatch
	case .Size_Mismatch:
		return .Size_Mismatch
	case .Encoded_Limit:
		return .Encoded_Limit
	case .Decoded_Limit:
		return .Decoded_Limit
	case .Metadata_Limit:
		return .Metadata_Limit
	case .Member_Limit:
		return .Member_Limit
	case .Trailing_Data:
		return .Trailing_Data
	case .Allocation_Failed:
		return .Allocation_Failed
	case .Memory_Limit:
		return .Memory_Limit
	}

	return .Malformed
}

trust_roots_error :: proc(error: async.TLS_Error) -> Trust_Roots_Error {
	if error == nil {
		return .None
	}

	if _, allocation := error.(mem.Allocator_Error); allocation {
		return .Allocation_Failed
	}

	general, is_general := error.(async.TLS_General_Error)
	if !is_general {
		return .Invalid_Roots
	}

	#partial switch general {
	case .Invalid_State:
		return .Invalid_State
	case .Limit_Exceeded:
		return .Limit_Exceeded
	}

	return .Invalid_Roots
}

credentials_error :: proc(error: async.Credential_Error) -> Credentials_Error {
	#partial switch error.kind {
	case .None:
		return .None
	case .Invalid_Config:
		return .Invalid_Config
	case .Invalid_Input:
		return .Invalid_Input
	case .Invalid_Store:
		return .Invalid_Store
	case .Invalid_Lease:
		return .Invalid_Lease
	case .Allocation_Failed:
		return .Allocation_Failed
	case .Closed:
		return .Closed
	case .Empty:
		return .Empty
	case .Busy:
		return .Busy
	case .Capacity:
		return .Capacity
	}

	return .Failed
}
