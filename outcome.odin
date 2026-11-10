package surf

import "core:net"

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

// Classify only facts available from existing typed diagnostics. A received
// response is not proof of business success, transaction commit, or replay safety.
http_error_classify :: proc(error: HTTP_Error, fallback: HTTP_Phase, effect: HTTP_Write_Effect, status: int = 0) -> HTTP_Error {
	result := error
	if result.kind == .None {return result}
	if result.phase == .Unknown {
		result.phase = fallback
		#partial switch result.kind {
		case .Invalid_Config, .Invalid_URL, .Insecure_URL, .Invalid_Method, .Reserved_Header:
			result.phase = .Configuration
		case .Invalid_Header:
			result.phase = .Configuration if fallback == .Configuration else .Protocol
		case .Body_Oversized: result.phase = .Body_Limit
		case .Deadline_Failed: result.phase = .Deadline
		case .Dial_Failed: result.phase = http_network_phase(result.network)
		case .TLS_Failed:
			result.phase = .TLS
			#partial switch result.tls_dial.kind {
			case .Invalid_Config, .Invalid_State: result.phase = .Configuration
			case .TCP_Dial_Failed: result.phase = http_network_phase(result.tls_dial.network)
			}
		case .Invalid_Status, .Conflicting_Framing, .Unsupported_Transfer_Encoding, .Invalid_Content_Length,
       .Invalid_Chunk, .Invalid_Trailer, .Header_Oversized, .Header_Limit, .Too_Many_Informational,
       .Redirect_Limit, .Invalid_Redirect, .Unsafe_Redirect:
			result.phase = .Protocol
		}
	}
	// Record/authentication failures remain TLS failures; transport failures
	// retain the read/write phase until a more specific timeout/cancel is known.
	#partial switch result.tls_io.kind {
	case .Handshake_Failed, .Unexpected_EOF, .Invalid_Record, .Encryption_Failed,
	     .Decryption_Failed, .Unexpected_Content_Type, .Peer_Alert, .Interleaved_Record,
	     .Record_Boundary_Violation, .Invalid_Post_Handshake, .Post_Handshake_Oversized:
		result.phase = .TLS
	}
	// TLS adapters retain their underlying timeout/cancellation diagnostics.
	transport := result.transport
	if result.tls_io.transport.kind != .None {transport = result.tls_io.transport}
	for candidate in ([?]net.Connection_Error{
		result.tls_dial.handshake.client_hello.transport,
		result.tls_dial.handshake.server_hello.record.transport,
		result.tls_dial.handshake.record.transport,
		result.tls_dial.handshake.transport,
	}) {
		if candidate.kind != .None {transport = candidate}
	}
	if transport.kind == .Timeout {result.phase = .Deadline}
	if transport.kind == .Cancelled {result.phase = .Cancellation}
	if result.tls_dial.handshake.kind == .Deadline_Failed {result.phase = .Deadline}
	result.write_effect = effect
	if result.status == 0 {result.status = status}
	return result
}

http_network_phase :: proc(error: net.Network_Error) -> HTTP_Phase {
	if error == nil {return .Unknown}
	#partial switch cause in error {
	case net.Resolve_Error: return .DNS
	case net.DNS_Error:
		if cause == .Timeout {return .Deadline}
		return .DNS
	case net.Dial_Error:
		if cause == .Timeout {return .Deadline}
		return .Connect
	case net.Create_Socket_Error: return .Connect
	case net.Parse_Endpoint_Error: return .Configuration
	}
	return .Unknown
}
