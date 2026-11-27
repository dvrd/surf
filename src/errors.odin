package surf

import "core:net"

// Classify only facts available from existing typed diagnostics. A received
// response is not proof of business success, transaction commit, or replay safety.
http_error_classify :: proc(
	error: HTTP_Error,
	fallback: HTTP_Phase,
	effect: HTTP_Write_Effect,
	status: int = 0,
) -> HTTP_Error {
	result := error
	if result.kind == .None {
		return result
	}
	if result.phase == .Unknown {
		result.phase = fallback
		#partial switch result.kind {
		case .Invalid_Config, .Invalid_URL, .Insecure_URL, .Invalid_Method, .Reserved_Header:
			result.phase = .Configuration
		case .Invalid_Header:
			result.phase = .Configuration if fallback == .Configuration else .Protocol
		case .Body_Oversized:
			result.phase = .Body_Limit
		case .Deadline_Failed:
			result.phase = .Deadline
		case .Dial_Failed:
			result.phase = http_network_phase(result.network)
		case .TLS_Failed:
			result.phase = .TLS
		case .Address_Rejected:
			result.phase = .Connect
		case .Invalid_Status,
		     .Conflicting_Framing,
		     .Unsupported_Transfer_Encoding,
		     .Invalid_Content_Length,
		     .Invalid_Chunk,
		     .Invalid_Trailer,
		     .Header_Oversized,
		     .Header_Limit,
		     .Too_Many_Informational,
		     .Redirect_Limit,
		     .Invalid_Redirect,
		     .Unsafe_Redirect:
			result.phase = .Protocol
		}
	}
	transport := result.transport

	#partial switch result.tls_error {
	case .None, .Close_Notify, .Transport, .Allocation_Failed:
	case .Invalid_Config, .Invalid_State, .Invalid_Trust_Roots:
		if result.kind == .TLS_Failed {
			result.phase = .Configuration
		}
	case .Cancelled:
		result.phase = .Cancellation
	case:
		result.phase = .TLS
	}

	// A transport cause keeps the read or write phase until a timeout or
	// cancellation is known.
	carried_phase := http_network_phase(transport)
	if carried_phase == .Deadline || carried_phase == .Cancellation {
		result.phase = carried_phase
	}
	result.write_effect = effect
	if result.status == 0 {
		result.status = status
	}
	return result
}

http_network_phase :: proc(error: net.Network_Error) -> HTTP_Phase {
	if error == nil {
		return .Unknown
	}

	#partial switch cause in error {
	case net.Resolve_Error:
		return .DNS
	case net.DNS_Error:
		if cause == .Timeout {
			return .Deadline
		}
		return .DNS
	case net.Dial_Error:
		if cause == .Timeout {
			return .Deadline
		}
		return .Connect
	case net.TCP_Recv_Error:
		if cause == .Timeout {
			return .Deadline
		}
		return .Read
	case net.TCP_Send_Error:
		if cause == .Timeout {
			return .Deadline
		}
		return .Write
	case net.Connection_Error:
		if cause == .Cancelled {
			return .Cancellation
		}
	case net.Create_Socket_Error:
		return .Connect
	case net.Parse_Endpoint_Error:
		return .Configuration
	}

	return .Unknown
}
