package surf

import "core:io"
import "shared:async"

UPLOAD_BUFFER_SIZE :: 32 * 1024

// Borrows the source at its current position. Exactly content_length bytes are
// consumed: excess bytes stay unread, and no EOF probe, rewind, close or replay
// occurs. Reads must be cooperatively bounded; a transport deadline cannot
// preempt an arbitrary blocking source callback. Files use os.to_stream(file).
Upload_Source :: struct {
	stream:         io.Stream,
	content_length: i64,
}


upload_validate :: proc(request: Request, source: Upload_Source) -> HTTP_Error {
	if source.content_length < 0 ||
	   (source.content_length > 0 && source.stream.procedure == nil) ||
	   len(request.body) != 0 {
		return {kind = .Invalid_Config, phase = .Configuration, write_effect = .Not_Sent}
	}

	if source.content_length > 0 &&
	   !async.http_request_body_allowed(method_async(request.method)) {
		return {kind = .Invalid_Method, phase = .Configuration, write_effect = .Not_Sent}
	}

	return {}
}
