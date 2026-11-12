package surf

import h2 "../http/v2"

// Matches the maximum accepted HTTP_Origin_Limits.max_streams. Closed request
// handles remain owned until event/output/credit disposal and the peer checkpoint
// permit physical reaping; returning a response is earlier than that boundary.
HTTP_RETIRED_REQUEST_SLOTS :: 32

@(private)
h2_retire_request :: proc(lane: ^HTTP_Lane, handle: h2.Stream_Handle) {
	error := h2.connection_reap(&lane.engine, handle)
	if error.kind == .None || error.kind == .Invalid_Input {return}
	if error.kind != .Invalid_State {lane.reusable = false; return}
	available := -1
	for slot, index in lane.retired_requests {
		if slot == handle {return}
		if slot == {} && available < 0 {available = index}
	}
	if available >= 0 {lane.retired_requests[available] = handle; return}
	// No handle may be forgotten at capacity. Lane close aborts and drains all
	// engine owners before a later request can select another connection.
	lane.reusable = false
}

@(private)
h2_retired_requests_reap :: proc(lane: ^HTTP_Lane) -> bool {
	if lane == nil || !lane.engine_up {return false}
	progress := false
	for &handle in lane.retired_requests {
		if handle == {} {continue}
		error := h2.connection_reap(&lane.engine, handle)
		if error.kind == .None || error.kind == .Invalid_Input {
			handle = {}; progress = true
		} else if error.kind != .Invalid_State {
			lane.reusable = false
		}
	}
	return progress
}

@(private)
h2_retired_request_event :: proc(lane: ^HTTP_Lane, event: h2.Event_View) -> bool {
	handle: h2.Stream_Handle
	#partial switch value in event.payload {
	case h2.Headers_Event: handle = value.stream
	case h2.Data_Event: handle = value.stream
	case h2.Stream_End_Event: handle = value.stream
	case h2.Reset_Event: handle = value.stream
	case h2.Not_Processed_Event: handle = value.stream
	case: return false
	}
	for retired in lane.retired_requests {if retired == handle {return true}}
	return false
}
