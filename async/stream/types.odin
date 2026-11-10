package surf_stream

import surf "../.."
import signal "../../../async/signal"
import "core:mem"
import charged "core:mem/budget"
import "core:mem/owned"
import "core:sync"
import scopes "core:sync/budget"

MAX_SLOTS :: 16
MAX_CHUNK_BYTES :: 64 << 10
MAX_STREAMS :: 4096
Limits :: struct {
 streams, response_chunks, upload_chunks: int,
 max_chunk_bytes, max_retained_bytes_per_stream: int,
}
Content_Decoding :: enum {Identity, Gzip}
Options :: struct {
 upload_length: Maybe(i64),
 max_encoded_bytes, max_decoded_bytes: u64,
 decoding: Content_Decoding,
}
Encoding :: enum {Wire, Decoded_Gzip}
Read_Status :: enum {Pending, Chunk, End}
Upload_Status :: enum {Accepted, Backpressure, Closed, Invalid, Limit_Exceeded, Allocation_Failed}
Error_Kind :: enum {None, Invalid, Closed, Pending, Capacity, Allocation_Failed}
Error :: struct {kind: Error_Kind, http: surf.HTTP_Error}
Head :: struct {
 response: surf.Response,
 wire_content_length: i64,
 delivery: Encoding,
 _owner: ^Channel,
}
Stats :: struct {
 streams, retiring_streams, response_chunks, held_response_chunks: int,
 upload_chunks, upload_bytes, response_backing_bytes, header_bytes: int,
}
Slot_State :: enum {Free, Filling, Ready, Taken}
Output :: struct {
 channel: ^Channel,
 storage: []u8,
 used: int,
 state: Slot_State,
 sequence: u64,
}
// Client and outstanding cells retain this owner independently of the runtime.
Bank :: struct {
 mu: sync.Mutex,
 references: int,
 closed: bool,
 limits: Limits,
 cells: []Cell_Entry,
 allocator: mem.Allocator,
 binding: charged.Binding,
}
Cell_Entry :: struct {channel: ^Channel, reserved, returning: bool}
Channel :: struct {
 mu: sync.Mutex,
 bank: ^Bank,
 index: int,
 references: int,
 claimed, returning, closed, request_released, terminal: bool,
 options: Options,
 wake: signal.Signal,
 outputs: [MAX_SLOTS]Output,
 output_storage: []u8,
 sequence: u64,
 uploads: [MAX_SLOTS]owned.Chunk,
 upload_head, upload_queued, upload_active, upload_bytes: int,
 upload_received: u64,
 upload_finished, upload_stopped: bool,
 upload_error: surf.HTTP_Error,
 lease: scopes.Lease,
 head: surf.Response,
 head_ready, head_taken: bool,
 wire_length: i64,
 header_bytes: int,
 encoding: Encoding,
 error: surf.HTTP_Error,
}

limits_normalize :: proc(input: Limits, requests: int) -> (Limits, bool) {
 result := input
 if result.streams == 0 do result.streams = min(requests, 8)
 if result.response_chunks == 0 do result.response_chunks = 2
 if result.upload_chunks == 0 do result.upload_chunks = 2
 if result.max_chunk_bytes == 0 do result.max_chunk_bytes = 16 << 10
 if result.max_retained_bytes_per_stream == 0 do result.max_retained_bytes_per_stream = 64 << 10
 if result.streams < 1 || result.streams > min(requests, MAX_STREAMS) ||
    result.response_chunks < 1 || result.response_chunks > MAX_SLOTS ||
    result.upload_chunks < 1 || result.upload_chunks > MAX_SLOTS ||
    result.max_chunk_bytes < 1 || result.max_chunk_bytes > MAX_CHUNK_BYTES ||
    result.max_retained_bytes_per_stream < result.response_chunks*result.max_chunk_bytes ||
    result.max_retained_bytes_per_stream > 64 << 20 {return {}, false}
 return result, true
}

options_normalize :: proc(input: Options, body_limit: int) -> (Options, bool) {
 result := input
 if result.max_encoded_bytes == 0 do result.max_encoded_bytes = u64(body_limit)
 if result.max_decoded_bytes == 0 do result.max_decoded_bytes = u64(body_limit)
 if result.max_encoded_bytes > 64 << 20 || result.max_decoded_bytes > 64 << 20 ||
    result.max_encoded_bytes == 0 || result.max_decoded_bytes == 0 {return {}, false}
 if size, yes := result.upload_length.?; yes && size < 0 {return {}, false}
 if result.decoding != .Identity && result.decoding != .Gzip {return {}, false}
 return result, true
}
