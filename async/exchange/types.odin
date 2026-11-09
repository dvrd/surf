package surf_exchange

import surf "../.."
import http "../../../http"
import h1 "../../../http/v1"
import "core:mem"
import "core:net"
import "core:time"

READ_BUFFER_SIZE :: 16 << 10
HEAD_BUFFER_SIZE :: http.MAX_HEADER_SIZE
MAX_WORK_PER_DRIVE :: 4096
// Root Surf accepts seven interim heads before a final eighth head. Its eighth
// interim is Too_Many_Informational; this limit counts interim responses only.
MAX_INFORMATIONAL_RESPONSES :: 7

Options :: struct {
 // Zero selects HTTP's8MiB default; positive values are bounded at64MiB.
 body_limit: int,
 // Zero selects Root Surf's existing seven-interim bound.
 informational_limit: int,
}
Resolved_Options :: struct {body_limit, informational_limit:int}

// The owner supplies both clocks from one retained mapping. Zero/zero is
// unlimited; positive at requires a nonzero absolute wall deadline. Pure shape
// validation cannot establish epoch identity, actual expiry or mapping accuracy.
Budget :: struct {at:i64, wall:time.Time}
// Borrowed until all accepted operations retire and reset/destroy clears it.
// wake may notify/enqueue the owning loop; it is not a completion callback and
// must not free an Exchange with pending operations. Callbacks snapshot Notify
// and perform no Exchange access after invoking it.
Notify :: struct {data:rawptr, wake:proc(rawptr)}
Drive_Status :: enum {Waiting, Progress, Done}
Drive_Result :: struct {
 status: Drive_Status,
 work_used: int,
 error: surf.HTTP_Error,
 // HTTP framing+lookahead only, NEVER proof of idle TLS/socket health.
 reuse_eligible: bool,
}

// Concrete state for the subsequent engine task, not executable driver stubs.
// Idle means initialized/no exchange. Done means every accepted operation's
// terminal callback arrived; a successful Response may still await take.
Exchange_Phase :: enum {
 Idle,
 Writing_Head,
 Writing_Body,
 Reading_Head,
 Copying_Head,
 Reading_Body,
 Draining,
 Done,
}
Operation_State :: struct {
 operation: net.Async_Operation,
 owner: ^Exchange,
 // accepted is independent of operation.pending: even a completed provider
 // slot remains borrowed until our callback actually records its result.
 accepted, ready, cancel_requested: bool,
 result: net.Async_Result,
}
// One move-forbidden caller-owned exchange on its Async_Connection's owning
// loop. No Runtime/Task/Client/Kernel, scheduler, transport close owner or lock.
// request.body is borrowed from the admitted Request_Owner through the last
// accepted write callback. No caller header/URL arena is retained after begin
// encodes the head. Response allocations retain their own allocator provenance.
Exchange :: struct {
 _self: ^Exchange,
 _busy: bool,
 _options: Resolved_Options,
 _allocator: mem.Allocator,
 _phase: Exchange_Phase,
 _stream: net.Async_Connection,
 _budget: Budget,
 _notify: Notify,
 _read, _write: Operation_State,
 _read_buffer: [READ_BUFFER_SIZE]u8,
 _read_at, _read_used: int,
 _request_head: [HEAD_BUFFER_SIZE]u8,
 _request_head_used, _request_head_at: int,
 _request_body: []u8,
 _request_body_at: int,
 _method: http.Method,
 _response_head: [HEAD_BUFFER_SIZE]u8,
 _response_head_used: int,
 // All borrowed fields in head refer to _response_head until copied; never
 // overwrite that backing while constructing owned Response header storage.
 _head: h1.Response_Head,
 _informational: int,
 _chunk: h1.Chunk_Decoder,
 _body_remaining: u64,
 _response: surf.Response,
 _failure: surf.HTTP_Error,
 _written: u64,
 _cancelled, _peer_eof, _reuse_eligible, _result_taken: bool,
}
