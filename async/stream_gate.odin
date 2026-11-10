package surf_async

import "core:sync"

// Sample through the registered-task witness before producer ownership moves.
// No user allocator/destructor or injected clock executes under ledger locks.
@(private)
client_upload_gate :: proc(s:^Client_State,handle:Request_Handle)->Client_Error {
 now,clock:=network_clock(s)
 if clock.kind!=.None {return clock}
 sync.lock(&s.kernel.mu);defer sync.unlock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,handle)
 if request==nil {return {kind=.Invalid_Handle}}
 if request.state!=.Queued && request.state!=.Active {return {kind=.Closed}}
 if request.cancel_requested || s.kernel.closed {
  return {kind=.Request_Error,http={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}}
 }
 if now.epoch!=request.deadline.epoch {return {kind=.Invalid_Config}}
 if now.at>=request.deadline.at {
  return {kind=.Request_Error,http={kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline}}
 }
 return {}
}
