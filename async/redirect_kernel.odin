package surf_async

import surf ".."
import runtime_async "../../async"
import "core:sync"

// Kernel.mu is held. The owner samples now after its physical work; this pure
// ledger has no Runtime/transport pointer and cannot certify callback drainage.
@(private)
redirect_cutoff_locked :: proc(k:^Kernel,r:^Request_Slot,now:runtime_async.Deadline)->Client_Error {
 if now.epoch!=r.deadline.epoch || now.at<=0 {return {kind=.Invalid_Config,http={kind=.Invalid_Config,phase=.Configuration}}}
 if k.closed {return {kind=.Closed}}
 if r.cancel_requested {return {kind=.Request_Error,http={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}}
 if now.at>=r.deadline.at {return {kind=.Request_Error,http={kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent}}}
 return {}
}

// Caller certifies that all old accepted IO callbacks and the physical stream
// close have completed. Retiring model metadata alone is not that proof.
// The returned disposal deliberately contains NO stream lease: the same lease
// remains in the accepted request until final success/failure, across all hops.
kernel_redirect_begin :: proc(k:^Kernel,h:Request_Handle,now:runtime_async.Deadline)->(Request_Disposal,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {},{kind=.Invalid_Handle}}
 if r.state!=.Active || r.error.kind!=.None || !completion_empty(&r.response) || r.completion_queued ||
    r.session.slot==0 || r.origin.slot==0 || k.counters.active_requests<1 ||
    k.returning<0 || k.returning==max(int) || k.counters.returning_requests==max(int) ||
    k.references<1 || k.references>=max(int)-2 {return {},{kind=.Invalid_State}}
 if error:=redirect_cutoff_locked(k,r,now);error.kind!=.None {return {},error}
 model:=pool_session_locked(k,r.session)
 origin:=admission_origin_locked(k,r.origin)
 if model==nil || model.state!=.Retiring || model.request!=h || model.origin!=r.origin ||
    origin==nil || origin.requests<1 || origin.sessions<1 || origin.preparing<0 || origin.waiters<0 ||
    k.counters.retiring_connections<1 || k.counters.origins<1 {return {},{kind=.Invalid_State}}
 old_origin:=r.origin
 if error:=admission_detach_claim_locked(k,h,r);error.kind!=.None {return {},error}
 detached,error:=kernel_origin_release_locked(k,old_origin,.Request)
 // The old physical model still holds its Origin.Session reference. Thus this
 // release cannot retire that origin or invoke any allocator callback.
 assert(error.kind==.None && detached.origin.slot==0)
 disposal:=Request_Disposal{request=h,returning_to=.Preparing,input=r.input,origin=detached}
 r.input={};r.origin={};r.state=.Returning;r.returning_to=.Preparing;r.stage=.Redirecting
 k.counters.active_requests-=1;k.returning+=1;k.counters.returning_requests+=1;k.references+=1
 k.dispatch_dirty=true;k.idle_dirty=true
 return disposal,{}
}

// The owner has disposed the Begin input/origin and physically retired the old
// model before calling Ready. Transfer the SAME ledger reference and lease;
// never recycle the request generation or append an intermediate completion.
kernel_redirect_ready :: proc(k:^Kernel,h:Request_Handle,now:runtime_async.Deadline)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {kind=.Invalid_Handle}}
 if r.state!=.Returning || r.returning_to!=.Preparing || r.stage!=.Redirecting ||
    r.input.storage!=nil || r.origin.slot!=0 || r.session.slot!=0 || !completion_empty(&r.response) ||
    r.error.kind!=.None || r.completion_queued || k.returning<1 || k.counters.returning_requests<1 ||
    k.references<=1 || k.preparing==max(int) || k.counters.preparing_requests==max(int) {return {kind=.Invalid_State}}
 if error:=redirect_cutoff_locked(k,r,now);error.kind!=.None {return error}
 r.state=.Preparing;r.returning_to=.Free
 // Redirecting distinguishes an already accepted Preparing ticket from an
 // original producer reservation; only the accepted form may use Fail below.
 k.returning-=1;k.counters.returning_requests-=1;k.preparing+=1;k.counters.preparing_requests+=1
 k.dispatch_dirty=true
 return {}
}

// Resolve a previously accepted hop, including failure before a new claim or
// after a Reserved/Waiter claim. Ordinary kernel_rollback would lose the public
// request and silently retire its handle, so it is never used on this path.
kernel_redirect_fail :: proc(k:^Kernel,h:Request_Handle,primary:surf.HTTP_Error)->(Request_Disposal,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if primary.kind==.None {return {},{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {},{kind=.Invalid_Handle}}
 returning:=r.state==.Returning && r.returning_to==.Preparing
 preparing:=r.state==.Preparing
 if (!returning && !preparing) || r.stage!=.Redirecting || r.error.kind!=.None ||
    !completion_empty(&r.response) || r.completion_queued || k.references<=1 {return {},{kind=.Invalid_State}}
 if returning && (r.origin.slot!=0 || r.session.slot!=0 || r.input.storage!=nil || k.returning<1 || k.counters.returning_requests<1) {return {},{kind=.Invalid_State}}
 if preparing && (k.preparing<1 || k.counters.preparing_requests<1 || k.returning==max(int) ||
    k.counters.returning_requests==max(int) || k.references==max(int)) {return {},{kind=.Invalid_State}}
 disposal:=Request_Disposal{request=h,returning_to=.Completed,input=r.input,lease=r.lease}
 if preparing {
  if error:=admission_detach_claim_locked(k,h,r);error.kind!=.None {return {},error}
  if r.origin.slot!=0 {
   origin,error:=kernel_origin_release_locked(k,r.origin,.Request)
   assert(error.kind==.None)
   disposal.origin=origin
  }
  k.preparing-=1;k.counters.preparing_requests-=1;k.returning+=1;k.counters.returning_requests+=1
 }
 // Preparing and Returning both already own one Kernel bookkeeping reference.
 // Transfer it to terminal Returning without adding or dropping another one.
 r.input={};r.origin={};r.session={};r.lease={};r.error=primary
 r.state=.Returning;r.returning_to=.Completed;r.stage=.Retiring
 k.dispatch_dirty=true;k.idle_dirty=true
 return disposal,{}
}
