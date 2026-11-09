package surf_async

import surf ".."
import runtime_async "../../async"
import "core:mem"
import scopes "core:sync/budget"
import "core:sync"

@(private)
completion_empty :: proc(response:^surf.Response)->bool {
 return response!=nil && response.status==0 && response.headers==nil && response.body==nil && response.header_storage==nil &&
        raw_data(response.body_storage)==nil && response.allocator.procedure==nil && response._allocator_scope==(scopes.Scope{})
}
@(private)
completion_queue_unlink_locked :: proc(k:^Kernel,index:u32,r:^Request_Slot) {
 if !r.completion_queued {return}
 previous,next:=r.completion_previous,r.completion_next
 if previous==0 {k.completion_head=next} else {k.requests[int(previous)-1].completion_next=next}
 if next==0 {k.completion_tail=previous} else {k.requests[int(next)-1].completion_previous=previous}
 r.completion_previous,r.completion_next=0,0;r.completion_queued=false
}
@(private)
completion_queue_append_locked :: proc(k:^Kernel,index:u32,r:^Request_Slot) {
 assert(!r.completion_queued)
 r.completion_previous=k.completion_tail;r.completion_next=0
 if k.completion_tail==0 {k.completion_head=index} else {k.requests[int(k.completion_tail)-1].completion_next=index}
 k.completion_tail=index;r.completion_queued=true
}

kernel_begin_complete :: proc(k:^Kernel,h:Request_Handle,response:^surf.Response,error:surf.HTTP_Error)->(Request_Disposal,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if response==nil || admission_alias(k,response,size_of(surf.Response)) {return {},{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {},{kind=.Invalid_Handle}}
 if r.state!=.Queued && r.state!=.Active {return {},{kind=.Pending}}
 if k.references<1 || k.references==max(int) || k.returning==max(int) {return {},{kind=.Invalid_State}}
 if cause:=admission_detach_claim_locked(k,h,r);cause.kind!=.None {return {},cause}
 result:=Request_Disposal{request=h,returning_to=.Completed,input=r.input,lease=r.lease}
 // A primary failure stays authoritative. Even an accidentally supplied owned
 // Response on that path must be detached and physically released, not hidden.
 if error.kind==.None {r.response=response^} else {result.response=response^;r.response={}}
 response^={};r.input={};r.lease={};r.error=error
 if r.state==.Queued {k.counters.queued_requests-=1} else {k.counters.active_requests-=1}
 r.state=.Returning;r.returning_to=.Completed;r.stage=.Retiring
 k.returning+=1;k.references+=1;k.counters.returning_requests+=1;k.dispatch_dirty=true
 return result,{}
}

@(private)
completion_late_failure :: proc(k:^Kernel,r:^Request_Slot,now:runtime_async.Deadline)->surf.HTTP_Error {
 effect:=surf.HTTP_Write_Effect.Unknown
 if r.response.status!=0 {effect=.Response_Received}
 if now.epoch!=r.deadline.epoch || now.at<=0 {return {kind=.Invalid_Config,phase=.Configuration,status=r.response.status,write_effect=effect}}
 if r.cancel_requested || k.closed {return {kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,status=r.response.status,write_effect=effect}}
 if now.at>=r.deadline.at {return {kind=.Deadline_Failed,phase=.Deadline,status=r.response.status,write_effect=effect}}
 return {}
}

kernel_cleanup_finish :: proc(k:^Kernel,h:Request_Handle,now:runtime_async.Deadline)->(Request_Disposal,bool,Client_Error) {
 if k==nil || k.self!=k {return {},false,{kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {},false,{kind=.Invalid_Handle}}
 if r.state!=.Returning || (r.returning_to!=.Free && r.returning_to!=.Completed) || k.returning<1 || k.references<=1 {return {},false,{kind=.Invalid_State}}
 if r.returning_to==.Completed {
  if r.error.kind==.None {
   error:=completion_late_failure(k,r,now)
   if error.kind!=.None {
    disposal:=Request_Disposal{request=h,returning_to=.Completed,response=r.response}
    r.response={};r.error=error
    // Keep the same Returning reference and withhold publication until the
    // detached successful payload's final physical free has returned.
    return disposal,false,{}
   }
  }
  r.state=.Completed;r.stage=.Completed;r.returning_to=.Free
  k.returning-=1;k.references-=1;k.counters.returning_requests-=1;k.counters.completed_requests+=1
  if (r.error.kind==.Deadline_Failed || r.error.phase==.Deadline) && k.counters.deadline_count!=max(u64) {k.counters.deadline_count+=1}
  completion_queue_append_locked(k,h.slot,r)
  return {},true,{}
 }
 if r.origin.slot!=0 || r.session.slot!=0 || r.input.storage!=nil || !completion_empty(&r.response) || r.lease!=(scopes.Lease{}) {return {},false,{kind=.Invalid_State}}
 if r.generation!=max(u64) && (k.request_free_count<0 || k.request_free_count>=len(k.request_free)) {return {},false,{kind=.Invalid_State}}
 generation:=r.generation
 r^={generation=generation,state=.Retired}
 if generation!=max(u64) {
  r.generation+=1;r.state=.Free
  k.request_free[k.request_free_count]=h.slot;k.request_free_count+=1
 }
 k.returning-=1;k.references-=1;k.counters.returning_requests-=1;k.dispatch_dirty=true
 return {},true,{}
}

kernel_poll :: proc(k:^Kernel)->(Completion,bool) {
 if k==nil || k.self!=k {return {},false}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 index:=k.completion_head
 if index==0 || u64(index)>u64(len(k.requests)) {return {},false}
 r:=&k.requests[int(index)-1]
 if r.state!=.Completed || !r.completion_queued {return {},false}
 completion_queue_unlink_locked(k,index,r)
 return {request={owner_id=k.owner_id,slot=index,generation=r.generation},error=r.error},true
}

// Both synchronous consumers use the same Returning machinery as asynchronous
// cleanup. No generation is recycled until Response/origin callbacks finish.
@(private)
completion_detach_locked :: proc(k:^Kernel,h:Request_Handle,r:^Request_Slot)->(Request_Disposal,Client_Error) {
 if r.state!=.Completed {return {},{kind=.Pending}}
 if k.references<1 || k.references>=max(int)-1 || k.returning==max(int) || k.counters.completed_requests<1 {return {},{kind=.Invalid_State}}
 if r.origin.slot!=0 {
  origin:=admission_origin_locked(k,r.origin)
  if origin==nil || origin.requests<1 {return {},{kind=.Invalid_State}}
 }
 result:=Request_Disposal{request=h,returning_to=.Free,input=r.input,response=r.response,lease=r.lease}
 if r.origin.slot!=0 {
  disposal,error:=kernel_origin_release_locked(k,r.origin,.Request)
  if error.kind!=.None {return {},error}
  result.origin=disposal
 }
 completion_queue_unlink_locked(k,h.slot,r)
 r.origin={};r.session={};r.input={};r.response={};r.lease={}
 r.state=.Returning;r.returning_to=.Free;r.stage=.Retiring
 k.references+=1;k.returning+=1;k.counters.returning_requests+=1;k.counters.completed_requests-=1;k.dispatch_dirty=true
 return result,{}
}
@(private)
completion_dispose_and_finish :: proc(k:^Kernel,h:Request_Handle,disposal:^Request_Disposal)->Client_Error {
 origin:=disposal.origin.origin
 request_disposal_destroy(disposal)
 if origin.slot!=0 {if error:=kernel_origin_cleanup_finish(k,origin);error.kind!=.None {return error}}
 next,done,error:=kernel_cleanup_finish(k,h,{})
 assert(next.input.storage==nil && next.response.body_storage==nil)
 if error.kind!=.None {return error}
 if !done {return {kind=.Invalid_State}}
 return {}
}

kernel_take :: proc(k:^Kernel,h:Request_Handle,destination:^surf.Response)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 if destination==nil || admission_alias(k,destination,size_of(surf.Response)) {return {kind=.Invalid_State}}
 sync.lock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {sync.unlock(&k.mu);return {kind=.Invalid_Handle}}
 if r.state!=.Completed {sync.unlock(&k.mu);return {kind=.Pending}}
 if !completion_empty(destination) {sync.unlock(&k.mu);return {kind=.Invalid_State}}
 if r.error.kind!=.None {error:=Client_Error{kind=.Request_Error,http=r.error};sync.unlock(&k.mu);return error}
 // Preflight/detach can fail without changing destination or the stored result.
 saved:=r.response
 disposal,error:=completion_detach_locked(k,h,r)
 if error.kind!=.None {sync.unlock(&k.mu);return error}
 destination^=saved;disposal.response={}
 sync.unlock(&k.mu)
 return completion_dispose_and_finish(k,h,&disposal)
}

kernel_release :: proc(k:^Kernel,h:Request_Handle)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {sync.unlock(&k.mu);return {kind=.Invalid_Handle}}
 disposal,error:=completion_detach_locked(k,h,r)
 sync.unlock(&k.mu)
 if error.kind!=.None {return error}
 return completion_dispose_and_finish(k,h,&disposal)
}
