package surf_async

import stream_api "stream"

import http "../../http"
import h1 "../../http/v1"
import runtime_async "../../async"
import signal "../../async/signal"
import scopes "core:sync/budget"
import "core:sync"

@(private)
client_rollback :: proc(s:^Client_State,preparing:Preparing_Request) {
 sync.lock(&s.mu)
 disposal,error:=kernel_rollback(&s.kernel,preparing)
 assert(error.kind==.None)
 network_queue_forget_locked(s,preparing.request)
 s.returning_calls+=1
 sync.unlock(&s.mu)
 origin:=disposal.origin.origin
 request_disposal_destroy(&disposal)
 if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&s.kernel,origin).kind==.None)}
 now,_:=network_clock(s)
 next,done,finish:=kernel_cleanup_finish(&s.kernel,preparing.request,now)
 assert(finish.kind==.None && done)
 request_disposal_destroy(&next)
 sync.lock(&s.mu);s.returning_calls-=1;network_queue_changed_locked(s);sync.unlock(&s.mu)
}

client_submit :: proc(c:^Client,request:http.Request,deadline:runtime_async.Deadline={})->(Request_Handle,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return {},error};defer client_leave(s)
 selected,cause:=submission_budget(s,deadline)
 if cause.kind!=.None {return {},cause}
 return client_submit_state(s,request,selected,nil)
}

@(private)
client_submit_state :: proc(s:^Client_State,request:http.Request,selected:Submission_Budget,input_stream:^stream_api.Channel)->(Request_Handle,Client_Error) {
 stream:=input_stream
 defer if stream!=nil {stream_api.release_request(stream)}
 now,cutoff:=selected.now,selected.cutoff
 if stream!=nil {
  sync.lock(&s.mu);published:=s.phase==.Published;sync.unlock(&s.mu)
  if !published {return {},{kind=.Closed}}
  fresh,clock:=network_clock(s)
  if clock.kind!=.None {return {},clock}
  if fresh.at>=cutoff.at {return {},{kind=.Request_Error,http={kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent}}}
  now=fresh
 }
 if len(request.url)<0 || len(request.url)>0 && raw_data(request.url)==nil {return {},{kind=.Request_Error,http={kind=.Invalid_URL}}}
 if len(request.body)<0 || len(request.body)>0 && raw_data(request.body)==nil {return {},{kind=.Request_Error,http={kind=.Invalid_Config}}}
 if len(request.headers)<0 || len(request.headers)>http.MAX_HEADERS {return {},{kind=.Request_Error,http={kind=.Header_Limit}}}
 if len(request.headers)>0 && raw_data(request.headers)==nil {return {},{kind=.Request_Error,http={kind=.Invalid_Header}}}
 for field in request.headers {
  if len(field.name)<0 || len(field.value)<0 || len(field.name)>0 && raw_data(field.name)==nil ||
     len(field.value)>0 && raw_data(field.value)==nil {return {},{kind=.Request_Error,http={kind=.Invalid_Header}}}
 }
 // Pure descriptor/wire validation precedes any source traversal or allocation.
 header:[http.MAX_HEADER_SIZE]u8
 if _,validation:=h1.request_encode_profile(header[:],request,.Keep_Alive);validation.kind!=.None {return {},{kind=.Request_Error,http={kind=validation.kind}}}
 lease,admission:=resources_request_lease(&s.resources)
 if admission.kind!=.None {return {},admission}
 defer scopes.release(&lease)
 sync.lock(&s.mu)
 if s.phase!=.Published {sync.unlock(&s.mu);return {},{kind=.Closed}}
 preparing,reserve:=kernel_reserve(&s.kernel,cutoff,&lease)
 sync.unlock(&s.mu)
 if reserve.kind!=.None {return {},reserve}
 if stream!=nil {
  sync.lock(&s.kernel.mu)
  slot:=admission_request_locked(&s.kernel,preparing.request)
  assert(slot!=nil)
  slot.stream=stream;stream_api.adopt_lease(stream,&slot.lease);stream=nil
  sync.unlock(&s.kernel.mu)
 }
 committed:=false
 defer if !committed {client_rollback(s,preparing)}
 origin,prepare:=origin_prepare(&s.profile,request.url,s.resources.allocator)
 if prepare.kind!=.None {return {},prepare}
 defer origin_destroy(&origin)
 if _,claim:=network_queue_claim(s,preparing,&origin,now.at);claim.kind!=.None {return {},claim}
 input,clone:=request_clone(request,s.resources.allocator)
 if clone.kind!=.None {return {},clone}
 defer request_owner_destroy(&input)
 fresh,sample:=network_clock(s)
 if sample.kind!=.None {return {},sample}
 sync.lock(&s.mu)
 commit:=network_queue_committed_locked(s,preparing,&input,fresh)
 sync.unlock(&s.mu)
 if commit.kind!=.None {return {},commit}
 committed=true
 _=signal.wake(s.coordinator.wake)
 return preparing.request,{}
}

@(private)
Submission_Budget :: struct {now,cutoff:runtime_async.Deadline}

// Select the immutable total cutoff before validation or any owned allocation.
@(private)
submission_budget :: proc(s:^Client_State,deadline:runtime_async.Deadline)->(Submission_Budget,Client_Error) {
 sync.lock(&s.mu);published:=s.phase==.Published;sync.unlock(&s.mu)
 if !published {return {},{kind=.Closed}}
 now,clock:=network_clock(s)
 if clock.kind!=.None {return {},clock}
 if (deadline.epoch==0 && deadline.at!=0) || deadline.epoch!=0 && (deadline.epoch!=now.epoch || deadline.at<=0) {return {},{kind=.Invalid_Config}}
 cutoff:=runtime_async.Deadline{epoch=now.epoch,at=now.at+min(i64(s.config.config.request_timeout),max(i64)-now.at)}
 if deadline.epoch!=0 {cutoff.at=min(cutoff.at,deadline.at)}
 if life:=s.config.config.lifetime;life.epoch!=0 {cutoff.at=min(cutoff.at,life.at)}
 if now.at>=cutoff.at {return {},{kind=.Request_Error,http={kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent}}}
 return {now=now,cutoff=cutoff},{}
}
