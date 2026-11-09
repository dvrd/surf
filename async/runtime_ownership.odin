package surf_async

import surf ".."
import runtime_async "../../async"
import signal "../../async/signal"
import "core:sync"

network_state_retain :: proc(s:^Client_State)->bool {
 if !network_valid(s) {return false}
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 if s.phase==.Disposing || s.references==0 || s.references==max(u64) {return false}
 s.references+=1;return true
}
network_state_release :: proc(s:^Client_State) {
 if !network_valid(s) {return}
 sync.lock(&s.mu)
 assert(s.references>0 && (s.references>1 || !s.base_owned))
 s.references-=1
 last:=s.references==0
 if last {
  assert(!s.base_owned && s.registered_tasks==0 && s.producer_calls==0 && s.returning_calls==0)
  s.phase=.Disposing
 }
 sync.unlock(&s.mu)
 if last {network_cleanup_storage(s)}
}

network_clock :: proc(s:^Client_State)->(runtime_async.Deadline,Client_Error) {
 if !network_valid(s) {return {},{kind=.Invalid_State}}
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 if s.phase==.Disposing || s.registered_tasks==0 || s.runtime==nil {return {},{kind=.Closed}}
 now:=runtime_async.deadline_after(s.runtime,0)
 if now.epoch!=s.runtime_epoch || now.at<=0 {return {},{kind=.Invalid_State}}
 s.last_clock=now
 return now,{}
}

// Bounded metadata-only transfer used by the actor implementation. Borrowed
// input/host views remain held by Kernel Request/Session refs through cleanup.
network_assignment_take :: proc(actor:^Session_Actor)->(Session_Assignment,Client_Error) {
 if actor==nil || !network_valid(actor.owner) {return {},{kind=.Invalid_State}}
 s:=actor.owner
 if actor.index==0 || u64(actor.index)>u64(len(s.actors)) || actor!=&s.actors[int(actor.index)-1] {return {},{kind=.Invalid_Handle}}
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 if s.phase!=.Published {return {},{kind=.Closed}}
 if !actor.command.pending {return {},{kind=.Pending}}
 assignment:=actor.command.assignment
 sync.lock(&s.kernel.mu);defer sync.unlock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,assignment.request)
 if request==nil || request.state!=.Active || request.session!=assignment.session ||
    assignment.session.slot!=actor.index || assignment.session.generation==0 {return {},{kind=.Invalid_Handle}}
 model:=&s.kernel.sessions[int(actor.index)-1]
 if model.generation!=assignment.session.generation || model.request!=assignment.request ||
    (model.state!=.Busy && model.state!=.Connecting) {return {},{kind=.Invalid_State}}
 origin:=admission_origin_locked(&s.kernel,request.origin)
 if origin==nil || model.origin!=request.origin {return {},{kind=.Invalid_State}}
 metadata:=&s.requests[int(assignment.request.slot)-1]
 if metadata.generation!=assignment.request.generation || metadata.ids.count<0 || metadata.ids.count>DNS_IDS_PER_QUERY ||
    metadata.prepared_address_count<0 || metadata.prepared_address_count>DNS_RESULT_CAPACITY ||
    metadata.query_budget_left<metadata.ids.count {return {},{kind=.Invalid_State}}
 if model.state==.Connecting && metadata.prepared_address_count==0 && metadata.ids.count==0 {return {},{kind=.Pending}}
 if s.registered_tasks==0 || s.runtime==nil {return {},{kind=.Closed}}
 now:=runtime_async.deadline_after(s.runtime,0)
 if now.epoch!=request.deadline.epoch || now.at<=0 {return {},{kind=.Invalid_State}}
 s.last_clock=now
 if request.cancel_requested || actor.command.cancel || actor.command.retire || s.kernel.closed {return {},{kind=.Closed}}
 if now.at>=request.deadline.at {return {},{kind=.Request_Error,http={kind=.Deadline_Failed,phase=.Deadline}}}
 setup:=request.deadline
 duration:=s.config.config.http.setup_timeout
 if duration>0 {setup.at=min(setup.at,now.at+min(i64(duration),max(i64)-now.at))}
 result:=Session_Assignment{assignment=assignment,request=request.input.request,cutoff=request.deadline,
  setup_cutoff=setup,secure=origin.owner.key.secure,host=origin.owner.key.host,port=origin.owner.key.port,
  ids=metadata.ids,addresses=metadata.prepared_addresses,address_count=metadata.prepared_address_count}
 metadata.query_budget_left-=metadata.ids.count;metadata.ids={};metadata.awaiting_ids=false
 actor.command.pending=false
 return result,{}
}

@(private)
network_unstarted_cancel :: proc(s:^Client_State) {
 assert(kernel_close(&s.kernel).kind==.None)
 for index in 0..<len(s.kernel.requests) {
  sync.lock(&s.kernel.mu)
  request:=&s.kernel.requests[index]
  queued:=request.state==.Queued
  handle:=Request_Handle{owner_id=s.kernel.owner_id,slot=u32(index+1),generation=request.generation}
  sync.unlock(&s.kernel.mu)
  if !queued {continue}
  response:surf.Response
  disposal,error:=kernel_begin_complete(&s.kernel,handle,&response,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent})
  assert(error.kind==.None)
  for {
   origin:=disposal.origin.origin
   request_disposal_destroy(&disposal)
   if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&s.kernel,origin).kind==.None)}
   now,clock_error:=network_clock(s)
   assert(clock_error.kind==.None) // This callback still owns its registered witness.
   next,done,failure:=kernel_cleanup_finish(&s.kernel,handle,now)
   assert(failure.kind==.None)
   disposal=next
   if done {break}
  }
 }
}

// No Task/TLS/adapter API is valid here: _current_task was cleared before the
// runtime invokes on_done. False certifies the caller's unstarted/no-I/O path.
network_task_done :: proc(s:^Client_State,actor_index:int,owner_drained:bool) {
 if !network_valid(s) || actor_index<0 || actor_index>len(s.actors) {return}
 sync.lock(&s.mu)
 registered:^bool
 done:^bool
 detached:^bool
 notification:signal.Signal
 if actor_index==0 {
  registered=&s.coordinator.registered;done=&s.coordinator.done;detached=&s.coordinator.detached;notification=s.coordinator.wake
 } else {
  actor:=&s.actors[actor_index-1]
  registered=&actor.registered;done=&actor.done;detached=&actor.detached;notification=actor.wake
 }
 if !registered^ {sync.unlock(&s.mu);return}
 assert(s.registered_tasks>0 && s.references>1)
 if !owner_drained {
  for actor in s.actors {assert(!actor.executor_initialized && !actor.transport_initialized && !actor.tls_initialized && !actor.handshake_started && !actor.close_started)}
 }
 registered^=false;done^=true
 s.phase=.Closing
 cleanup:=!owner_drained && !s.unstarted_cleanup_started
 if cleanup {s.unstarted_cleanup_started=true}
 sync.unlock(&s.mu)
 signal.detach(notification)
 if cleanup {
  network_unstarted_cancel(s)
  sync.lock(&s.mu);s.unstarted_cleanup_done=true;sync.unlock(&s.mu)
 }
 sync.lock(&s.mu)
 detached^=true
 s.registered_tasks-=1
 if s.registered_tasks==0 {s.runtime=nil}
 sync.unlock(&s.mu)
 network_state_release(s) // FINAL State access; last release may physically free.
}
