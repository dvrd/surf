package surf_async

import surf ".."
import runtime_async "../../async"
import signal "../../async/signal"
import "core:sync"

@(private)
network_coordinator_wake :: proc(notification:signal.Signal) {
 owner,valid:=signal.retain(notification)
 if valid {_=signal.wake(owner);signal.release(&owner)}
}

// Idempotent whole-State close. The caller owns a State reference. Snapshot
// retained producer handles while State.mu protects registration metadata; no
// scheduler notification or physical release executes under either owner lock.
network_close_state :: proc(s:^Client_State) {
 if !network_valid(s) {return}
 notifications:[MAX_CONNECTIONS+1]signal.Signal
 count:=0
 sync.lock(&s.mu)
 if s.phase==.Disposing {sync.unlock(&s.mu);return}
 sync.lock(&s.kernel.mu)
 first:=s.phase!=.Closing || !s.kernel.closed
 sync.unlock(&s.kernel.mu)
 if first {
  s.phase=.Closing
  assert(kernel_close(&s.kernel).kind==.None)
  network_queue_changed_locked(s)
  if s.coordinator.registered && !s.coordinator.detached {
   owner,valid:=signal.retain(s.coordinator.wake)
   if valid {notifications[count]=owner;count+=1}
  }
  for actor in s.actors {
   if actor.registered && !actor.detached {
    owner,valid:=signal.retain(actor.wake)
    if valid {notifications[count]=owner;count+=1}
   }
  }
 }
 sync.unlock(&s.mu)
 for &notification in notifications[:count] {
  _=signal.wake(notification)
  signal.release(&notification)
 }
}

// The caller's registration reference keeps State alive through arbitrary input
// and lease disposal callbacks. No physical callback runs under either mutex.
@(private)
network_coordinator_complete :: proc(s:^Client_State,handle:Request_Handle,error:surf.HTTP_Error)->Client_Error {
 sync.lock(&s.mu)
 response:surf.Response
 disposal,failure:=kernel_begin_complete(&s.kernel,handle,&response,error)
 if failure.kind==.None {network_queue_forget_locked(s,handle)}
 s.returning_calls+=1
 sync.unlock(&s.mu)
 if failure.kind==.None {
  for {
   origin:=disposal.origin.origin
   request_disposal_destroy(&disposal)
   if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&s.kernel,origin).kind==.None)}
   now,clock_error:=network_clock(s)
   assert(clock_error.kind==.None)
   next,done,finish_error:=kernel_cleanup_finish(&s.kernel,handle,now)
   assert(finish_error.kind==.None)
   disposal=next
   if done {break}
  }
 }
 sync.lock(&s.mu)
 assert(s.returning_calls>0);s.returning_calls-=1
 network_queue_changed_locked(s)
 sync.unlock(&s.mu)
 return failure
}

// One request-capacity inspection. Active request completion belongs solely to
// its actor; the coordinator only delivers a cancellation mailbox notification.
@(private)
network_coordinator_request_step :: proc(s:^Client_State,now:runtime_async.Deadline)->bool {
 sync.lock(&s.mu)
 if s.coordinator.scan_remaining==0 {sync.unlock(&s.mu);return false}
 index:=int(s.coordinator.request_cursor)%len(s.requests)
 s.coordinator.request_cursor=u32((index+1)%len(s.requests));s.coordinator.scan_remaining-=1
 sync.lock(&s.kernel.mu)
 request:=&s.kernel.requests[index]
 handle:=Request_Handle{owner_id=s.kernel.owner_id,slot=u32(index+1),generation=request.generation}
 closing:=s.phase==.Closing || s.kernel.closed
 cancellation:=closing || request.cancel_requested
 failed:=cancellation || (request.deadline.at!=0 && now.at>=request.deadline.at)
 complete:=request.state==.Queued && failed
 notification:signal.Signal
 if request.state==.Active && failed && request.session.slot!=0 {
  actor:=&s.actors[int(request.session.slot)-1]
  // An expired Active cutoff remains the actor's Deadline result. Do not
// turn it into an explicit cancellation merely because we also wake its owner.
  if cancellation {actor.command.cancel=true}
  notification=actor.wake
 }
 if request.state==.Queued && !failed && request.deadline.at>0 {
  next:=&s.coordinator.next_deadline
  if next.at==0 || request.deadline.at<next.at {next^=request.deadline}
 }
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 network_coordinator_wake(notification)
 if complete {
  error:=surf.HTTP_Error{kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent}
  if cancellation {error={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
  assert(network_coordinator_complete(s,handle,error).kind==.None)
  return true
 }
 return false
}

// One request metadata cell and at most one finite16-ID transfer. Only the
// unassigned origin FIFO head is unparked; no later waiter bypasses that head.
@(private)
network_coordinator_dns_step :: proc(s:^Client_State)->bool {
 sync.lock(&s.mu)
 index:=int(s.coordinator.dns_cursor)%len(s.requests)
 s.coordinator.dns_cursor=u32((index+1)%len(s.requests))
 sync.lock(&s.kernel.mu)
 request:=&s.kernel.requests[index];metadata:=&s.requests[index]
 handle:=Request_Handle{owner_id=s.kernel.owner_id,slot=u32(index+1),generation=request.generation}
 origin:=admission_origin_locked(&s.kernel,request.origin)
 eligible:=s.phase==.Published && request.state==.Queued && request.session.slot==0 && !request.cancel_requested &&
  metadata.generation==request.generation && metadata.awaiting_ids && metadata.ids.count==0 && metadata.query_budget_left>0 &&
  origin!=nil && origin.queue_head==handle.slot
 maximum:=min(DNS_IDS_PER_QUERY,metadata.query_budget_left)
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if !eligible {return false}
 block,error:=network_dns_reserve(s,maximum)
 if error.kind!=.None {return false}
 installed:=false
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 request=admission_request_locked(&s.kernel,handle);metadata=&s.requests[index]
 if s.phase==.Published && request!=nil && request.state==.Queued && request.session.slot==0 && !request.cancel_requested &&
    metadata.generation==handle.generation && metadata.awaiting_ids && metadata.ids.count==0 {
  origin=admission_origin_locked(&s.kernel,request.origin)
  if origin!=nil && origin.queue_head==handle.slot {
   metadata.ids=block;block={};metadata.awaiting_ids=false;request.stage=.Queued
   s.kernel.dispatch_dirty=true;network_queue_changed_locked(s);installed=true
  }
 }
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 network_dns_burn(s,&block)
 return installed
}

@(private)
network_coordinator_dispatch_step :: proc(s:^Client_State,now:i64)->bool {
 sync.lock(&s.mu)
 if s.phase!=.Published {sync.unlock(&s.mu);return true}
 assignment,_,error:=pool_dispatch(&s.kernel,1,now)
 notification:signal.Signal
 if assignment.request.slot!=0 {
  actor:=&s.actors[int(assignment.session.slot)-1]
  assert(!actor.command.pending)
  actor.command={assignment=assignment,pending=true}
  notification=actor.wake
 }
 sync.unlock(&s.mu)
 network_coordinator_wake(notification)
 return error.kind!=.Pending && assignment.request.slot==0
}

@(private)
network_coordinator_idle_step :: proc(s:^Client_State,now:i64)->bool {
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 needs_scan:=s.kernel.idle_dirty || s.kernel.idle_remaining>0 || (s.kernel.idle_deadline>0 && now>=s.kernel.idle_deadline)
 sync.unlock(&s.kernel.mu)
 if !needs_scan {sync.unlock(&s.mu);return true}
 candidate,_,error:=pool_idle_candidate(&s.kernel,1,now)
 notification:signal.Signal
 if candidate.slot!=0 {
  assert(pool_session_state(&s.kernel,candidate,.Retiring,now).kind==.None)
  actor:=&s.actors[int(candidate.slot)-1]
  actor.command.retire=true;notification=actor.wake
 }
 sync.lock(&s.kernel.mu)
 stable:=s.kernel.idle_remaining==0 && !s.kernel.idle_dirty
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 network_coordinator_wake(notification)
 return error.kind!=.Pending && candidate.slot==0 && stable
}

network_coordinator_resume :: proc(data:rawptr)->runtime_async.Resume_Result {
 coordinator:=cast(^Coordinator_State)data
 if coordinator==nil || !network_valid(coordinator.owner) {return .Done}
 s:=coordinator.owner
 now,error:=network_clock(s)
 assert(error.kind==.None)
 sync.lock(&s.mu)
 lifetime:=s.config.config.lifetime
 closing_at_entry:=s.phase==.Closing
 sync.unlock(&s.mu)
 if closing_at_entry || lifetime.epoch!=0 && now.at>=lifetime.at {network_close_state(s)}
 sync.lock(&s.mu)
 if coordinator.scan_remaining==0 {network_queue_changed_locked(s)}
 work:=s.config.config.capacities.work_per_resume
 sync.unlock(&s.mu)
 dispatch_stable,idle_stable:=false,false
 // Each unit is a documented COMPOSITE upper bound: one request inspection,
// one DNS cell+at most16 copied IDs, one charged pool dispatch inspection and
// one charged Idle inspection. Parser/I/O/entropy and unbounded scans are absent.
 for _ in 0..<work {
  if network_coordinator_request_step(s,now) {return .Yield}
  _=network_coordinator_dns_step(s)
  dispatch_stable=network_coordinator_dispatch_step(s,now.at)
  idle_stable=network_coordinator_idle_step(s,now.at)
 }
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 closing:=s.phase==.Closing || s.kernel.closed
 done:=closing && s.kernel.preparing==0 && s.kernel.returning==0 && s.kernel.counters.queued_requests==0 &&
  s.kernel.counters.active_requests==0 && s.kernel.counters.reserved_connections==0 &&
  s.kernel.counters.idle_connections==0 && s.producer_calls==0 && s.returning_calls==0
 if done {coordinator.done=true}
 scanned:=coordinator.scan_remaining==0
 deadline:=coordinator.next_deadline
 if s.kernel.idle_deadline>0 && (deadline.at==0 || s.kernel.idle_deadline<deadline.at) {
  deadline={epoch=s.runtime_epoch,at=s.kernel.idle_deadline}
 }
 if !closing && lifetime.epoch!=0 && (deadline.at==0 || lifetime.at<deadline.at) {deadline=lifetime}
 runtime:=s.runtime
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if done {return .Done}
 if closing || !scanned || !dispatch_stable || !idle_stable {return .Yield}
 if deadline.at>0 {
  failure:=runtime_async.sleep_until(runtime,deadline)
  if failure.kind!=.Pending {return .Yield}
 }
 return .Waiting
}

network_coordinator_cancel :: proc(data:rawptr)->runtime_async.Resume_Result {
 coordinator:=cast(^Coordinator_State)data
 if coordinator==nil || !network_valid(coordinator.owner) {return .Done}
 s:=coordinator.owner
 network_close_state(s)
 return network_coordinator_resume(data)
}
network_coordinator_done :: proc(data:rawptr) {
 coordinator:=cast(^Coordinator_State)data
 if coordinator==nil || !network_valid(coordinator.owner) {return}
 s:=coordinator.owner
 sync.lock(&s.mu);drained:=coordinator.done;sync.unlock(&s.mu)
 network_task_done(s,0,drained)
}
