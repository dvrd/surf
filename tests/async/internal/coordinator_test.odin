package surf_async

import surf ".."
import signal "../../async/signal"
import "base:intrinsics"
import scopes "core:sync/budget"
import "core:time"
import "core:thread"

import runtime_async "../../async"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:sync"
import "core:testing"

@(test)
coordinator_unstarted_close_burns_queued_reserved_dns_metadata :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&track)
 runtime:runtime_async.Runtime;bootstrap_runtime(&runtime)
 config:=bootstrap_config({},17)
 servers:=[1]net.Endpoint{{net.IP4_Loopback,53}}
 config.http.resolver.name_servers=servers[:]
 state,error:=network_prepare(&runtime,config,allocator);assert(error.kind==.None)
 handle:=bootstrap_queued(state,&runtime,"http://queued.example/path")
 block,reserved:=network_dns_reserve(state,6);assert(reserved.kind==.None && block.count==6)
 sync.lock(&state.mu)
 state.requests[handle.slot-1].ids=block;block={}
 state.requests[handle.slot-1].awaiting_ids=true;state.requests[handle.slot-1].needs_dns=true
 sync.unlock(&state.mu)
 contexts:[2]Bootstrap_Task_Context
 for task,index in state.task_index {
  contexts[index]={state=state,task=task,index=index}
  task^={resume=bootstrap_registered_resume,on_cancel=bootstrap_registered_cancel,on_done=bootstrap_registered_done,data=&contexts[index]}
  assert(network_state_retain(state))
 }
 sync.lock(&state.mu)
 state.registered_tasks=2;state.coordinator.registered=true;state.actors[0].registered=true;state.phase=.Published
 sync.unlock(&state.mu)
 assert(runtime_async.register_group(&runtime,state.task_index).kind==.None)
 // Real Runtime.destroy invokes on_done synchronously without ever running IO.
 assert(runtime_async.destroy(&runtime).kind==.None)
 testing.expect_value(t,state.requests[handle.slot-1].ids.count,0)
 testing.expect_value(t,state.requests[handle.slot-1].awaiting_ids,false)
 testing.expect_value(t,state.dns_draws_reserved,u64(6))
 testing.expect_value(t,state.dns_draws_burned,u64(6))
 completion,available:=kernel_poll(&state.kernel)
 testing.expect(t,available && completion.request==handle && completion.error.transport.kind==.Cancelled)
 assert(kernel_release(&state.kernel,handle).kind==.None)
 fmt.printf("COORD17 unstarted_reserved_dns_burn=%d no_protocol_io=true\n",state.dns_draws_burned)
 sync.lock(&state.mu);state.base_owned=false;sync.unlock(&state.mu)
 network_state_release(state)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&track)
}

Coordinator_Test_Actor :: struct {
 actor:^Session_Actor,
 assignment:Assignment,
 hold,assigned,completed,done,resumes,observed_cancel,keep_idle,retired:int,
 idle:Cell_Handle,
 last_error:surf.HTTP_Error,
}
Coordinator_Test_Case :: struct {
 track:mem.Tracking_Allocator,
 allocator:mem.Allocator,
 scope:scopes.Scope,
 runtime:runtime_async.Runtime,
 state:^Client_State,
 actors:[2]Coordinator_Test_Actor,
}
coordinator_test_finish :: proc(c:^Coordinator_Test_Actor,error:surf.HTTP_Error) {
 s:=c.actor.owner;assignment:=c.assignment
 sync.lock(&s.mu)
 keep_idle:=error.kind==.None && intrinsics.atomic_load(&c.keep_idle)!=0 && s.phase==.Published
 if !keep_idle {assert(pool_session_state(&s.kernel,assignment.session,.Retiring,runtime_async.deadline_after(s.runtime,0).at).kind==.None)}
 response:surf.Response
 // Controlled metadata actor only; this status is NOT a received HTTP result.
 if error.kind==.None {response.status=200}
 disposal,cause:=kernel_begin_complete(&s.kernel,assignment.request,&response,error);assert(cause.kind==.None)
 network_queue_forget_locked(s,assignment.request)
 sync.unlock(&s.mu)
 for {
  origin:=disposal.origin.origin;request_disposal_destroy(&disposal)
  if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&s.kernel,origin).kind==.None)}
  now,clock:=network_clock(s);assert(clock.kind==.None)
  next,done,failure:=kernel_cleanup_finish(&s.kernel,assignment.request,now);assert(failure.kind==.None)
  disposal=next;if done {break}
 }
 if keep_idle {
  sync.lock(&s.mu);assert(pool_session_state(&s.kernel,assignment.session,.Idle,runtime_async.deadline_after(s.runtime,0).at).kind==.None);sync.unlock(&s.mu)
  c.idle=assignment.session
 } else {assert(pool_retire(&s.kernel,assignment.session).kind==.None)}
 c.last_error=error;c.assignment={}
 sync.lock(&s.mu);network_queue_changed_locked(s);sync.unlock(&s.mu)
 _=signal.wake(s.coordinator.wake)
 intrinsics.atomic_add(&c.completed,1)
}
coordinator_test_actor_resume :: proc(data:rawptr)->runtime_async.Resume_Result {
 c:=cast(^Coordinator_Test_Actor)data;a:=c.actor;s:=a.owner
 sync.lock(&s.mu)
 closing:=s.phase==.Closing
 cancel:=a.command.cancel
 retire:=a.command.retire
 pending:=a.command.pending
 intrinsics.atomic_add(&c.resumes,1)
 intrinsics.atomic_store(&c.observed_cancel,1 if cancel else 0)
 if pending && c.assignment.request.slot==0 && (closing || cancel) {
  c.assignment=a.command.assignment;a.command.pending=false
 }
 sync.unlock(&s.mu)
 if pending && c.assignment.request.slot==0 && !closing && !cancel {
  assigned,error:=network_assignment_take(a);assert(error.kind==.None)
  c.assignment=assigned.assignment
  network_dns_burn(s,&assigned.ids)
  sync.lock(&s.mu)
  sync.lock(&s.kernel.mu)
  connecting:=s.kernel.sessions[c.assignment.session.slot-1].state==.Connecting
  sync.unlock(&s.kernel.mu)
  if connecting {
   assert(pool_session_state(&s.kernel,c.assignment.session,.Busy,runtime_async.deadline_after(s.runtime,0).at).kind==.None)
  }
  sync.unlock(&s.mu)
  intrinsics.atomic_add(&c.assigned,1)
 }
 if c.assignment.request.slot!=0 && (closing || cancel || intrinsics.atomic_load(&c.hold)==0) {
  error:surf.HTTP_Error
  if closing || cancel {error={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
  coordinator_test_finish(c,error)
 }
 if (retire || closing) && c.idle.slot!=0 {
  sync.lock(&s.mu);sync.lock(&s.kernel.mu)
  state:=s.kernel.sessions[c.idle.slot-1].state
  sync.unlock(&s.kernel.mu)
  if state==.Idle {assert(pool_session_state(&s.kernel,c.idle,.Retiring,runtime_async.deadline_after(s.runtime,0).at).kind==.None)}
  a.command.retire=false
  sync.unlock(&s.mu)
  assert(pool_retire(&s.kernel,c.idle).kind==.None);c.idle={}
  intrinsics.atomic_add(&c.retired,1)
  sync.lock(&s.mu);network_queue_changed_locked(s);sync.unlock(&s.mu)
  _=signal.wake(s.coordinator.wake)
 }
 if closing {a.owner_drained=true;return .Done}
 return .Waiting
}
coordinator_test_actor_cancel :: proc(data:rawptr)->runtime_async.Resume_Result {
 c:=cast(^Coordinator_Test_Actor)data
 sync.lock(&c.actor.owner.mu);c.actor.owner.phase=.Closing;sync.unlock(&c.actor.owner.mu)
 return coordinator_test_actor_resume(data)
}
coordinator_test_actor_done :: proc(data:rawptr) {
 c:=cast(^Coordinator_Test_Actor)data
 s,index,drained:=c.actor.owner,c.actor.index,c.actor.owner_drained
 network_task_done(s,int(index),drained)
 intrinsics.atomic_store(&c.done,1)
}
coordinator_test_init :: proc(c:^Coordinator_Test_Case,dns:int=0,connections:int=1,idle_timeout:time.Duration=0,requests:int=4,lifetime:time.Duration=0) {
 mem.tracking_allocator_init(&c.track,rt.heap_allocator(),rt.heap_allocator());c.allocator=mem.tracking_allocator(&c.track)
 scope,error:=scopes.create_root({bytes=32<<20,streams=8,jobs=8},c.allocator);assert(error==.None);c.scope=scope
 bootstrap_runtime(&c.runtime)
 config:=bootstrap_config(scope,dns)
 if idle_timeout>0 {config.idle_timeout=idle_timeout}
 if lifetime>0 {config.lifetime=runtime_async.deadline_after(&c.runtime,lifetime)}
 config.capacities.requests=requests;config.capacities.origins=4;config.capacities.connections=connections
 servers:=[1]net.Endpoint{{net.IP4_Loopback,53}}
 if dns>0 {config.http.resolver.name_servers=servers[:]}
 state,cause:=network_prepare(&c.runtime,config,c.allocator);assert(cause.kind==.None);c.state=state
 state.coordinator.task={data=&state.coordinator,resume=network_coordinator_resume,on_cancel=network_coordinator_cancel,on_done=network_coordinator_done}
 for &actor,index in state.actors {
  actor_context:=&c.actors[index];actor_context.actor=&actor
  actor.task={data=actor_context,resume=coordinator_test_actor_resume,on_cancel=coordinator_test_actor_cancel,on_done=coordinator_test_actor_done}
  actor.registered=true;assert(network_state_retain(state))
 }
 assert(network_state_retain(state))
 state.coordinator.registered=true;state.registered_tasks=len(state.task_index);state.phase=.Published
 assert(runtime_async.register_group(&c.runtime,state.task_index).kind==.None)
 assert(runtime_async.start(&c.runtime).kind==.None)
}
coordinator_test_admit :: proc(c:^Coordinator_Test_Case,url:string,duration:time.Duration)->Request_Handle {
 s:=c.state;now:=runtime_async.deadline_after(&c.runtime,0)
 lease,error:=resources_request_lease(&s.resources);assert(error.kind==.None)
 preparing,cause:=kernel_reserve(&s.kernel,runtime_async.deadline_after(&c.runtime,duration),&lease);assert(cause.kind==.None)
 origin,prepared:=origin_prepare(&s.profile,url,s.resources.allocator);assert(prepared.kind==.None)
 _,claim:=network_queue_claim(s,preparing,&origin,now.at);origin_destroy(&origin);assert(claim.kind==.None)
 input,cloned:=request_clone({method=.GET,url=url},s.resources.allocator);assert(cloned.kind==.None)
 sync.lock(&s.mu)
 committed:=network_queue_committed_locked(s,preparing,&input,runtime_async.deadline_after(&c.runtime,0))
 sync.unlock(&s.mu)
 assert(committed.kind==.None && input.storage==nil)
 _=signal.wake(s.coordinator.wake)
 return preparing.request
}
coordinator_test_wait :: proc(c:^Coordinator_Test_Case)->Completion {
 start:=time.tick_now()
 for time.tick_since(start)<3*time.Second {
  completion,ready:=kernel_poll(&c.state.kernel)
  if ready {return completion}
  time.sleep(time.Millisecond)
 }
 panic("coordinator completion watchdog")
}
coordinator_test_destroy :: proc(c:^Coordinator_Test_Case) {
 s:=c.state
 sync.lock(&s.mu);s.phase=.Closing;network_queue_changed_locked(s);sync.unlock(&s.mu)
 _=signal.wake(s.coordinator.wake)
 for actor in s.actors {_=signal.wake(actor.wake)}
 start:=time.tick_now()
 for {
  sync.lock(&s.mu);done:=s.registered_tasks==0 && s.references==1;sync.unlock(&s.mu)
  if done {break}
  assert(time.tick_since(start)<3*time.Second,"coordinator shutdown watchdog")
  time.sleep(time.Millisecond)
 }
 assert(runtime_async.wait_idle(&c.runtime).kind==.None)
 assert(runtime_async.destroy(&c.runtime).kind==.None)
 sync.lock(&s.mu);s.base_owned=false;sync.unlock(&s.mu)
 network_state_release(s)
 testing_snapshot,error:=scopes.snapshot(c.scope);assert(error==.None && testing_snapshot.used==(scopes.Usage{}))
 scopes.release_scope(&c.scope)
 assert(c.track.current_memory_allocated==0 && len(c.track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&c.track)
}

@(test)
coordinator_parked_bankempty_requests_expire_without_connection_claim :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 request:=coordinator_test_admit(&c,"http://needs-dns.example/path",30*time.Millisecond)
 sync.lock(&c.state.mu);sync.lock(&c.state.kernel.mu)
 testing.expect_value(t,c.state.kernel.requests[request.slot-1].stage,.Awaiting_DNS_IDs)
 testing.expect_value(t,c.state.kernel.counters.reserved_connections,0)
 testing.expect_value(t,c.state.kernel.counters.connecting_connections,0)
 sync.unlock(&c.state.kernel.mu);sync.unlock(&c.state.mu)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==request && completed.error.kind==.Deadline_Failed && completed.error.write_effect==.Not_Sent)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_dns_refill_unparks_real_fifo_and_burns_terminal_blocks :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c,1)
 initial,removed:=network_dns_reserve(c.state,1);assert(removed.kind==.None);network_dns_burn(c.state,&initial)
 request:=coordinator_test_admit(&c,"http://refill.example/path",time.Second)
 time.sleep(5*time.Millisecond)
 testing.expect_value(t,intrinsics.atomic_load(&c.actors[0].assigned),0)
 ids:=[1]u16{31337};assert(network_dns_refill(c.state,ids[:]).kind==.None)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==request && completed.error.kind==.None)
 testing.expect_value(t,ids[0],u16(31337))
 testing.expect_value(t,intrinsics.atomic_load(&c.actors[0].assigned),1)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_cancellation_of_parked_waiter_preserves_terminal_once :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 request:=coordinator_test_admit(&c,"http://cancel.example/path",time.Second)
 sync.lock(&c.state.mu)
 assert(kernel_cancel(&c.state.kernel,request).kind==.None);network_queue_changed_locked(c.state)
 sync.unlock(&c.state.mu)
 _=signal.wake(c.state.coordinator.wake)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==request && completed.error.transport.kind==.Cancelled && completed.error.phase==.Cancellation)
 _,again:=kernel_poll(&c.state.kernel);testing.expect(t,!again)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 coordinator_test_destroy(&c)
}

Coordinator_Test_Producer :: struct {state:^Client_State,stop,changes:int}
coordinator_test_produce_changes :: proc(p:^Coordinator_Test_Producer) {
 for intrinsics.atomic_load(&p.stop)==0 {
  sync.lock(&p.state.mu);network_queue_changed_locked(p.state);sync.unlock(&p.state.mu)
  _=signal.wake(p.state.coordinator.wake)
  intrinsics.atomic_add(&p.changes,1)
  time.sleep(100*time.Microsecond)
 }
}

@(test)
coordinator_work1_persistent_cursor_expires_behind_continuous_changes :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 sync.lock(&c.state.mu)
 c.state.coordinator.request_cursor=1;c.state.coordinator.dns_cursor=2
 network_queue_changed_locked(c.state)
 testing.expect_value(t,c.state.coordinator.request_cursor,u32(1))
 testing.expect_value(t,c.state.coordinator.dns_cursor,u32(2))
 sync.unlock(&c.state.mu)
 request:=coordinator_test_admit(&c,"http://behind-cursor.example/path",30*time.Millisecond)
 producer:=Coordinator_Test_Producer{state=c.state}
 worker:=thread.create_and_start_with_poly_data(&producer,coordinator_test_produce_changes);assert(worker!=nil)
 completion:Completion;ready:=false
 start:=time.tick_now()
 for time.tick_since(start)<500*time.Millisecond {
  completion,ready=kernel_poll(&c.state.kernel)
  if ready {break}
  time.sleep(time.Millisecond)
 }
 // The producer was still changing scan state when the terminal was observed.
 changes:=intrinsics.atomic_load(&producer.changes)
 intrinsics.atomic_store(&producer.stop,1);thread.join(worker);thread.destroy(worker)
 testing.expect(t,ready && changes>0)
 if !ready {completion=coordinator_test_wait(&c)}
 testing.expect(t,completion.request==request && completion.error.kind==.Deadline_Failed)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 fmt.printf("COORD17 persistent_cursor_expired_during_changes=%v producer_changes=%d\n",ready,changes)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_numeric_progress_bypasses_bankempty_named_queue :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 blocked:=coordinator_test_admit(&c,"http://bankempty.example/path",time.Second)
 ready:=coordinator_test_admit(&c,"http://127.0.0.1/cheap",time.Second)
 completion:=coordinator_test_wait(&c)
 testing.expect(t,completion.request==ready && completion.error.kind==.None)
 sync.lock(&c.state.mu);sync.lock(&c.state.kernel.mu)
 testing.expect_value(t,c.state.kernel.requests[blocked.slot-1].state,.Queued)
 testing.expect_value(t,c.state.kernel.requests[blocked.slot-1].stage,.Awaiting_DNS_IDs)
 testing.expect_value(t,c.state.kernel.requests[blocked.slot-1].session,Cell_Handle{})
 sync.unlock(&c.state.kernel.mu)
 assert(kernel_cancel(&c.state.kernel,blocked).kind==.None);network_queue_changed_locked(c.state)
 sync.unlock(&c.state.mu)
 _=signal.wake(c.state.coordinator.wake)
 cancelled:=coordinator_test_wait(&c)
 testing.expect(t,cancelled.request==blocked && cancelled.error.transport.kind==.Cancelled)
 assert(kernel_release(&c.state.kernel,ready).kind==.None)
 assert(kernel_release(&c.state.kernel,blocked).kind==.None)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_active_expiry_wakes_owner_without_forging_explicit_cancel :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 intrinsics.atomic_store(&c.actors[0].hold,1)
 request:=coordinator_test_admit(&c,"http://127.0.0.1/held",30*time.Millisecond)
 start:=time.tick_now()
 for intrinsics.atomic_load(&c.actors[0].assigned)==0 {
  assert(time.tick_since(start)<time.Second);time.sleep(time.Millisecond)
 }
 time.sleep(40*time.Millisecond)
 intrinsics.atomic_store(&c.actors[0].observed_cancel,-1)
 sync.lock(&c.state.mu);network_queue_changed_locked(c.state);sync.unlock(&c.state.mu)
 _=signal.wake(c.state.coordinator.wake)
 start=time.tick_now()
 for intrinsics.atomic_load(&c.actors[0].observed_cancel)==-1 {
  assert(time.tick_since(start)<time.Second,"expired Active actor was not woken");time.sleep(time.Millisecond)
 }
 testing.expect_value(t,intrinsics.atomic_load(&c.actors[0].observed_cancel),0)
 intrinsics.atomic_store(&c.actors[0].hold,0);_=signal.wake(c.state.actors[0].wake)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==request && completed.error.kind==.Deadline_Failed)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_idle_deadline_retires_metadata_owner_without_new_notification :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c,0,1,20*time.Millisecond)
 intrinsics.atomic_store(&c.actors[0].keep_idle,1)
 request:=coordinator_test_admit(&c,"http://127.0.0.1/idle",time.Second)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==request && completed.error.kind==.None)
 assert(kernel_release(&c.state.kernel,request).kind==.None)
 start:=time.tick_now()
 for intrinsics.atomic_load(&c.actors[0].retired)==0 {
  assert(time.tick_since(start)<time.Second,"idle timer lost without external wake");time.sleep(time.Millisecond)
 }
 sync.lock(&c.state.mu);sync.lock(&c.state.kernel.mu)
 testing.expect_value(t,c.state.kernel.counters.idle_connections,0)
 testing.expect_value(t,c.state.kernel.counters.retiring_connections,0)
 testing.expect_value(t,c.state.kernel.session_free_count,1)
 sync.unlock(&c.state.kernel.mu);sync.unlock(&c.state.mu)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_immutable_lifetime_closes_unassigned_task_group_without_external_wake :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c,0,2,0,3,100*time.Millisecond)
 // No request/idle/request timer exists. The Client cap itself must wake the
 // coordinator, and its Closing transition must notify every unassigned owner.
 _=signal.wake(c.state.coordinator.wake)
 ended:=false
 start:=time.tick_now()
 for time.tick_since(start)<500*time.Millisecond {
  sync.lock(&c.state.mu)
  ended=c.state.registered_tasks==0 && c.state.references==1
  sync.unlock(&c.state.mu)
  if ended {break}
  time.sleep(time.Millisecond)
 }
 testing.expect(t,ended,"immutable Client cap did not wake and retire unassigned actors")
 fmt.printf("COORD17 no_request_lifetime_group_retired=%v\n",ended)
 coordinator_test_destroy(&c)
}

@(test)
coordinator_commit_dns_stage_is_atomic_and_rejection_keeps_input :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,10*time.Second)
 c:Coordinator_Test_Case;coordinator_test_init(&c)
 s:=c.state;url:="http://atomic-dns.example/path"
 now:=runtime_async.deadline_after(&c.runtime,0)
 lease,error:=resources_request_lease(&s.resources);assert(error.kind==.None)
 preparing,cause:=kernel_reserve(&s.kernel,runtime_async.deadline_after(&c.runtime,time.Second),&lease);assert(cause.kind==.None)
 origin,ready:=origin_prepare(&s.profile,url,s.resources.allocator);assert(ready.kind==.None)
 _,claimed:=network_queue_claim(s,preparing,&origin,now.at);origin_destroy(&origin);assert(claimed.kind==.None)
 input,cloned:=request_clone({method=.GET,url=url},s.resources.allocator);assert(cloned.kind==.None)
 pointer,length:=raw_data(input.storage),len(input.storage)
 sync.lock(&s.mu)
 metadata:=&s.requests[preparing.request.slot-1]
 metadata.generation+=1
 rejected:=network_queue_committed_locked(s,preparing,&input,runtime_async.deadline_after(&c.runtime,0))
 testing.expect_value(t,rejected.kind,.Invalid_State)
 testing.expect_value(t,raw_data(input.storage),pointer);testing.expect_value(t,len(input.storage),length)
 sync.lock(&s.kernel.mu)
 testing.expect_value(t,s.kernel.requests[preparing.request.slot-1].state,.Preparing)
 sync.unlock(&s.kernel.mu)
 metadata.generation=preparing.request.generation
 accepted:=network_queue_committed_locked(s,preparing,&input,runtime_async.deadline_after(&c.runtime,0));assert(accepted.kind==.None)
 testing.expect(t,input.storage==nil && metadata.awaiting_ids)
 sync.lock(&s.kernel.mu)
 testing.expect_value(t,s.kernel.requests[preparing.request.slot-1].state,.Queued)
 testing.expect_value(t,s.kernel.requests[preparing.request.slot-1].stage,.Awaiting_DNS_IDs)
 sync.unlock(&s.kernel.mu)
 assert(kernel_cancel(&s.kernel,preparing.request).kind==.None);network_queue_changed_locked(s)
 sync.unlock(&s.mu)
 _=signal.wake(s.coordinator.wake)
 completed:=coordinator_test_wait(&c)
 testing.expect(t,completed.request==preparing.request && completed.error.transport.kind==.Cancelled)
 assert(kernel_release(&s.kernel,preparing.request).kind==.None)
 coordinator_test_destroy(&c)
}
