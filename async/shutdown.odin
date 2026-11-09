package surf_async

import runtime_async "../../async"
import "core:sync"

@(private)
client_drained_locked :: proc(s:^Client_State,own_call:bool)->bool {
 callers:=s.producer_calls
 if own_call {callers-=1}
 return s.phase==.Closing && s.registered_tasks==0 && callers==0 && s.returning_calls==0 &&
  s.kernel.preparing==0 && s.kernel.returning==0 && s.kernel.counters.active_requests==0 && s.kernel.counters.queued_requests==0
}
client_close :: proc(c:^Client)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 network_close_state(s)
 sync.lock(&s.mu)
 runtime:=s.runtime
 registered:=s.registered_tasks
 sync.unlock(&s.mu)
 // Runtime start/join/destroy and this prestart ownership return are controller
 // serialized. shutdown remains allowed to race ordinary operational methods.
 if registered>0 && runtime!=nil {
  retirement:=runtime_async.retire_group_unstarted(runtime,s.task_index)
  if retirement.kind==.None {
   for index in 0..<len(s.task_index) {network_task_done(s,index,false)}
  } else if retirement.kind!=.Already_Started && retirement.kind!=.Not_Registered {return {kind=.Runtime_Error,runtime=retirement}}
 }
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 drained:=client_drained_locked(s,true)
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if !drained {return {kind=.Pending}}
 return {}
}
client_quiescent :: proc(c:^Client)->bool {
 s,error:=client_enter(c);if error.kind!=.None {return false};defer client_leave(s)
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 drained:=client_drained_locked(s,true)
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 return drained
}
client_destroy :: proc(c:^Client)->Client_Error {
 if c==nil || c._self!=c || c._state==nil {return {kind=.Invalid_State}}
 s:=cast(^Client_State)c._state
 if !network_valid(s) {return {kind=.Invalid_State}}
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 ready:=client_drained_locked(s,false) && s.references==1 && s.base_owned && s.kernel.references==1 &&
  s.kernel.counters.completed_requests==0 && s.kernel.counters.origins==0 &&
  s.kernel.counters.reserved_connections==0 && s.kernel.counters.connecting_connections==0 &&
  s.kernel.counters.active_connections==0 && s.kernel.counters.idle_connections==0 && s.kernel.counters.retiring_connections==0
 if ready {s.base_owned=false;c^={}}
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if !ready {return {kind=.Pending}}
 // Final backing callback may physically free the public header. Locals only.
 network_state_release(s)
 return {}
}
