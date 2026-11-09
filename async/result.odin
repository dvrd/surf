package surf_async

import surf ".."
import runtime_async "../../async"
import signal "../../async/signal"
import scopes "core:sync/budget"
import "core:sync"

@(private)
client_ranges_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return av<=bv && bv-av<uintptr(an) || bv<av && av-bv<uintptr(bn)
}
@(private)
client_destination_alias :: proc(s:^Client_State,c:^Client,destination:^surf.Response)->bool {
 return client_ranges_overlap(destination,size_of(surf.Response),c,size_of(Client)) ||
  client_ranges_overlap(destination,size_of(surf.Response),s,size_of(Client_State)) ||
  client_ranges_overlap(destination,size_of(surf.Response),raw_data(s.actors),len(s.actors)*size_of(Session_Actor)) ||
  client_ranges_overlap(destination,size_of(surf.Response),raw_data(s.requests),len(s.requests)*size_of(Request_Network)) ||
  client_ranges_overlap(destination,size_of(surf.Response),raw_data(s.task_index),len(s.task_index)*size_of(^runtime_async.Task)) ||
  client_ranges_overlap(destination,size_of(surf.Response),raw_data(s.dns_ids),len(s.dns_ids)*size_of(u16)) ||
  client_ranges_overlap(destination,size_of(surf.Response),raw_data(s.profile.storage),len(s.profile.storage))
}

client_request_stage :: proc(c:^Client,handle:Request_Handle)->(Request_Stage,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return {},error};defer client_leave(s)
 return kernel_stage(&s.kernel,handle)
}
client_poll :: proc(c:^Client)->(Completion,bool) {
 s,error:=client_enter(c);if error.kind!=.None {return {},false};defer client_leave(s)
 return kernel_poll(&s.kernel)
}
client_take :: proc(c:^Client,handle:Request_Handle,destination:^surf.Response)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 if destination==nil || client_destination_alias(s,c,destination) {return {kind=.Invalid_State}}
 return kernel_take(&s.kernel,handle,destination)
}
client_release :: proc(c:^Client,handle:Request_Handle)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 return kernel_release(&s.kernel,handle)
}
client_cancel :: proc(c:^Client,handle:Request_Handle)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 sync.lock(&s.mu)
 cause:=kernel_cancel(&s.kernel,handle)
 wake:=s.coordinator.wake
 if cause.kind==.None {
  network_queue_changed_locked(s)
  sync.lock(&s.kernel.mu)
  request:=admission_request_locked(&s.kernel,handle)
  if request!=nil && request.session.slot>0 {wake=s.actors[int(request.session.slot)-1].wake}
  sync.unlock(&s.kernel.mu)
 }
 sync.unlock(&s.mu)
 if cause.kind==.None {_=signal.wake(wake);_=signal.wake(s.coordinator.wake)}
 return cause
}
client_refill_dns_ids :: proc(c:^Client,ids:[]u16)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 return network_dns_refill(s,ids)
}
client_stats :: proc(c:^Client)->(Client_Stats,bool) {
 s,error:=client_enter(c);if error.kind!=.None {return {},false};defer client_leave(s)
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 stats:=s.kernel.counters
 stats.capacities=s.config.config.capacities;stats.tasks=s.registered_tasks
 stats.dns_ids=s.dns_count;stats.signal_cells=s.signal_cells
 for metadata in s.requests {if metadata.awaiting_ids {stats.dns_waiters+=1}}
 scope:=s.resources.scope
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if scope!=(scopes.Scope{}) {stats.scope,_=scopes.snapshot(scope)}
 return stats,true
}
