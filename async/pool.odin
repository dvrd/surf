package surf_async

import "core:sync"

@(private)
pool_request_locked :: proc(k:^Kernel,handle:Request_Handle)->^Request_Slot {
 if handle.owner_id!=k.owner_id || handle.slot==0 || u64(handle.slot)>u64(len(k.requests)) || handle.generation==0 {return nil}
 slot:=&k.requests[int(handle.slot)-1]
 if slot.generation!=handle.generation || slot.state==.Free || slot.state==.Retired {return nil}
 return slot
}
@(private)
pool_session_locked :: proc(k:^Kernel,handle:Cell_Handle)->^Session_Model {
 if handle.slot==0 || u64(handle.slot)>u64(len(k.sessions)) || handle.generation==0 {return nil}
 slot:=&k.sessions[int(handle.slot)-1]
 if slot.generation!=handle.generation || slot.state==.Free || slot.state==.Retired {return nil}
 return slot
}
@(private)
pool_expired :: proc(s:^Session_Model,k:^Kernel,now:i64)->bool {
 // Compare elapsed intervals without signed subtraction overflow. Future times
 // are not expired; caller supplies one monotonic clock domain.
 age_expired:=now>=s.created_at && u64(now)-u64(s.created_at)>=u64(k.config.max_age)
 idle_expired:=now>=s.idle_since && u64(now)-u64(s.idle_since)>=u64(k.config.idle_timeout)
 return age_expired || idle_expired
}

pool_reserve :: proc(k:^Kernel,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if origin==nil || origin.key.profile_id!=k.profile.owner_id || origin.key.port==0 || len(origin.key.host)==0 ||
    len(origin.storage)!=len(origin.key.host) || raw_data(origin.storage)!=raw_data(origin.key.host) ||
    origin.allocator.procedure==nil || now<0 {return {},{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.closed {return {},{kind=.Closed}}
 request:=pool_request_locked(k,preparing.request)
 if request==nil {return {},{kind=.Invalid_Handle}}
 if request.state!=.Preparing || request.origin.slot!=0 || request.session.slot!=0 || request.cancel_requested {return {},{kind=.Invalid_State}}
 origin_index:u32
 for slot,i in k.origins {
  if slot.state==.Occupied && origin_equal(slot.owner.key,origin.key) {origin_index=u32(i+1);break}
 }
 new_origin:=origin_index==0
 if new_origin {
  if k.origin_free_count==0 {return {},{kind=.Capacity}}
  origin_index=k.origin_free[k.origin_free_count-1]
 }
 selected:=&k.origins[int(origin_index)-1]
 origin_handle:=Cell_Handle{slot=origin_index,generation=selected.generation}
 session_index:u32
 if !new_origin {
  for session,i in k.sessions {
   if session.state==.Idle && session.origin==origin_handle && !pool_expired(&k.sessions[i],k,now) {session_index=u32(i+1);break}
  }
 }
 new_session:=false
 if session_index==0 && selected.sessions<k.config.capacities.connections_per_origin && k.session_free_count>0 {
  session_index=k.session_free[k.session_free_count-1];new_session=true
 }
 waiting:=session_index==0
 if waiting && selected.waiters>=k.config.capacities.waiters_per_origin {return {},{kind=.Capacity}}
 // Every mutation below is infallible after these counter/shape preflights.
 if selected.requests==max(int) || selected.preparing==max(int) || selected.waiters==max(int) || selected.sessions==max(int) {return {},{kind=.Capacity}}
 if new_origin {
  if selected.state!=.Free || selected.generation==0 {return {},{kind=.Invalid_State}}
  selected.state=.Occupied;selected.owner=origin^;origin^={}
  k.origin_free_count-=1;k.counters.origins+=1
 }
 assert(kernel_origin_retain_locked(k,origin_handle,.Request).kind==.None)
 assert(kernel_origin_retain_locked(k,origin_handle,.Preparing).kind==.None)
 request.origin=origin_handle
 reservation:=Pool_Reservation{request=preparing.request,origin=origin_handle,waiting=waiting}
 k.dispatch_dirty=true;k.idle_dirty=true
 if waiting {assert(kernel_origin_retain_locked(k,origin_handle,.Waiter).kind==.None);return reservation,{}}
 session:=&k.sessions[int(session_index)-1]
 previous:=session.state
 if new_session {
  k.session_free_count-=1
  assert(kernel_origin_retain_locked(k,origin_handle,.Session).kind==.None)
  generation:=session.generation
  session^={generation=generation,state=.Free,created_at=now,origin=origin_handle}
 }
 if previous==.Idle {k.counters.idle_connections-=1}
 session.reserved_from=previous;session.state=.Reserved;session.request=preparing.request
 k.counters.reserved_connections+=1
 reservation.session={slot=session_index,generation=session.generation}
 request.session=reservation.session
 return reservation,{}
}

pool_session_state :: proc(k:^Kernel,handle:Cell_Handle,state:Session_State,now:i64)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 if now<0 {return {kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 session:=pool_session_locked(k,handle)
 if session==nil {return {kind=.Invalid_Handle}}
 previous:=session.state
 if previous==.Connecting && state==.Busy {
  request:=pool_request_locked(k,session.request)
  if request==nil || request.state!=.Active || request.session!=handle {return {kind=.Invalid_State}}
 } else if previous==.Busy && state==.Idle {
  if session.request!=(Request_Handle{}) {return {kind=.Pending}}
 } else if state==.Retiring && (previous==.Connecting || previous==.Busy || previous==.Idle) {
  // Transport close can begin before the active request's terminal cleanup.
 } else {return {kind=.Invalid_State}}
 session.state=state
 k.dispatch_dirty=true;k.idle_dirty=true
 if state==.Idle {session.idle_since=now}
 if previous==.Connecting {k.counters.connecting_connections-=1}
 if previous==.Busy {k.counters.active_connections-=1}
 if previous==.Idle {k.counters.idle_connections-=1}
 if state==.Busy {k.counters.active_connections+=1}
 if state==.Idle {k.counters.idle_connections+=1}
 if state==.Retiring {k.counters.retiring_connections+=1}
 return {}
}

pool_retire :: proc(k:^Kernel,handle:Cell_Handle)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu)
 session:=pool_session_locked(k,handle)
 if session==nil {sync.unlock(&k.mu);return {kind=.Invalid_Handle}}
 if session.state!=.Retiring || session.request!=(Request_Handle{}) {sync.unlock(&k.mu);return {kind=.Pending}}
 if session.generation!=max(u64) && k.session_free_count>=len(k.session_free) {sync.unlock(&k.mu);return {kind=.Invalid_State}}
 origin:=session.origin
 disposal,error:=kernel_origin_release_locked(k,origin,.Session)
 if error.kind!=.None {sync.unlock(&k.mu);return error}
 // Keep this session and Kernel alive until all physical origin cleanup returns.
 session.state=.Returning
 k.references+=1
 k.dispatch_dirty=true;k.idle_dirty=true
 sync.unlock(&k.mu)
 origin_ticket:=disposal.origin
 origin_disposal_destroy(&disposal)
 if origin_ticket.slot!=0 {
  error=kernel_origin_cleanup_finish(k,origin_ticket)
  if error.kind!=.None {return error}
 }
 sync.lock(&k.mu)
 generation:=session.generation
 session^={generation=generation,state=.Retired}
 if generation!=max(u64) {
  session.generation+=1;session.state=.Free
  k.session_free[k.session_free_count]=handle.slot;k.session_free_count+=1
 }
 k.counters.retiring_connections-=1;k.references-=1;k.dispatch_dirty=true;k.idle_dirty=true
 if k.counters.close_count!=max(u64) {k.counters.close_count+=1}
 sync.unlock(&k.mu)
 return {}
}
