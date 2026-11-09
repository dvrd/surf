package surf_async

import "core:sync"

@(private)
pool_dispatchable :: proc(request:^Request_Slot,now:i64)->bool {
 return request!=nil && request.state==.Queued && !request.cancel_requested &&
        (request.deadline.at==0 || now<request.deadline.at)
}
@(private)
pool_head_locked :: proc(k:^Kernel,origin:Cell_Handle,now:i64)->^Request_Slot {
 slot:=&k.origins[int(origin.slot)-1]
 if slot.queue_head==0 || u64(slot.queue_head)>u64(len(k.requests)) {return nil}
 request:=&k.requests[int(slot.queue_head)-1]
 if !pool_dispatchable(request,now) || request.origin!=origin || request.session.slot!=0 {return nil}
 return request
}
@(private)
pool_assign_locked :: proc(k:^Kernel,origin:Cell_Handle,session_index:u32,now:i64,waiting:bool)->Assignment {
 session:=&k.sessions[int(session_index)-1]
 selected:=&k.origins[int(origin.slot)-1]
 request:^Request_Slot
 handle:Request_Handle
 if waiting {
  request=pool_head_locked(k,origin,now)
  assert(request!=nil)
  handle={owner_id=k.owner_id,slot=selected.queue_head,generation=request.generation}
  selected.queue_head=request.queue_next
  if selected.queue_head!=0 {k.requests[int(selected.queue_head)-1].queue_previous=0} else {selected.queue_tail=0}
  request.queue_previous,request.queue_next=0,0
  disposal,error:=kernel_origin_release_locked(k,origin,.Waiter)
  assert(error.kind==.None && disposal.origin.slot==0)
  session.request=handle
  request.session={slot=session_index,generation=session.generation}
 } else {
  handle=session.request
  request=pool_request_locked(k,handle)
  assert(request!=nil)
 }
 old:=session.state
 if old==.Reserved {k.counters.reserved_connections-=1}
 if old==.Reserved && session.reserved_from==.Idle || old==.Idle {
  session.state=.Busy
  k.counters.active_connections+=1
  if old==.Idle {k.counters.idle_connections-=1}
  if k.counters.reuse_count!=max(u64) {k.counters.reuse_count+=1}
  request.stage=.Writing
 } else {
  session.state=.Connecting
  k.counters.connecting_connections+=1
  request.stage=.Connecting
 }
 session.reserved_from=.Free
 request.state=.Active
 k.counters.queued_requests-=1;k.counters.active_requests+=1
 k.dispatch_origin={};k.dispatch_session_cursor=0;k.dispatch_dirty=true;k.idle_dirty=true
 return {request=handle,session={slot=session_index,generation=session.generation}}
}

// One inspection per charged work unit, including unoccupied fixed capacity.
// Origin and within-origin progress persist across work1 calls.
pool_dispatch :: proc(k:^Kernel,work:int,now:i64)->(Assignment,int,Client_Error) {
 if k==nil || k.self!=k {return {},0,{kind=.Invalid_State}}
 if work<1 || work>MAX_WORK_PER_RESUME || now<0 {return {},0,{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.closed {return {},0,{kind=.Closed}}
 used:=0
 for used<work {
  if k.dispatch_origin.slot==0 {
   if k.dispatch_remaining==0 {
    if !k.dispatch_dirty {return {},used,{}}
    k.dispatch_dirty=false;k.dispatch_remaining=len(k.origins)
   }
   index:=int(k.dispatch_cursor)%len(k.origins)
   k.dispatch_cursor=u32((index+1)%len(k.origins));k.dispatch_remaining-=1
   used+=1
   origin:=&k.origins[index]
   if origin.state!=.Occupied {continue}
   k.dispatch_origin={slot=u32(index+1),generation=origin.generation}
   k.dispatch_session_cursor=0
   continue
  }
  origin_handle:=k.dispatch_origin
  origin:=&k.origins[int(origin_handle.slot)-1]
  if origin.state!=.Occupied || origin.generation!=origin_handle.generation {
   // A preceding API retired this origin; advancing metadata costs no scan.
   k.dispatch_origin={};continue
  }
  if int(k.dispatch_session_cursor)<len(k.sessions) {
   index:=int(k.dispatch_session_cursor);k.dispatch_session_cursor+=1;used+=1
   session:=&k.sessions[index]
   if session.origin!=origin_handle {continue}
   if session.state==.Reserved {
    request:=pool_request_locked(k,session.request)
    if pool_dispatchable(request,now) && request.origin==origin_handle &&
       request.session==(Cell_Handle{slot=u32(index+1),generation=session.generation}) {
     return pool_assign_locked(k,origin_handle,u32(index+1),now,false),used,{}
    }
   } else if session.state==.Idle && !pool_expired(session,k,now) && pool_head_locked(k,origin_handle,now)!=nil {
    return pool_assign_locked(k,origin_handle,u32(index+1),now,true),used,{}
   }
   continue
  }
  // Free-stack selection is a separate bounded metadata unit, never a scan.
  used+=1
  request:=pool_head_locked(k,origin_handle,now)
  if request!=nil && origin.sessions<k.config.capacities.connections_per_origin && k.session_free_count>0 {
   index:=k.session_free[k.session_free_count-1]
   session:=&k.sessions[int(index)-1]
   assert(session.state==.Free && session.generation!=0)
   k.session_free_count-=1
   assert(kernel_origin_retain_locked(k,origin_handle,.Session).kind==.None)
   generation:=session.generation
   session^={generation=generation,origin=origin_handle,created_at=now}
   return pool_assign_locked(k,origin_handle,index,now,true),used,{}
  }
  k.dispatch_origin={};k.dispatch_session_cursor=0
 }
 if k.dispatch_origin.slot==0 && k.dispatch_remaining==0 && !k.dispatch_dirty {return {},used,{}}
 return {},used,{kind=.Pending}
}

@(private)
pool_deadline :: proc(start,duration:i64)->i64 {
 if start>max(i64)-duration {return max(i64)}
 return start+duration
}

pool_idle_candidate :: proc(k:^Kernel,work:int,now:i64)->(Cell_Handle,int,Client_Error) {
 if k==nil || k.self!=k {return {},0,{kind=.Invalid_State}}
 if work<1 || work>MAX_WORK_PER_RESUME || now<0 {return {},0,{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.idle_remaining==0 {
  k.idle_remaining=len(k.sessions);k.idle_deadline=0;k.idle_dirty=false
 }
 used:=0
 for used<work {
  index:=int(k.idle_cursor)%len(k.sessions)
  k.idle_cursor=u32((index+1)%len(k.sessions));k.idle_remaining-=1;used+=1
  session:=&k.sessions[index]
  if session.state==.Idle {
   if k.closed || pool_expired(session,k,now) {return {slot=u32(index+1),generation=session.generation},used,{}}
   deadline:=min(pool_deadline(session.created_at,i64(k.config.max_age)),pool_deadline(session.idle_since,i64(k.config.idle_timeout)))
   if k.idle_deadline==0 || deadline<k.idle_deadline {k.idle_deadline=deadline}
  }
  if k.idle_remaining==0 {
   if !k.idle_dirty {return {},used,{}}
   // A mutation behind this cursor may already have consumed its external wake.
   // Recompute the entire deadline before allowing the coordinator to park.
   k.idle_remaining=len(k.sessions);k.idle_deadline=0;k.idle_dirty=false
  }
 }
 return {},used,{kind=.Pending}
}
