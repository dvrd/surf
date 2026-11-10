package surf_async

import http "../../http"
import h1 "../../http/v1"
import runtime_async "../../async"
import "core:bytes"
import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"
import "core:strings"
import "core:sync"

@(private)
admission_request_locked :: proc(k:^Kernel,h:Request_Handle)->^Request_Slot {
 if h.owner_id!=k.owner_id || h.slot==0 || u64(h.slot)>u64(len(k.requests)) || h.generation==0 {return nil}
 r:=&k.requests[int(h.slot)-1]
 if r.generation!=h.generation || r.state==.Free || r.state==.Retired {return nil}
 return r
}
@(private)
admission_origin_locked :: proc(k:^Kernel,h:Cell_Handle)->^Origin_Slot {
 if h.slot==0 || u64(h.slot)>u64(len(k.origins)) || h.generation==0 {return nil}
 o:=&k.origins[int(h.slot)-1]
 if o.generation!=h.generation || o.state!=.Occupied {return nil}
 return o
}
@(private)
admission_alias :: proc(k:^Kernel,p:rawptr,size:int)->bool {
 region:=mem.byte_slice(p,size)
 if bytes.alias(region,mem.byte_slice(k,size_of(Kernel))) {return true}
 for storage in ([6][]u8{mem.slice_to_bytes(k.requests),mem.slice_to_bytes(k.origins),mem.slice_to_bytes(k.sessions),mem.slice_to_bytes(k.request_free),mem.slice_to_bytes(k.origin_free),mem.slice_to_bytes(k.session_free)}) {
  if bytes.alias(region,storage) {return true}
 }
 return false
}
@(private)
admission_region :: proc(storage:[]u8,p:rawptr,size:int)->bool {
 if size==0 {return true}
 if p==nil || size<0 {return false}
 start,at:=uintptr(raw_data(storage)),uintptr(p)
 return at>=start && at-start<=uintptr(len(storage)) && uintptr(size)<=uintptr(len(storage))-(at-start)
}
@(private)
admission_input :: proc(k:^Kernel,input:^Request_Owner)->(http.URL,Client_Error) {
 if input==nil || admission_alias(k,input,size_of(Request_Owner)) || input.allocator.procedure==nil || len(input.storage)==0 || raw_data(input.storage)==nil {return {},{kind=.Invalid_Config}}
 if bytes.alias(mem.byte_slice(input,size_of(Request_Owner)),input.storage) || admission_alias(k,raw_data(input.storage),len(input.storage)) || uintptr(raw_data(input.storage))%align_of(http.Header)!=0 {return {},{kind=.Invalid_Config}}
 r:=input.request
 if len(r.headers)>http.MAX_HEADERS || !admission_region(input.storage,raw_data(r.headers),len(r.headers)*size_of(http.Header)) ||
    len(r.headers)>0 && uintptr(raw_data(r.headers))%align_of(http.Header)!=0 ||
    !admission_region(input.storage,raw_data(r.url),len(r.url)) || !admission_region(input.storage,raw_data(r.body),len(r.body)) {return {},{kind=.Invalid_Config}}
 for header in r.headers {
  if !admission_region(input.storage,raw_data(header.name),len(header.name)) || !admission_region(input.storage,raw_data(header.value),len(header.value)) {return {},{kind=.Invalid_Config}}
 }
 wire:[http.MAX_HEADER_SIZE]u8
 _,validation:=h1.request_encode_profile(wire[:],r,.Keep_Alive)
 if validation.kind!=.None {return {},{kind=.Request_Error,http={kind=validation.kind}}}
 if k.resources.scope!=(scopes.Scope{}) {
  covered:=false
  // A physical-free wrapper can forward a real managed allocation without
  // itself being a managed allocator. Query only known Binding registries.
  for allocator in ([2]mem.Allocator{input.allocator,k.resources.allocator}) {
   info,valid:=charged.allocation_info(allocator,raw_data(input.storage))
   if valid && info.size==len(input.storage) && scopes.covers(info.scope,k.resources.scope) {covered=true;break}
  }
  if !covered {return {},{kind=.Invalid_Config,http={kind=.Invalid_Config,budget=.Foreign_Root}}}
 }
 url,error:=http.url_parse(r.url)
 if error.kind!=.None {return {},{kind=.Request_Error,http={kind=error.kind}}}
 return url,{}
}

kernel_reserve :: proc(k:^Kernel,deadline:runtime_async.Deadline,lease:^scopes.Lease)->(Preparing_Request,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if lease==nil || admission_alias(k,lease,size_of(scopes.Lease)) || deadline.epoch==0 || deadline.at<=0 {return {},{kind=.Invalid_Config}}
 selected:=deadline
 if lifetime:=k.config.lifetime;lifetime.epoch!=0 {
  if lifetime.epoch!=deadline.epoch {return {},{kind=.Invalid_Config}}
  selected.at=min(selected.at,lifetime.at)
 }
 scope:=k.resources.scope
 if scope==(scopes.Scope{}) {
  if lease^!=(scopes.Lease{}) {return {},{kind=.Invalid_Config}}
 } else {
  actual:=scopes.scope_of(lease^)
  if actual==(scopes.Scope{}) || !scopes.covers(actual,scope) {
   cause:=scopes.Error.Invalid_Config
   if actual!=(scopes.Scope{}) && !scopes.same_root(actual,scope) {cause=.Foreign_Root}
   return {},{kind=.Invalid_Config,http={kind=.Invalid_Config,budget=cause}}
  }
  if scopes.cost_of(lease^)!=(scopes.Cost{streams=1}) || scopes.phase_of(lease^)!=.None {return {},{kind=.Invalid_Config}}
 }
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.closed {return {},{kind=.Closed}}
 if k.request_free_count==0 {return {},{kind=.Capacity}}
 if k.request_free_count<0 || k.request_free_count>len(k.request_free) || k.references<1 || k.references==max(int) || k.preparing==max(int) {return {},{kind=.Invalid_State}}
 index:=k.request_free[k.request_free_count-1]
 if index==0 || u64(index)>u64(len(k.requests)) {return {},{kind=.Invalid_State}}
 r:=&k.requests[int(index)-1]
 if r.state!=.Free || r.generation==0 {return {},{kind=.Invalid_State}}
 generation:=r.generation
 r^={generation=generation,state=.Preparing,stage=.Queued,deadline=selected,lease=lease^};lease^={}
 k.request_free_count-=1;k.request_free[k.request_free_count]=0
 k.preparing+=1;k.references+=1;k.counters.preparing_requests+=1;k.dispatch_dirty=true
 return {request={owner_id=k.owner_id,slot=index,generation=generation}},{}
}

kernel_commit :: proc(k:^Kernel,p:Preparing_Request,input:^Request_Owner,now:runtime_async.Deadline)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 url,validation:=admission_input(k,input)
 if validation.kind!=.None {return validation}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,p.request)
 if r==nil {return {kind=.Invalid_Handle}}
 if r.state!=.Preparing {return {kind=.Invalid_State}}
 if now.epoch!=r.deadline.epoch || now.at<=0 {return {kind=.Invalid_Config,http={kind=.Invalid_Config,phase=.Configuration}}}
 if k.closed {return {kind=.Closed}}
 if r.cancel_requested {return {kind=.Request_Error,http={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}}
 if now.at>=r.deadline.at {return {kind=.Request_Error,http={kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent}}}
 o:=admission_origin_locked(k,r.origin)
 if o==nil || o.requests<1 || o.preparing<1 || k.preparing<1 || k.references<=1 {return {kind=.Invalid_State}}
 if o.owner.key.profile_id!=k.profile.owner_id || o.owner.key.secure!=url.secure || int(o.owner.key.port)!=url.port || !strings.equal_fold(o.owner.key.host,url.host) {return {kind=.Invalid_Config}}
 if r.session.slot!=0 {
  if u64(r.session.slot)>u64(len(k.sessions)) {return {kind=.Invalid_State}}
  s:=&k.sessions[int(r.session.slot)-1]
  if s.generation!=r.session.generation || s.state!=.Reserved || s.request!=p.request || s.origin!=r.origin || (s.reserved_from!=.Free && s.reserved_from!=.Idle) {return {kind=.Invalid_State}}
 } else {
  if o.waiters<1 || (o.queue_head==0)!=(o.queue_tail==0) {return {kind=.Invalid_State}}
  if o.queue_tail!=0 {
   if u64(o.queue_tail)>u64(len(k.requests)) {return {kind=.Invalid_State}}
   tail:=&k.requests[int(o.queue_tail)-1]
   if tail.state!=.Queued || tail.origin!=r.origin || tail.session.slot!=0 || tail.queue_next!=0 {return {kind=.Invalid_State}}
  }
 }
 disposal,error:=kernel_origin_release_locked(k,r.origin,.Preparing)
 assert(error.kind==.None && disposal.origin.slot==0)
 if r.session.slot==0 {
  r.queue_previous=o.queue_tail
  if o.queue_tail!=0 {k.requests[int(o.queue_tail)-1].queue_next=p.request.slot} else {o.queue_head=p.request.slot}
  o.queue_tail=p.request.slot
 }
 r.input=input^;input^={};r.state=.Queued;r.stage=.Queued
 k.preparing-=1;k.references-=1;k.counters.preparing_requests-=1;k.counters.queued_requests+=1;k.dispatch_dirty=true
 return {}
}

@(private)
admission_unlink_waiter_locked :: proc(k:^Kernel,index:u32,r:^Request_Slot,o:^Origin_Slot)->Client_Error {
 previous,next:=r.queue_previous,r.queue_next
 if previous==0 {if o.queue_head!=index {return {kind=.Invalid_State}}} else {
  if u64(previous)>u64(len(k.requests)) || k.requests[int(previous)-1].queue_next!=index || k.requests[int(previous)-1].origin!=r.origin {return {kind=.Invalid_State}}
 }
 if next==0 {if o.queue_tail!=index {return {kind=.Invalid_State}}} else {
  if u64(next)>u64(len(k.requests)) || k.requests[int(next)-1].queue_previous!=index || k.requests[int(next)-1].origin!=r.origin {return {kind=.Invalid_State}}
 }
 if previous!=0 {k.requests[int(previous)-1].queue_next=next} else {o.queue_head=next}
 if next!=0 {k.requests[int(next)-1].queue_previous=previous} else {o.queue_tail=previous}
 r.queue_previous,r.queue_next=0,0
 return {}
}

// Detach a Preparing/accepted session claim using only verified07 origin
// bookkeeping. The caller preflights all fields before this mutation phase.
@(private)
admission_detach_claim_locked :: proc(k:^Kernel,h:Request_Handle,r:^Request_Slot)->Client_Error {
 if r.origin.slot==0 {
  if r.session.slot!=0 {return {kind=.Invalid_State}}
  return {}
 }
 o:=admission_origin_locked(k,r.origin)
 if o==nil || o.requests<1 || o.sessions<0 || o.preparing<0 || o.waiters<0 || k.counters.origins<1 {return {kind=.Invalid_State}}
 if r.state==.Preparing && o.preparing<1 {return {kind=.Invalid_State}}
 if r.session.slot==0 {
  if o.waiters<1 {return {kind=.Invalid_State}}
  if r.state==.Queued {if error:=admission_unlink_waiter_locked(k,h.slot,r,o);error.kind!=.None {return error}}
  disposal,error:=kernel_origin_release_locked(k,r.origin,.Waiter);assert(error.kind==.None && disposal.origin.slot==0)
 } else {
  if u64(r.session.slot)>u64(len(k.sessions)) {return {kind=.Invalid_State}}
  s:=&k.sessions[int(r.session.slot)-1]
  if s.generation!=r.session.generation || s.origin!=r.origin || s.request!=h {return {kind=.Invalid_State}}
  if s.state==.Reserved {
   if (r.state!=.Preparing && r.state!=.Queued) || (s.reserved_from!=.Idle && s.reserved_from!=.Free) || k.counters.reserved_connections<1 {return {kind=.Invalid_State}}
   if s.reserved_from==.Free && (o.sessions<1 || s.generation!=max(u64) && k.session_free_count>=len(k.session_free)) {return {kind=.Invalid_State}}
   k.counters.reserved_connections-=1
   if s.reserved_from==.Idle {
    s.state=.Idle;s.reserved_from=.Free;s.request={};k.counters.idle_connections+=1;k.idle_dirty=true
   } else {
    index,generation:=r.session.slot,s.generation
    s^={generation=generation,state=.Retired}
    if generation!=max(u64) {s.generation+=1;s.state=.Free;k.session_free[k.session_free_count]=index;k.session_free_count+=1}
    disposal,error:=kernel_origin_release_locked(k,r.origin,.Session);assert(error.kind==.None && disposal.origin.slot==0)
   }
  } else if r.state==.Active && (s.state==.Connecting || s.state==.Busy || s.state==.Retiring) {
   s.request={}
  } else {return {kind=.Invalid_State}}
  r.session={}
 }
 if r.state==.Preparing {disposal,error:=kernel_origin_release_locked(k,r.origin,.Preparing);assert(error.kind==.None && disposal.origin.slot==0)}
 k.dispatch_dirty=true
 return {}
}

kernel_rollback :: proc(k:^Kernel,p:Preparing_Request)->(Request_Disposal,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,p.request)
 if r==nil {return {},{kind=.Invalid_Handle}}
 if r.state!=.Preparing || k.preparing<1 || k.references<=1 || k.references==max(int) {return {},{kind=.Invalid_State}}
 if error:=admission_detach_claim_locked(k,p.request,r);error.kind!=.None {return {},error}
 result:=Request_Disposal{request=p.request,returning_to=.Free,input=r.input,response=r.response,lease=r.lease,stream=r.stream}
 r.stream=nil
 if r.origin.slot!=0 {
  disposal,error:=kernel_origin_release_locked(k,r.origin,.Request);assert(error.kind==.None);result.origin=disposal
 }
 r.input={};r.response={};r.lease={};r.origin={};r.state=.Returning;r.returning_to=.Free;r.stage=.Retiring
 k.preparing-=1;k.counters.preparing_requests-=1;k.returning+=1;k.counters.returning_requests+=1;k.dispatch_dirty=true
 return result,{}
}

kernel_cancel :: proc(k:^Kernel,h:Request_Handle)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {kind=.Invalid_Handle}}
 if r.state==.Completed {return {}}
 if r.state==.Returning && r.returning_to==.Free {return {kind=.Invalid_State}}
 if !r.cancel_requested {r.cancel_requested=true;if k.counters.cancel_count!=max(u64) {k.counters.cancel_count+=1}}
 k.dispatch_dirty=true
 return {}
}

kernel_close :: proc(k:^Kernel)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 k.closed=true;k.dispatch_dirty=true;k.idle_dirty=true
 for &r in k.requests {
  if r.state==.Preparing || r.state==.Queued || r.state==.Active || r.state==.Returning && r.returning_to==.Completed {
   if !r.cancel_requested {r.cancel_requested=true;if k.counters.cancel_count!=max(u64) {k.counters.cancel_count+=1}}
  }
 }
 return {}
}
kernel_stage :: proc(k:^Kernel,h:Request_Handle)->(Request_Stage,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 r:=admission_request_locked(k,h)
 if r==nil {return {},{kind=.Invalid_Handle}}
 return r.stage,{}
}
