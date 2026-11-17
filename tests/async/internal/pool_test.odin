package surf_async

import surf ".."
import runtime_async "../../async"
import rt "base:runtime"
import "core:mem"
import scopes "core:sync/budget"
import "core:sync"
import "core:testing"
import "core:time"

Pool_Case :: struct {track:mem.Tracking_Allocator,allocator:mem.Allocator,scope:scopes.Scope,profile:Profile,resources:Kernel_Resources,kernel:Kernel,now:i64}
pool_case_init :: proc(f:^Pool_Case,capacities:Capacities,idle:time.Duration=5,max_age:time.Duration=20) {
 mem.tracking_allocator_init(&f.track,rt.heap_allocator(),rt.heap_allocator());f.allocator=mem.tracking_allocator(&f.track)
 scope,error:=scopes.create_root({bytes=64<<20,streams=u64(capacities.requests)},f.allocator);assert(error==.None);f.scope=scope
 config,cause:=config_normalize({http={scope=scope},capacities=capacities,idle_timeout=idle,max_age=max_age});assert(cause.kind==.None)
 assert(profile_init(&f.profile,config,f.allocator).kind==.None)
 assert(resources_init(&f.resources,scope,f.allocator).kind==.None)
 assert(kernel_init(&f.kernel,&f.profile,&f.resources).kind==.None)
}
pool_case_time :: proc(f:^Pool_Case,given:i64=0)->i64 {
 now:=given
 if now==0 {now=100 if f.now==0 else min(f.now,max(i64)-1)+1}
 assert(now>0 && now>=f.now);f.now=now;return now
}
pool_case_clock :: proc(at:i64=101)->runtime_async.Deadline {return {epoch=77,at=at}}
pool_case_prepare :: proc(f:^Pool_Case)->Preparing_Request {
 lease,error:=resources_request_lease(&f.resources);assert(error.kind==.None)
 preparing,cause:=kernel_reserve(&f.kernel,{epoch=77,at=max(i64)},&lease)
 assert(cause.kind==.None && lease==(scopes.Lease{}));return preparing
}
pool_case_claim :: proc(f:^Pool_Case,p:Preparing_Request,url:string,now:i64=0,allocator:mem.Allocator={})->(Pool_Reservation,Client_Error) {
 at:=pool_case_time(f,now)
 selected:=allocator;if selected.procedure==nil {selected=f.resources.allocator}
 origin,error:=origin_prepare(&f.profile,url,selected);assert(error.kind==.None)
 pointer,size:=raw_data(origin.storage),len(origin.storage)
 reservation,cause:=pool_reserve(&f.kernel,p,&origin,at)
 if cause.kind!=.None {assert(raw_data(origin.storage)==pointer && len(origin.storage)==size)}
 origin_destroy(&origin);return reservation,cause
}
pool_case_commit :: proc(f:^Pool_Case,p:Preparing_Request,url:string,now:i64=0) {
 at:=pool_case_time(f,now)
 input,error:=request_clone({method=.GET,url=url},f.resources.allocator);assert(error.kind==.None)
 assert(kernel_commit(&f.kernel,p,&input,pool_case_clock(at)).kind==.None && input.storage==nil)
}
pool_case_accept :: proc(f:^Pool_Case,url:string,now:i64=0)->(Request_Handle,Pool_Reservation) {
 p:=pool_case_prepare(f);reservation,error:=pool_case_claim(f,p,url,now);assert(error.kind==.None)
 pool_case_commit(f,p,url,now);return p.request,reservation
}
pool_case_dispose :: proc(f:^Pool_Case,disposal:^Request_Disposal) {
 ticket:=disposal.origin.origin
 request_disposal_destroy(disposal)
 if ticket!=(Cell_Handle{}) {assert(kernel_origin_cleanup_finish(&f.kernel,ticket).kind==.None)}
}
pool_case_finish :: proc(f:^Pool_Case,request:Request_Handle,now:i64=0) {
 at:=pool_case_time(f,now)
 for _ in 0..<8 {
  disposal,done,error:=kernel_cleanup_finish(&f.kernel,request,pool_case_clock(at));assert(error.kind==.None)
  pool_case_dispose(f,&disposal)
  if done {return}
 }
 assert(false,"cleanup did not finish")
}
pool_case_rollback :: proc(f:^Pool_Case,p:Preparing_Request) {
 disposal,error:=kernel_rollback(&f.kernel,p);assert(error.kind==.None)
 pool_case_dispose(f,&disposal);pool_case_finish(f,p.request)
}
pool_case_complete :: proc(f:^Pool_Case,request:Request_Handle,now:i64=0) {
 response:=surf.Response{status=200}
 disposal,error:=kernel_begin_complete(&f.kernel,request,&response,{});assert(error.kind==.None)
 pool_case_dispose(f,&disposal);pool_case_finish(f,request,now)
 assert(kernel_release(&f.kernel,request).kind==.None)
}
pool_case_dispatch :: proc(f:^Pool_Case,expected:Request_Handle,reused:bool=false,now:i64=0)->Assignment {
 at:=pool_case_time(f,now)
 limit:=4*(len(f.kernel.requests)+len(f.kernel.origins)+len(f.kernel.sessions))+16
 for _ in 0..<limit {
  assignment,used,error:=pool_dispatch(&f.kernel,1,at)
  assert((error.kind==.None || error.kind==.Pending) && used>=0 && used<=1)
  if assignment.request==(Request_Handle{}) {continue}
  assert(error.kind==.None && assignment.request==expected)
  state:=f.kernel.sessions[assignment.session.slot-1].state
  assert(state==.Busy if reused else state==.Connecting)
  if !reused {assert(pool_session_state(&f.kernel,assignment.session,.Busy,at).kind==.None)}
  return assignment
 }
 assert(false,"work1 failed to dispatch eligible request");return {}
}
pool_case_idle :: proc(f:^Pool_Case,session:Cell_Handle,now:i64=0) {assert(pool_session_state(&f.kernel,session,.Idle,pool_case_time(f,now)).kind==.None)}
pool_case_retire :: proc(f:^Pool_Case,session:Cell_Handle,now:i64=0) {
 assert(pool_session_state(&f.kernel,session,.Retiring,pool_case_time(f,now)).kind==.None)
 assert(pool_retire(&f.kernel,session).kind==.None)
}
pool_case_destroy :: proc(f:^Pool_Case) {
 for slot,index in f.kernel.sessions {
  if slot.state==.Free || slot.state==.Retired {continue}
  assert(slot.request==(Request_Handle{}) && (slot.state==.Idle || slot.state==.Retiring))
  handle:=Cell_Handle{u32(index+1),slot.generation}
  if slot.state==.Idle {assert(pool_session_state(&f.kernel,handle,.Retiring,pool_case_time(f)).kind==.None)}
  assert(pool_retire(&f.kernel,handle).kind==.None)
 }
 assert(kernel_destroy(&f.kernel).kind==.None)
 profile_destroy(&f.profile);resources_destroy(&f.resources)
 usage,error:=scopes.snapshot(f.scope);assert(error==.None && usage.used==(scopes.Usage{}));scopes.release_scope(&f.scope)
 assert(f.track.current_memory_allocated==0 && len(f.track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&f.track)
}
pool_case_caps :: proc()->Capacities {return {requests=8,origins=3,connections=2,connections_per_origin=1,waiters_per_origin=2,dns_ids=0,work_per_resume=1}}

@(test)
pool_global_per_origin_origin_and_waiter_caps_are_real :: proc(t:^testing.T) {
 f:Pool_Case;pool_case_init(&f,pool_case_caps());defer pool_case_destroy(&f)
 a,a_claim:=pool_case_accept(&f,"https://a.test")
 testing.expect(t,!a_claim.waiting && a_claim.session!=(Cell_Handle{}))
 assigned_a:=pool_case_dispatch(&f,a)
 b,b_claim:=pool_case_accept(&f,"https://b.test")
 testing.expect(t,!b_claim.waiting && b_claim.session!=a_claim.session)
 assigned_b:=pool_case_dispatch(&f,b)
 waiting1,claim1:=pool_case_accept(&f,"https://a.test")
 waiting2,claim2:=pool_case_accept(&f,"https://a.test")
 testing.expect(t,claim1.waiting && claim2.waiting && claim1.session==(Cell_Handle{}) && claim2.session==(Cell_Handle{}))
 p:=pool_case_prepare(&f)
 _,cause:=pool_case_claim(&f,p,"https://a.test")
 testing.expect_value(t,cause.kind,.Capacity)
 testing.expect_value(t,f.kernel.requests[p.request.slot-1].state,.Preparing)
 pool_case_rollback(&f,p)
 pool_case_complete(&f,a);pool_case_idle(&f,assigned_a.session)
 first:=pool_case_dispatch(&f,waiting1,true);pool_case_complete(&f,waiting1);pool_case_idle(&f,first.session)
 second:=pool_case_dispatch(&f,waiting2,true);pool_case_complete(&f,waiting2);pool_case_idle(&f,second.session)
 pool_case_complete(&f,b);pool_case_idle(&f,assigned_b.session)
 // An exhausted origin table rejects a new key even with free connection cells.
 caps:=pool_case_caps();caps.origins=1;caps.waiters_per_origin=0
 isolated:Pool_Case;pool_case_init(&isolated,caps)
 request,_:=pool_case_accept(&isolated,"https://a.test");session:=pool_case_dispatch(&isolated,request)
 p=pool_case_prepare(&isolated);_,cause=pool_case_claim(&isolated,p,"https://b.test")
 testing.expect_value(t,cause.kind,.Capacity);pool_case_rollback(&isolated,p)
 pool_case_complete(&isolated,request);pool_case_idle(&isolated,session.session);pool_case_destroy(&isolated)
}

@(test)
pool_zero_waiter_requires_claim_and_rollback_restores_idle_or_free :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=0
 f:Pool_Case;pool_case_init(&f,caps);defer pool_case_destroy(&f)
 preparing:=pool_case_prepare(&f)
 reservation,error:=pool_case_claim(&f,preparing,"https://a.test");assert(error.kind==.None)
 testing.expect_value(t,f.kernel.sessions[reservation.session.slot-1].state,.Reserved)
 pool_case_rollback(&f,preparing)
 testing.expect_value(t,f.kernel.sessions[reservation.session.slot-1].state,.Free)
 request,_:=pool_case_accept(&f,"https://a.test")
 assignment:=pool_case_dispatch(&f,request)
 denied:=pool_case_prepare(&f);_,cause:=pool_case_claim(&f,denied,"https://a.test")
 testing.expect_value(t,cause.kind,.Capacity);pool_case_rollback(&f,denied)
 pool_case_complete(&f,request);pool_case_idle(&f,assignment.session,110)
 before:=f.kernel.sessions[assignment.session.slot-1]
 preparing=pool_case_prepare(&f);reservation,error=pool_case_claim(&f,preparing,"https://a.test",111);assert(error.kind==.None)
 testing.expect(t,reservation.session==assignment.session && f.kernel.sessions[assignment.session.slot-1].reserved_from==.Idle)
 pool_case_rollback(&f,preparing)
 after:=f.kernel.sessions[assignment.session.slot-1]
 testing.expect(t,after.state==.Idle && after.generation==before.generation && after.created_at==before.created_at && after.idle_since==before.idle_since)
}

@(test)
pool_retiring_keeps_capacity_and_retired_generations_never_reuse :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=0
 f:Pool_Case;pool_case_init(&f,caps);defer pool_case_destroy(&f)
 request,_:=pool_case_accept(&f,"https://a.test")
 assignment:=pool_case_dispatch(&f,request);pool_case_complete(&f,request);pool_case_idle(&f,assignment.session)
 assert(pool_session_state(&f.kernel,assignment.session,.Retiring,104).kind==.None)
 p:=pool_case_prepare(&f);_,cause:=pool_case_claim(&f,p,"https://b.test",105)
 testing.expect_value(t,cause.kind,.Capacity);pool_case_rollback(&f,p)
 assert(pool_retire(&f.kernel,assignment.session).kind==.None)
 testing.expect(t,pool_retire(&f.kernel,assignment.session).kind!=.None)
 request,_=pool_case_accept(&f,"https://b.test",106)
 next:=pool_case_dispatch(&f,request,false,107)
 testing.expect(t,next.session.slot==assignment.session.slot && next.session.generation!=assignment.session.generation)
 testing.expect(t,pool_session_state(&f.kernel,assignment.session,.Retiring,107).kind!=.None)
 pool_case_complete(&f,request,108);pool_case_idle(&f,next.session,109)
 // Explicit finite counter-boundary fixture on a real admitted/retired session;
 // no claim of executing max(u64) lifetimes.
 f.kernel.sessions[next.session.slot-1].generation=max(u64)
 exhausted:=Cell_Handle{next.session.slot,max(u64)}
 pool_case_retire(&f,exhausted,110)
 testing.expect_value(t,f.kernel.sessions[exhausted.slot-1].state,.Retired)
 p=pool_case_prepare(&f);_,cause=pool_case_claim(&f,p,"https://c.test",111)
 testing.expect_value(t,cause.kind,.Capacity);pool_case_rollback(&f,p)
}

Pool_Free_Probe :: struct {backing:mem.Allocator,kernel:^Kernel,session:Cell_Handle,target:rawptr,calls:int,armed:bool}
pool_probe_allocator :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 p:=cast(^Pool_Free_Probe)data
 if mode==.Free && old_memory==p.target && p.armed {
  p.armed=false;p.calls+=1
  assert(sync.try_lock(&p.kernel.mu));sync.unlock(&p.kernel.mu)
  assert(p.kernel.sessions[p.session.slot-1].state==.Returning)
  assert(kernel_destroy(p.kernel).kind==.Pending)
 }
 return p.backing.procedure(p.backing.data,mode,size,alignment,old_memory,old_size,location)
}

@(test)
pool_origin_physical_free_is_unlocked_and_session_stays_returning :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=0
 f:Pool_Case;pool_case_init(&f,caps);defer pool_case_destroy(&f)
 p:=pool_case_prepare(&f);probe:=Pool_Free_Probe{backing=f.allocator,kernel=&f.kernel}
 origin,error:=origin_prepare(&f.profile,"https://owned.test",{pool_probe_allocator,&probe});assert(error.kind==.None)
 probe.target=raw_data(origin.storage)
 reservation,cause:=pool_reserve(&f.kernel,p,&origin,100);assert(cause.kind==.None && origin.storage==nil)
 pool_case_commit(&f,p,"https://owned.test")
 assignment:=pool_case_dispatch(&f,p.request);pool_case_complete(&f,p.request);pool_case_idle(&f,assignment.session)
 probe.session=reservation.session;probe.armed=true
 pool_case_retire(&f,assignment.session)
 testing.expect_value(t,probe.calls,1)
 testing.expect_value(t,f.kernel.counters.origins,0)
}

@(test)
pool_state_guards_preserve_active_associations_until_completion :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=0
 f:Pool_Case;pool_case_init(&f,caps,1000,10000);defer pool_case_destroy(&f)
 request,_:=pool_case_accept(&f,"https://a.test")
 assignment:=pool_case_dispatch(&f,request)
 before:=f.kernel.sessions[assignment.session.slot-1]
 testing.expect_value(t,pool_session_state(&f.kernel,assignment.session,.Idle,pool_case_time(&f)).kind,.Pending)
 testing.expect_value(t,pool_retire(&f.kernel,assignment.session).kind,.Pending)
 testing.expect_value(t,f.kernel.sessions[assignment.session.slot-1],before)
 for invalid in ([4]Session_State{.Free,.Reserved,.Returning,.Retired}) {
  testing.expect(t,pool_session_state(&f.kernel,assignment.session,invalid,pool_case_time(&f)).kind!=.None)
  testing.expect_value(t,f.kernel.sessions[assignment.session.slot-1],before)
 }
 assert(pool_session_state(&f.kernel,assignment.session,.Retiring,pool_case_time(&f)).kind==.None)
 testing.expect_value(t,pool_retire(&f.kernel,assignment.session).kind,.Pending)
 testing.expect_value(t,f.kernel.sessions[assignment.session.slot-1].request,request)
 pool_case_complete(&f,request)
 testing.expect_value(t,f.kernel.sessions[assignment.session.slot-1].state,.Retiring)
 assert(pool_retire(&f.kernel,assignment.session).kind==.None)
}
