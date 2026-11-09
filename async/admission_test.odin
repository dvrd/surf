package surf_async

import surf ".."
import runtime_async "../../async"
import rt "base:runtime"
import "core:mem"
import "core:bytes"
import scopes "core:sync/budget"
import "core:testing"

Admission_Probe :: struct {
 track:mem.Tracking_Allocator,
 allocator:mem.Allocator,
 scope:scopes.Scope,
 profile:Profile,
 resources:Kernel_Resources,
 kernel:Kernel,
}
adm_init :: proc(p:^Admission_Probe,requests:=3,connections:=1,waiters:=3,managed:=true) {
 mem.tracking_allocator_init(&p.track,rt.heap_allocator(),rt.heap_allocator())
 p.allocator=mem.tracking_allocator(&p.track)
 if managed {
  scope,error:=scopes.create_root({bytes=1<<24,streams=64,jobs=64},p.allocator);assert(error==.None)
  p.scope=scope
 }
 config,error:=config_normalize({http={allow_http=true,scope=p.scope},capacities=Capacities{
  requests=requests,origins=requests,connections=connections,connections_per_origin=connections,
  waiters_per_origin=waiters,dns_ids=0,work_per_resume=8}})
 assert(error.kind==.None)
 assert(profile_init(&p.profile,config,p.allocator).kind==.None)
 assert(resources_init(&p.resources,p.scope,p.allocator).kind==.None)
 assert(kernel_init(&p.kernel,&p.profile,&p.resources).kind==.None)
}
adm_destroy :: proc(p:^Admission_Probe) {
 assert(kernel_destroy(&p.kernel).kind==.None)
 profile_destroy(&p.profile);resources_destroy(&p.resources)
 if p.scope!=(scopes.Scope{}) {
  snapshot,error:=scopes.snapshot(p.scope);assert(error==.None && snapshot.used==(scopes.Usage{}))
  scopes.release_scope(&p.scope)
 }
 assert(p.track.current_memory_allocated==0 && len(p.track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&p.track)
}
adm_metadata_snapshot :: proc(k:^Kernel)->[]u8 {
 header:=k^;header.mu={}
 header_bytes:=(cast(^[size_of(Kernel)]u8)&header)[:]
 total:=len(header_bytes)+len(mem.slice_to_bytes(k.requests))+len(mem.slice_to_bytes(k.origins))+
  len(mem.slice_to_bytes(k.sessions))+4*(len(k.request_free)+len(k.origin_free)+len(k.session_free))
 result:=make([]u8,total);at:=copy(result,header_bytes)
 for part in ([6][]u8{mem.slice_to_bytes(k.requests),mem.slice_to_bytes(k.origins),mem.slice_to_bytes(k.sessions),
  mem.slice_to_bytes(k.request_free),mem.slice_to_bytes(k.origin_free),mem.slice_to_bytes(k.session_free)}) {at+=copy(result[at:],part)}
 assert(at==len(result));return result
}
adm_reserve_noalloc :: proc(k:^Kernel,deadline:runtime_async.Deadline,lease:^scopes.Lease)->(Preparing_Request,Client_Error) {
 previous:=context;context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous
 return kernel_reserve(k,deadline,lease)
}
adm_deadline :: proc()->runtime_async.Deadline {return {epoch=7,at=1000}}
adm_now :: proc()->runtime_async.Deadline {return {epoch=7,at=10}}
adm_clone :: proc(p:^Admission_Probe)->Request_Owner {
 owner,error:=request_clone({method=.POST,url="https://example.test/path",body=[]u8{'q'}},p.resources.allocator)
 assert(error.kind==.None);return owner
}
adm_prepare :: proc(p:^Admission_Probe)->(Preparing_Request,Pool_Reservation) {
 lease,error:=resources_request_lease(&p.resources);assert(error.kind==.None)
 preparing,cause:=kernel_reserve(&p.kernel,adm_deadline(),&lease)
 assert(cause.kind==.None && lease==(scopes.Lease{}))
 origin,failure:=origin_prepare(&p.profile,"https://example.test/",p.resources.allocator);assert(failure.kind==.None)
 reservation,reserve_error:=pool_reserve(&p.kernel,preparing,&origin,adm_now().at)
 origin_destroy(&origin)
 assert(reserve_error.kind==.None)
 return preparing,reservation
}
adm_commit :: proc(p:^Admission_Probe,preparing:Preparing_Request)->Request_Handle {
 owner:=adm_clone(p)
 assert(kernel_commit(&p.kernel,preparing,&owner,adm_now()).kind==.None)
 assert(owner.storage==nil && owner.request.url=="")
 return preparing.request
}
adm_dispose :: proc(p:^Admission_Probe,disposal:^Request_Disposal,now:=runtime_async.Deadline{epoch=7,at=10})->int {
 for round in 1..=3 {
  request:=disposal.request;origin:=disposal.origin.origin
  request_disposal_destroy(disposal)
  if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&p.kernel,origin).kind==.None)}
  next,done,error:=kernel_cleanup_finish(&p.kernel,request,now)
  assert(error.kind==.None);disposal^=next
  if done {assert(disposal.input.storage==nil && disposal.response.body_storage==nil);return round}
 }
 panic("cleanup failed to converge")
}
adm_rollback :: proc(p:^Admission_Probe,preparing:Preparing_Request) {
 disposal,error:=kernel_rollback(&p.kernel,preparing);assert(error.kind==.None)
 assert(adm_dispose(p,&disposal)==1)
}
adm_response :: proc(p:^Admission_Probe)->surf.Response {
 body:=make([dynamic]u8,3,64,p.resources.allocator);copy(body[:],[]u8{'y','e','s'})
 return {status=200,allocator=p.resources.allocator,body_storage=body,body=body[:]}
}
adm_terminal :: proc(p:^Admission_Probe,request:Request_Handle,response:^surf.Response,error:=surf.HTTP_Error{},now:=runtime_async.Deadline{epoch=7,at=10})->int {
 disposal,cause:=kernel_begin_complete(&p.kernel,request,response,error);assert(cause.kind==.None)
 return adm_dispose(p,&disposal,now)
}
adm_activate :: proc(p:^Admission_Probe,request:Request_Handle)->Cell_Handle {
 for _ in 0..<1000 {
  assignment,work,error:=pool_dispatch(&p.kernel,1,adm_now().at)
  assert(work<=1 && (error.kind==.None || error.kind==.Pending))
  if assignment.request.owner_id!=0 {
   assert(assignment.request==request)
   assert(pool_session_state(&p.kernel,assignment.session,.Busy,adm_now().at).kind==.None)
   return assignment.session
  }
 }
 panic("assignment missing")
}
adm_retire :: proc(p:^Admission_Probe,session:Cell_Handle) {
 assert(pool_session_state(&p.kernel,session,.Retiring,adm_now().at).kind==.None)
 assert(pool_retire(&p.kernel,session).kind==.None)
}

@(test)
admission_preparing_close_and_expiry_preserve_unaccepted_inputs :: proc(t:^testing.T) {
 for mode in 0..<4 {
  p:Admission_Probe;adm_init(&p)
  preparing,_:=adm_prepare(&p)
  _,has_completion:=kernel_poll(&p.kernel);testing.expect(t,!has_completion)
  owner:=adm_clone(&p);input:=raw_data(owner.storage)
  now:=runtime_async.Deadline{epoch=7,at=10}
  want:=Client_Error_Kind.Invalid_Config
  if mode==0 {assert(kernel_close(&p.kernel).kind==.None);want=.Closed}
  if mode==1 {now.at=1000;want=.Request_Error}
  if mode==2 {now.epoch=8}
  if mode==3 {assert(kernel_cancel(&p.kernel,preparing.request).kind==.None);want=.Request_Error}
  cause:=kernel_commit(&p.kernel,preparing,&owner,now)
  testing.expect_value(t,cause.kind,want)
  testing.expect(t,raw_data(owner.storage)==input && owner.request.url=="https://example.test/path")
  if mode==1 {testing.expect_value(t,cause.http.kind,.Deadline_Failed)}
  if mode==3 {testing.expect_value(t,cause.http.transport.kind,.Cancelled)}
  request_owner_destroy(&owner)
  adm_rollback(&p,preparing)
  _,has_completion=kernel_poll(&p.kernel);testing.expect(t,!has_completion)
  testing.expect_value(t,p.kernel.counters.deadline_count,u64(0))
  adm_destroy(&p)
 }
}

@(test)
admission_lease_provenance_rejection_preserves_sources :: proc(t:^testing.T) {
 p:Admission_Probe;adm_init(&p)
 foreign_scope,error:=scopes.create_root({streams=8},p.allocator);assert(error==.None)
 for mode in 0..<4 {
  source:=p.scope;if mode==0 {source=foreign_scope}
  cost:=scopes.Cost{streams=1}
  if mode==1 {cost.streams=2}
  if mode==2 {cost.bytes=1}
  phase:=scopes.Job_Phase.None
  if mode==3 {cost.jobs=1;phase=.Held}
  lease,cause:=scopes.reserve(source,cost,phase);assert(cause==.None)
  snapshot:=lease
  free_before:=p.kernel.request_free_count;references:=p.kernel.references
  metadata:=adm_metadata_snapshot(&p.kernel)
  _,failure:=adm_reserve_noalloc(&p.kernel,adm_deadline(),&lease)
  after:=adm_metadata_snapshot(&p.kernel)
  testing.expect(t,bytes.equal(metadata,after));delete(metadata);delete(after)
  testing.expect_value(t,failure.kind,.Invalid_Config)
  if mode==0 {testing.expect_value(t,failure.http.budget,.Foreign_Root)}
  testing.expect_value(t,lease,snapshot)
  testing.expect_value(t,p.kernel.request_free_count,free_before)
  testing.expect_value(t,p.kernel.references,references)
  scopes.release(&lease)
 }
 scopes.release_scope(&foreign_scope)
 // Empty unmanaged mode may not silently consume a foreign physical lease.
 other:Admission_Probe;adm_init(&other,managed=false)
 lease,cause:=resources_request_lease(&p.resources);assert(cause.kind==.None)
 original:=lease
 _,cause=kernel_reserve(&other.kernel,adm_deadline(),&lease)
 testing.expect_value(t,cause.kind,.Invalid_Config);testing.expect_value(t,lease,original)
 scopes.release(&lease);adm_destroy(&other)
 // Local owner-reference overflow boundary; rejection must not wrap or move.
 lease,cause=resources_request_lease(&p.resources);assert(cause.kind==.None)
 original=lease
 references:=p.kernel.references;p.kernel.references=max(int)
 _,cause=kernel_reserve(&p.kernel,adm_deadline(),&lease)
 testing.expect(t,cause.kind!=.None)
 testing.expect_value(t,p.kernel.references,max(int));testing.expect_value(t,lease,original)
 p.kernel.references=references
 scopes.release(&lease);adm_destroy(&p)
}

@(test)
admission_capacity_and_stale_tokens_do_not_consume_owners :: proc(t:^testing.T) {
 p:Admission_Probe;adm_init(&p,requests=1,waiters=1)
 preparing,_:=adm_prepare(&p)
 lease,error:=resources_request_lease(&p.resources);assert(error.kind==.None)
 before:=lease
 _,error=kernel_reserve(&p.kernel,adm_deadline(),&lease)
 testing.expect_value(t,error.kind,.Capacity);testing.expect_value(t,lease,before)
 scopes.release(&lease)
 bad:=preparing;bad.request.generation+=1
 disposal,rollback_error:=kernel_rollback(&p.kernel,bad)
 testing.expect_value(t,rollback_error.kind,.Invalid_Handle);testing.expect(t,disposal.input.storage==nil)
 alias:=p.kernel
 owner:=adm_clone(&p);input:=raw_data(owner.storage)
 testing.expect_value(t,kernel_commit(&alias,preparing,&owner,adm_now()).kind,.Invalid_State)
 testing.expect_value(t,raw_data(owner.storage),input);request_owner_destroy(&owner)
 adm_rollback(&p,preparing)
 testing.expect_value(t,kernel_cancel(&p.kernel,preparing.request).kind,.Invalid_Handle)
 testing.expect_value(t,p.kernel.request_free_count,1)
 adm_destroy(&p)
}

@(test)
admission_rollback_and_queued_cancel_restore_reserved_provenance :: proc(t:^testing.T) {
 p:Admission_Probe;adm_init(&p,requests=2,waiters=2)
 fresh,claim:=adm_prepare(&p)
 fresh_generation:=claim.session.generation
 adm_rollback(&p,fresh)
 testing.expect_value(t,p.kernel.sessions[int(claim.session.slot)-1].state,.Free)
 testing.expect(t,p.kernel.sessions[int(claim.session.slot)-1].generation>fresh_generation)
 initial,_:=adm_prepare(&p);handle:=adm_commit(&p,initial);session:=adm_activate(&p,handle)
 response:=adm_response(&p);assert(adm_terminal(&p,handle,&response)==1)
 assert(kernel_release(&p.kernel,handle).kind==.None)
 assert(pool_session_state(&p.kernel,session,.Idle,adm_now().at).kind==.None)
 for mode in 0..<2 {
  preparing,reservation:=adm_prepare(&p)
  testing.expect_value(t,reservation.session,session)
  if mode==0 {adm_rollback(&p,preparing)} else {
   handle=adm_commit(&p,preparing)
   assert(kernel_cancel(&p.kernel,handle).kind==.None)
   empty:surf.Response
   assert(adm_terminal(&p,handle,&empty,{kind=.IO_Failed,transport={kind=.Cancelled}})==1)
   assert(kernel_release(&p.kernel,handle).kind==.None)
  }
  testing.expect_value(t,p.kernel.sessions[int(session.slot)-1].state,.Idle)
  testing.expect_value(t,p.kernel.sessions[int(session.slot)-1].generation,session.generation)
 }
 adm_retire(&p,session);adm_destroy(&p)
}

@(test)
admission_same_profile_kernels_have_distinct_nonreused_handle_owners :: proc(t:^testing.T) {
 p:Admission_Probe;adm_init(&p)
 other:Kernel
 assert(kernel_init(&other,&p.profile,&p.resources).kind==.None)
 testing.expect(t,other.owner_id!=0 && other.owner_id!=p.kernel.owner_id)
 lease,error:=resources_request_lease(&p.resources);assert(error.kind==.None)
 first,first_error:=kernel_reserve(&p.kernel,adm_deadline(),&lease);assert(first_error.kind==.None)
 lease,error=resources_request_lease(&p.resources);assert(error.kind==.None)
 second,second_error:=kernel_reserve(&other,adm_deadline(),&lease);assert(second_error.kind==.None)
 testing.expect_value(t,first.request.slot,second.request.slot)
 testing.expect_value(t,first.request.generation,second.request.generation)
 testing.expect_value(t,kernel_cancel(&other,first.request).kind,.Invalid_Handle)
 adm_rollback(&p,first)
 disposal,rollback_error:=kernel_rollback(&other,second);assert(rollback_error.kind==.None)
 ticket:=disposal.request;request_disposal_destroy(&disposal)
 next,done,failure:=kernel_cleanup_finish(&other,ticket,adm_now());assert(failure.kind==.None && done && next.input.storage==nil)
 previous:=other.owner_id
 assert(kernel_destroy(&other).kind==.None)
 assert(kernel_init(&other,&p.profile,&p.resources).kind==.None)
 testing.expect(t,other.owner_id!=previous && other.owner_id!=p.kernel.owner_id)
 testing.expect_value(t,kernel_cancel(&other,second.request).kind,.Invalid_Handle)
 assert(kernel_destroy(&other).kind==.None)
 adm_destroy(&p)
}
