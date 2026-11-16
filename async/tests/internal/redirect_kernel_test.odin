package surf_async

import surf ".."
import runtime_async "../../async"
import "core:mem"
import scopes "core:sync/budget"
import "core:testing"

// Independent metadata/owner tests. Actual factories and claims create every
// state; this file does not claim that a TLS close or HTTP exchange occurred.
redirect_ledger_init :: proc(f:^Pool_Case,connections:int=1) {
 caps:=pool_case_caps();caps.connections=connections;caps.origins=3;caps.requests=4
 pool_case_init(f,caps,10000,100000)
}
redirect_ledger_start :: proc(f:^Pool_Case,allocator:mem.Allocator={},retiring:bool=true)->(Request_Handle,Assignment) {
 start:=pool_case_time(f)
 lease,error:=resources_request_lease(&f.resources);assert(error.kind==.None)
 preparing,reserved:=kernel_reserve(&f.kernel,{epoch=77,at=1000},&lease);assert(reserved.kind==.None)
 _,claim:=pool_case_claim(f,preparing,"https://old.test/original",start);assert(claim.kind==.None)
 selected:=allocator;if selected.procedure==nil {selected=f.resources.allocator}
 payload:="original-body"
 input,cloned:=request_clone({method=.POST,url="https://old.test/original",body=transmute([]u8)payload},selected);assert(cloned.kind==.None)
 assert(kernel_commit(&f.kernel,preparing,&input,pool_case_clock(start+1)).kind==.None)
 assigned:=pool_case_dispatch(f,preparing.request,now=start+2)
 if retiring {assert(pool_session_state(&f.kernel,assigned.session,.Retiring,start+3).kind==.None)}
 return preparing.request,assigned
}
redirect_ledger_streams :: proc(f:^Pool_Case)->u64 {usage,error:=scopes.snapshot(f.scope);assert(error==.None);return usage.used.streams}
redirect_ledger_dispose_finish :: proc(f:^Pool_Case,handle:Request_Handle,disposal:^Request_Disposal,now:runtime_async.Deadline)->Completion {
 pool_case_dispose(f,disposal)
 next,done,error:=kernel_cleanup_finish(&f.kernel,handle,now)
 assert(error.kind==.None&&done)
 pool_case_dispose(f,&next)
 result,available:=kernel_poll(&f.kernel);assert(available&&result.request==handle)
 _,again:=kernel_poll(&f.kernel);assert(!again)
 assert(kernel_release(&f.kernel,handle).kind==.None)
 return result
}
redirect_ledger_cleanup_active :: proc(f:^Pool_Case,handle:Request_Handle,session:Cell_Handle) {
 response:surf.Response
 disposal,error:=kernel_begin_complete(&f.kernel,handle,&response,{kind=.Invalid_Redirect,phase=.Protocol,status=302,write_effect=.Response_Received});assert(error.kind==.None)
 _=redirect_ledger_dispose_finish(f,handle,&disposal,pool_case_clock(300))
 assert(pool_retire(&f.kernel,session).kind==.None)
}

@(test)
redirect_ledger_two_hops_keep_one_stream_lease_handle_and_cutoff :: proc(t:^testing.T) {
 f:Pool_Case;redirect_ledger_init(&f);defer pool_case_destroy(&f)
 handle,assignment:=redirect_ledger_start(&f)
 original_lease:=f.kernel.requests[handle.slot-1].lease
 original_deadline:=f.kernel.requests[handle.slot-1].deadline
 for hop in 0..<2 {
  before:=f.kernel.references
  disposal,error:=kernel_redirect_begin(&f.kernel,handle,pool_case_clock(120+100*i64(hop)))
  testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,disposal.request,handle)
  testing.expect_value(t,disposal.returning_to,.Preparing)
  testing.expect_value(t,disposal.lease,scopes.Lease{})
  testing.expect(t,len(disposal.input.storage)>0)
  testing.expect_value(t,f.kernel.references,before+1)
  testing.expect_value(t,f.kernel.counters.active_requests,0)
  testing.expect_value(t,f.kernel.counters.returning_requests,1)
  testing.expect_value(t,f.kernel.sessions[assignment.session.slot-1].request,Request_Handle{})
  testing.expect_value(t,f.kernel.counters.retiring_connections,1)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].lease,original_lease)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].deadline,original_deadline)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  _,available:=kernel_poll(&f.kernel);testing.expect(t,!available)
  pool_case_dispose(&f,&disposal)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  testing.expect_value(t,pool_retire(&f.kernel,assignment.session).kind,.None)
  testing.expect_value(t,f.kernel.counters.origins,0)
  testing.expect_value(t,kernel_redirect_ready(&f.kernel,handle,pool_case_clock(130+100*i64(hop))).kind,.None)
  testing.expect_value(t,f.kernel.references,before+1)
  testing.expect_value(t,f.kernel.counters.returning_requests,0)
  testing.expect_value(t,f.kernel.counters.preparing_requests,1)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].stage,.Redirecting)
  url:="https://middle.test/target" if hop==0 else "https://final.test/target"
  accepted:=Preparing_Request{request=handle} // Actual accepted Preparing ticket.
  _,claimed:=pool_case_claim(&f,accepted,url,140+100*i64(hop));testing.expect_value(t,claimed.kind,.None)
  input,cloned:=request_clone({method=.POST,url=url},f.resources.allocator);assert(cloned.kind==.None)
  testing.expect_value(t,kernel_commit(&f.kernel,accepted,&input,pool_case_clock(150+100*i64(hop))).kind,.None)
  testing.expect_value(t,f.kernel.references,before)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].generation,handle.generation)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].lease,original_lease)
  assignment=pool_case_dispatch(&f,handle,now=160+100*i64(hop))
  testing.expect_value(t,pool_session_state(&f.kernel,assignment.session,.Retiring,170+100*i64(hop)).kind,.None)
 }
 redirect_ledger_cleanup_active(&f,handle,assignment.session)
 testing.expect_value(t,redirect_ledger_streams(&f),u64(0))
 testing.expect_value(t,f.kernel.references,1)
 testing.expect_value(t,kernel_release(&f.kernel,handle).kind,.Invalid_Handle)
}

@(test)
redirect_ledger_begin_rejections_preserve_all_accepted_owners :: proc(t:^testing.T) {
 for mode in 0..<9 {
  f:Pool_Case;redirect_ledger_init(&f)
  handle,assignment:=redirect_ledger_start(&f,retiring=mode!=8)
  bad:=handle;now:=pool_case_clock(120)
  switch mode {
  case 0:bad.owner_id+=1
  case 1:bad.generation+=1
  case 2:bad.slot=u32(len(f.kernel.requests)+1)
  case 3:bad={}
  case 4:now.epoch+=1
  case 5:now.at=1000
  case 6:assert(kernel_cancel(&f.kernel,handle).kind==.None)
  case 7:assert(kernel_close(&f.kernel).kind==.None)
  case 8:
  }
  before:=f.kernel.requests[handle.slot-1]
  counters:=f.kernel.counters;references:=f.kernel.references
  disposal,error:=kernel_redirect_begin(&f.kernel,bad,now)
  testing.expect(t,error.kind!=.None)
  testing.expect_value(t,disposal.request,Request_Handle{})
  testing.expect_value(t,raw_data(disposal.input.storage),nil)
  after:=f.kernel.requests[handle.slot-1]
  testing.expect_value(t,after.state,before.state)
  testing.expect_value(t,after.stage,before.stage)
  testing.expect_value(t,after.deadline,before.deadline)
  testing.expect_value(t,after.lease,before.lease)
  testing.expect_value(t,raw_data(after.input.storage),raw_data(before.input.storage))
  testing.expect_value(t,string(after.input.request.body),"original-body")
  testing.expect_value(t,after.origin,before.origin);testing.expect_value(t,after.session,before.session)
  testing.expect_value(t,f.kernel.counters,counters);testing.expect_value(t,f.kernel.references,references)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  if mode==8 {assert(pool_session_state(&f.kernel,assignment.session,.Retiring,130).kind==.None)}
  redirect_ledger_cleanup_active(&f,handle,assignment.session)
  pool_case_destroy(&f)
 }
}

@(test)
redirect_ledger_ready_rechecks_fresh_clock_cancel_close_then_fails_once :: proc(t:^testing.T) {
 for mode in 0..<4 {
  f:Pool_Case;redirect_ledger_init(&f)
  handle,assignment:=redirect_ledger_start(&f)
  disposal,error:=kernel_redirect_begin(&f.kernel,handle,pool_case_clock(120));assert(error.kind==.None)
  pool_case_dispose(&f,&disposal);assert(pool_retire(&f.kernel,assignment.session).kind==.None)
  now:=pool_case_clock(140)
  if mode==0 {now.epoch+=1}
  if mode==1 {now.at=1000}
  if mode==2 {assert(kernel_cancel(&f.kernel,handle).kind==.None)}
  if mode==3 {assert(kernel_close(&f.kernel).kind==.None)}
  before_refs:=f.kernel.references
  failure:=kernel_redirect_ready(&f.kernel,handle,now)
  testing.expect(t,failure.kind!=.None)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].state,.Returning)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].returning_to,.Preparing)
  testing.expect_value(t,f.kernel.references,before_refs)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  primary:=failure.http
  if mode==3 {primary={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}}
  failed,cause:=kernel_redirect_fail(&f.kernel,handle,primary);assert(cause.kind==.None)
  testing.expect_value(t,f.kernel.references,before_refs)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  result:=redirect_ledger_dispose_finish(&f,handle,&failed,now)
  testing.expect_value(t,result.error,primary)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(0))
  testing.expect_value(t,f.kernel.references,1)
  pool_case_destroy(&f)
 }
}

@(test)
redirect_ledger_accepted_failure_cleans_returning_unclaimed_reserved_waiter_and_idle :: proc(t:^testing.T) {
 for mode in 0..<5 {
  f:Pool_Case;redirect_ledger_init(&f,connections=2 if mode==4 else 1)
  idle:Assignment
  if mode==4 {
   warm,_:=pool_case_accept(&f,"https://target.test/")
   idle=pool_case_dispatch(&f,warm)
   pool_case_complete(&f,warm);pool_case_idle(&f,idle.session)
  }
  handle,old:=redirect_ledger_start(&f)
  original:=f.kernel.requests[handle.slot-1].lease
  begin,error:=kernel_redirect_begin(&f.kernel,handle,pool_case_clock(120));assert(error.kind==.None)
  pool_case_dispose(&f,&begin);assert(pool_retire(&f.kernel,old.session).kind==.None)
  if mode>0 {assert(kernel_redirect_ready(&f.kernel,handle,pool_case_clock(130)).kind==.None)}
  claim:=Pool_Reservation{}
  if mode>=2 {
   candidate,prepared:=origin_prepare(&f.profile,"https://target.test/",f.resources.allocator);assert(prepared.kind==.None)
   claim,error=pool_reserve_policy(&f.kernel,{handle},&candidate,140,mode!=3)
   assert(error.kind==.None);origin_destroy(&candidate)
   if mode==3 {testing.expect(t,claim.waiting&&claim.session.slot==0)}
   if mode==4 {testing.expect_value(t,claim.session,idle.session);testing.expect_value(t,f.kernel.sessions[claim.session.slot-1].reserved_from,.Idle)}
  }
  references:=f.kernel.references
  primary:=surf.HTTP_Error{kind=.Unsafe_Redirect,phase=.Protocol,status=307,write_effect=.Response_Received}
  if mode==2 {primary={kind=.IO_Failed,transport={kind=.Write_Failed},phase=.Write,status=503,write_effect=.Unknown}}
  disposal,cause:=kernel_redirect_fail(&f.kernel,handle,primary)
  testing.expect_value(t,cause.kind,.None)
  testing.expect_value(t,disposal.lease,original)
  testing.expect_value(t,f.kernel.requests[handle.slot-1].lease,scopes.Lease{})
  // A retiring target Origin has its OWN detached-disposal Kernel keepalive.
  testing.expect_value(t,f.kernel.references,references+(1 if disposal.origin.origin.slot!=0 else 0))
  testing.expect_value(t,f.kernel.preparing,0)
  testing.expect_value(t,f.kernel.returning,1)
  testing.expect_value(t,f.kernel.counters.reserved_connections,0)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  if mode==4 {
   testing.expect_value(t,f.kernel.sessions[idle.session.slot-1].state,.Idle)
   testing.expect_value(t,f.kernel.sessions[idle.session.slot-1].generation,idle.session.generation)
  }
  result:=redirect_ledger_dispose_finish(&f,handle,&disposal,pool_case_clock(160))
  testing.expect_value(t,result.error,primary)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(0))
  testing.expect_value(t,f.kernel.references,1)
  pool_case_destroy(&f)
 }
}

@(test)
redirect_ledger_fail_rejects_original_preparing_and_absent_primary :: proc(t:^testing.T) {
 f:Pool_Case;redirect_ledger_init(&f);defer pool_case_destroy(&f)
 producer:=pool_case_prepare(&f)
 before:=f.kernel.requests[producer.request.slot-1].lease
 _,error:=kernel_redirect_fail(&f.kernel,producer.request,{kind=.Invalid_Redirect})
 testing.expect_value(t,error.kind,.Invalid_State)
 testing.expect_value(t,f.kernel.requests[producer.request.slot-1].lease,before)
 pool_case_rollback(&f,producer) // Only this never-accepted producer may roll back.
 handle,assignment:=redirect_ledger_start(&f)
 disposal,cause:=kernel_redirect_begin(&f.kernel,handle,pool_case_clock(120));assert(cause.kind==.None)
 pool_case_dispose(&f,&disposal);assert(pool_retire(&f.kernel,assignment.session).kind==.None)
 references:=f.kernel.references
 _,error=kernel_redirect_fail(&f.kernel,handle,{})
 testing.expect_value(t,error.kind,.Invalid_Config)
 testing.expect_value(t,f.kernel.references,references)
 testing.expect_value(t,f.kernel.requests[handle.slot-1].returning_to,.Preparing)
 failure,failed:=kernel_redirect_fail(&f.kernel,handle,{kind=.Invalid_Redirect});assert(failed.kind==.None)
 _=redirect_ledger_dispose_finish(&f,handle,&failure,pool_case_clock(160))
}

Redirect_Ledger_Callback :: struct {backing:mem.Allocator,kernel:^Kernel,scope:scopes.Scope,handle:Request_Handle,storage:rawptr,armed:bool,calls,action:int}
redirect_ledger_allocator :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 p:=cast(^Redirect_Ledger_Callback)data
 if mode==.Free&&old_memory==p.storage&&p.armed {
  p.armed=false;p.calls+=1
  assert(p.kernel.requests[p.handle.slot-1].state==.Returning&&p.kernel.requests[p.handle.slot-1].stage==.Redirecting)
  assert(kernel_destroy(p.kernel).kind==.Pending) // Would deadlock under Kernel.mu.
  usage,error:=scopes.snapshot(p.scope);assert(error==.None&&usage.used.streams==1)
  if p.action==0 {assert(kernel_cancel(p.kernel,p.handle).kind==.None)}else{assert(kernel_close(p.kernel).kind==.None)}
 }
 grant,error:=p.backing.procedure(p.backing.data,mode,size,alignment,old_memory,old_size,location)
 if mode==.Alloc {p.storage=raw_data(grant)}
 return grant,error
}

@(test)
redirect_ledger_physical_old_input_free_can_cancel_or_close_outside_mutex :: proc(t:^testing.T) {
 for action in 0..<2 {
  f:Pool_Case;redirect_ledger_init(&f)
  p:=Redirect_Ledger_Callback{backing=f.resources.allocator,kernel=&f.kernel,scope=f.scope,action=action}
  handle,assignment:=redirect_ledger_start(&f,{redirect_ledger_allocator,&p})
  p.handle=handle;p.armed=true
  disposal,error:=kernel_redirect_begin(&f.kernel,handle,pool_case_clock(120));assert(error.kind==.None)
  pool_case_dispose(&f,&disposal)
  testing.expect_value(t,p.calls,1)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(1))
  assert(pool_retire(&f.kernel,assignment.session).kind==.None)
  rejected:=kernel_redirect_ready(&f.kernel,handle,pool_case_clock(140))
  testing.expect_value(t,rejected.kind,.Request_Error if action==0 else .Closed)
  primary:=surf.HTTP_Error{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}
  failure,cause:=kernel_redirect_fail(&f.kernel,handle,primary);assert(cause.kind==.None)
  result:=redirect_ledger_dispose_finish(&f,handle,&failure,pool_case_clock(160))
  testing.expect_value(t,result.error,primary)
  testing.expect_value(t,redirect_ledger_streams(&f),u64(0))
  pool_case_destroy(&f)
 }
}
