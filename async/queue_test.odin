package surf_async

import "core:mem"
import "core:bytes"
import "core:time"
import "core:testing"

@(test)
queue_preparing_waiters_are_not_fifo_and_commit_order_is_fifo :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=3
 f:Pool_Case;pool_case_init(&f,caps,1000,10000);defer pool_case_destroy(&f)
 held:=pool_case_prepare(&f);held_claim,error:=pool_case_claim(&f,held,"https://a.test");assert(error.kind==.None && !held_claim.waiting)
 first:=pool_case_prepare(&f);first_claim,cause:=pool_case_claim(&f,first,"https://a.test");assert(cause.kind==.None && first_claim.waiting)
 second:=pool_case_prepare(&f);_,cause=pool_case_claim(&f,second,"https://a.test");assert(cause.kind==.None)
 origin:=&f.kernel.origins[held_claim.origin.slot-1]
 testing.expect(t,origin.requests==3 && origin.preparing==3 && origin.waiters==2 && origin.queue_head==0 && origin.queue_tail==0)
 testing.expect(t,f.kernel.requests[first.request.slot-1].queue_next==0 && f.kernel.requests[second.request.slot-1].queue_previous==0)
 pool_case_commit(&f,second,"https://a.test");pool_case_commit(&f,first,"https://a.test")
 testing.expect(t,origin.queue_head==second.request.slot && origin.queue_tail==first.request.slot && origin.preparing==1)
 pool_case_commit(&f,held,"https://a.test")
 testing.expect(t,origin.queue_head==second.request.slot && origin.queue_tail==first.request.slot && origin.preparing==0)
 // The held earlier resource claim is not a waiter. It can dispatch before the
 // FIFO even though the waiting requests committed first.
 active:=pool_case_dispatch(&f,held.request)
 testing.expect_value(t,origin.waiters,2)
 pool_case_complete(&f,held.request);pool_case_idle(&f,active.session)
 active=pool_case_dispatch(&f,second.request,true)
 testing.expect(t,origin.waiters==1 && origin.queue_head==first.request.slot && origin.queue_tail==first.request.slot)
 pool_case_complete(&f,second.request);pool_case_idle(&f,active.session)
 active=pool_case_dispatch(&f,first.request,true)
 testing.expect(t,origin.waiters==0 && origin.queue_head==0 && origin.queue_tail==0)
 pool_case_complete(&f,first.request);pool_case_idle(&f,active.session)
}

@(test)
queue_reserved_idle_commit_or_rollback_preserves_claim_provenance :: proc(t:^testing.T) {
 for rollback in ([2]bool{false,true}) {
  caps:=pool_case_caps();caps.connections=1
  f:Pool_Case;pool_case_init(&f,caps,1000,10000)
  old,_:=pool_case_accept(&f,"https://a.test");transport:=pool_case_dispatch(&f,old)
  pool_case_complete(&f,old);pool_case_idle(&f,transport.session)
  before:=f.kernel.sessions[transport.session.slot-1]
  held:=pool_case_prepare(&f);claim,error:=pool_case_claim(&f,held,"https://a.test");assert(error.kind==.None)
  testing.expect(t,claim.session==transport.session && f.kernel.sessions[claim.session.slot-1].reserved_from==.Idle)
  waiter,waiting:=pool_case_accept(&f,"https://a.test")
  testing.expect(t,waiting.waiting && f.kernel.origins[claim.origin.slot-1].queue_head==waiter.slot)
  if rollback {
   pool_case_rollback(&f,held)
   restored:=f.kernel.sessions[transport.session.slot-1]
   testing.expect(t,restored.state==.Idle && restored.generation==before.generation && restored.created_at==before.created_at && restored.idle_since==before.idle_since)
   _,present:=kernel_poll(&f.kernel);testing.expect(t,!present)
  } else {
   pool_case_commit(&f,held,"https://a.test")
   dispatched:=pool_case_dispatch(&f,held.request,true)
   pool_case_complete(&f,held.request);pool_case_idle(&f,dispatched.session)
  }
  ready:=pool_case_dispatch(&f,waiter,true)
  testing.expect_value(t,ready.session,transport.session)
  pool_case_complete(&f,waiter);pool_case_idle(&f,ready.session)
  pool_case_destroy(&f)
 }
}

@(test)
queue_work1_unrelated_origin_progress_and_round_robin_fairness :: proc(t:^testing.T) {
 f:Pool_Case;pool_case_init(&f,pool_case_caps(),1000,10000);defer pool_case_destroy(&f)
 a,_:=pool_case_accept(&f,"https://a.test");session_a:=pool_case_dispatch(&f,a)
 waiting_a,_:=pool_case_accept(&f,"https://a.test")
 b,_:=pool_case_accept(&f,"https://b.test");session_b:=pool_case_dispatch(&f,b)
 waiting_b,_:=pool_case_accept(&f,"https://b.test")
 // OriginA's busy session cannot prevent B's queued work progressing.
 pool_case_complete(&f,b);pool_case_idle(&f,session_b.session)
 ready_b:=pool_case_dispatch(&f,waiting_b,true)
 testing.expect_value(t,f.kernel.requests[a.slot-1].state,.Active)
 pool_case_complete(&f,waiting_b);pool_case_idle(&f,ready_b.session)
 pool_case_complete(&f,a);pool_case_idle(&f,session_a.session)
 ready_a:=pool_case_dispatch(&f,waiting_a,true)
 pool_case_complete(&f,waiting_a);pool_case_idle(&f,ready_a.session)
 // Both origins now have Idle sessions. Keep replenishing the origin most
 // recently served: next-origin RR must still give the other origin a turn.
 qa,_:=pool_case_accept(&f,"https://a.test")
 qb,_:=pool_case_accept(&f,"https://b.test")
 first:Assignment
 for step in 0..<128 {
  assignment,used,error:=pool_dispatch(&f.kernel,1,pool_case_time(&f))
  assert((error.kind==.None || error.kind==.Pending) && used<=1 && used>=0)
  if assignment.request!=(Request_Handle{}) {first=assignment;break}
 }
 assert(first.request==qa || first.request==qb)
 testing.expect_value(t,f.kernel.sessions[first.session.slot-1].state,.Busy)
 pool_case_complete(&f,first.request);pool_case_idle(&f,first.session)
 first_url:="https://a.test";other:=qb
 if first.request==qb {first_url="https://b.test";other=qa}
 replacement,_:=pool_case_accept(&f,first_url)
 second:=pool_case_dispatch(&f,other,true)
 pool_case_complete(&f,other);pool_case_idle(&f,second.session)
 third:=pool_case_dispatch(&f,replacement,true)
 pool_case_complete(&f,replacement);pool_case_idle(&f,third.session)
}

@(test)
queue_work_limits_and_idle_cursor_are_independent :: proc(t:^testing.T) {
 f:Pool_Case;pool_case_init(&f,pool_case_caps(),5,20);defer pool_case_destroy(&f)
 request,_:=pool_case_accept(&f,"https://a.test")
 busy:=pool_case_dispatch(&f,request)
 other,_:=pool_case_accept(&f,"https://b.test")
 assignment:=pool_case_dispatch(&f,other);pool_case_complete(&f,other);pool_case_idle(&f,assignment.session)
 testing.expect(t,assignment.session.slot!=busy.session.slot)
 for work in ([4]int{-1,0,4097,max(int)}) {
  before:[size_of(Kernel)]u8;copy(before[:],mem.byte_slice(&f.kernel,size_of(Kernel)))
  none,used,error:=pool_dispatch(&f.kernel,work,f.now)
  testing.expect(t,error.kind==.Invalid_Config && used==0 && none==(Assignment{}))
  testing.expect(t,bytes.equal(before[:],mem.byte_slice(&f.kernel,size_of(Kernel))))
 }
 // Interleave a completely quiescent dispatch scan with idle expiry scans.
 // Shared/reset cursors would make work1 starve the late allocated session.
 now:=pool_case_time(&f,1000);found:=Cell_Handle{}
 for step in 0..<128 {
  none,used,error:=pool_dispatch(&f.kernel,1,now)
  assert((error.kind==.None || error.kind==.Pending) && none==(Assignment{}) && used<=1)
  candidate,idle_used,idle_error:=pool_idle_candidate(&f.kernel,1,now)
  assert((idle_error.kind==.None || idle_error.kind==.Pending) && idle_used<=1)
  if candidate!=(Cell_Handle{}) {found=candidate;break}
 }
 testing.expect_value(t,found,assignment.session)
 testing.expect_value(t,f.kernel.sessions[found.slot-1].state,.Idle)
 pool_case_complete(&f,request);pool_case_idle(&f,busy.session)
}

@(test)
queue_idle_and_max_age_boundaries_do_not_overflow :: proc(t:^testing.T) {
 for maximum in ([2]bool{false,true}) {
  caps:=pool_case_caps();caps.connections=1;caps.waiters_per_origin=0
  idle,max_age:=time.Duration(5),time.Duration(20)
  if maximum {idle=max(time.Duration);max_age=max(time.Duration)}
  f:Pool_Case;pool_case_init(&f,caps,idle,max_age)
  start:i64=100;if maximum {start=max(i64)-10}
  request,_:=pool_case_accept(&f,"https://a.test",start)
  assignment:=pool_case_dispatch(&f,request,false,start+1)
  pool_case_complete(&f,request,start+2);pool_case_idle(&f,assignment.session,start+3)
  before:=f.kernel.sessions[assignment.session.slot-1]
  check_at:=pool_case_time(&f,start+7)
  for count in 0..<32 {
   candidate,used,error:=pool_idle_candidate(&f.kernel,1,check_at)
   assert((error.kind==.None || error.kind==.Pending) && used<=1)
   testing.expect_value(t,candidate,Cell_Handle{})
   if error.kind==.None {break}
  }
  if maximum {
   high:=pool_case_time(&f,max(i64))
   for count in 0..<32 {
    candidate,used,error:=pool_idle_candidate(&f.kernel,1,high)
    assert((error.kind==.None || error.kind==.Pending) && used<=1)
    testing.expect_value(t,candidate,Cell_Handle{})
    if error.kind==.None {break}
   }
  } else {
   found:=Cell_Handle{}
   expiry:=pool_case_time(&f,start+8)
   for count in 0..<32 {
    candidate,used,error:=pool_idle_candidate(&f.kernel,1,expiry)
    assert((error.kind==.None || error.kind==.Pending) && used<=1)
    if candidate!=(Cell_Handle{}) {found=candidate;break}
   }
   testing.expect_value(t,found,assignment.session)
  }
  testing.expect(t,f.kernel.sessions[assignment.session.slot-1].state==.Idle && f.kernel.sessions[assignment.session.slot-1].generation==before.generation)
  pool_case_destroy(&f)
 }
}

@(test)
queue_quiescent_scan_wakes_on_admission_and_close_makes_idle_due :: proc(t:^testing.T) {
 f:Pool_Case;pool_case_init(&f,pool_case_caps(),1000,10000);defer pool_case_destroy(&f)
 quiet:=false
 for step in 0..<64 {
  assignment,used,error:=pool_dispatch(&f.kernel,1,pool_case_time(&f))
  assert((error.kind==.None || error.kind==.Pending) && assignment==(Assignment{}) && used<=1)
  if error.kind==.None {quiet=true;break}
 }
 testing.expect(t,quiet)
 none,used,error:=pool_dispatch(&f.kernel,1,pool_case_time(&f))
 testing.expect(t,error.kind==.None && none==(Assignment{}) && used==0)
 request,_:=pool_case_accept(&f,"https://a.test")
 assignment:=pool_case_dispatch(&f,request)
 pool_case_complete(&f,request);pool_case_idle(&f,assignment.session)
 // A fresh future idle deadline must not delay explicit Client/kernel close.
 for step in 0..<64 {
  candidate,_,cause:=pool_idle_candidate(&f.kernel,1,pool_case_time(&f))
  testing.expect_value(t,candidate,Cell_Handle{})
  assert(cause.kind==.None || cause.kind==.Pending)
  if cause.kind==.None {break}
 }
 preparing:=pool_case_prepare(&f)
 assert(kernel_close(&f.kernel).kind==.None)
 _,cause:=pool_case_claim(&f,preparing,"https://b.test")
 testing.expect_value(t,cause.kind,.Closed)
 pool_case_rollback(&f,preparing)
 none,used,error=pool_dispatch(&f.kernel,1,pool_case_time(&f))
 testing.expect(t,error.kind==.Closed && used==0 && none==(Assignment{}))
 due:=Cell_Handle{}
 for step in 0..<64 {
  candidate,_,pending:=pool_idle_candidate(&f.kernel,1,pool_case_time(&f))
  assert(pending.kind==.None || pending.kind==.Pending)
  if candidate!=(Cell_Handle{}) {due=candidate;break}
 }
 testing.expect_value(t,due,assignment.session)
}

@(test)
queue_max_age_can_expire_a_recently_idle_session :: proc(t:^testing.T) {
 caps:=pool_case_caps();caps.connections=1
 f:Pool_Case;pool_case_init(&f,caps,1000,20);defer pool_case_destroy(&f)
 request,_:=pool_case_accept(&f,"https://a.test",100)
 assignment:=pool_case_dispatch(&f,request,false,101)
 created:=f.kernel.sessions[assignment.session.slot-1].created_at
 pool_case_complete(&f,request,102);pool_case_idle(&f,assignment.session,created+19)
 for step in 0..<32 {
  candidate,used,error:=pool_idle_candidate(&f.kernel,1,created+19)
  assert((error.kind==.None || error.kind==.Pending) && used<=1)
  testing.expect_value(t,candidate,Cell_Handle{})
  if error.kind==.None {break}
 }
 f.now=created+20
 found:=Cell_Handle{}
 for step in 0..<32 {
  candidate,used,error:=pool_idle_candidate(&f.kernel,1,f.now)
  assert((error.kind==.None || error.kind==.Pending) && used<=1)
  if candidate!=(Cell_Handle{}) {found=candidate;break}
 }
 testing.expect_value(t,found,assignment.session)
}

@(test)
queue_idle_scan_restarts_after_behind_cursor_idle_transition :: proc(t:^testing.T) {
 f:Pool_Case;pool_case_init(&f,pool_case_caps(),5,10000);defer pool_case_destroy(&f)
 a,_:=pool_case_accept(&f,"https://a.test");sa:=pool_case_dispatch(&f,a)
 b,_:=pool_case_accept(&f,"https://b.test");sb:=pool_case_dispatch(&f,b)
 candidate,used,error:=pool_idle_candidate(&f.kernel,1,pool_case_time(&f))
 assert(candidate==(Cell_Handle{}) && used==1 && error.kind==.Pending)
 visited:=u32((int(f.kernel.idle_cursor)+len(f.kernel.sessions)-1)%len(f.kernel.sessions)+1)
 completed,session,other,other_session:=a,sa.session,b,sb.session
 if sb.session.slot==visited {completed,session,other,other_session=b,sb.session,a,sa.session}
 assert(session.slot==visited)
 pool_case_complete(&f,completed);pool_case_idle(&f,session)
 idle_since:=f.kernel.sessions[session.slot-1].idle_since
 now:=pool_case_time(&f)
 candidate,used,error=pool_idle_candidate(&f.kernel,1,now)
 testing.expect(t,candidate==(Cell_Handle{}) && used==1 && error.kind==.Pending)
 quiet:=false
 for step in 0..<32 {
  candidate,used,error=pool_idle_candidate(&f.kernel,1,now)
  assert(used<=1 && (error.kind==.None || error.kind==.Pending))
  testing.expect_value(t,candidate,Cell_Handle{})
  if error.kind==.None {quiet=true;break}
 }
 testing.expect(t,quiet && f.kernel.idle_deadline==idle_since+5)
 // No new state notification occurs between clean sweep and actual expiry.
 cutoff:=pool_case_time(&f,idle_since+5)
 found:=Cell_Handle{}
 for step in 0..<32 {
  next,spent,pending:=pool_idle_candidate(&f.kernel,1,cutoff)
  assert(spent<=1 && (pending.kind==.None || pending.kind==.Pending))
  if next!=(Cell_Handle{}) {found=next;break}
 }
 testing.expect_value(t,found,session)
 pool_case_complete(&f,other);pool_case_idle(&f,other_session)
}
