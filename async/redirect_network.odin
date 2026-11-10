package surf_async

import surf ".."
import runtime_async "../../async"
import "core:sync"

@(private)
redirect_dispose :: proc(s:^Client_State,disposal:^Request_Disposal) {
 origin:=disposal.origin.origin
 request_disposal_destroy(disposal)
 if origin.slot!=0 {assert(kernel_origin_cleanup_finish(&s.kernel,origin).kind==.None)}
}

// Fresh monotonic sample supplied after each synchronous prefix destructor.
// The accepted request stays exclusively actor-owned until terminal/requeue.
@(private)
redirect_live_error :: proc(a:^Session_Actor,h:Request_Handle,now:runtime_async.Deadline)->surf.HTTP_Error {
 s:=a.owner
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 r:=admission_request_locked(&s.kernel,h)
 result:surf.HTTP_Error
 if r==nil || now.epoch!=r.deadline.epoch || now.at<=0 {result={kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}
 } else if now.at>=r.deadline.at {result={kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline,write_effect=.Not_Sent}
 } else if s.phase!=.Published || s.kernel.closed || r.cancel_requested || runtime_async.cancelled(&a.task) {
  result={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}
 }
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 return result
}

@(private)
redirect_terminal :: proc(a:^Session_Actor,error:surf.HTTP_Error) {
 s:=a.owner;h:=a.redirect.request
 primary:=redirect_status_error(error,a.redirect.last_status)
 assert(primary.kind!=.None)
 // Snapshot scalar custody before destruction clears the move-only target.
 // This prefix may call close/stats/cancel and must precede final publication.
 redirect_handoff_destroy(&a.redirect)
 sync.lock(&s.mu)
 disposal,cause:=kernel_redirect_fail(&s.kernel,h,primary)
 assert(cause.kind==.None)
 network_queue_forget_locked(s,h)
 sync.unlock(&s.mu)
 for {
  redirect_dispose(s,&disposal)
  now,clock:=network_clock(s);assert(clock.kind==.None)
  next,done,finish:=kernel_cleanup_finish(&s.kernel,h,now);assert(finish.kind==.None)
  disposal=next
  if done {break}
 }
 sync.lock(&s.mu)
 assert(s.returning_calls>0);s.returning_calls-=1;network_queue_changed_locked(s)
 sync.unlock(&s.mu)
}

@(private)
redirect_requeue :: proc(a:^Session_Actor) {
 s:=a.owner;h:=a.redirect.request
 now,clock:=network_clock(s)
 if clock.kind!=.None {redirect_terminal(a,redirect_client_error(clock));return}
 if error:=redirect_live_error(a,h,now);error.kind!=.None {redirect_terminal(a,error);return}
 sync.lock(&s.mu)
 ready:=kernel_redirect_ready(&s.kernel,h,now)
 sync.unlock(&s.mu)
 if ready.kind!=.None {redirect_terminal(a,redirect_client_error(ready));return}
 _,claim:=network_queue_claim_budget(s,{request=h},&a.redirect.origin,now.at,a.redirect.queries_remaining)
 if claim.kind!=.None {redirect_terminal(a,redirect_client_error(claim));return}
 // A pre-existing origin leaves the prepared candidate with us. Release it
 // before the final fresh-clock commit barrier, outside every owner mutex.
 origin_destroy(&a.redirect.origin)
 fresh,sample:=network_clock(s)
 if sample.kind!=.None {redirect_terminal(a,redirect_client_error(sample));return}
 if error:=redirect_live_error(a,h,fresh);error.kind!=.None {redirect_terminal(a,error);return}
 sync.lock(&s.mu)
 metadata:=&s.requests[int(h.slot)-1]
 assert(metadata.generation==h.generation)
 metadata.redirects=a.redirect.next_hop;metadata.last_status=a.redirect.last_status
 commit:=network_queue_committed_locked(s,{request=h},&a.redirect.input,fresh)
 if commit.kind==.None {
  assert(a.redirect.input.storage==nil && a.redirect.origin.storage==nil)
  a.redirect={}
  assert(s.returning_calls>0);s.returning_calls-=1;network_queue_changed_locked(s)
 }
 sync.unlock(&s.mu)
 if commit.kind!=.None {redirect_terminal(a,redirect_client_error(commit));return}
}
