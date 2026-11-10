package surf_async

import surf ".."
import runtime_async "../../async"
import "core:sync"

@(private)
redirect_status_error :: proc(error:surf.HTTP_Error,status:int)->surf.HTTP_Error {
 result:=error
 if result.status==0 {result.status=status}
 if status!=0 && result.write_effect==.Not_Sent {result.write_effect=.Response_Received}
 return result
}

// Match Root's logical-request error context: never replace Unknown from an
// ambiguous later-hop write merely because an earlier response was received.
@(private)
redirect_error_context :: proc(a:^Session_Actor,error:surf.HTTP_Error)->surf.HTTP_Error {
 status:=0
 h:=a.request
 if a.redirect.phase==.Ready {
  status=a.redirect.last_status
  if h==(Request_Handle{}) {h=a.redirect.request}
 }
 if status==0 && h!=(Request_Handle{}) {
  s:=a.owner
  sync.lock(&s.mu)
  if h.owner_id==s.kernel.owner_id && h.slot>0 && u64(h.slot)<=u64(len(s.requests)) {
   metadata:=&s.requests[int(h.slot)-1]
   if metadata.generation==h.generation {status=metadata.last_status}
  }
  sync.unlock(&s.mu)
 }
 return redirect_status_error(error,status)
}

@(private)
redirect_client_error :: proc(error:Client_Error)->surf.HTTP_Error {
 if error.http.kind!=.None {return error.http}
 if error.kind==.Closed {return {kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
 // HTTP_Error has no local admission Capacity category. Initial submission
 // returns Client_Error.Capacity; an accepted target reports only the honest
 // broad inability to establish that hop, without inventing OOM/Scope causes.
 if error.kind==.Capacity {return {kind=.Dial_Failed,phase=.Connect,write_effect=.Not_Sent}}
 if error.kind==.Runtime_Error {return session_runtime_error(error.runtime,.Connect)}
 return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}
}

// Return true only when this response is consumed by redirect processing.
// A disabled policy returns the original successful3xx to its caller unchanged.
@(private)
redirect_response :: proc(a:^Session_Actor,response:^surf.Response)->bool {
 if a.owner.config.config.http.max_redirects==0 {return false}
 status:=response.status
 if status!=301 && status!=302 && status!=303 && status!=307 && status!=308 {return false}
 s:=a.owner
 sync.lock(&s.mu)
 metadata:=s.requests[int(a.request.slot)-1]
 sync.unlock(&s.mu)
 current,_,borrow:=session_borrow(a)
 cause:=borrow
 if metadata.generation!=a.request.generation {cause={kind=.Invalid_State}}
 if cause.kind==.None {
  cause=redirect_prepare(&a.redirect,&s.profile,a.request,current,response,metadata.redirects,metadata.query_budget_left,s.resources.allocator)
 }
 // Preflight errors can preserve Response ownership; every handled path must
 // dispose any remainder before its next fresh deadline/cancellation barrier.
 surf.response_destroy(response)
 if cause.kind!=.None {
  session_error(a,redirect_status_error(redirect_client_error(cause),status));return true
 }
 now,clock:=network_clock(s)
 if clock.kind!=.None {session_error(a,redirect_client_error(clock));return true}
 if failure:=redirect_live_error(a,a.redirect.request,now);failure.kind!=.None {session_error(a,failure);return true}
 // Even same-origin redirects retire the old physical stream before requeue.
 a.phase=.Retiring
 return true
}

// Called only after old close/app callbacks and adapter quiescence. On Begin
// rejection the old request remains Active and normal closed-stream completion
// handles it. On success the handoff becomes its sole actor custody across reset.
@(private)
redirect_closed_begin :: proc(a:^Session_Actor) {
 if a.redirect.phase!=.Ready {return}
 s:=a.owner;h:=a.redirect.request;status:=a.redirect.last_status
 if a.request==(Request_Handle{}) {return} // Begin already owns Returning.
 assert(a.request==h)
 primary:=a.error
 now,clock:=network_clock(s)
 if primary.kind==.None && clock.kind!=.None {primary=redirect_client_error(clock)}
 disposal:Request_Disposal
 if primary.kind==.None {
  sync.lock(&s.mu)
  next,cause:=kernel_redirect_begin(&s.kernel,h,now)
  if cause.kind==.None {
   disposal=next;s.returning_calls+=1;network_queue_forget_locked(s,h);a.request={}
  } else {primary=redirect_client_error(cause)}
  sync.unlock(&s.mu)
 }
 if primary.kind!=.None {
  primary=redirect_status_error(primary,status)
  redirect_handoff_destroy(&a.redirect)
  session_error(a,primary)
  return
 }
 redirect_dispose(s,&disposal)
}

// After old model retirement, all remaining ledger and physical cleanup is
// synchronous and bounded by the owned input/origin limits. Keep running until
// the accepted request is Queued or Completed, including global close paths.
@(private)
redirect_closed_resolve :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 assert(a.redirect.phase==.Ready && a.request==(Request_Handle{}) && a.model.slot==0)
 redirect_requeue(a)
 assert(a.redirect.phase==.Empty)
 session_notify_coordinator(a)
 if session_stopping(a) {a.owner_drained=true;a.phase=.Done;return .Done}
 a.phase=.Idle
 return .Yield
}
