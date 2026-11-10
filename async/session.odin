package surf_async

import surf ".."
import http "../../http"
import runtime_async "../../async"
import adapter "../../async/connection"
import signal "../../async/signal"
import exchange_api "exchange"
import tls_api "core:crypto/tls"
import "core:net"
import "core:sync"

@(private)
session_valid :: proc(a:^Session_Actor)->bool {
 return a!=nil && network_valid(a.owner) && a.index!=0 && u64(a.index)<=u64(len(a.owner.actors)) && a==&a.owner.actors[int(a.index)-1]
}
@(private)
session_notify :: proc(data:rawptr) {a:=cast(^Session_Actor)data;_=signal.wake(a.wake)}
@(private)
session_notify_coordinator :: proc(a:^Session_Actor) {_=signal.wake(a.owner.coordinator.wake)}
@(private)
session_borrow :: proc(a:^Session_Actor)->(http.Request,Origin_Key,Client_Error) {
 s:=a.owner
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 sync.lock(&s.kernel.mu);defer sync.unlock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,a.request)
 if request==nil || request.state!=.Active || request.session!=a.model {return {},{},{kind=.Invalid_Handle}}
 origin:=admission_origin_locked(&s.kernel,request.origin)
 if origin==nil {return {},{},{kind=.Invalid_State}}
 return request.input.request,origin.owner.key,{}
}
@(private)
session_stopping :: proc(a:^Session_Actor)->bool {
 s:=a.owner
 sync.lock(&s.mu);closing:=s.phase==.Closing || s.phase==.Disposing;sync.unlock(&s.mu)
 return closing || runtime_async.cancelled(&a.task)
}
@(private)
session_cancelled :: proc(a:^Session_Actor)->bool {
 s:=a.owner
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 if s.phase==.Closing || s.phase==.Disposing || a.command.cancel || a.command.retire {return true}
 if a.request==(Request_Handle{}) {return false}
 sync.lock(&s.kernel.mu);defer sync.unlock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,a.request)
 return request==nil || request.cancel_requested || s.kernel.closed
}
@(private)
session_runtime_error :: proc(error:runtime_async.Error,phase:surf.HTTP_Phase)->surf.HTTP_Error {
 if error.kind==.Timeout {return {kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline,write_effect=.Not_Sent}}
 if error.kind==.Cancelled || error.kind==.Stopping {return {kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
 if error.allocation_cause!=nil {return {kind=.Allocation_Failed,allocation=error.allocation_cause,phase=phase,write_effect=.Not_Sent}}
 if error.network_cause!=nil {return {kind=.IO_Failed,network=error.network_cause,phase=phase,write_effect=.Not_Sent}}
 if error.kind==.Closed || error.kind==.Peer_Closed {return {kind=.IO_Failed,transport={kind=.Peer_Closed},phase=phase,write_effect=.Not_Sent}}
 if error.kind==.Task_Busy || error.kind==.Pending {return {kind=.IO_Failed,transport={kind=.Operation_Pending},phase=phase,write_effect=.Not_Sent}}
 return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}
}
@(private)
session_error :: proc(a:^Session_Actor,error:surf.HTTP_Error) {
 if a.error.kind==.None {a.error=redirect_error_context(a,error)}
 a.phase=.Retiring
}
@(private)
session_before_http :: proc(a:^Session_Actor,now:runtime_async.Deadline)->bool {
 if session_cancelled(a) || runtime_async.cancelled(&a.task) {
  session_error(a,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent});return false
 }
 if now.at>=a.cutoff.at {
  session_error(a,{kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline,write_effect=.Not_Sent});return false
 }
 return true
}

// A pending mailbox can already represent an Active Kernel assignment even if
// the actor never took it. Cancellation must complete that handle without I/O.
@(private)
session_take_cancelled_mailbox :: proc(a:^Session_Actor) {
 s:=a.owner
 sync.lock(&s.mu)
 if a.request!=(Request_Handle{}) || !a.command.pending {sync.unlock(&s.mu);return}
 assignment:=a.command.assignment
 sync.lock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,assignment.request)
 if request!=nil && request.state==.Active && request.session==assignment.session && assignment.session.slot==a.index {
  a.request=assignment.request;a.model=assignment.session;a.cutoff=request.deadline
  a.command.pending=false
 }
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
}

network_assignment_finish :: proc(a:^Session_Actor,response:^surf.Response,error:surf.HTTP_Error)->Client_Error {
 if !session_valid(a) || a.request==(Request_Handle{}) || response==nil {return {kind=.Invalid_State}}
 s:=a.owner;handle:=a.request
 sync.lock(&s.mu)
 sync.lock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,handle)
 returning:=request!=nil && request.state==.Returning && request.returning_to==.Completed
 sync.unlock(&s.kernel.mu)
 disposal:Request_Disposal
 if !returning {
  // Terminal metadata cleanup is one transaction with begin-complete. An
  // untaken mailbox may still own a reserved DNS block in Request_Network.
  next,cause:=kernel_begin_complete(&s.kernel,handle,response,error)
  if cause.kind!=.None {sync.unlock(&s.mu);return cause}
  disposal=next
  network_queue_forget_locked(s,handle)
  s.returning_calls+=1
 }
 sync.unlock(&s.mu)
 for {
  origin:=disposal.origin.origin
  request_disposal_destroy(&disposal)
  if origin.slot!=0 {if cleanup:=kernel_origin_cleanup_finish(&s.kernel,origin);cleanup.kind!=.None {return cleanup}}
  now,clock:=network_clock(s)
  if clock.kind!=.None {return clock}
  // A late failure can have detached the successful Response on a previous
  // resume. It stays Returning until the physical transport is retired.
  sync.lock(&s.kernel.mu)
  current:=admission_request_locked(&s.kernel,handle)
  failure:surf.HTTP_Error
  if current!=nil && current.state==.Returning {failure=current.error}
  sync.unlock(&s.kernel.mu)
  if failure.kind!=.None && a.transport_initialized && !a.close_done {
   if a.error.kind==.None {a.error=failure}
   a.phase=.Retiring;return {kind=.Pending}
  }
  next,done,finish:=kernel_cleanup_finish(&s.kernel,handle,now)
  if finish.kind!=.None {return finish}
  if !done {
   // Destroy the returned move-owning disposal synchronously. Only the Kernel
   // Returning ticket/error/ref persists across the asynchronous close.
   request_disposal_destroy(&next)
   sync.lock(&s.kernel.mu)
   current=admission_request_locked(&s.kernel,handle)
   failure={}
   if current!=nil {failure=current.error}
   sync.unlock(&s.kernel.mu)
   if a.error.kind==.None {a.error=failure}
   if a.transport_initialized && !a.close_done {a.phase=.Retiring;return {kind=.Pending}}
   disposal={};continue
  }
  break
 }
 sync.lock(&s.mu)
 assert(s.returning_calls>0);s.returning_calls-=1
 network_queue_changed_locked(s)
 sync.unlock(&s.mu)
 a.request={}
 session_notify_coordinator(a)
 return {}
}

@(private)
session_assign :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 snapshot,error:=network_assignment_take(a)
 if error.kind!=.None {
  if error.kind==.Pending {return .Waiting}
  session_take_cancelled_mailbox(a)
  if a.request!=(Request_Handle{}) {
   failure:=error.http
   if failure.kind==.None {failure={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
   session_error(a,failure);return .Yield
  }
  return .Waiting
 }
 a.request=snapshot.assignment.request;a.model=snapshot.assignment.session
 a.cutoff=snapshot.cutoff;a.setup_cutoff=snapshot.setup_cutoff;a.secure=snapshot.secure
 a.ids=snapshot.ids;a.prepared_addresses=snapshot.addresses;a.prepared_address_count=snapshot.address_count;a.prepared_address_at=0
 // A waiter may have reserved IDs before a healthy Idle became available.
 // Reuse needs no query; burn that moved block instead of overwriting it later.
 if a.transport_initialized {network_dns_burn(a.owner,&a.ids)}
 a.error={};a.phase=.Assigned
 return .Yield
}

@(private)
session_exchange_step :: proc(a:^Session_Actor,now:runtime_async.Deadline)->runtime_async.Resume_Result {
 if a.stream_exchange!=nil {return session_stream_step(a,now)}
 // The selected absolute cutoff has priority once expired. Let the Engine
 // classify Deadline with its received status and write-effect context.
 cancelled:=(session_cancelled(a) || runtime_async.cancelled(&a.task)) && now.at<a.cutoff.at
 result:=exchange_api.exchange_drive(&a.exchange,now.at,cancelled,a.owner.config.config.capacities.work_per_resume)
 if result.error.kind!=.None {
  error:=result.error
  if a.tls_initialized {error.tls_io=tls_api.async_failure(&a.tls)}
  session_error(a,error);return .Yield
 }
 if result.status!=.Done {return .Waiting if result.status==.Waiting else .Yield}
 response:surf.Response
 if error:=exchange_api.exchange_take(&a.exchange,&response);error.kind!=.None {session_error(a,error);return .Yield}
 // A full buffered response is not permission to publish after a late owner
 // cancellation, monotonic timeout or synchronous allocator callback.
 fresh,clock:=network_clock(a.owner)
 failure:surf.HTTP_Error
 if clock.kind!=.None {failure={kind=.Invalid_Config,phase=.Configuration}} else {
  if session_cancelled(a) || runtime_async.cancelled(&a.task) {failure={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}}
  if failure.kind==.None {if budget:=adapter.budget_error(&a.executor);budget.kind!=.None {failure=surf.http_error_classify({kind=.IO_Failed,transport=budget},.Read,.Response_Received,response.status)}}
  if failure.kind==.None && fresh.at>=a.cutoff.at {failure={kind=.Deadline_Failed,phase=.Deadline}}
 }
 if failure.kind!=.None {
  failure.status=response.status;failure.write_effect=.Response_Received
  surf.response_destroy(&response)
  session_error(a,failure);return .Yield
 }
 if redirect_response(a,&response) {return .Yield}
 if error:=network_assignment_finish(a,&response,{});error.kind!=.None {
  surf.response_destroy(&response);session_error(a,{kind=.Invalid_Config,phase=.Configuration});return .Yield
 }
 if reset:=exchange_api.exchange_reset(&a.exchange);reset.kind!=.None {session_error(a,reset);return .Yield}
 return session_finish_reuse(a,result.reuse_eligible)
}

@(private)
session_finish_reuse :: proc(a:^Session_Actor,eligible:bool)->runtime_async.Resume_Result {
 reusable:=eligible && !session_stopping(a) && !session_cancelled(a)
 if reusable && a.secure {reusable=tls_api.async_idle_state(&a.tls)==.Ready}
 if reusable {reusable=adapter.set_request_budget(&a.executor,a.cutoff).kind==.None}
 if reusable {
  observation,error:=adapter.probe_stream(&a.transport)
  reusable=error.kind==.None && observation==.Empty
 }
 if reusable {
  now,_:=network_clock(a.owner)
  sync.lock(&a.owner.mu)
  idle:=a.owner.phase==.Published && !a.command.cancel && !a.command.retire
  if idle {idle=pool_session_state(&a.owner.kernel,a.model,.Idle,now.at).kind==.None}
  if idle {a.phase=.Idle}
  sync.unlock(&a.owner.mu)
  if idle {session_notify_coordinator(a);return .Waiting}
 }
 a.phase=.Retiring;return .Yield
}

network_session_resume :: proc(data:rawptr)->runtime_async.Resume_Result {return session_resume(cast(^Session_Actor)data,false)}
network_session_cancel :: proc(data:rawptr)->runtime_async.Resume_Result {return session_resume(cast(^Session_Actor)data,true)}

// Owner-thread observation after provider jobs have run. Public readers touch
// only this synchronized Kernel metadata, never TLS/Exchange/actor internals.
// Returning/Preparing redirect tickets retain the ledger's Redirecting stage.
@(private)
session_publish_stage :: proc(a:^Session_Actor) {
 h:=a.request
 if h==(Request_Handle{}) {return}
 stage:Request_Stage
 switch a.phase {
 case .Assigned:
  stage=.Writing if a.transport_initialized else .Connecting
 case .Resolving_A,.Resolving_AAAA,.Connecting:stage=.Connecting
 case .Handshaking:stage=.Handshaking
 case .Exchanging:
  phase,valid:=exchange_api.exchange_phase(&a.exchange)
  if a.stream_exchange!=nil {phase,valid=exchange_api.exchange_phase(&a.stream_exchange.base)}
  if !valid {return}
  switch phase {
  case .Writing_Head,.Writing_Body:stage=.Writing
  case .Reading_Head,.Copying_Head,.Reading_Body:stage=.Reading
  case .Draining,.Done:stage=.Retiring
  case .Idle:return
  }
 case .Retiring:stage=.Retiring
 case .Prepared,.Idle,.Done:return
 }
 s:=a.owner
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,h)
 model:=pool_session_locked(&s.kernel,a.model)
 if request!=nil && request.state==.Active && request.session==a.model && a.model.slot==a.index &&
    model!=nil && model.request==h {
  request.stage=stage
 }
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
}

@(private)
session_resume :: proc(a:^Session_Actor,force:bool)->runtime_async.Resume_Result {
 if !session_valid(a) {return .Done}
 // DNS/TCP state is thread-confined too: pin before its first operation,
 // rather than waiting until a later successful adapter initialization.
 _,pin:=runtime_async.pin_current_task()
 assert(pin.kind==.None)
 if force {
  network_close_state(a.owner)
 }
 now,clock:=network_clock(a.owner)
 // Registered actor ownership pins the Runtime clock witness until on_done.
 // Losing it cannot certify physical I/O drainage.
 assert(clock.kind==.None)
 lifetime:=a.owner.config.config.lifetime
 if lifetime.epoch!=0 && now.at>=lifetime.at {
  network_close_state(a.owner)
  if a.request!=(Request_Handle{}) && a.phase!=.Exchanging {
   session_error(a,{kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline,write_effect=.Not_Sent})
  }
 }
 stopping:=force || session_stopping(a)
 if a.phase!=.Exchanging && a.phase!=.Retiring && a.phase!=.Done && (stopping || session_cancelled(a)) {
  session_take_cancelled_mailbox(a)
  if a.request!=(Request_Handle{}) {session_error(a,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent})} else {a.phase=.Retiring}
 }
 result:runtime_async.Resume_Result
 switch a.phase {
 case .Prepared,.Idle:
  sync.lock(&a.owner.mu);pending:=a.command.pending;retire:=a.command.retire;sync.unlock(&a.owner.mu)
  if pending {result=session_assign(a)} else if retire || stopping {a.phase=.Retiring;result=.Yield} else {a.phase=.Idle;result=.Waiting}
 case .Assigned:
  if !session_before_http(a,now) {result=.Yield} else if a.transport_initialized {result=session_reuse(a)} else {result=session_dial_begin(a)}
 case .Resolving_A,.Resolving_AAAA,.Connecting:result=session_dial_step(a,now)
 case .Handshaking:result=session_tls_step(a,now)
 case .Exchanging:result=session_exchange_step(a,now)
 case .Retiring:result=session_close_step(a)
 case .Done:a.owner_drained=true;return .Done
 }
 // Once Idle, do not run the expired PREVIOUS request cap. A future request
 // installs its own cap before any drive/write. Closing runs through callbacks.
 if a.executor_initialized && a.transport_initialized && a.phase!=.Idle && a.phase!=.Done {
  driven:=adapter.drive(&a.executor)
  if driven==.Yield {result=.Yield}
 }
 session_publish_stage(a)
 return result
}
network_session_done :: proc(data:rawptr) {
 a:=cast(^Session_Actor)data
 if !session_valid(a) {return}
 s,index,drained:=a.owner,int(a.index),a.owner_drained
 network_task_done(s,index,drained)
}
