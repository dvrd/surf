package surf_async

import surf ".."
import runtime_async "../../async"
import adapter "../../async/connection"
import exchange_api "exchange"
import tls_api "core:crypto/tls"
import "core:net"
import "core:sync"

@(private)
session_close_done :: proc(op:^net.Async_Operation) {
 a:=cast(^Session_Actor)op.user_data
 a.close_done=true
 session_notify(a)
}
@(private)
session_mark_retiring :: proc(a:^Session_Actor) {
 if a.model.slot==0 {return}
 now,_:=network_clock(a.owner)
 k:=&a.owner.kernel
 sync.lock(&a.owner.mu);defer sync.unlock(&a.owner.mu)
 sync.lock(&k.mu)
 model:=pool_session_locked(k,a.model)
 state:=Session_State.Free
 if model!=nil {state=model.state}
 sync.unlock(&k.mu)
 if state==.Idle || state==.Connecting || state==.Busy {
  assert(pool_session_state(k,a.model,.Retiring,now.at).kind==.None)
 }
}

// Reset only a fully closed transport generation. Task, Signal, owner/index and
// the cross-thread mailbox and redirect custody MUST survive: coordinator may already have queued
// the next generation as soon as pool_retire made the model slot available.
@(private)
session_reset_io :: proc(a:^Session_Actor) {
 assert(exchange_api.exchange_reset(&a.exchange).kind==.None)
 network_dns_burn(a.owner,&a.ids)
 a.executor={};a.transport={};a.tls={};a.handshake={};a.close={};a.query={};a.dial={}
 a.cutoff={};a.setup_cutoff={};a.request={}
 a.prepared_address_count=0;a.prepared_address_at=0;a.dns_server_count=0
 a.secure=false;a.executor_initialized=false;a.transport_initialized=false;a.tls_initialized=false
 a.handshake_started=false;a.handshake_done=false;a.close_started=false;a.close_done=false
 a.error={}
}

@(private)
session_close_step :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 session_mark_retiring(a)
 // Consume only flags attached to this old generation before freeing its pool
 // model. Never clear a new pending assignment during I/O field reset.
 sync.lock(&a.owner.mu)
 if !a.command.pending {a.command.cancel=false;a.command.retire=false}
 sync.unlock(&a.owner.mu)
 _=runtime_async.close_dns_connect(&a.dial)
 _=runtime_async.close_dns(&a.query)
 if a.tls_initialized && a.handshake_started && !a.handshake_done {_=tls_api.async_cancel_handshake(&a.tls)}
 if a.transport_initialized && !a.close_started {
  stream:=adapter.stream(&a.transport)
  if a.tls_initialized {stream=tls_api.async_connection(&a.tls)}
  a.close={callback=session_close_done,user_data=a}
  error:=net.async_close(stream,&a.close)
  if error.kind==.None {a.close_started=true} else {
   // Owned validated streams normally accept exactly one close. Keep driving
   // the owner rather than treating a rejection as callback/FD retirement.
   adapter.abort(&a.executor)
   return .Yield
  }
 }
 if a.transport_initialized {
  if a.error.kind!=.None || session_stopping(a) {adapter.abort(&a.executor)}
  // Engine cancellation must also observe every app callback emitted by TLS
  // shutdown; a raw close alone is not permission to discard accepted buffers.
  if !exchange_api.exchange_quiescent(&a.exchange) {
   now,_:=network_clock(a.owner)
   result:=exchange_api.exchange_drive(&a.exchange,now.at,true,a.owner.config.config.capacities.work_per_resume)
   if a.error.kind==.None && result.error.kind!=.None {a.error=result.error}
  }
  if !a.close_done || !adapter.quiescent(&a.executor) || !exchange_api.exchange_quiescent(&a.exchange) {return .Waiting}
 }
 // Redirect begin happens only after actual old IO retirement, before normal
 // terminalization and before model retirement needs its request detached.
 if a.redirect.phase!=.Empty {redirect_closed_begin(a)}
 if a.request!=(Request_Handle{}) {
  response:surf.Response
  _=exchange_api.exchange_take(&a.exchange,&response)
  failure:=a.error
  if failure.kind==.None {failure={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation,write_effect=.Not_Sent}}
  if response.status>0 {failure.status=response.status;failure.write_effect=.Response_Received}
  if error:=network_assignment_finish(a,&response,failure);error.kind!=.None {
   surf.response_destroy(&response)
   return .Yield
  }
 }
 // All old application operations/interfaces are now retired. Reset BEFORE
 // releasing model capacity, but preserve its handle for final pool retirement.
 model:=a.model
 session_reset_io(a)
 if model.slot!=0 {
  if error:=pool_retire(&a.owner.kernel,model);error.kind!=.None {return .Yield}
 }
 a.model={}
 session_notify_coordinator(a)
 // No Waiting/Idle/Done path may strand an accepted Returning/Preparing hop.
 if a.redirect.phase!=.Empty {return redirect_closed_resolve(a)}
 if session_stopping(a) {a.owner_drained=true;a.phase=.Done;return .Done}
 a.phase=.Idle
 return .Waiting
}
