package surf_async

import runtime_async "../../async"
import adapter "../../async/connection"
import exchange_api "exchange"
import tls_api "core:crypto/tls"
import "core:net"
import "core:time"

@(private)
session_handshake_done :: proc(op:^tls_api.Async_Handshake_Operation) {
 a:=cast(^Session_Actor)op.user_data
 a.handshake_done=true
 session_notify(a)
}
@(private)
session_tls_begin :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 _,origin,borrow:=session_borrow(a)
 if borrow.kind!=.None {session_error(a,{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent});return .Yield}
 config:=a.owner.profile.config.http.tls;config.server_name=origin.host
 timeout:=config.handshake_timeout
 if timeout==0 {timeout=10*time.Second}
 now,clock:=network_clock(a.owner)
 if clock.kind!=.None {session_error(a,{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent});return .Yield}
 a.setup_cutoff.at=min(a.setup_cutoff.at,now.at+min(i64(timeout),max(i64)-now.at))
 if cap:=adapter.set_request_budget(&a.executor,a.setup_cutoff);cap.kind!=.None {session_error(a,session_runtime_error(cap,.TLS));return .Yield}
 if init:=tls_api.async_client(&a.tls,adapter.stream(&a.transport),adapter.executor(&a.executor),config,a.owner.resources.allocator);init!=.None {
  session_error(a,{kind=.TLS_Failed,tls_dial={kind=.Invalid_Config,config=init},phase=.TLS,write_effect=.Not_Sent});return .Yield
 }
 a.tls_initialized=true
 a.handshake={callback=session_handshake_done,user_data=a}
 if error:=tls_api.async_handshake(&a.tls,&a.handshake,adapter.wall_budget(&a.executor));error.kind!=.None {
  session_error(a,{kind=.TLS_Failed,transport=error,phase=.TLS,write_effect=.Not_Sent});return .Yield
 }
 a.handshake_started=true;a.phase=.Handshaking
 return .Yield
}
@(private)
session_tls_step :: proc(a:^Session_Actor,now:runtime_async.Deadline)->runtime_async.Resume_Result {
 if !session_before_http(a,now) {return .Yield}
 if now.at>=a.setup_cutoff.at {session_error(a,{kind=.Deadline_Failed,phase=.Deadline,transport={kind=.Timeout},write_effect=.Not_Sent});return .Yield}
 if !a.handshake_done {return .Waiting}
 if a.handshake.err.kind!=.None {
  session_error(a,{kind=.TLS_Failed,transport=a.handshake.err,tls_dial={kind=.Handshake_Failed,handshake=a.handshake.result},tls_io=tls_api.async_failure(&a.tls),phase=.TLS,write_effect=.Not_Sent});return .Yield
 }
 state:=tls_api.async_idle_state(&a.tls)
 if state==.Busy {return .Yield}
 if state!=.Ready {session_error(a,{kind=.TLS_Failed,tls_io={kind=.Invalid_State},phase=.TLS,write_effect=.Not_Sent});return .Yield}
 // No handshake callback/accepted raw slot can be rebudgeted while live.
 cap:=adapter.set_request_budget(&a.executor,a.cutoff)
 if cap.kind==.Task_Busy {return .Yield}
 if cap.kind!=.None {session_error(a,session_runtime_error(cap,.TLS));return .Yield}
 return session_begin_exchange(a,true)
}

@(private)
session_reuse :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 if !exchange_api.exchange_quiescent(&a.exchange) {session_error(a,{kind=.IO_Failed,transport={kind=.Protocol_Failed},phase=.Protocol,write_effect=.Not_Sent});return .Yield}
 if a.secure && tls_api.async_idle_state(&a.tls)!=.Ready {session_error(a,{kind=.IO_Failed,transport={kind=.Protocol_Failed},phase=.Protocol,write_effect=.Not_Sent});return .Yield}
 if cap:=adapter.set_request_budget(&a.executor,a.cutoff);cap.kind!=.None {session_error(a,session_runtime_error(cap,.TLS));return .Yield}
 observed,error:=adapter.probe_stream(&a.transport)
 if error.kind!=.None {session_error(a,session_runtime_error(error,.Read));return .Yield}
 if observed!=.Empty {
  session_error(a,{kind=.IO_Failed,transport={kind=.Peer_Closed if observed==.Closed else .Protocol_Failed},phase=.Read,write_effect=.Not_Sent});return .Yield
 }
 return session_begin_exchange(a,false)
}
@(private)
session_begin_exchange :: proc(a:^Session_Actor,fresh:bool)->runtime_async.Resume_Result {
 request,_,borrow:=session_borrow(a)
 if borrow.kind!=.None {session_error(a,{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent});return .Yield}
 now,clock:=network_clock(a.owner)
 if clock.kind!=.None || !session_before_http(a,now) {return .Yield}
 if !a.secure {
  cap:=adapter.set_request_budget(&a.executor,a.cutoff)
  if cap.kind==.Task_Busy {return .Yield}
  if cap.kind!=.None {session_error(a,session_runtime_error(cap,.TLS));return .Yield}
 }
 if fresh {if error:=pool_session_state(&a.owner.kernel,a.model,.Busy,now.at);error.kind!=.None {session_error(a,{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent});return .Yield}}
 stream:=adapter.stream(&a.transport)
 if a.secure {stream=tls_api.async_connection(&a.tls)}
 budget:=exchange_api.Budget{at=a.cutoff.at,wall=adapter.wall_budget(&a.executor)}
 if error:=exchange_api.exchange_begin(&a.exchange,stream,request,budget,{data=a,wake=session_notify});error.kind!=.None {
  session_error(a,error);return .Yield
 }
 a.phase=.Exchanging
 return .Yield
}
