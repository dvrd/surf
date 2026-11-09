package surf_async

import runtime_async "../../async"
import signal "../../async/signal"
import tls "core:crypto/tls"
import "core:mem"
import "core:sync"

@(private)
client_enter :: proc(c:^Client)->(^Client_State,Client_Error) {
 if c==nil || c._self!=c || c._state==nil {return nil,{kind=.Invalid_State}}
 s:=cast(^Client_State)c._state
 if !network_state_retain(s) {return nil,{kind=.Closed}}
 sync.lock(&s.mu)
 if s.phase==.Disposing || s.producer_calls==max(int) {
  sync.unlock(&s.mu);network_state_release(s);return nil,{kind=.Closed}
 }
 s.producer_calls+=1
 sync.unlock(&s.mu)
 return s,{}
}
@(private)
client_leave :: proc(s:^Client_State) {
 sync.lock(&s.mu);assert(s.producer_calls>0);s.producer_calls-=1;sync.unlock(&s.mu)
 // Closing coordinator may be waiting for this producer's physical disposal.
 _=signal.wake(s.coordinator.wake)
 network_state_release(s)
}

client_init :: proc(c:^Client,runtime:^runtime_async.Runtime,config:Client_Config,allocator:mem.Allocator)->Client_Error {
 if c==nil || c._self!=nil || c._state!=nil {return {kind=.Invalid_State}}
 servers:=config.http.resolver.name_servers
 roots:=config.http.tls.root_cas
 offers:=config.http.tls.alpn_protocols
 name:=config.http.tls.server_name
 if len(servers)<0 || len(servers)>MAX_NAME_SERVERS || len(servers)>0 && raw_data(servers)==nil ||
    len(roots)<0 || len(roots)>0 && raw_data(roots)==nil ||
    len(offers)<0 || len(offers)>tls.MAX_ALPN_PROTOCOLS || len(offers)>0 && raw_data(offers)==nil ||
    len(name)<0 || len(name)>0 && raw_data(name)==nil {return {kind=.Invalid_Config}}
 for offer in offers {if len(offer)<0 || len(offer)>0 && raw_data(offer)==nil {return {kind=.Invalid_Config}}}
 normalized,error:=config_normalize(config)
 if error.kind!=.None {return error}
 // Own the original public address before even Query_Features can execute an
 // arbitrary allocator callback. The marker exposes no partially built State.
 c._self=c
 s,prepare:=network_prepare(runtime,normalized,allocator)
 if prepare.kind!=.None {c^={};return prepare}
 s.coordinator.task={resume=network_coordinator_resume,on_cancel=network_coordinator_cancel,on_done=network_coordinator_done,data=&s.coordinator}
 for &actor in s.actors {
  actor.task={resume=network_session_resume,on_cancel=network_session_cancel,on_done=network_session_done,data=&actor}
 }
 // Every callback target, Signal and registered reference exists before the
 // atomic scheduler publication; no fallible allocation follows publication.
 sync.lock(&s.mu)
 s.references+=u64(len(s.task_index));s.registered_tasks=len(s.task_index)
 s.coordinator.registered=true
 for &actor in s.actors {actor.registered=true}
 sync.unlock(&s.mu)
 registration:=runtime_async.register_group(runtime,s.task_index)
 if registration.kind!=.None {
  sync.lock(&s.mu)
  s.references-=u64(len(s.task_index));s.registered_tasks=0
  s.coordinator.registered=false
  for &actor in s.actors {actor.registered=false}
  sync.unlock(&s.mu)
  // A final backing callback may physically free this public header. Publish
  // failure first, then use only detached State and scalar error locals.
  c^={}
  assert(network_dispose_prepared(s).kind==.None)
  return {kind=.Runtime_Error,runtime=registration}
 }
 sync.lock(&s.mu)
 if s.phase==.Constructing {s.phase=.Published}
 sync.unlock(&s.mu)
 c^={_self=c,_state=s}
 _=signal.wake(s.coordinator.wake)
 return {}
}
