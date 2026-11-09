package surf_async

import surf ".."
import runtime_async "../../async"
import adapter "../../async/connection"
import "core:net"
import "core:strings"
import "core:sync"

@(private)
session_dns_error :: proc(error:runtime_async.DNS_Error)->surf.HTTP_Error {
 result:=surf.HTTP_Error{kind=.Dial_Failed,phase=.DNS,write_effect=.Not_Sent,network=net.Resolve_Error.Unable_To_Resolve}
 if error.cause.network_cause!=nil {result.network=error.cause.network_cause}
 if error.cause.allocation_cause!=nil {return {kind=.Allocation_Failed,allocation=error.cause.allocation_cause,phase=.DNS,write_effect=.Not_Sent}}
 if error.status==.Timeout || error.cause.kind==.Timeout {return {kind=.Deadline_Failed,phase=.Deadline,write_effect=.Not_Sent,transport={kind=.Timeout}}}
 if error.status==.Cancelled || error.cause.kind==.Cancelled {return {kind=.IO_Failed,phase=.Cancellation,write_effect=.Not_Sent,transport={kind=.Cancelled}}}
 return result
}
@(private)
session_dns_block :: proc(a:^Session_Actor)->bool {
 s:=a.owner
 sync.lock(&s.mu)
 metadata:=&s.requests[int(a.request.slot)-1]
 remaining:=metadata.query_budget_left
 if metadata.generation!=a.request.generation {remaining=0}
 sync.unlock(&s.mu)
 if remaining<=0 {return false}
 block,error:=network_dns_reserve(s,min(DNS_IDS_PER_QUERY,remaining))
 if error.kind!=.None {return false}
 sync.lock(&s.mu)
 metadata=&s.requests[int(a.request.slot)-1]
 valid:=metadata.generation==a.request.generation && metadata.query_budget_left>=block.count
 if valid {metadata.query_budget_left-=block.count}
 sync.unlock(&s.mu)
 if !valid {network_dns_burn(s,&block);return false}
 a.ids=block
 return true
}
@(private)
session_query_begin :: proc(a:^Session_Actor,host:string,port:int,family:runtime_async.DNS_Family)->runtime_async.DNS_Error {
 s:=a.owner
 config:=runtime_async.DNS_Config{nameservers=a.dns_servers[:a.dns_server_count],ids=a.ids.values[:a.ids.count],
  max_queries=a.ids.count,rounds=DNS_ROUNDS,attempt_timeout=DNS_ATTEMPT_TIMEOUT,max_messages=DNS_MESSAGE_LIMIT}
 workspace:=runtime_async.DNS_Workspace{tx=a.dns_tx[:],rx=a.dns_rx[:],aliases=a.dns_aliases[:],results=a.dns_results[:]}
 error:=runtime_async.begin_dns(s.runtime,&a.task,&a.query,host,port,family,config,workspace,a.setup_cutoff)
 if error.status!=.Success {return error}
 return runtime_async.begin_dns_connect(&a.dial,&a.query)
}
@(private)
session_numeric_begin :: proc(a:^Session_Actor)->runtime_async.DNS_Error {
 endpoint:=a.prepared_addresses[a.prepared_address_at]
 storage:[64]u8
 builder:=strings.builder_from_bytes(storage[:])
 text:=net.address_to_string(endpoint.address,&builder)
 if text=="" {return {status=.Invalid_Config}}
 // begin_dns copies the numeric address into exclusive actor workspace before
 // this stack string dies. DNS_Connect then performs actual nonblocking TCP.
 return session_query_begin(a,text,endpoint.port,.Both_A_First)
}

@(private)
session_dial_begin :: proc(a:^Session_Actor)->runtime_async.Resume_Result {
 _,origin,borrow:=session_borrow(a)
 if borrow.kind!=.None {session_error(a,{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent});return .Yield}
 if a.prepared_address_count>0 {
  error:=session_numeric_begin(a)
  if error.status!=.Success {session_error(a,session_dns_error(error));return .Yield}
  a.phase=.Connecting;return .Yield
 }
 servers,ready:=net.resolver_snapshot_name_servers(&a.owner.resolver)
 if !ready || len(servers)==0 || a.ids.count==0 {session_error(a,{kind=.Dial_Failed,phase=.DNS,network=net.Resolve_Error.Unable_To_Resolve,write_effect=.Not_Sent});return .Yield}
 a.dns_server_count=copy(a.dns_servers[:],servers)
 error:=session_query_begin(a,origin.host,int(origin.port),.A_Only)
 if error.status!=.Success {session_error(a,session_dns_error(error));return .Yield}
 a.phase=.Resolving_A;return .Yield
}

@(private)
session_dial_step :: proc(a:^Session_Actor,now:runtime_async.Deadline)->runtime_async.Resume_Result {
 if !session_before_http(a,now) {return .Yield}
 if now.at>=a.setup_cutoff.at {session_error(a,{kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline,write_effect=.Not_Sent});return .Yield}
 socket,status,error:=runtime_async.finish_dns_connect(&a.dial)
 if status!=.Done {return status}
 _=runtime_async.close_dns_connect(&a.dial);_=runtime_async.close_dns(&a.query)
 network_dns_burn(a.owner,&a.ids)
 if error.status!=.Success {
  if a.phase==.Connecting && a.prepared_address_at+1<a.prepared_address_count && error.status!=.Timeout && error.status!=.Cancelled {
   a.prepared_address_at+=1;a.query={};a.dial={}
   if next:=session_numeric_begin(a);next.status==.Success {return .Yield} else {error=next}
  } else if a.phase==.Resolving_A && error.status!=.Timeout && error.status!=.Cancelled && error.status!=.Limit && session_dns_block(a) {
   _,origin,borrow:=session_borrow(a)
   if borrow.kind==.None {
    a.query={};a.dial={}
    next:=session_query_begin(a,origin.host,int(origin.port),.AAAA_Only)
    if next.status==.Success {a.phase=.Resolving_AAAA;return .Yield}
    error=next
   }
  }
  session_error(a,session_dns_error(error));return .Yield
 }
 // Socket ownership transfers immediately into the actor's adapter; no raw
 // Socket needs to be retained in the frozen actor schema.
 if init:=adapter.init_executor(&a.executor,a.owner.runtime,&a.task,a.owner.config.config.lifetime);init.kind!=.None {
  _=runtime_async.close(socket);session_error(a,session_runtime_error(init,.Connect));return .Yield
 }
 a.executor_initialized=true
 if init:=adapter.init_transport(&a.transport,&a.executor,socket);init.kind!=.None {
  _=runtime_async.close(socket);session_error(a,session_runtime_error(init,.Connect));return .Yield
 }
 a.transport_initialized=true
 if cap:=adapter.set_request_budget(&a.executor,a.setup_cutoff);cap.kind!=.None {session_error(a,session_runtime_error(cap,.Connect));return .Yield}
 if a.secure {return session_tls_begin(a)}
 return session_begin_exchange(a,true)
}
