package surf_async

import runtime_async "../../async"
import "core:crypto/x509"
import "core:fmt"
import "core:mem"
import "core:net"
import scopes "core:sync/budget"
import "core:testing"
import "core:time"

network_schema_normalize :: proc(input:Normalized_Config)->(Network_Config,Client_Error) {
 previous:=context
 context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous
 return network_config_normalize(input)
}
network_schema_base :: proc()->Normalized_Config {
 result,error:=config_normalize({});assert(error.kind==.None);return result
}
network_schema_reject :: proc(t:^testing.T,input:Normalized_Config) {
 result,error:=network_schema_normalize(input)
 testing.expect_value(t,error.kind,.Invalid_Config)
 testing.expect_value(t,result.task_count,0)
 testing.expect_value(t,result.state_bytes,0)
 testing.expect_value(t,result.actor_storage_bytes,0)
 testing.expect_value(t,result.request_storage_bytes,0)
 testing.expect_value(t,result.task_index_bytes,0)
 testing.expect_value(t,result.dns_storage_bytes,0)
 testing.expect_value(t,result.config.request_timeout,time.Duration(0))
 testing.expect_value(t,raw_data(result.config.http.resolver.name_servers),nil)
}

@(test)
network_schema_dns_intent_is_original_borrowed_policy :: proc(t:^testing.T) {
 input:=network_schema_base()
 result,error:=network_schema_normalize(input)
 testing.expect_value(t,error.kind,.None);testing.expect_value(t,result.dns_preparation,.System)
 testing.expect_value(t,result.task_count,9)
 testing.expect_value(t,result.resolver_limits,net.Resolver_Snapshot_Limits{256<<10,4<<10,1024,64<<10,8})
 servers:[9]net.Endpoint
 for &server in servers {server={net.IP4_Loopback,53}}
 servers[7]={net.IP6_Loopback,65535}
 for count in ([2]int{1,8}) {
  input.http.resolver.name_servers=servers[:count]
  result,error=network_schema_normalize(input)
  testing.expect_value(t,error.kind,.None);testing.expect_value(t,result.dns_preparation,.Explicit)
  testing.expect_value(t,raw_data(result.config.http.resolver.name_servers),raw_data(servers[:count]))
  testing.expect_value(t,len(result.config.http.resolver.name_servers),count)
  testing.expect_value(t,servers[0].port,53);testing.expect_value(t,servers[7].port,65535)
  input.capacities.dns_ids=0
  result,error=network_schema_normalize(input)
  testing.expect_value(t,error.kind,.None);testing.expect_value(t,result.dns_preparation,.Numeric_Only)
  testing.expect_value(t,result.dns_storage_bytes,0)
  testing.expect_value(t,raw_data(result.config.http.resolver.name_servers),raw_data(servers[:count]))
  input.capacities.dns_ids=256
 }
 input.http.resolver.name_servers=servers[:0]
 // Explicit-empty must reject BEFORE profile_init collapses empty views to nil.
 testing.expect(t,raw_data(input.http.resolver.name_servers)!=nil)
 network_schema_reject(t,input)
 input.capacities.dns_ids=0;network_schema_reject(t,input)
 input.http.resolver.name_servers=nil
 result,error=network_schema_normalize(input)
 testing.expect_value(t,error.kind,.None);testing.expect_value(t,result.dns_preparation,.Numeric_Only)
 input.capacities.dns_ids=256
 input.http.resolver.name_servers=servers[:]
 network_schema_reject(t,input)
 input.http.resolver.name_servers=servers[:1]
 for port in ([5]int{0,-1,65536,min(int),max(int)}) {
  servers[0].port=port;network_schema_reject(t,input)
 }
 servers[0].port=53;servers[0].address=nil;network_schema_reject(t,input)
 fmt.println("NETWORK_SCHEMA dns_intent_original=true explicit_empty_rejected_before_profile=true")
}

@(test)
network_schema_rejects_forged_normalization_and_invalid_redirect_policy :: proc(t:^testing.T) {
 for field in 0..<4 {
  for value in ([4]i64{0,-1,min(i64),max(i64)}) {
   input:=network_schema_base()
   switch field {
   case 0:input.request_timeout=time.Duration(value)
   case 1:input.response_body_limit=int(value)
   case 2:input.idle_timeout=time.Duration(value)
   case 3:input.max_age=time.Duration(value)
   }
   // Positive idle/age values are already valid normalization, even at max.
   if field>=2 && value==max(i64) {
    _,error:=network_schema_normalize(input);testing.expect_value(t,error.kind,.None)
   } else {network_schema_reject(t,input)}
  }
 }
 input:=network_schema_base();input.request_timeout+=1;network_schema_reject(t,input)
 input=network_schema_base();input.response_body_limit+=1;network_schema_reject(t,input)
 for redirects in 0..=5 {
  input=network_schema_base();input.http.max_redirects=redirects
  result,error:=network_schema_normalize(input);testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,result.config.http.max_redirects,redirects)
 }
 for redirects in ([3]int{-1,6,max(int)}) {
  input=network_schema_base();input.http.max_redirects=redirects;network_schema_reject(t,input)
 }
 input=network_schema_base();input.http.tls.alpn_protocols=[]string{"h3"};network_schema_reject(t,input)
 input=network_schema_base();input.http.timeout=-1;network_schema_reject(t,input)
 input=network_schema_base();input.lifetime={at=1};network_schema_reject(t,input)
}

@(test)
network_schema_descriptor_shapes_reject_before_borrowed_traversal :: proc(t:^testing.T) {
 cases:=0
 for length in ([3]int{-1,1,max(int)}) {
  for field in 0..<5 {
   input:=network_schema_base()
   switch field {
   case 0:(cast(^mem.Raw_Slice)&input.http.resolver.name_servers)^={data=nil,len=length}
   case 1:(cast(^mem.Raw_Slice)&input.http.tls.alpn_protocols)^={data=nil,len=length}
   case 2:(cast(^mem.Raw_Slice)&input.http.tls.root_cas)^={data=nil,len=length}
   case 3:(cast(^mem.Raw_String)&input.http.tls.server_name)^={data=nil,len=length}
   case 4:
    offer:string
    (cast(^mem.Raw_String)&offer)^={data=nil,len=length}
    offers:=[1]string{offer}
    input.http.tls.alpn_protocols=offers[:]
    network_schema_reject(t,input);cases+=1;continue
   }
   network_schema_reject(t,input);cases+=1
  }
 }
 testing.expect_value(t,cases,15)
 fmt.println("NETWORK_SCHEMA malformed_descriptor_cells=15 noalloc=true")
}

@(test)
network_schema_actual_owner_sizing_and_finite_dns_workspace_bounds :: proc(t:^testing.T) {
 for caps in ([3]Capacities{
  {1,1,1,1,0,0,1},
  {32,16,8,2,32,256,128},
  {4096,1024,256,256,4096,65536,4096},
 }) {
  input:=network_schema_base();input.capacities=caps
  result,error:=network_schema_normalize(input)
  testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,result.task_count,caps.connections+1)
  testing.expect_value(t,result.state_bytes,size_of(Client_State))
  testing.expect_value(t,result.actor_storage_bytes,caps.connections*size_of(Session_Actor))
  testing.expect_value(t,result.request_storage_bytes,caps.requests*size_of(Request_Network))
  testing.expect_value(t,result.task_index_bytes,(caps.connections+1)*size_of(^runtime_async.Task))
  testing.expect_value(t,result.dns_storage_bytes,caps.dns_ids*2)
 }
 for field in 0..<7 {
  for extreme in ([2]int{min(int),max(int)}) {
   input:=network_schema_base()
   fields:=[7]^int{&input.capacities.requests,&input.capacities.origins,&input.capacities.connections,
    &input.capacities.connections_per_origin,&input.capacities.waiters_per_origin,&input.capacities.dns_ids,&input.capacities.work_per_resume}
   fields[field]^=extreme;network_schema_reject(t,input)
  }
 }
 testing.expect_value(t,DNS_IDS_PER_QUERY,16);testing.expect_value(t,DNS_TOTAL_QUERY_LIMIT,32)
 testing.expect_value(t,DNS_MESSAGE_LIMIT,64);testing.expect_value(t,DNS_ROUNDS,2)
 testing.expect_value(t,DNS_ATTEMPT_TIMEOUT,time.Second)
 actor:=new(Session_Actor);defer free(actor)
 request:Request_Network;state:Client_State
 testing.expect_value(t,len(actor.dns_tx),4096);testing.expect_value(t,len(actor.dns_rx),4096)
 testing.expect_value(t,len(actor.dns_aliases),9);testing.expect_value(t,len(actor.dns_results),64)
 testing.expect_value(t,len(actor.dns_servers),8);testing.expect_value(t,len(actor.prepared_addresses),64)
 testing.expect_value(t,len(request.prepared_addresses),64);testing.expect_value(t,len(request.ids.values),16)
 testing.expect_value(t,state.references,u64(0));testing.expect_value(t,state.base_owned,false)
 testing.expect_value(t,state.registered_tasks,0);testing.expect_value(t,state.runtime,nil)
 testing.expect_value(t,state.coordinator.owner,nil);testing.expect_value(t,actor.owner,nil)
 testing.expect_value(t,actor.owner_drained,false)
 // Layout/defaults certify no construction, registration, DNS or lifecycle work.
 fmt.println("NETWORK_SCHEMA bounded_sizing_profiles=3 workspace_only=true native_execution=0")
}

@(test)
network_schema_borrows_policy_and_scope_without_retaining_or_admitting :: proc(t:^testing.T) {
 scope,cause:=scopes.create_root({bytes=0,streams=0,jobs=0},context.allocator);assert(cause==.None)
 defer scopes.release_scope(&scope)
 input:=network_schema_base();input.http.scope=scope
 roots:=[1]^x509.Certificate{nil};offers:=[1]string{"http/1.1"}
 input.http.tls.root_cas=roots[:];input.http.tls.alpn_protocols=offers[:]
 input.http.tls.server_name="borrowed.example"
 for closed in 0..<2 {
  if closed==1 {assert(scopes.close(scope)==.None)}
  before,_:=scopes.snapshot(scope)
  result,error:=network_schema_normalize(input)
  testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,result.config.http.scope,scope)
  testing.expect_value(t,raw_data(result.config.http.tls.root_cas),raw_data(roots[:]))
  testing.expect_value(t,raw_data(result.config.http.tls.alpn_protocols),raw_data(offers[:]))
  testing.expect_value(t,raw_data(result.config.http.tls.server_name),raw_data(input.http.tls.server_name))
  after,_:=scopes.snapshot(scope);testing.expect_value(t,after,before)
 }
 input.http.allocator_scope=scope;network_schema_reject(t,input)
}
