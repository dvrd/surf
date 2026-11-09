package surf_async

import runtime_async "../../async"
import signal "../../async/signal"
import exchange_api "exchange"
import charged "core:mem/budget"
import "core:mem"
import "core:net"
import "core:os"
import scopes "core:sync/budget"
import "core:sync"

@(private)
network_valid :: proc(s:^Client_State)->bool {return s!=nil && s.self==s}
@(private)
network_snapshot_error :: proc(error:net.Resolver_Snapshot_Error)->Client_Error {
 if error.kind==.Allocation_Failed {return {kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=error.allocation}}}
 if error.kind==.Unsupported {return {kind=.Runtime_Error,runtime={kind=.Unsupported},http={kind=.Dial_Failed,network=net.DNS_Error.Unsupported}}}
 if error.kind==.Read_Failed {
  code,_:=os.is_platform_error(error.io)
  return {kind=.Runtime_Error,runtime={kind=.System_Error,system_code=code},http={kind=.Dial_Failed,network=net.DNS_Error.Invalid_Resolv_Config_Error}}
 }
 return {kind=.Invalid_Config,http={kind=.Invalid_Config,network=net.DNS_Error.Invalid_Resolv_Config_Error}}
}
@(private)
network_scope_probe :: proc(scope:scopes.Scope)->Client_Error {
 if scope==(scopes.Scope{}) {return {}}
 lease,error:=scopes.reserve(scope,{})
 if error!=.None {return resource_failure(error)}
 scopes.release(&lease)
 return {}
}
@(private)
network_backing :: proc(scope:scopes.Scope,allocator:mem.Allocator)->(State_Backing,Client_Error) {
 if allocator.procedure==nil || .Free not_in mem.query_features(allocator) {return {},{kind=.Invalid_Config}}
 source_scope,managed:=charged.allocator_scope(allocator)
 if managed && scope!=(scopes.Scope{}) && !scopes.covers(source_scope,scope) {
  cause:=scopes.Error.Invalid_Config
  if !scopes.same_root(source_scope,scope) {cause=.Foreign_Root}
  return {},{kind=.Invalid_Config,http={kind=.Invalid_Config,budget=cause}}
 }
 if error:=network_scope_probe(scope);error.kind!=.None {return {},error}
 if managed {if error:=network_scope_probe(source_scope);error.kind!=.None {return {},error}}
 lease:scopes.Lease
 if !managed && scope!=(scopes.Scope{}) {
  owner,error:=scopes.reserve(scope,{bytes=u64(size_of(Client_State))})
  if error!=.None {return {},resource_failure(error)}
  lease=owner
 }
 storage,error:=kernel_grant(size_of(Client_State),align_of(Client_State),allocator)
 if error.kind!=.None {scopes.release(&lease);return {},error}
 for &byte in storage {byte=0}
 return {storage=storage,allocator=allocator,lease=lease},{}
}

// No Task registration or protocol I/O. Runtime/controller and certificate
// objects remain caller-owned through this preparation and every later close.
network_prepare :: proc(runtime:^runtime_async.Runtime,config:Normalized_Config,allocator:mem.Allocator)->(^Client_State,Client_Error) {
 if runtime==nil {return nil,{kind=.Invalid_Config}}
 options,error:=network_config_normalize(config)
 if error.kind!=.None {return nil,error}
 if options.dns_preparation!=.Numeric_Only && runtime_async.worker_thread_active() {
  return nil,{kind=.Runtime_Error,runtime={kind=.Current_Worker_Active}}
 }
 now:=runtime_async.deadline_after(runtime,0)
 if now.epoch==0 || now.at<=0 {return nil,{kind=.Runtime_Error,runtime={kind=.Not_Initialized}}}
 if config.lifetime.epoch!=0 && config.lifetime.epoch!=now.epoch {return nil,{kind=.Invalid_Config}}
 if config.lifetime.epoch!=0 && config.lifetime.at<=now.at {return nil,{kind=.Runtime_Error,runtime={kind=.Timeout}}}
 backing,allocation:=network_backing(config.http.scope,allocator)
 if allocation.kind!=.None {return nil,allocation}
 s:=cast(^Client_State)raw_data(backing.storage)
 s^={self=s,config=options,backing=backing,references=1,base_owned=true,
     runtime=runtime,runtime_epoch=now.epoch,last_clock=now,producer_calls=1}
 success:=false
 defer if !success {s.references=0;s.base_owned=false;s.producer_calls=0;network_cleanup_storage(s)}
 error=resources_init(&s.resources,config.http.scope,allocator)
 if error.kind!=.None {return nil,error}
 error=profile_init(&s.profile,config,s.resources.allocator)
 if error.kind!=.None {return nil,error}
 // Only owned Profile views survive preparation; original resolver intent was
 // already captured by options before Profile canonicalized empty slices.
 s.config.config=s.profile.config
 error=kernel_init(&s.kernel,&s.profile,&s.resources)
 if error.kind!=.None {return nil,error}
 s.actors,error=kernel_array(Session_Actor,config.capacities.connections,s.resources.allocator)
 if error.kind!=.None {return nil,error}
 for &actor in s.actors {actor={}}
 s.requests,error=kernel_array(Request_Network,config.capacities.requests,s.resources.allocator)
 if error.kind!=.None {return nil,error}
 for &request,index in s.requests {request={generation=s.kernel.requests[index].generation,query_budget_left=DNS_TOTAL_QUERY_LIMIT}}
 s.task_index,error=kernel_array(^runtime_async.Task,options.task_count,s.resources.allocator)
 if error.kind!=.None {return nil,error}
 s.dns_ids,error=kernel_array(u16,config.capacities.dns_ids,s.resources.allocator)
 if error.kind!=.None {return nil,error}
 if options.dns_preparation!=.Numeric_Only {
  prepared:=net.resolver_snapshot_prepare(&s.resolver,{name_servers=s.profile.config.http.resolver.name_servers,limits=options.resolver_limits},s.resources.allocator)
  if prepared.kind!=.None {return nil,network_snapshot_error(prepared)}
  if entropy:=runtime_async.prepare_dns_ids(s.dns_ids);entropy.kind!=.None {return nil,{kind=.Runtime_Error,runtime=entropy}}
  s.dns_count=len(s.dns_ids)
 }
 s.coordinator.owner=s;s.coordinator.task.data=&s.coordinator;s.task_index[0]=&s.coordinator.task
 wake,ready:=signal.create(runtime,&s.coordinator.task)
 if !ready {return nil,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=.Out_Of_Memory}}}
 s.coordinator.wake=wake;s.signal_cells+=1
 for &actor,index in s.actors {
  actor.owner=s;actor.index=u32(index+1);actor.task.data=&actor
  s.task_index[index+1]=&actor.task
  if init:=exchange_api.exchange_init(&actor.exchange,{body_limit=config.response_body_limit},s.resources.allocator);init.kind!=.None {
   return nil,{kind=.Invalid_Config,http=init}
  }
  notification,created:=signal.create(runtime,&actor.task)
  if !created {return nil,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=.Out_Of_Memory}}}
  actor.wake=notification;s.signal_cells+=1
 }
 // Synchronous preparation may have taken time or raced Scope.close. No
 // expired/closed constructor is published merely because its first check won.
 now=runtime_async.deadline_after(runtime,0)
 if config.lifetime.epoch!=0 && now.at>=config.lifetime.at {return nil,{kind=.Runtime_Error,runtime={kind=.Timeout}}}
 if probe:=network_scope_probe(s.resources.scope);probe.kind!=.None {return nil,probe}
 source,managed:=charged.allocator_scope(s.resources.allocator)
 if managed {if probe:=network_scope_probe(source);probe.kind!=.None {return nil,probe}}
 s.last_clock=now;s.producer_calls=0
 success=true
 return s,{}
}

// Destroy stable subowners IN PLACE. The last raw free can physically destroy
// State; its independent bootstrap lease is released afterward from locals only.
@(private)
network_cleanup_storage :: proc(s:^Client_State) {
 assert(network_valid(s))
 s.phase=.Disposing
 if s.kernel.self==&s.kernel {assert(kernel_destroy(&s.kernel).kind==.None)}
 signal.detach(s.coordinator.wake);signal.release(&s.coordinator.wake)
 for &actor in s.actors {
  signal.detach(actor.wake);signal.release(&actor.wake)
  if actor.exchange._self==&actor.exchange {assert(exchange_api.exchange_destroy(&actor.exchange).kind==.None)}
 }
 net.resolver_snapshot_destroy(&s.resolver)
 profile_destroy(&s.profile)
 allocator:=s.resources.allocator
 actors,requests,tasks,ids:=s.actors,s.requests,s.task_index,s.dns_ids
 s.actors=nil;s.requests=nil;s.task_index=nil;s.dns_ids=nil
 kernel_free_array(actors,allocator);kernel_free_array(requests,allocator)
 kernel_free_array(tasks,allocator);kernel_free_array(ids,allocator)
 resources_destroy(&s.resources)
 backing:=s.backing
 s.backing={};s.self=nil
 kernel_free(backing.storage,align_of(Client_State),backing.allocator)
 scopes.release(&backing.lease)
}

network_dispose_prepared :: proc(s:^Client_State)->Client_Error {
 if !network_valid(s) {return {kind=.Invalid_State}}
 sync.lock(&s.mu)
 if s.phase!=.Constructing || s.references!=1 || !s.base_owned || s.registered_tasks!=0 || s.producer_calls!=0 || s.returning_calls!=0 {
  sync.unlock(&s.mu);return {kind=.Pending}
 }
 // Kernel destroy is a no-mutation rejection when live children remain. Mark
 // this private State unavailable before any arbitrary raw destructor callback.
 s.phase=.Disposing
 sync.unlock(&s.mu)
 if error:=kernel_destroy(&s.kernel);error.kind!=.None {
  sync.lock(&s.mu);s.phase=.Constructing;sync.unlock(&s.mu);return error
 }
 s.base_owned=false;s.references=0
 network_cleanup_storage(s)
 return {}
}
