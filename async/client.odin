package surf_async

import surf ".."
import stream_api "stream"
import http "../../http"
import runtime_async "../../async"
import "core:mem"
import charged "core:mem/budget"
import "core:sync"
import scopes "core:sync/budget"
import "core:time"
import signal "../../async/signal"
import tls "core:crypto/tls"
import "core:net"
import "core:crypto/x509"

// Stable public header. Phase2 supplies only the pure kernel, not a network Client.
// Operational APIs must verify the original address before using opaque state.
Client :: struct {
 _self: ^Client,
 _state: rawptr,
}
Request_Handle :: struct {owner_id:u64, slot:u32, generation:u64}
Capacities :: struct {
 requests, origins, connections, connections_per_origin: int,
 waiters_per_origin, dns_ids, work_per_resume: int,
}
DEFAULT_CAPACITIES :: Capacities{32,16,8,2,32,256,128}
MAX_REQUESTS :: 4096
MAX_ORIGINS :: 1024
MAX_CONNECTIONS :: 256
MAX_DNS_IDS :: 65536
MAX_WORK_PER_RESUME :: 4096
MAX_NAME_SERVERS :: 8
Client_Config :: struct {
 http: surf.Config,
 capacities: Maybe(Capacities),
 idle_timeout, max_age: time.Duration,
 lifetime: runtime_async.Deadline,
 streaming: Maybe(Stream_Client_Limits),
}
// Pure borrowed view: config_normalize neither clones nor retains any member.
Normalized_Config :: struct {
 http: surf.Config,
 capacities: Capacities,
 idle_timeout, max_age, request_timeout: time.Duration,
 response_body_limit: int,
 streaming: Maybe(Stream_Client_Limits),
 lifetime: runtime_async.Deadline,
}
Client_Error_Kind :: enum {
 None, Invalid_Config, Invalid_State, Capacity, Closed, Invalid_Handle, Pending,
 Allocation_Failed, Budget_Rejected, Request_Error, Runtime_Error,
}
Client_Error :: struct {
 kind: Client_Error_Kind,
 http: surf.HTTP_Error,
 runtime: runtime_async.Error,
}
Request_Stage :: enum {
 Queued, Awaiting_DNS_IDs, Connecting, Handshaking, Writing, Reading,
 Redirecting, Retiring, Completed,
}
Completion :: struct {request:Request_Handle, error:surf.HTTP_Error}
Client_Stats :: struct {
 capacities: Capacities,
 preparing_requests, queued_requests, active_requests, completed_requests, returning_requests: int,
 reserved_connections, connecting_connections, active_connections, idle_connections, retiring_connections: int,
 origins, dns_ids, dns_waiters, tasks: int,
 reuse_count, close_count, cancel_count, deadline_count: u64,
 scope: scopes.Snapshot,
 // Signal control cells use the existing fixed heap ABI outside the scope.
 signal_cells: int,
 streaming: Stream_Stats,
}

// All following types are internal kernel handoffs, not public network owners.
// Indices are one-based; zero is absent. Generation0 never names a live cell.
Cell_Handle :: struct {slot:u32, generation:u64}
Request_State :: enum {Free, Preparing, Queued, Active, Completed, Returning, Retired}
Session_State :: enum {Free, Reserved, Connecting, Busy, Idle, Retiring, Returning, Retired}
Origin_State :: enum {Free, Occupied, Returning, Retired}
Origin_Reference :: enum {Request, Session, Preparing, Waiter}

// Owns cloned descriptors/octet storage; root certificate objects remain borrowed
// immutable until all sessions using this profile have physically closed.
Profile :: struct {
 self: ^Profile,
 owner_id: u64,
 config: Normalized_Config,
 storage: []u8,
 allocator: mem.Allocator,
}
Origin_Key :: struct {
 profile_id: u64,
 secure: bool,
 host: string,
 port: u16,
}
Prepared_Origin :: struct {
 key: Origin_Key,
 storage: []u8,
 allocator: mem.Allocator,
}
Origin_Slot :: struct {
 generation: u64,
 state: Origin_State,
 owner: Prepared_Origin,
 requests, sessions, preparing, waiters: int,
 queue_head, queue_tail: u32,
}
// Move-only cloned inputs; all strings/descriptors/body point into storage.
// No caller arena or request slice remains borrowed after successful cloning.
Request_Owner :: struct {
 request: http.Request,
 storage: []u8,
 allocator: mem.Allocator,
}
Request_Slot :: struct {
 generation: u64,
 state: Request_State,
 // Free rollback/release versus Completed publication after physical cleanup.
 returning_to: Request_State,
 stage: Request_Stage,
 cancel_requested: bool,
 deadline: runtime_async.Deadline,
 origin, session: Cell_Handle,
 input: Request_Owner,
 response: surf.Response,
 stream: ^stream_api.Channel,
 error: surf.HTTP_Error,
 lease: scopes.Lease,
 queue_previous, queue_next: u32,
 completion_previous, completion_next: u32,
 completion_queued: bool,
}
Session_Model :: struct {
 generation: u64,
 state: Session_State,
 // Reserved claims restore Idle transport or Free capacity on rollback.
 reserved_from: Session_State,
 origin: Cell_Handle,
 request: Request_Handle,
 created_at, idle_since: i64,
}
Kernel_Resources :: struct {
 self: ^Kernel_Resources,
 scope: scopes.Scope,
 binding: charged.Binding,
 allocator, backing: mem.Allocator,
}
// Stable, move-forbidden metadata owner. Pure model operations use this mutex;
// physical allocation/disposal and future actor/scheduler calls occur outside it.
Kernel :: struct {
 self: ^Kernel,
 mu: sync.Mutex,
 owner_id: u64,
 config: Normalized_Config,
 resources: ^Kernel_Resources,
 profile: ^Profile,
 closed: bool,
 preparing, returning, references: int,
 requests: []Request_Slot,
 origins: []Origin_Slot,
 sessions: []Session_Model,
 request_free, origin_free, session_free: []u32,
 request_free_count, origin_free_count, session_free_count: int,
 completion_head, completion_tail, dispatch_cursor: u32,
 // Independent bounded scan state. Every allocated-capacity inspection is work.
 dispatch_origin: Cell_Handle,
 dispatch_session_cursor: u32,
 dispatch_remaining: int,
 dispatch_dirty: bool,
 idle_cursor: u32,
 idle_remaining: int,
 idle_dirty: bool,
 // Earliest future idle/age expiry after a complete idle scan;0 means absent.
 idle_deadline: i64,
 counters: Client_Stats,
 allocator: mem.Allocator,
}
Preparing_Request :: struct {request:Request_Handle}
Pool_Reservation :: struct {
 request: Request_Handle,
 origin, session: Cell_Handle,
 waiting: bool,
}
Assignment :: struct {request:Request_Handle, session:Cell_Handle}
// Detached out-of-lock cleanup. Slot remains Returning and Kernel retained until
// cleanup_finish; physical callbacks cannot race a cell's generation reuse.
Origin_Disposal :: struct {origin:Cell_Handle, owner:Prepared_Origin}
Request_Disposal :: struct {
 request: Request_Handle,
 returning_to: Request_State,
 input: Request_Owner,
 response: surf.Response,
 stream: ^stream_api.Channel,
 stream_finish: ^stream_api.Channel,
 stream_error: surf.HTTP_Error,
 lease: scopes.Lease,
 origin: Origin_Disposal,
}

// Shape/bounds only. No allocation, scope admission/retention, clock, resolver,
// entropy or runtime access. The returned configuration still borrows all inputs.
config_normalize :: proc(input:Client_Config) -> (Normalized_Config,Client_Error) {
 cause := surf.config_validate(input.http)
 if cause.kind != .None do return {}, {kind=.Invalid_Config,http=cause}
 if input.idle_timeout < 0 || input.max_age < 0 ||
    input.http.tls.handshake_timeout < 0 || input.http.allocator_scope != (scopes.Scope{}) {
  return {}, {kind=.Invalid_Config}
 }
 lifetime := input.lifetime
 if (lifetime.epoch == 0 && lifetime.at != 0) ||
    (lifetime.epoch != 0 && lifetime.at <= 0) { return {}, {kind=.Invalid_Config} }
 capacities := DEFAULT_CAPACITIES
 if explicit,ok := input.capacities.?; ok do capacities = explicit
 if capacities.requests < 1 || capacities.requests > MAX_REQUESTS ||
    capacities.origins < 1 || capacities.origins > MAX_ORIGINS ||
    capacities.connections < 1 || capacities.connections > MAX_CONNECTIONS ||
    capacities.connections_per_origin < 1 || capacities.connections_per_origin > capacities.connections ||
    capacities.waiters_per_origin < 0 || capacities.waiters_per_origin > capacities.requests ||
    capacities.dns_ids < 0 || capacities.dns_ids > MAX_DNS_IDS ||
    capacities.work_per_resume < 1 || capacities.work_per_resume > MAX_WORK_PER_RESUME {
  return {}, {kind=.Invalid_Config}
 }
 if len(input.http.resolver.name_servers) > MAX_NAME_SERVERS do return {}, {kind=.Invalid_Config}
 for endpoint in input.http.resolver.name_servers {
  if endpoint.port < 1 || endpoint.port > 65535 do return {}, {kind=.Invalid_Config}
 }
 streaming:Maybe(Stream_Client_Limits)
 if limits,enabled:=input.streaming.?;enabled {
  normalized,valid:=stream_api.limits_normalize(limits,capacities.requests)
  if !valid {return {},{kind=.Invalid_Config}}
  streaming=normalized
 }
 result := Normalized_Config{
  http=input.http, capacities=capacities, idle_timeout=input.idle_timeout,
  max_age=input.max_age, request_timeout=surf.effective_timeout(input.http),
  response_body_limit=input.http.max_body_size, lifetime=lifetime, streaming=streaming,
 }
 if result.idle_timeout == 0 do result.idle_timeout = 30*time.Second
 if result.max_age == 0 do result.max_age = 5*time.Minute
 if result.response_body_limit == 0 do result.response_body_limit = http.DEFAULT_MAX_BODY_SIZE
 return result, {}
}

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

@(private)
resource_failure :: proc(error:scopes.Error)->Client_Error {
 return {kind=.Budget_Rejected,http={kind=.Allocation_Failed,budget=error}}
}
@(private)
resource_allocation_failure :: proc(error:charged.Error)->Client_Error {
 if error.kind==.Budget_Rejected || error.kind==.Overflow {return resource_failure(error.budget if error.kind==.Budget_Rejected else .Overflow)}
 if error.kind==.Invalid_Config || error.kind==.Invalid_Handle || error.kind==.Invalid_Argument {
  return {kind=.Invalid_Config,http={kind=.Invalid_Config,budget=error.budget}}
 }
 return {kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=error.allocation}}
}
resources_init :: proc(r:^Kernel_Resources,scope:scopes.Scope,backing:mem.Allocator)->Client_Error {
 if r==nil || backing.procedure==nil {return {kind=.Invalid_Config}}
 if r.self!=nil {return {kind=.Invalid_State}}
 if .Free not_in mem.query_features(backing) {return {kind=.Invalid_Config}}
 source_scope,managed:=charged.allocator_scope(backing)
 if scope!=(scopes.Scope{}) && managed && !scopes.covers(source_scope,scope) {
  cause:=scopes.Error.Invalid_Config
  if !scopes.same_root(source_scope,scope) do cause=.Foreign_Root
  return {kind=.Invalid_Config,http={kind=.Invalid_Config,budget=cause}}
 }
 // Logical request admission and the inherited allocator's byte admission may
 // be different nodes. Both must be open; checking only an ancestor permits a
 // closed child binding to appear usable until the first physical allocation.
 probes:=[2]scopes.Scope{scope,{}}
 if managed do probes[1]=source_scope
 for candidate,index in probes {
  if candidate==(scopes.Scope{}) || index==1 && candidate==probes[0] do continue
  probe,error:=scopes.reserve(candidate,{})
  if error!=.None do return resource_failure(error)
  scopes.release(&probe)
 }
 retained:scopes.Scope
 if scope!=(scopes.Scope{}) {
  owner,error:=scopes.retain_scope(scope)
  if error!=.None do return resource_failure(error)
  retained=owner
 }
 binding:charged.Binding
 error:charged.Error
 if managed {binding,error=charged.retain_allocator(backing)}
 else if scope!=(scopes.Scope{}) {binding,error=charged.create(scope,{backing=backing})}
 if error.kind!=.None {
  scopes.release_scope(&retained)
  return resource_allocation_failure(error)
 }
 allocator:=backing
 if binding!=(charged.Binding{}) do allocator=charged.allocator(binding)
 r^={self=r,scope=retained,binding=binding,allocator=allocator,backing=backing}
 return {}
}
resources_destroy :: proc(r:^Kernel_Resources) {
 if r==nil || r.self!=r do return
 old:=r^;r^={}
 charged.release(&old.binding)
 scopes.release_scope(&old.scope)
}
resources_request_lease :: proc(r:^Kernel_Resources)->(scopes.Lease,Client_Error) {
 if r==nil || r.self!=r {return {},{kind=.Invalid_State}}
 if r.scope==(scopes.Scope{}) {return {},{}}
 lease,error:=scopes.reserve(r.scope,{streams=1})
 if error!=.None {return {},resource_failure(error)}
 return lease,{}
}

// Validate the physical grant before constructing any typed/sized view. A
// failed allocator may still report storage; release that exact whole extent.
@(private)
kernel_grant :: proc(size,alignment:int,allocator:mem.Allocator)->([]u8,Client_Error) {
 if size<0 || alignment<1 || allocator.procedure==nil {return nil,{kind=.Invalid_Config}}
 if size==0 {return nil,{}}
 if charged.is_managed_allocator(allocator) {
  binding,error:=charged.retain_allocator(allocator)
  if error.kind!=.None {return nil,resource_allocation_failure(error)}
  storage,cause:=charged.allocate(binding,size,alignment)
  charged.release(&binding)
  if cause.kind!=.None {return nil,resource_allocation_failure(cause)}
  return storage,{}
 }
 return profile_allocate(size,alignment,allocator)
}
@(private)
kernel_free :: proc(storage:[]u8,alignment:int,allocator:mem.Allocator) {
 if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(storage),len(storage))}
}
@(private)
kernel_array :: proc($T:typeid,count:int,allocator:mem.Allocator)->([]T,Client_Error) {
 if count<0 || count>max(int)/size_of(T) {return nil,{kind=.Invalid_Config}}
 storage,error:=kernel_grant(count*size_of(T),align_of(T),allocator)
 if error.kind!=.None {return nil,error}
 return (cast([^]T)raw_data(storage))[:count],{}
}
@(private)
kernel_free_array :: proc(values:[]$T,allocator:mem.Allocator) {
 kernel_free(mem.slice_to_bytes(values),align_of(T),allocator)
}

@(private) profile_identity_mu: sync.Mutex
@(private) profile_identity_serial: u64

// Counter ownership is explicit so exhaustion can be tested without mutating
// the shared identity namespace used by concurrently initialized profiles.
@(private)
profile_identity_next :: proc(serial:^u64,mu:^sync.Mutex)->(u64,bool) {
 sync.mutex_lock(mu)
 defer sync.mutex_unlock(mu)
 if serial^==max(u64) {return 0,false}
 serial^+=1
 return serial^,true
}

// Descriptor offsets are aligned before any cast. A single checked physical
// backing owns every copied descriptor/string, keeping rollback one-step.
@(private)
profile_region :: proc(total:^int,count,size,alignment:int)->(int,bool) {
 if count<0 || size<1 || count>max(int)/size {return 0,false}
 padding := (alignment-total^%alignment)%alignment
 bytes := count*size
 if total^>max(int)-padding || total^+padding>max(int)-bytes {return 0,false}
 offset := total^+padding
 total^=offset+bytes
 return offset,true
}
@(private)
profile_allocate :: proc(size,alignment:int,allocator:mem.Allocator)->([]u8,Client_Error) {
 if size<0 || allocator.procedure==nil {return nil,{kind=.Invalid_Config}}
 if size==0 {return nil,{}}
 storage,cause:=allocator.procedure(allocator.data,.Alloc,size,alignment,nil,0)
 if cause!=nil || len(storage)!=size || raw_data(storage)==nil || uintptr(raw_data(storage))%uintptr(alignment)!=0 {
  if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(storage),len(storage))}
  if cause==nil {cause=.Out_Of_Memory}
  return nil,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=cause}}
 }
 for &byte in storage {byte=0}
 return storage,{}
}
@(private)
profile_valid :: proc(p:^Profile)->bool {return p!=nil && p.self==p && p.owner_id!=0}

profile_init :: proc(p:^Profile,config:Normalized_Config,allocator:mem.Allocator)->Client_Error {
 if p==nil || p.self!=nil || p.owner_id!=0 || raw_data(p.storage)!=nil {return {kind=.Invalid_State}}
 p^={}
 normalized,error:=config_normalize({http=config.http,capacities=config.capacities,
  idle_timeout=config.idle_timeout,max_age=config.max_age,lifetime=config.lifetime,streaming=config.streaming})
 if error.kind!=.None {return error}
 if allocator.procedure==nil || normalized.request_timeout!=config.request_timeout ||
    normalized.response_body_limit!=config.response_body_limit {return {kind=.Invalid_Config}}
 // The caller must keep Config's borrowed inputs immutable for this call.
 total:=0
 roots_at,roots_ok:=profile_region(&total,len(config.http.tls.root_cas),size_of(^x509.Certificate),align_of(^x509.Certificate))
 offers_at,offers_ok:=profile_region(&total,len(config.http.tls.alpn_protocols),size_of(string),align_of(string))
 servers_at,servers_ok:=profile_region(&total,len(config.http.resolver.name_servers),size_of(net.Endpoint),align_of(net.Endpoint))
 name_at,name_ok:=profile_region(&total,len(config.http.tls.server_name),1,1)
 if !roots_ok || !offers_ok || !servers_ok || !name_ok {return {kind=.Invalid_Config}}
 text_at:=total
 for offer in config.http.tls.alpn_protocols {
  if len(offer)>max(int)-total {return {kind=.Invalid_Config}}
  total+=len(offer)
 }
 alignment:=max(align_of(^x509.Certificate),align_of(string),align_of(net.Endpoint))
 storage,allocation:=profile_allocate(total,alignment,allocator)
 if allocation.kind!=.None {return allocation}
 snapshot:=normalized
 if len(config.http.tls.root_cas)>0 {
  roots:=(cast([^]^x509.Certificate)raw_data(storage[roots_at:]))[:len(config.http.tls.root_cas)]
  copy(roots,config.http.tls.root_cas);snapshot.http.tls.root_cas=roots
 } else {snapshot.http.tls.root_cas=nil}
 if len(config.http.resolver.name_servers)>0 {
  servers:=(cast([^]net.Endpoint)raw_data(storage[servers_at:]))[:len(config.http.resolver.name_servers)]
  copy(servers,config.http.resolver.name_servers);snapshot.http.resolver.name_servers=servers
 } else {snapshot.http.resolver.name_servers=nil}
 copy(storage[name_at:name_at+len(config.http.tls.server_name)],config.http.tls.server_name)
 snapshot.http.tls.server_name=string(storage[name_at:name_at+len(config.http.tls.server_name)])
 if len(config.http.tls.alpn_protocols)>0 {
  offers:=(cast([^]string)raw_data(storage[offers_at:]))[:len(config.http.tls.alpn_protocols)]
  at:=text_at
  for offer,i in config.http.tls.alpn_protocols {
   copy(storage[at:at+len(offer)],offer);offers[i]=string(storage[at:at+len(offer)]);at+=len(offer)
  }
  snapshot.http.tls.alpn_protocols=offers
 } else {snapshot.http.tls.alpn_protocols=nil}
 identity,available:=profile_identity_next(&profile_identity_serial,&profile_identity_mu)
 if !available {
  kernel_free(storage,alignment,allocator)
  return {kind=.Capacity}
 }
 p^={self=p,owner_id=identity,config=snapshot,storage=storage,allocator=allocator}
 return {}
}

profile_destroy :: proc(p:^Profile) {
 if !profile_valid(p) {return}
 storage,allocator:=p.storage,p.allocator
 p^={}
 alignment:=max(align_of(^x509.Certificate),align_of(string),align_of(net.Endpoint))
 kernel_free(storage,alignment,allocator)
}

@(private)
ranges_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return av<=bv && bv-av<uintptr(an) || bv<av && av-bv<uintptr(bn)
}
@(private)
client_destination_alias :: proc(s:^Client_State,c:^Client,destination:^surf.Response)->bool {
 return ranges_overlap(destination,size_of(surf.Response),c,size_of(Client)) ||
  ranges_overlap(destination,size_of(surf.Response),s,size_of(Client_State)) ||
  ranges_overlap(destination,size_of(surf.Response),raw_data(s.actors),len(s.actors)*size_of(Session_Actor)) ||
  ranges_overlap(destination,size_of(surf.Response),raw_data(s.requests),len(s.requests)*size_of(Request_Network)) ||
  ranges_overlap(destination,size_of(surf.Response),raw_data(s.task_index),len(s.task_index)*size_of(^runtime_async.Task)) ||
  ranges_overlap(destination,size_of(surf.Response),raw_data(s.dns_ids),len(s.dns_ids)*size_of(u16)) ||
  ranges_overlap(destination,size_of(surf.Response),raw_data(s.profile.storage),len(s.profile.storage))
}

client_request_stage :: proc(c:^Client,handle:Request_Handle)->(Request_Stage,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return {},error};defer client_leave(s)
 return kernel_stage(&s.kernel,handle)
}
client_poll :: proc(c:^Client)->(Completion,bool) {
 s,error:=client_enter(c);if error.kind!=.None {return {},false};defer client_leave(s)
 return kernel_poll(&s.kernel)
}
client_take :: proc(c:^Client,handle:Request_Handle,destination:^surf.Response)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 if destination==nil || client_destination_alias(s,c,destination) {return {kind=.Invalid_State}}
 return kernel_take(&s.kernel,handle,destination)
}
client_release :: proc(c:^Client,handle:Request_Handle)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 return kernel_release(&s.kernel,handle)
}
client_cancel :: proc(c:^Client,handle:Request_Handle)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 sync.lock(&s.mu)
 cause:=kernel_cancel(&s.kernel,handle)
 wake:=s.coordinator.wake
 if cause.kind==.None {
  network_queue_changed_locked(s)
  sync.lock(&s.kernel.mu)
  request:=admission_request_locked(&s.kernel,handle)
  if request!=nil && request.session.slot>0 {wake=s.actors[int(request.session.slot)-1].wake}
  sync.unlock(&s.kernel.mu)
 }
 sync.unlock(&s.mu)
 if cause.kind==.None {_=signal.wake(wake);_=signal.wake(s.coordinator.wake)}
 return cause
}
client_refill_dns_ids :: proc(c:^Client,ids:[]u16)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 return network_dns_refill(s,ids)
}
client_stats :: proc(c:^Client)->(Client_Stats,bool) {
 s,error:=client_enter(c);if error.kind!=.None {return {},false};defer client_leave(s)
 sync.lock(&s.mu);sync.lock(&s.kernel.mu)
 stats:=s.kernel.counters
 stats.streaming=stream_api.bank_stats(s.stream_bank)
 stats.capacities=s.config.config.capacities;stats.tasks=s.registered_tasks
 stats.dns_ids=s.dns_count;stats.signal_cells=s.signal_cells
 for metadata in s.requests {if metadata.awaiting_ids {stats.dns_waiters+=1}}
 scope:=s.resources.scope
 sync.unlock(&s.kernel.mu);sync.unlock(&s.mu)
 if scope!=(scopes.Scope{}) {stats.scope,_=scopes.snapshot(scope)}
 return stats,true
}
