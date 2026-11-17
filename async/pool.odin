package surf_async

import "core:sync"
import http "../../http"
import surf ".."
import "core:mem"
import "core:strings"
import signal "../../async/signal"
import stream_api "stream"
import runtime_async "../../async"
import adapter "../../async/connection"
import exchange_api "exchange"
import tls_api "core:crypto/tls"
import "core:net"
import scopes "core:sync/budget"
import "core:time"

@(private)
pool_request_locked :: proc(k:^Kernel,handle:Request_Handle)->^Request_Slot {
 if handle.owner_id!=k.owner_id || handle.slot==0 || u64(handle.slot)>u64(len(k.requests)) || handle.generation==0 {return nil}
 slot:=&k.requests[int(handle.slot)-1]
 if slot.generation!=handle.generation || slot.state==.Free || slot.state==.Retired {return nil}
 return slot
}
@(private)
pool_session_locked :: proc(k:^Kernel,handle:Cell_Handle)->^Session_Model {
 if handle.slot==0 || u64(handle.slot)>u64(len(k.sessions)) || handle.generation==0 {return nil}
 slot:=&k.sessions[int(handle.slot)-1]
 if slot.generation!=handle.generation || slot.state==.Free || slot.state==.Retired {return nil}
 return slot
}
@(private)
pool_expired :: proc(s:^Session_Model,k:^Kernel,now:i64)->bool {
 // Compare elapsed intervals without signed subtraction overflow. Future times
 // are not expired; caller supplies one monotonic clock domain.
 age_expired:=now>=s.created_at && u64(now)-u64(s.created_at)>=u64(k.config.max_age)
 idle_expired:=now>=s.idle_since && u64(now)-u64(s.idle_since)>=u64(k.config.idle_timeout)
 return age_expired || idle_expired
}

// A borrowed selection witness, valid ONLY while the same Kernel.mu remains
// held. It neither pins cells nor owns the key. Both ordinary admission and
// accepted-hop consumers use this one policy before their own atomic commits.
Pool_Selection :: struct {
 origin,session:Cell_Handle,
 new_origin,new_session,waiting:bool,
}

@(private)
pool_select_locked :: proc(k:^Kernel,key:Origin_Key,now:i64,allow_new:bool)->(Pool_Selection,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if key.profile_id!=k.profile.owner_id || key.port==0 || len(key.host)<=0 || raw_data(key.host)==nil || now<0 {return {},{kind=.Invalid_Config}}
 if k.closed {return {},{kind=.Closed}}
 origin_index:u32
 for slot,i in k.origins {
  if slot.state==.Occupied && origin_equal(slot.owner.key,key) {origin_index=u32(i+1);break}
 }
 new_origin:=origin_index==0
 if new_origin {
  if k.origin_free_count==0 {return {},{kind=.Capacity}}
  origin_index=k.origin_free[k.origin_free_count-1]
 }
 selected:=&k.origins[int(origin_index)-1]
 origin_handle:=Cell_Handle{slot=origin_index,generation=selected.generation}
 session_index:u32
 if !new_origin {
  for session,i in k.sessions {
   if session.state==.Idle && session.origin==origin_handle && !pool_expired(&k.sessions[i],k,now) {session_index=u32(i+1);break}
  }
 }
 new_session:=false
 if allow_new && session_index==0 && selected.sessions<k.config.capacities.connections_per_origin && k.session_free_count>0 {
  session_index=k.session_free[k.session_free_count-1];new_session=true
 }
 waiting:=session_index==0
 if waiting && selected.waiters>=k.config.capacities.waiters_per_origin {return {},{kind=.Capacity}}
 // Preserve the existing conservative counter rejection even if a particular
 // selection would not increment every category. No ownership changes occur.
 if selected.requests==max(int) || selected.preparing==max(int) || selected.waiters==max(int) || selected.sessions==max(int) {return {},{kind=.Capacity}}
 if new_origin && (selected.state!=.Free || selected.generation==0) {return {},{kind=.Invalid_State}}
 selection:=Pool_Selection{origin=origin_handle,new_origin=new_origin,new_session=new_session,waiting=waiting}
 if session_index!=0 {selection.session={slot=session_index,generation=k.sessions[int(session_index)-1].generation}}
 return selection,{}
}

// Keep this exact callable signature for pure-kernel consumers.
pool_reserve :: proc(k:^Kernel,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error) {
 return pool_reserve_policy(k,preparing,origin,now,true)
}

// allow_new=false still permits healthy same-origin Idle reuse. Otherwise it
// claims a configured waiter; it NEVER reserves an unopened physical session.
pool_reserve_policy :: proc(k:^Kernel,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64,allow_new:bool)->(Pool_Reservation,Client_Error) {
 if k==nil || k.self!=k {return {},{kind=.Invalid_State}}
 if origin==nil || origin.key.profile_id!=k.profile.owner_id || origin.key.port==0 || len(origin.key.host)==0 ||
    len(origin.storage)!=len(origin.key.host) || raw_data(origin.storage)!=raw_data(origin.key.host) ||
    origin.allocator.procedure==nil || now<0 {return {},{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.closed {return {},{kind=.Closed}}
 request:=pool_request_locked(k,preparing.request)
 if request==nil {return {},{kind=.Invalid_Handle}}
 if request.state!=.Preparing || request.origin.slot!=0 || request.session.slot!=0 || request.cancel_requested {return {},{kind=.Invalid_State}}
 selection,error:=pool_select_locked(k,origin.key,now,allow_new)
 if error.kind!=.None {return {},error}
 // Selection and ownership commit share this lock. A selection copied across
// an unlock is not an admission right and must be recomputed by its consumer.
 origin_handle:=selection.origin
 selected:=&k.origins[int(origin_handle.slot)-1]
 if selection.new_origin {
  selected.state=.Occupied;selected.owner=origin^;origin^={}
  k.origin_free_count-=1;k.counters.origins+=1
 }
 assert(kernel_origin_retain_locked(k,origin_handle,.Request).kind==.None)
 assert(kernel_origin_retain_locked(k,origin_handle,.Preparing).kind==.None)
 request.origin=origin_handle
 reservation:=Pool_Reservation{request=preparing.request,origin=origin_handle,waiting=selection.waiting}
 k.dispatch_dirty=true;k.idle_dirty=true
 if selection.waiting {assert(kernel_origin_retain_locked(k,origin_handle,.Waiter).kind==.None);return reservation,{}}
 session_index:=selection.session.slot
 session:=&k.sessions[int(session_index)-1]
 previous:=session.state
 if selection.new_session {
  k.session_free_count-=1
  assert(kernel_origin_retain_locked(k,origin_handle,.Session).kind==.None)
  generation:=session.generation
  session^={generation=generation,state=.Free,created_at=now,origin=origin_handle}
 }
 if previous==.Idle {k.counters.idle_connections-=1}
 session.reserved_from=previous;session.state=.Reserved;session.request=preparing.request
 k.counters.reserved_connections+=1
 reservation.session={slot=session_index,generation=session.generation}
 request.session=reservation.session
 return reservation,{}
}

pool_session_state :: proc(k:^Kernel,handle:Cell_Handle,state:Session_State,now:i64)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 if now<0 {return {kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 session:=pool_session_locked(k,handle)
 if session==nil {return {kind=.Invalid_Handle}}
 previous:=session.state
 if previous==.Connecting && state==.Busy {
  request:=pool_request_locked(k,session.request)
  if request==nil || request.state!=.Active || request.session!=handle {return {kind=.Invalid_State}}
 } else if previous==.Busy && state==.Idle {
  if session.request!=(Request_Handle{}) {return {kind=.Pending}}
 } else if state==.Retiring && (previous==.Connecting || previous==.Busy || previous==.Idle) {
  // Transport close can begin before the active request's terminal cleanup.
 } else {return {kind=.Invalid_State}}
 session.state=state
 k.dispatch_dirty=true;k.idle_dirty=true
 if state==.Idle {session.idle_since=now}
 if previous==.Connecting {k.counters.connecting_connections-=1}
 if previous==.Busy {k.counters.active_connections-=1}
 if previous==.Idle {k.counters.idle_connections-=1}
 if state==.Busy {k.counters.active_connections+=1}
 if state==.Idle {k.counters.idle_connections+=1}
 if state==.Retiring {k.counters.retiring_connections+=1}
 return {}
}

pool_retire :: proc(k:^Kernel,handle:Cell_Handle)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu)
 session:=pool_session_locked(k,handle)
 if session==nil {sync.unlock(&k.mu);return {kind=.Invalid_Handle}}
 if session.state!=.Retiring || session.request!=(Request_Handle{}) {sync.unlock(&k.mu);return {kind=.Pending}}
 if session.generation!=max(u64) && k.session_free_count>=len(k.session_free) {sync.unlock(&k.mu);return {kind=.Invalid_State}}
 origin:=session.origin
 disposal,error:=kernel_origin_release_locked(k,origin,.Session)
 if error.kind!=.None {sync.unlock(&k.mu);return error}
 // Keep this session and Kernel alive until all physical origin cleanup returns.
 session.state=.Returning
 k.references+=1
 k.dispatch_dirty=true;k.idle_dirty=true
 sync.unlock(&k.mu)
 origin_ticket:=disposal.origin
 origin_disposal_destroy(&disposal)
 if origin_ticket.slot!=0 {
  error=kernel_origin_cleanup_finish(k,origin_ticket)
  if error.kind!=.None {return error}
 }
 sync.lock(&k.mu)
 generation:=session.generation
 session^={generation=generation,state=.Retired}
 if generation!=max(u64) {
  session.generation+=1;session.state=.Free
  k.session_free[k.session_free_count]=handle.slot;k.session_free_count+=1
 }
 k.counters.retiring_connections-=1;k.references-=1;k.dispatch_dirty=true;k.idle_dirty=true
 if k.counters.close_count!=max(u64) {k.counters.close_count+=1}
 sync.unlock(&k.mu)
 return {}
}

origin_prepare :: proc(profile:^Profile,url:string,allocator:mem.Allocator)->(Prepared_Origin,Client_Error) {
 if !profile_valid(profile) {return {},{kind=.Invalid_State}}
 if allocator.procedure==nil {return {},{kind=.Invalid_Config}}
 parsed,cause:=http.url_parse(url)
 if cause.kind!=.None {return {},{kind=.Request_Error,http=surf.http_protocol_error(cause)}}
 if !parsed.secure && !profile.config.http.allow_http {return {},{kind=.Request_Error,http={kind=.Insecure_URL}}}
 // Snapshot profile fields before the allocator can execute arbitrary callbacks.
 identity:=profile.owner_id
 storage,error:=profile_allocate(len(parsed.host),1,allocator)
 if error.kind!=.None {return {},error}
 copy(storage,parsed.host)
 // DNS ASCII case only; IPv6 spelling remains conservative textual identity.
 if !strings.contains(parsed.host,":") {
  for &byte in storage {if byte>='A' && byte<='Z' {byte+=32}}
 }
 return {key={profile_id=identity,secure=parsed.secure,host=string(storage),port=u16(parsed.port)},storage=storage,allocator=allocator},{}
}
origin_equal :: proc(a,b:Origin_Key)->bool {
 return a.profile_id==b.profile_id && a.secure==b.secure && a.port==b.port && a.host==b.host
}
origin_destroy :: proc(owner:^Prepared_Origin) {
 if owner==nil {return}
 storage,allocator:=owner.storage,owner.allocator
 owner^={}
 kernel_free(storage,1,allocator)
}

@(private)
network_alias :: proc(s:^Client_State,p:rawptr,n:int)->bool {
 return ranges_overlap(p,n,s,size_of(Client_State)) ||
        ranges_overlap(p,n,raw_data(s.actors),len(s.actors)*size_of(Session_Actor)) ||
        ranges_overlap(p,n,raw_data(s.requests),len(s.requests)*size_of(Request_Network)) ||
        ranges_overlap(p,n,raw_data(s.task_index),len(s.task_index)*size_of(rawptr)) ||
        ranges_overlap(p,n,raw_data(s.dns_ids),len(s.dns_ids)*size_of(u16))
}
@(private)
network_saturate :: proc(counter:^u64,amount:u64) {counter^+=min(amount,max(u64)-counter^)}

network_dns_refill :: proc(s:^Client_State,ids:[]u16)->Client_Error {
 if !network_valid(s) || len(ids)<0 || len(ids)>MAX_DNS_IDS || len(ids)>0 && raw_data(ids)==nil {return {kind=.Invalid_Config}}
 if network_alias(s,raw_data(ids),len(ids)*size_of(u16)) {return {kind=.Invalid_Config}}
 if !network_state_retain(s) {return {kind=.Closed}}
 sync.lock(&s.mu)
 if s.phase==.Closing || s.phase==.Disposing {
  sync.unlock(&s.mu);network_state_release(s);return {kind=.Closed}
 }
 if len(ids)>len(s.dns_ids)-s.dns_count {
  sync.unlock(&s.mu);network_state_release(s);return {kind=.Capacity}
 }
 for value,index in ids {s.dns_ids[(s.dns_head+s.dns_count+index)%len(s.dns_ids)]=value}
 s.dns_count+=len(ids)
 notification:=s.coordinator.wake
 sync.unlock(&s.mu)
 // State ownership keeps the Signal control cell alive across this out-of-lock
 // retain/wake/release, even if on_done detaches the target concurrently.
 if len(ids)>0 {
  owned,valid:=signal.retain(notification)
  if valid {_=signal.wake(owned);signal.release(&owned)}
 }
 network_state_release(s)
 return {}
}

network_dns_reserve :: proc(s:^Client_State,maximum:int)->(DNS_ID_Block,Client_Error) {
 if !network_valid(s) {return {},{kind=.Invalid_State}}
 if maximum<1 || maximum>DNS_IDS_PER_QUERY {return {},{kind=.Invalid_Config}}
 sync.lock(&s.mu);defer sync.unlock(&s.mu)
 if s.phase==.Closing || s.phase==.Disposing {return {},{kind=.Closed}}
 if s.dns_count==0 {return {},{kind=.Pending}}
 result:=DNS_ID_Block{count=min(maximum,s.dns_count)}
 for i in 0..<result.count {
  result.values[i]=s.dns_ids[s.dns_head];s.dns_ids[s.dns_head]=0
  s.dns_head=(s.dns_head+1)%len(s.dns_ids)
 }
 s.dns_count-=result.count
 network_saturate(&s.dns_draws_reserved,u64(result.count))
 return result,{}
}

// The block is a move-only draw owner by convention. Repeated burn of the same
// cleared variable is harmless; scalar copies do not authorize draw reuse.
network_dns_burn :: proc(s:^Client_State,block:^DNS_ID_Block) {
 if block==nil {return}
 count:=block.count;block^={}
 if !network_valid(s) || count<0 || count>DNS_IDS_PER_QUERY {return}
 sync.lock(&s.mu)
 network_saturate(&s.dns_draws_burned,u64(count))
 sync.unlock(&s.mu)
}

DNS_IDS_PER_QUERY :: 16
DNS_TOTAL_QUERY_LIMIT :: 32
DNS_MESSAGE_LIMIT :: 64
DNS_ROUNDS :: 2
DNS_ATTEMPT_TIMEOUT :: time.Second
DNS_TX_BYTES :: 4096
DNS_RX_BYTES :: 4096
DNS_ALIAS_CAPACITY :: 9
DNS_RESULT_CAPACITY :: 64

DNS_Preparation :: enum {Numeric_Only, Explicit, System}
Network_Config :: struct {
 // Original borrowed normalization, including nil versus explicit-empty DNS.
 // Call this pure validator BEFORE profile_init canonicalizes empty slices.
 config: Normalized_Config,
 dns_preparation: DNS_Preparation,
 resolver_limits: net.Resolver_Snapshot_Limits,
 task_count: int,
 state_bytes, actor_storage_bytes, request_storage_bytes, task_index_bytes, dns_storage_bytes: int,
}
// These bytes are a consumed draw block, not an entropy generator or refillable
// query state. Copy to an actor once then clear the source count; never return
// potentially used entries to the bank by inspecting private DNS_Query fields.
DNS_ID_Block :: struct {values:[DNS_IDS_PER_QUERY]u16, count:int}
Request_Network :: struct {
 generation: u64,
 // Original accepted-request history survives same-handle redirect requeue.
 redirects,last_status:int,
 ids: DNS_ID_Block,
 query_budget_left: int,
 needs_dns, awaiting_ids: bool,
 // Prepared hosts/numeric endpoints need neither file I/O nor a DNS draw.
 prepared_addresses: [DNS_RESULT_CAPACITY]net.Endpoint,
 prepared_address_count: int,
}
State_Phase :: enum {Constructing, Published, Closing, Disposing}
Actor_Phase :: enum {
 Prepared, Idle, Assigned, Resolving_A, Resolving_AAAA, Connecting,
 Handshaking, Exchanging, Retiring, Done,
}
// State.mu protects the mailbox; the actor takes a snapshot before I/O. Kernel
// association/generation is independently validated under Kernel.mu.
Session_Command :: struct {
 assignment: Assignment,
 pending, cancel, retire: bool,
}
State_Backing :: struct {
 storage: []u8,
 allocator: mem.Allocator,
 // Only for unmanaged backing under nonzero scope. A covered managed grant
 // already holds its physical charge and must not reserve this second lease.
 lease: scopes.Lease,
}
Coordinator_State :: struct {
 owner: ^Client_State,
 task: runtime_async.Task,
 wake: signal.Signal,
 registered, done, detached: bool,
 request_cursor, dns_cursor: u32,
 scan_remaining: int,
 next_deadline: runtime_async.Deadline,
}
Session_Actor :: struct {
 owner: ^Client_State,
 index: u32,
 task: runtime_async.Task,
 wake: signal.Signal,
 registered, done, detached: bool,
 command: Session_Command,
 // Remaining fields are actor-owner-thread only until owner_drained is latched
 // before Done. on_done cannot drive/check TLS or adapter APIs.
 phase: Actor_Phase,
 model: Cell_Handle,
 request: Request_Handle,
 cutoff, setup_cutoff: runtime_async.Deadline,
 executor: adapter.Executor,
 transport: adapter.Transport,
 tls: tls_api.Async_Conn,
 handshake: tls_api.Async_Handshake_Operation,
 close: net.Async_Operation,
 exchange: exchange_api.Exchange,
 stream_exchange: ^exchange_api.Stream_Exchange,
 query: runtime_async.DNS_Query,
 dial: runtime_async.DNS_Connect,
 ids: DNS_ID_Block,
 dns_tx: [DNS_TX_BYTES]u8,
 dns_rx: [DNS_RX_BYTES]u8,
 dns_aliases: [DNS_ALIAS_CAPACITY]runtime_async.DNS_Name,
 dns_results: [DNS_RESULT_CAPACITY]net.Endpoint,
 dns_servers: [MAX_NAME_SERVERS]net.Endpoint,
 dns_server_count: int,
 prepared_addresses: [DNS_RESULT_CAPACITY]net.Endpoint,
 prepared_address_count, prepared_address_at: int,
 error: surf.HTTP_Error,
 // Independent of the next-generation mailbox and explicit IO reset fields.
 redirect: Redirect_Handoff,
 secure, executor_initialized, transport_initialized, tls_initialized: bool,
 handshake_started, handshake_done, close_started, close_done: bool,
 owner_drained: bool,
}
// Private stable heap owner. No Client header pointer is retained: a physical
// callback may free that public header after its method has committed/cleared it.
Client_State :: struct {
 self: ^Client_State,
 mu: sync.Mutex,
 phase: State_Phase,
 config: Network_Config,
 stream_bank: ^stream_api.Bank,
 backing: State_Backing,
 resources: Kernel_Resources,
 profile: Profile,
 kernel: Kernel,
 resolver: net.Resolver_Snapshot,
 coordinator: Coordinator_State,
 actors: []Session_Actor,
 requests: []Request_Network,
 task_index: []^runtime_async.Task,
 dns_ids: []u16,
 dns_head, dns_count: int,
 // Construction reference becomes the Client base on publication. Last drop
 // requires all child owners disposed; registered refs survive final on_done.
 references: u64,
 base_owned: bool,
 registered_tasks: int,
 // runtime is borrowed only while registration witness is protected by mu.
 // Last on_done clears it under the same mutex; no check-unlock-clock TOCTOU.
 runtime: ^runtime_async.Runtime,
 runtime_epoch: u64,
 last_clock: runtime_async.Deadline,
 unstarted_cleanup_started, unstarted_cleanup_done: bool,
 producer_calls, returning_calls: int,
 signal_cells: int,
 dns_draws_reserved, dns_draws_burned: u64,
}
// Detached command/result metadata; no owner copies of Response/Input/Kernel.
Session_Assignment :: struct {
 assignment: Assignment,
 request: http.Request,
 cutoff, setup_cutoff: runtime_async.Deadline,
 secure: bool,
 host: string,
 port: u16,
 ids: DNS_ID_Block,
 addresses: [DNS_RESULT_CAPACITY]net.Endpoint,
 address_count: int,
}

// Pure sizing/mode selection only. Physical backing, scope admission, files,
// entropy, Runtime liveness and Task registration belong to later real owners.
network_config_normalize :: proc(input:Normalized_Config)->(Network_Config,Client_Error) {
 servers:=input.http.resolver.name_servers
 if len(servers)<0 || len(servers)>MAX_NAME_SERVERS || len(servers)>0 && raw_data(servers)==nil {return {},{kind=.Invalid_Config}}
 offers:=input.http.tls.alpn_protocols
 if len(offers)<0 || len(offers)>tls_api.MAX_ALPN_PROTOCOLS || len(offers)>0 && raw_data(offers)==nil {return {},{kind=.Invalid_Config}}
 for offer in offers {if len(offer)<0 || len(offer)>0 && raw_data(offer)==nil {return {},{kind=.Invalid_Config}}}
 if len(input.http.tls.server_name)<0 || len(input.http.tls.server_name)>0 && raw_data(input.http.tls.server_name)==nil ||
    len(input.http.tls.root_cas)<0 || len(input.http.tls.root_cas)>0 && raw_data(input.http.tls.root_cas)==nil {return {},{kind=.Invalid_Config}}
 normalized,error:=config_normalize({http=input.http,capacities=input.capacities,
  idle_timeout=input.idle_timeout,max_age=input.max_age,lifetime=input.lifetime,streaming=input.streaming})
 if error.kind!=.None {return {},error}
 if normalized.request_timeout!=input.request_timeout || normalized.response_body_limit!=input.response_body_limit ||
    normalized.idle_timeout!=input.idle_timeout || normalized.max_age!=input.max_age {
  return {},{kind=.Invalid_Config}
 }
 // Root config validation bounds redirects0..5. The accepted-hop actor keeps
 // their original request handle, admission lease and total deadline.
 if servers!=nil && len(servers)==0 {return {},{kind=.Invalid_Config}}
 for server in servers {if server.address==nil {return {},{kind=.Invalid_Config}}}
 mode:=DNS_Preparation.Numeric_Only
 if input.capacities.dns_ids>0 {mode=.System;if servers!=nil {mode=.Explicit}}
 result:=Network_Config{config=input,dns_preparation=mode,
  resolver_limits=net.DEFAULT_RESOLVER_SNAPSHOT_LIMITS,
  task_count=input.capacities.connections+1,state_bytes=size_of(Client_State)}
 counts:=[4]int{input.capacities.connections,input.capacities.requests,result.task_count,input.capacities.dns_ids}
 sizes:=[4]int{size_of(Session_Actor),size_of(Request_Network),size_of(^runtime_async.Task),size_of(u16)}
 outputs:=[4]^int{&result.actor_storage_bytes,&result.request_storage_bytes,&result.task_index_bytes,&result.dns_storage_bytes}
 for count,index in counts {
  if count>max(int)/sizes[index] {return {},{kind=.Invalid_Config}}
  outputs[index]^=count*sizes[index]
 }
 return result,{}
}

// State.mu is held, Kernel.mu is NOT. Preserve scan positions so frequent
// producers cannot starve cells behind a repeatedly reset cursor.
network_queue_changed_locked :: proc(s:^Client_State) {
 s.coordinator.scan_remaining=len(s.requests)
 s.coordinator.next_deadline={}
}

// State.mu is held. The exact generation is cleared BEFORE physical disposal;
// unused reserved draws are burned, never put back in the fresh-ID ring.
@(private)
network_queue_forget_locked :: proc(s:^Client_State,handle:Request_Handle) {
 if handle.owner_id!=s.kernel.owner_id || handle.slot==0 || u64(handle.slot)>u64(len(s.requests)) {return}
 metadata:=&s.requests[int(handle.slot)-1]
 if metadata.generation!=handle.generation {return}
 assert(metadata.ids.count>=0 && metadata.ids.count<=DNS_IDS_PER_QUERY)
 network_saturate(&s.dns_draws_burned,u64(metadata.ids.count))
 metadata^={generation=handle.generation}
 network_queue_changed_locked(s)
}

// Preserve ordinary first-hop admission and its exact callable type.
network_queue_claim :: proc(s:^Client_State,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error) {
 return network_queue_claim_budget(s,preparing,origin,now,DNS_TOTAL_QUERY_LIMIT)
}

// The allowance belongs to the original accepted request, including redirects.
// Reserve no more than its remainder; assignment_take deducts the moved block
// once. This helper does not replenish that allowance or inspect query state.
// Zero allowance can still reuse verified Idle or use prepared/numeric addresses.
network_queue_claim_budget :: proc(s:^Client_State,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64,total_queries_remaining:int)->(Pool_Reservation,Client_Error) {
 if !network_valid(s) || origin==nil || now<0 || total_queries_remaining<0 || total_queries_remaining>DNS_TOTAL_QUERY_LIMIT {return {},{kind=.Invalid_Config}}
 if origin.key.profile_id!=s.profile.owner_id || origin.key.port==0 || len(origin.key.host)<=0 || raw_data(origin.key.host)==nil ||
    len(origin.storage)!=len(origin.key.host) || raw_data(origin.storage)!=raw_data(origin.key.host) || origin.allocator.procedure==nil {return {},{kind=.Invalid_Config}}
 if !network_state_retain(s) {return {},{kind=.Closed}}
 defer network_state_release(s)
 metadata:=Request_Network{generation=preparing.request.generation,query_budget_left=total_queries_remaining}
 address:=net.parse_address(origin.key.host)
 if address!=nil {
  metadata.prepared_addresses[0]={address=address,port=int(origin.key.port)};metadata.prepared_address_count=1
 } else {
  metadata.needs_dns=true
  // Prepared resolver storage is immutable while this retained State lives.
  _,valid:=net.resolver_snapshot_name_servers(&s.resolver)
  if valid {
   count,found,error:=net.resolver_snapshot_lookup(&s.resolver,origin.key.host,metadata.prepared_addresses[:],int(origin.key.port))
   if error.kind!=.None {return {},network_snapshot_error(error)}
   if found {metadata.prepared_address_count=count;metadata.needs_dns=false}
  }
 }
 block:DNS_ID_Block
 sync.lock(&s.mu)
 if s.phase==.Closing || s.phase==.Disposing {sync.unlock(&s.mu);return {},{kind=.Closed}}
 // An Idle peek avoids consuming scarce IDs. It is never carried across an
// unlock as an admission right: pool_reserve_policy recomputes its own commit.
 sync.lock(&s.kernel.mu)
 request:=pool_request_locked(&s.kernel,preparing.request)
 if request==nil {sync.unlock(&s.kernel.mu);sync.unlock(&s.mu);return {},{kind=.Invalid_Handle}}
 if request.state!=.Preparing || request.origin.slot!=0 || request.session.slot!=0 || request.cancel_requested {
  sync.unlock(&s.kernel.mu);sync.unlock(&s.mu);return {},{kind=.Invalid_State}
 }
 selection,selection_error:=pool_select_locked(&s.kernel,origin.key,now,false)
 sync.unlock(&s.kernel.mu)
 idle:=selection_error.kind==.None && selection.session.slot!=0
 if metadata.needs_dns && !idle {
  // An exhausted original allowance cannot be repaired by fresh bank refill.
  // Reject before committing any physical/waiter/origin claim. State.mu keeps
  // the Idle observation serialized with network admission and publication.
  if total_queries_remaining==0 {
   sync.unlock(&s.mu)
   return {},{kind=.Request_Error,http={kind=.Dial_Failed,phase=.DNS,network=net.Resolve_Error.Unable_To_Resolve,write_effect=.Not_Sent}}
  }
  sync.unlock(&s.mu)
  reserved,error:=network_dns_reserve(s,min(DNS_IDS_PER_QUERY,total_queries_remaining))
  if error.kind!=.None && error.kind!=.Pending {return {},error}
  block=reserved
  sync.lock(&s.mu)
 }
 if s.phase==.Closing || s.phase==.Disposing {
  sync.unlock(&s.mu);network_dns_burn(s,&block);return {},{kind=.Closed}
 }
 reservation,error:=pool_reserve_policy(&s.kernel,preparing,origin,now,!metadata.needs_dns || block.count>0)
 if error.kind!=.None {sync.unlock(&s.mu);network_dns_burn(s,&block);return {},error}
 // A concurrent producer may have made Idle reusable while draws were being
// reserved. Keep the draw block only if a new dial/waiter can actually use it.
 sync.lock(&s.kernel.mu)
 reused:=reservation.session.slot!=0 && s.kernel.sessions[int(reservation.session.slot)-1].reserved_from==.Idle
 sync.unlock(&s.kernel.mu)
 if !reused {metadata.ids=block;block={}}
 metadata.awaiting_ids=metadata.needs_dns && metadata.ids.count==0 && !reused
 s.requests[int(preparing.request.slot)-1]=metadata
 network_queue_changed_locked(s)
 sync.unlock(&s.mu)
 network_dns_burn(s,&block)
 return reservation,{}
}

// State.mu is held, Kernel.mu is NOT. Commit and DNS-stage publication are one
// serialized network transaction: dispatch cannot observe a transient Queued
// named request without its required IDs. Rejection preserves input ownership.
network_queue_committed_locked :: proc(s:^Client_State,preparing:Preparing_Request,input:^Request_Owner,now:runtime_async.Deadline)->Client_Error {
 if s.phase==.Closing || s.phase==.Disposing {return {kind=.Closed}}
 if preparing.request.owner_id!=s.kernel.owner_id || preparing.request.slot==0 || u64(preparing.request.slot)>u64(len(s.requests)) {return {kind=.Invalid_Handle}}
 metadata:=&s.requests[int(preparing.request.slot)-1]
 if metadata.generation!=preparing.request.generation {return {kind=.Invalid_State}}
 error:=kernel_commit(&s.kernel,preparing,input,now)
 if error.kind!=.None {return error}
 sync.lock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,preparing.request)
 assert(request!=nil && request.state==.Queued)
 if metadata.awaiting_ids {request.stage=.Awaiting_DNS_IDs}
 s.kernel.dispatch_dirty=true
 sync.unlock(&s.kernel.mu)
 network_queue_changed_locked(s)
 return {}
}

@(private)
pool_dispatchable :: proc(request:^Request_Slot,now:i64,allow_waiting_dns:bool=false)->bool {
 return request!=nil && request.state==.Queued && !request.cancel_requested &&
        (request.stage!=.Awaiting_DNS_IDs || allow_waiting_dns) &&
        (request.deadline.at==0 || now<request.deadline.at)
}
@(private)
pool_head_locked :: proc(k:^Kernel,origin:Cell_Handle,now:i64,allow_waiting_dns:bool=false)->^Request_Slot {
 slot:=&k.origins[int(origin.slot)-1]
 if slot.queue_head==0 || u64(slot.queue_head)>u64(len(k.requests)) {return nil}
 request:=&k.requests[int(slot.queue_head)-1]
 if !pool_dispatchable(request,now,allow_waiting_dns) || request.origin!=origin || request.session.slot!=0 {return nil}
 return request
}
@(private)
pool_assign_locked :: proc(k:^Kernel,origin:Cell_Handle,session_index:u32,now:i64,waiting:bool)->Assignment {
 session:=&k.sessions[int(session_index)-1]
 selected:=&k.origins[int(origin.slot)-1]
 request:^Request_Slot
 handle:Request_Handle
 if waiting {
  // Only an already healthy Idle connection can bypass missing DNS IDs.
  request=pool_head_locked(k,origin,now,session.state==.Idle)
  assert(request!=nil)
  handle={owner_id=k.owner_id,slot=selected.queue_head,generation=request.generation}
  selected.queue_head=request.queue_next
  if selected.queue_head!=0 {k.requests[int(selected.queue_head)-1].queue_previous=0} else {selected.queue_tail=0}
  request.queue_previous,request.queue_next=0,0
  disposal,error:=kernel_origin_release_locked(k,origin,.Waiter)
  assert(error.kind==.None && disposal.origin.slot==0)
  session.request=handle
  request.session={slot=session_index,generation=session.generation}
 } else {
  handle=session.request
  request=pool_request_locked(k,handle)
  assert(request!=nil)
 }
 old:=session.state
 if old==.Reserved {k.counters.reserved_connections-=1}
 if old==.Reserved && session.reserved_from==.Idle || old==.Idle {
  session.state=.Busy
  k.counters.active_connections+=1
  if old==.Idle {k.counters.idle_connections-=1}
  if k.counters.reuse_count!=max(u64) {k.counters.reuse_count+=1}
  request.stage=.Writing
 } else {
  session.state=.Connecting
  k.counters.connecting_connections+=1
  request.stage=.Connecting
 }
 session.reserved_from=.Free
 request.state=.Active
 k.counters.queued_requests-=1;k.counters.active_requests+=1
 k.dispatch_origin={};k.dispatch_session_cursor=0;k.dispatch_dirty=true;k.idle_dirty=true
 return {request=handle,session={slot=session_index,generation=session.generation}}
}

// One inspection per charged work unit, including unoccupied fixed capacity.
// Origin and within-origin progress persist across work1 calls.
pool_dispatch :: proc(k:^Kernel,work:int,now:i64)->(Assignment,int,Client_Error) {
 if k==nil || k.self!=k {return {},0,{kind=.Invalid_State}}
 if work<1 || work>MAX_WORK_PER_RESUME || now<0 {return {},0,{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.closed {return {},0,{kind=.Closed}}
 used:=0
 for used<work {
  if k.dispatch_origin.slot==0 {
   if k.dispatch_remaining==0 {
    if !k.dispatch_dirty {return {},used,{}}
    k.dispatch_dirty=false;k.dispatch_remaining=len(k.origins)
   }
   index:=int(k.dispatch_cursor)%len(k.origins)
   k.dispatch_cursor=u32((index+1)%len(k.origins));k.dispatch_remaining-=1
   used+=1
   origin:=&k.origins[index]
   if origin.state!=.Occupied {continue}
   k.dispatch_origin={slot=u32(index+1),generation=origin.generation}
   k.dispatch_session_cursor=0
   continue
  }
  origin_handle:=k.dispatch_origin
  origin:=&k.origins[int(origin_handle.slot)-1]
  if origin.state!=.Occupied || origin.generation!=origin_handle.generation {
   // A preceding API retired this origin; advancing metadata costs no scan.
   k.dispatch_origin={};continue
  }
  if int(k.dispatch_session_cursor)<len(k.sessions) {
   index:=int(k.dispatch_session_cursor);k.dispatch_session_cursor+=1;used+=1
   session:=&k.sessions[index]
   if session.origin!=origin_handle {continue}
   if session.state==.Reserved {
    request:=pool_request_locked(k,session.request)
    if pool_dispatchable(request,now,session.reserved_from==.Idle) && request.origin==origin_handle &&
       request.session==(Cell_Handle{slot=u32(index+1),generation=session.generation}) {
     return pool_assign_locked(k,origin_handle,u32(index+1),now,false),used,{}
    }
   } else if session.state==.Idle && !pool_expired(session,k,now) && pool_head_locked(k,origin_handle,now,true)!=nil {
    return pool_assign_locked(k,origin_handle,u32(index+1),now,true),used,{}
   }
   continue
  }
  // Free-stack selection is a separate bounded metadata unit, never a scan.
  used+=1
  request:=pool_head_locked(k,origin_handle,now)
  if request!=nil && origin.sessions<k.config.capacities.connections_per_origin && k.session_free_count>0 {
   index:=k.session_free[k.session_free_count-1]
   session:=&k.sessions[int(index)-1]
   assert(session.state==.Free && session.generation!=0)
   k.session_free_count-=1
   assert(kernel_origin_retain_locked(k,origin_handle,.Session).kind==.None)
   generation:=session.generation
   session^={generation=generation,origin=origin_handle,created_at=now}
   return pool_assign_locked(k,origin_handle,index,now,true),used,{}
  }
  k.dispatch_origin={};k.dispatch_session_cursor=0
 }
 if k.dispatch_origin.slot==0 && k.dispatch_remaining==0 && !k.dispatch_dirty {return {},used,{}}
 return {},used,{kind=.Pending}
}

@(private)
pool_deadline :: proc(start,duration:i64)->i64 {
 if start>max(i64)-duration {return max(i64)}
 return start+duration
}

pool_idle_candidate :: proc(k:^Kernel,work:int,now:i64)->(Cell_Handle,int,Client_Error) {
 if k==nil || k.self!=k {return {},0,{kind=.Invalid_State}}
 if work<1 || work>MAX_WORK_PER_RESUME || now<0 {return {},0,{kind=.Invalid_Config}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 if k.idle_remaining==0 {
  k.idle_remaining=len(k.sessions);k.idle_deadline=0;k.idle_dirty=false
 }
 used:=0
 for used<work {
  index:=int(k.idle_cursor)%len(k.sessions)
  k.idle_cursor=u32((index+1)%len(k.sessions));k.idle_remaining-=1;used+=1
  session:=&k.sessions[index]
  if session.state==.Idle {
   if k.closed || pool_expired(session,k,now) {return {slot=u32(index+1),generation=session.generation},used,{}}
   deadline:=min(pool_deadline(session.created_at,i64(k.config.max_age)),pool_deadline(session.idle_since,i64(k.config.idle_timeout)))
   if k.idle_deadline==0 || deadline<k.idle_deadline {k.idle_deadline=deadline}
  }
  if k.idle_remaining==0 {
   if !k.idle_dirty {return {},used,{}}
   // A mutation behind this cursor may already have consumed its external wake.
   // Recompute the entire deadline before allowing the coordinator to park.
   k.idle_remaining=len(k.sessions);k.idle_deadline=0;k.idle_dirty=false
  }
 }
 return {},used,{kind=.Pending}
}
