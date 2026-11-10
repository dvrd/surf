package surf_async

import surf ".."
import http "../../http"
import runtime_async "../../async"
import adapter "../../async/connection"
import signal "../../async/signal"
import exchange_api "exchange"
import tls_api "core:crypto/tls"
import "core:mem"
import "core:net"
import "core:sync"
import scopes "core:sync/budget"
import "core:time"

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
  idle_timeout=input.idle_timeout,max_age=input.max_age,lifetime=input.lifetime})
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
