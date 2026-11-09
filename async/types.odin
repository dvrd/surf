package surf_async

import surf ".."
import http "../../http"
import runtime_async "../../async"
import "core:mem"
import charged "core:mem/budget"
import "core:sync"
import scopes "core:sync/budget"
import "core:time"

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
}
// Pure borrowed view: config_normalize neither clones nor retains any member.
Normalized_Config :: struct {
 http: surf.Config,
 capacities: Capacities,
 idle_timeout, max_age, request_timeout: time.Duration,
 response_body_limit: int,
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
 connecting_connections, active_connections, idle_connections, retiring_connections: int,
 origins, dns_ids, dns_waiters, tasks: int,
 reuse_count, close_count, cancel_count, deadline_count: u64,
 scope: scopes.Snapshot,
 // Signal control cells use the existing fixed heap ABI outside the scope.
 signal_cells: int,
}

// All following types are internal kernel handoffs, not public network owners.
// Indices are one-based; zero is absent. Generation0 never names a live cell.
Cell_Handle :: struct {slot:u32, generation:u64}
Request_State :: enum {Free, Preparing, Queued, Active, Completed, Returning, Retired}
Session_State :: enum {Free, Reserved, Connecting, Busy, Idle, Retiring, Retired}
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
 lease: scopes.Lease,
 origin: Origin_Disposal,
}
