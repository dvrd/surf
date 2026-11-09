package surf_async

import runtime_async "../../async"
import "core:net"
import "core:sync"

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

network_queue_claim :: proc(s:^Client_State,preparing:Preparing_Request,origin:^Prepared_Origin,now:i64)->(Pool_Reservation,Client_Error) {
 if !network_valid(s) || origin==nil || now<0 {return {},{kind=.Invalid_Config}}
 if origin.key.profile_id!=s.profile.owner_id || origin.key.port==0 || len(origin.key.host)<=0 || raw_data(origin.key.host)==nil ||
    len(origin.storage)!=len(origin.key.host) || raw_data(origin.storage)!=raw_data(origin.key.host) || origin.allocator.procedure==nil {return {},{kind=.Invalid_Config}}
 if !network_state_retain(s) {return {},{kind=.Closed}}
 defer network_state_release(s)
 metadata:=Request_Network{generation=preparing.request.generation,query_budget_left=DNS_TOTAL_QUERY_LIMIT}
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
  sync.unlock(&s.mu)
  reserved,error:=network_dns_reserve(s,DNS_IDS_PER_QUERY)
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
