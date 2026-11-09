package surf_async

import signal "../../async/signal"
import "core:sync"

@(private)
network_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return (av<=bv && bv-av<uintptr(an)) || (bv<av && av-bv<uintptr(bn))
}
@(private)
network_alias :: proc(s:^Client_State,p:rawptr,n:int)->bool {
 return network_overlap(p,n,s,size_of(Client_State)) ||
        network_overlap(p,n,raw_data(s.actors),len(s.actors)*size_of(Session_Actor)) ||
        network_overlap(p,n,raw_data(s.requests),len(s.requests)*size_of(Request_Network)) ||
        network_overlap(p,n,raw_data(s.task_index),len(s.task_index)*size_of(rawptr)) ||
        network_overlap(p,n,raw_data(s.dns_ids),len(s.dns_ids)*size_of(u16))
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
