package surf_async

import surf ".."
import http "../../http"
import h1 "../../http/v1"
import "core:mem"
import "core:sync"
import scopes "core:sync/budget"

@(private) kernel_identity_mu: sync.Mutex
@(private) kernel_identity_serial: u64

request_clone :: proc(request:http.Request,allocator:mem.Allocator)->(Request_Owner,Client_Error) {
 header:[http.MAX_HEADER_SIZE]u8
 _,error:=h1.request_encode_profile(header[:],request,.Keep_Alive)
 if error.kind!=.None {return {},{kind=.Request_Error,http={kind=error.kind}}}
 total:=len(request.headers)*size_of(http.Header)
 for size in ([2]int{len(request.url),len(request.body)}) {
  if size>max(int)-total {return {},{kind=.Invalid_Config}}
  total+=size
 }
 for field in request.headers {
  for size in ([2]int{len(field.name),len(field.value)}) {
   if size>max(int)-total {return {},{kind=.Invalid_Config}}
   total+=size
  }
 }
 storage,failure:=kernel_grant(total,align_of(http.Header),allocator)
 if failure.kind!=.None {return {},failure}
 result:=Request_Owner{storage=storage,allocator=allocator,request={method=request.method}}
 at:=len(request.headers)*size_of(http.Header)
 result.request.headers=(cast([^]http.Header)raw_data(storage))[:len(request.headers)]
 n:=copy(storage[at:],request.url)
 result.request.url=cast(string)storage[at:at+n];at+=n
 for field,index in request.headers {
  n=copy(storage[at:],field.name)
  result.request.headers[index].name=cast(string)storage[at:at+n];at+=n
  n=copy(storage[at:],field.value)
  result.request.headers[index].value=cast(string)storage[at:at+n];at+=n
 }
 n=copy(storage[at:],request.body)
 result.request.body=storage[at:at+n]
 return result,{}
}
request_owner_destroy :: proc(owner:^Request_Owner) {
 if owner==nil do return
 old:=owner^;owner^={}
 kernel_free(old.storage,align_of(http.Header),old.allocator)
}

kernel_init :: proc(k:^Kernel,profile:^Profile,resources:^Kernel_Resources)->Client_Error {
 if k==nil || profile==nil || profile.self!=profile || profile.owner_id==0 ||
    resources==nil || resources.self!=resources {return {kind=.Invalid_Config}}
 if k.self!=nil {return {kind=.Invalid_State}}
 normalized,error:=config_normalize({http=profile.config.http,capacities=profile.config.capacities,
  idle_timeout=profile.config.idle_timeout,max_age=profile.config.max_age,lifetime=profile.config.lifetime})
 if error.kind!=.None do return error
 if normalized.capacities!=profile.config.capacities || normalized.request_timeout!=profile.config.request_timeout ||
    normalized.response_body_limit!=profile.config.response_body_limit || normalized.idle_timeout!=profile.config.idle_timeout ||
    normalized.max_age!=profile.config.max_age {return {kind=.Invalid_Config}}
 temporary:=Kernel{config=profile.config,resources=resources,profile=profile,
  references=1,allocator=resources.allocator}
 success:=false
 defer if !success {kernel_free_arrays(&temporary)}
 capacities:=profile.config.capacities
 temporary.requests,error=kernel_array(Request_Slot,capacities.requests,temporary.allocator)
 if error.kind!=.None do return error
 temporary.origins,error=kernel_array(Origin_Slot,capacities.origins,temporary.allocator)
 if error.kind!=.None do return error
 temporary.sessions,error=kernel_array(Session_Model,capacities.connections,temporary.allocator)
 if error.kind!=.None do return error
 temporary.request_free,error=kernel_array(u32,capacities.requests,temporary.allocator)
 if error.kind!=.None do return error
 temporary.origin_free,error=kernel_array(u32,capacities.origins,temporary.allocator)
 if error.kind!=.None do return error
 temporary.session_free,error=kernel_array(u32,capacities.connections,temporary.allocator)
 if error.kind!=.None do return error
 for &slot,index in temporary.requests {slot.generation=1;temporary.request_free[index]=u32(len(temporary.requests)-index)}
 for &slot,index in temporary.origins {slot.generation=1;temporary.origin_free[index]=u32(len(temporary.origins)-index)}
 for &slot,index in temporary.sessions {slot.generation=1;temporary.session_free[index]=u32(len(temporary.sessions)-index)}
 temporary.request_free_count=len(temporary.requests)
 temporary.origin_free_count=len(temporary.origins)
 temporary.session_free_count=len(temporary.sessions)
 temporary.counters.capacities=capacities
 // A fresh kernel domain prevents stale handles from aliasing another Kernel,
 // including later reuse of the same immutable Profile and slot generations.
 identity,available:=profile_identity_next(&kernel_identity_serial,&kernel_identity_mu)
 if !available {return {kind=.Capacity}}
 temporary.owner_id=identity
 temporary.self=k
 k^=temporary
 success=true
 return {}
}
@(private)
kernel_free_arrays :: proc(k:^Kernel) {
 // Locals only after clearing the owner: arbitrary backing frees may reenter.
 old:=k^;k^={}
 kernel_free_array(old.requests,old.allocator)
 kernel_free_array(old.origins,old.allocator)
 kernel_free_array(old.sessions,old.allocator)
 kernel_free_array(old.request_free,old.allocator)
 kernel_free_array(old.origin_free,old.allocator)
 kernel_free_array(old.session_free,old.allocator)
}
kernel_destroy :: proc(k:^Kernel)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu)
 busy:=k.references!=1 || k.preparing!=0 || k.returning!=0 || k.completion_head!=0 || k.completion_tail!=0
 for slot in k.requests {if slot.state!=.Free && slot.state!=.Retired do busy=true}
 for slot in k.origins {if slot.state!=.Free && slot.state!=.Retired do busy=true}
 for slot in k.sessions {if slot.state!=.Free && slot.state!=.Retired do busy=true}
 sync.unlock(&k.mu)
 if busy {return {kind=.Pending}}
 kernel_free_arrays(k)
 return {}
}

// Disposal snapshots never contain the Kernel, Client, Runtime or an active Task.
// Only the scalar cleanup tickets survive, copied separately by the caller.
origin_disposal_destroy :: proc(disposal:^Origin_Disposal) {
 if disposal==nil do return
 old:=disposal^;disposal^={}
 kernel_free(old.owner.storage,1,old.owner.allocator)
}
request_disposal_destroy :: proc(disposal:^Request_Disposal) {
 if disposal==nil do return
 old:=disposal^;disposal^={}
 request_owner_destroy(&old.input)
 surf.response_destroy(&old.response)
 scopes.release(&old.lease)
 origin_disposal_destroy(&old.origin)
}

@(private)
kernel_origin_cell_locked :: proc(k:^Kernel,handle:Cell_Handle)->^Origin_Slot {
 if k==nil || k.self!=k || handle.slot==0 || u64(handle.slot)>u64(len(k.origins)) || handle.generation==0 {return nil}
 slot:=&k.origins[int(handle.slot)-1]
 if slot.generation!=handle.generation {return nil}
 return slot
}
@(private)
origin_reference_counter :: proc(slot:^Origin_Slot,reference:Origin_Reference)->^int {
 switch reference {
 case .Request:return &slot.requests
 case .Session:return &slot.sessions
 case .Preparing:return &slot.preparing
 case .Waiter:return &slot.waiters
 case:return nil
 }
}
kernel_origin_retain_locked :: proc(k:^Kernel,origin:Cell_Handle,reference:Origin_Reference)->Client_Error {
 slot:=kernel_origin_cell_locked(k,origin)
 if slot==nil || slot.state!=.Occupied {return {kind=.Invalid_Handle}}
 counter:=origin_reference_counter(slot,reference)
 if counter==nil {return {kind=.Invalid_Config}}
 if counter^<0 || counter^==max(int) {return {kind=.Capacity}}
 counter^+=1
 return {}
}
kernel_origin_release_locked :: proc(k:^Kernel,origin:Cell_Handle,reference:Origin_Reference)->(Origin_Disposal,Client_Error) {
 slot:=kernel_origin_cell_locked(k,origin)
 if slot==nil || slot.state!=.Occupied {return {},{kind=.Invalid_Handle}}
 counter:=origin_reference_counter(slot,reference)
 if counter==nil {return {},{kind=.Invalid_Config}}
 if counter^<=0 {return {},{kind=.Invalid_State}}
 // Preflight retirement before changing even the reference being released.
 final:=counter^==1
 for other in ([4]^int{&slot.requests,&slot.sessions,&slot.preparing,&slot.waiters}) {
  if other^<0 {return {},{kind=.Invalid_State}}
  if other!=counter && other^!=0 do final=false
 }
 if final && (slot.queue_head!=0 || slot.queue_tail!=0 || k.counters.origins<1 || k.references<1 || k.references==max(int)) {
  return {},{kind=.Invalid_State}
 }
 counter^-=1
 if slot.requests!=0 || slot.sessions!=0 || slot.preparing!=0 || slot.waiters!=0 {return {},{}}
 result:=Origin_Disposal{origin=origin,owner=slot.owner}
 slot.owner={};slot.state=.Returning
 k.references+=1
 return result,{}
}
kernel_origin_cleanup_finish :: proc(k:^Kernel,origin:Cell_Handle)->Client_Error {
 if k==nil || k.self!=k {return {kind=.Invalid_State}}
 sync.lock(&k.mu);defer sync.unlock(&k.mu)
 slot:=kernel_origin_cell_locked(k,origin)
 if slot==nil || slot.state!=.Returning {return {kind=.Invalid_Handle}}
 if slot.requests!=0 || slot.sessions!=0 || slot.preparing!=0 || slot.waiters!=0 ||
    slot.queue_head!=0 || slot.queue_tail!=0 || k.counters.origins<1 || k.references<=1 {return {kind=.Invalid_State}}
 if slot.generation!=max(u64) && k.origin_free_count>=len(k.origin_free) {return {kind=.Invalid_State}}
 generation:=slot.generation
 slot^={generation=generation,state=.Retired}
 if generation!=max(u64) {
  slot.generation+=1;slot.state=.Free
  k.origin_free[k.origin_free_count]=origin.slot;k.origin_free_count+=1
 }
 k.counters.origins-=1
 k.references-=1
 return {}
}
