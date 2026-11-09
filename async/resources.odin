package surf_async

import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"

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
 storage,cause:=allocator.procedure(allocator.data,.Alloc,size,alignment,nil,0)
 if cause!=nil || len(storage)!=size || raw_data(storage)==nil || uintptr(raw_data(storage))%uintptr(alignment)!=0 {
  if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(storage),len(storage))}
  if cause==nil do cause=.Out_Of_Memory
  return nil,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=cause}}
 }
 for &byte in storage do byte=0
 return storage,{}
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
