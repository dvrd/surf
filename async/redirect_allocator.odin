package surf_async

import http "../../http"
import "core:mem"
import charged "core:mem/budget"

@(private)
Redirect_Grant :: struct {storage:[]u8,alignment:int}
@(private)
Redirect_Allocator :: struct {
 backing:mem.Allocator,
 binding:charged.Binding,
 grants:[2]Redirect_Grant,
 failure:Client_Error,
}
@(private)
redirect_allocator_failure :: proc(state:^Redirect_Allocator,error:Client_Error) {
 if state.failure.kind==.None {state.failure=error}
}

// Root redirect_url makes at most two simultaneously live URL grants. After it
// returns, the surviving URL and one origin grant share this same finite ledger.
// No pointer to this stack allocator may appear in a published owner.
@(private)
redirect_allocator_proc :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 state:=cast(^Redirect_Allocator)data
 switch mode {
 case .Query_Features:
  if old_memory==nil {return nil,.Invalid_Argument}
  (cast(^mem.Allocator_Mode_Set)old_memory)^={.Alloc,.Alloc_Non_Zeroed,.Free,.Query_Features}
  return nil,nil
 case .Alloc,.Alloc_Non_Zeroed:
  if state.failure.kind!=.None {return nil,.Out_Of_Memory}
  if size<0 || size>http.MAX_HEADER_SIZE || alignment<1 || alignment&(alignment-1)!=0 {
   redirect_allocator_failure(state,{kind=.Invalid_Config,http={kind=.Invalid_Config}})
   return nil,.Invalid_Argument
  }
  if size==0 {return nil,nil}
  index:=-1
  for grant,i in state.grants {if raw_data(grant.storage)==nil {index=i;break}}
  if index<0 {
   redirect_allocator_failure(state,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=.Out_Of_Memory}})
   return nil,.Out_Of_Memory
  }
  storage:[]u8
  cause:mem.Allocator_Error
  if state.binding!=(charged.Binding{}) {
   grant,error:=charged.allocate(state.binding,size,alignment)
   storage=grant
   if error.kind!=.None {
    redirect_allocator_failure(state,resource_allocation_failure(error))
    return nil,.Out_Of_Memory
   }
  }else{storage,cause=state.backing.procedure(state.backing.data,mode,size,alignment,nil,0,location)}
  // Validate before Root make can construct/copy into any sized view. Even a
// failed grant may report storage; free its full reported extent and alignment.
  if cause!=nil || raw_data(storage)==nil || len(storage)!=size || uintptr(raw_data(storage))%uintptr(alignment)!=0 {
   if raw_data(storage)!=nil {_,_=state.backing.procedure(state.backing.data,.Free,0,alignment,raw_data(storage),len(storage),location)}
   if cause==nil {cause=.Out_Of_Memory}
   redirect_allocator_failure(state,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=cause}})
   return nil,cause
  }
  state.grants[index]={storage=storage,alignment=alignment}
  return storage,nil
 case .Free:
  if old_memory==nil {return nil,nil}
  for &grant in state.grants {
   if raw_data(grant.storage)==old_memory {
    // Odin delete/free use alignment0; unsized free also uses old_size0.
    // A known base pointer authorizes only this recorded whole grant. Never
    // forward those sentinels or a caller-provided extent to the backing.
    if old_size!=0 && len(grant.storage)!=old_size || alignment!=0 && grant.alignment!=alignment {break}
    old:=grant;grant={}
    return state.backing.procedure(state.backing.data,.Free,0,old.alignment,raw_data(old.storage),len(old.storage),location)
   }
  }
  redirect_allocator_failure(state,{kind=.Invalid_Config,http={kind=.Invalid_Config,allocation=.Invalid_Pointer}})
  return nil,.Invalid_Pointer
 case .Free_All,.Resize,.Resize_Non_Zeroed,.Query_Info:
  return nil,.Mode_Not_Implemented
 }
 return nil,.Mode_Not_Implemented
}

@(private)
redirect_allocator_init :: proc(state:^Redirect_Allocator,backing:mem.Allocator)->Client_Error {
 if backing.procedure==nil || .Free not_in mem.query_features(backing) {return {kind=.Invalid_Config}}
 state.backing=backing
 if charged.is_managed_allocator(backing) {
  binding,error:=charged.retain_allocator(backing)
  if error.kind!=.None {return resource_allocation_failure(error)}
  state.binding=binding
 }
 return {}
}

// Transfer one exact origin allocation to its permanent allocator provenance.
// This removes the temporary ledger's ownership without releasing the bytes.
@(private)
redirect_allocator_detach :: proc(state:^Redirect_Allocator,storage:[]u8,alignment:int)->bool {
 for &grant in state.grants {
  if raw_data(grant.storage)==raw_data(storage) && len(grant.storage)==len(storage) && grant.alignment==alignment {
   grant={};return true
  }
 }
 return false
}
@(private)
redirect_allocator_destroy :: proc(state:^Redirect_Allocator) {
 old:=state^;state^={}
 for grant in old.grants {
  if raw_data(grant.storage)!=nil {_,_=old.backing.procedure(old.backing.data,.Free,0,grant.alignment,raw_data(grant.storage),len(grant.storage))}
 }
 charged.release(&old.binding)
}
