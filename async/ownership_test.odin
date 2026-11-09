package surf_async

import surf ".."
import http "../../http"
import rt "base:runtime"
import "core:bytes"
import "core:fmt"
import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"
import "core:sync"
import "core:testing"

Ownership_Fault :: struct {
 backing:mem.Allocator,
 at,calls,mode,returned:int,
 triggered:bool,
 whole,reported:[]u8,
 on_free:proc(rawptr),
 user:rawptr,
}
ownership_allocate :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 f:=cast(^Ownership_Fault)data
 if mode==.Free && old_memory!=nil {
  if callback:=f.on_free;callback!=nil {f.on_free=nil;callback(f.user)}
  if old_memory==raw_data(f.reported) {
   assert(old_size==len(f.reported))
   whole:=f.whole;f.whole=nil;f.reported=nil;f.returned+=1
   return f.backing.procedure(f.backing.data,.Free,0,alignment,raw_data(whole),len(whole),location)
  }
 }
 if mode==.Alloc || mode==.Alloc_Non_Zeroed {
  f.calls+=1
  if f.at>0 && f.calls==f.at {
   f.triggered=true
   if f.mode==0 {return nil,.Out_Of_Memory}
   if f.mode==1 {return nil,nil}
   requested:=size
   if f.mode==3 {requested-=1}
   if f.mode==4 {requested+=1}
   if f.mode==5 {requested+=alignment}
   grant,error:=f.backing.procedure(f.backing.data,mode,requested,alignment,nil,0,location)
   assert(error==nil && raw_data(grant)!=nil)
   f.whole,f.reported=grant,grant
   if f.mode==5 {f.reported=grant[1:size+1]}
   return f.reported,.Out_Of_Memory if f.mode==2 else nil
  }
 }
 return f.backing.procedure(f.backing.data,mode,size,alignment,old_memory,old_size,location)
}
ownership_usage :: proc(scope:scopes.Scope)->scopes.Snapshot {value,error:=scopes.snapshot(scope);assert(error==.None);return value}
ownership_config :: proc()->Normalized_Config {
 caps:=Capacities{requests=2,origins=2,connections=2,connections_per_origin=2,waiters_per_origin=1,dns_ids=0,work_per_resume=1}
 config,error:=config_normalize({capacities=caps});assert(error.kind==.None);return config
}
ownership_inside :: proc(storage:[]u8,p:rawptr,size:int)->bool {
 if size==0 {return true}
 start,at:=uintptr(raw_data(storage)),uintptr(p)
 return at>=start && at-start<=uintptr(len(storage)) && uintptr(size)<=uintptr(len(storage))-(at-start)
}

@(test)
ownership_request_clone_is_aligned_deep_and_rejection_atomic :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator
 mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 defer mem.tracking_allocator_destroy(&track)
 allocator:=mem.tracking_allocator(&track)
 url:[64]u8;url_text:="https://example.test/path?q=1";copy(url[:],transmute([]u8)url_text)
 name:=[4]u8{'X','-','O','k'};value:=[3]u8{'y','e','s'};body:=[3]u8{'a','b','c'}
 headers:=[1]http.Header{{string(name[:]),string(value[:])}}
 request:=http.Request{method=.POST,url=string(url[:len(url_text)]),headers=headers[:],body=body[:]}
 source_url,source_name,source_value,source_body:=url,name,value,body
 owner,error:=request_clone(request,allocator)
 assert(error.kind==.None)
 testing.expect(t,bytes.equal(url[:],source_url[:]) && bytes.equal(name[:],source_name[:]) && bytes.equal(value[:],source_value[:]) && bytes.equal(body[:],source_body[:]))
 testing.expect(t,uintptr(raw_data(owner.request.headers))%align_of(http.Header)==0)
 testing.expect(t,ownership_inside(owner.storage,raw_data(owner.request.headers),size_of(http.Header)))
 testing.expect(t,ownership_inside(owner.storage,raw_data(owner.request.url),len(owner.request.url)))
 testing.expect(t,ownership_inside(owner.storage,raw_data(owner.request.headers[0].name),len(owner.request.headers[0].name)))
 testing.expect(t,ownership_inside(owner.storage,raw_data(owner.request.headers[0].value),len(owner.request.headers[0].value)))
 testing.expect(t,ownership_inside(owner.storage,raw_data(owner.request.body),len(owner.request.body)))
 url[0]='x';name[0]='z';value[0]='n';body[0]='z';headers[0]={"Changed","changed"}
 testing.expect_value(t,owner.request.url,url_text)
 testing.expect_value(t,owner.request.headers[0],http.Header{"X-Ok","yes"})
 testing.expect_value(t,string(owner.request.body),"abc")
 request_owner_destroy(&owner);request_owner_destroy(&owner)
 testing.expect(t,owner.storage==nil && owner.request.body==nil && track.current_memory_allocated==0 && len(track.bad_free_array)==0)
 // Invalid input is rejected before any allocator call and never retained.
 for invalid in ([]http.Request{{method=cast(http.Method)99,url="https://example.test"},{method=.GET,url="not a URL"},{method=.GET,url="https://example.test",body=[]u8{'x'}},{method=.GET,url="https://example.test",headers={{"X","bad\r\nvalue"}}}}) {
  f:=Ownership_Fault{backing=allocator};a:=mem.Allocator{ownership_allocate,&f}
  rejected,cause:=request_clone(invalid,a)
  testing.expect(t,cause.kind!=.None && rejected.storage==nil && f.calls==0 && track.current_memory_allocated==0)
 }
}

@(test)
ownership_clone_and_kernel_ctor_all_grants_roll_back :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator
 mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 request:=http.Request{method=.POST,url="https://example.test/path",headers={{"X","yes"}},body=[]u8{'a','b','c'}}
 clone_points:=0
 healthy:=Ownership_Fault{backing=a};owner,error:=request_clone(request,{ownership_allocate,&healthy});assert(error.kind==.None)
 clone_points=healthy.calls;assert(clone_points>0);request_owner_destroy(&owner)
 assert(track.current_memory_allocated==0)
 for at in 1..=clone_points {for mode in 0..<6 {
  f:=Ownership_Fault{backing=a,at=at,mode=mode}
  failed,cause:=request_clone(request,{ownership_allocate,&f})
  testing.expect(t,cause.kind!=.None && failed.storage==nil && f.triggered && f.whole==nil)
  testing.expect_value(t,f.returned,0 if mode<2 else 1)
  testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
  testing.expect(t,request.url=="https://example.test/path" && request.headers[0].value=="yes" && string(request.body)=="abc")
 }}
 profile:Profile;assert(profile_init(&profile,ownership_config(),a).kind==.None)
 baseline:=track.current_memory_allocated
 healthy={backing=a};resources:Kernel_Resources;assert(resources_init(&resources,{},{ownership_allocate,&healthy}).kind==.None)
 kernel:Kernel;assert(kernel_init(&kernel,&profile,&resources).kind==.None)
 kernel_points:=healthy.calls;assert(kernel_points>0)
 assert(kernel_destroy(&kernel).kind==.None);resources_destroy(&resources)
 assert(track.current_memory_allocated==baseline)
 for at in 1..=kernel_points {for mode in 0..<6 {
  f:=Ownership_Fault{backing=a,at=at,mode=mode}
  assert(resources_init(&resources,{},{ownership_allocate,&f}).kind==.None)
  cause:=kernel_init(&kernel,&profile,&resources)
  testing.expect(t,cause.kind!=.None && kernel.self==nil && kernel.requests==nil && kernel.origins==nil && kernel.sessions==nil)
  testing.expect(t,f.triggered && f.whole==nil && f.returned==(0 if mode<2 else 1))
  // Check before fixture teardown: no destructor can hide an unpublished grant.
  testing.expect(t,track.current_memory_allocated==baseline && len(track.bad_free_array)==0)
  resources_destroy(&resources)
 }}
 profile_destroy(&profile)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
 fmt.printf("OWNERSHIP07 unmanaged clone_points=%d kernel_points=%d fault_cells=%d\n",clone_points,kernel_points,6*(clone_points+kernel_points))
}


@(test)
ownership_managed_backing_malformed_grants_do_not_retain_charges :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 scope,error:=scopes.create_root({bytes=1<<20,streams=2},a);assert(error==.None)
 profile:Profile;assert(profile_init(&profile,ownership_config(),a).kind==.None)
 baseline:=track.current_memory_allocated
 healthy:=Ownership_Fault{backing=a};resources:Kernel_Resources
 assert(resources_init(&resources,scope,{ownership_allocate,&healthy}).kind==.None)
 owner,cause:=request_clone({method=.GET,url="https://example.test"},resources.allocator);assert(cause.kind==.None)
 clone_points:=healthy.calls;request_owner_destroy(&owner)
 kernel:Kernel;assert(kernel_init(&kernel,&profile,&resources).kind==.None)
 kernel_points:=healthy.calls-clone_points;assert(kernel_destroy(&kernel).kind==.None)
 resources_destroy(&resources)
 assert(track.current_memory_allocated==baseline && ownership_usage(scope).used==(scopes.Usage{}))
 for constructor in 0..<2 {
  points:=clone_points if constructor==0 else kernel_points
  assert(points>0)
  for at in 1..=points {for mode in 0..<6 {
   f:=Ownership_Fault{backing=a,at=at,mode=mode}
   assert(resources_init(&resources,scope,{ownership_allocate,&f}).kind==.None)
   failure:Client_Error
   if constructor==0 {owner,failure=request_clone({method=.GET,url="https://example.test"},resources.allocator)} else {failure=kernel_init(&kernel,&profile,&resources)}
   testing.expect(t,failure.kind==.Allocation_Failed && owner.storage==nil && kernel.self==nil && f.triggered && f.whole==nil)
   testing.expect(t,f.returned==(0 if mode<2 else 1) && ownership_usage(scope).used==(scopes.Usage{}))
   testing.expect(t,track.current_memory_allocated==baseline && len(track.bad_free_array)==0)
   resources_destroy(&resources)
  }}
 }
 profile_destroy(&profile);scopes.release_scope(&scope)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
 fmt.printf("OWNERSHIP07 managed clone_points=%d kernel_points=%d fault_cells=%d\n",clone_points,kernel_points,6*(clone_points+kernel_points))
}

@(test)
ownership_resources_scope_and_existing_binding_are_exact :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator
 mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 root,error:=scopes.create_root({bytes=1<<20,streams=1},a);assert(error==.None)
 child,ce:=scopes.create_child(root,{bytes=1<<19,streams=1});assert(ce==.None)
 sibling,se:=scopes.create_child(root,{bytes=1<<19,streams=1});assert(se==.None)
 foreign_scope,fe:=scopes.create_root({bytes=1<<20,streams=1},a);assert(fe==.None)
 binding,be:=charged.create(child,{backing=a,metadata_allocator=a});assert(be.kind==.None)
 managed:=charged.allocator(binding)
 resources:Kernel_Resources;assert(resources_init(&resources,root,managed).kind==.None)
 testing.expect(t,resources.allocator.procedure==managed.procedure && resources.allocator.data==managed.data)
 lease,admission:=resources_request_lease(&resources);assert(admission.kind==.None)
 testing.expect_value(t,ownership_usage(root).used.streams,u64(1))
 _,rejected:=resources_request_lease(&resources)
 testing.expect(t,rejected.kind==.Budget_Rejected && rejected.http.budget==.Limit_Exceeded)
 bytes,allocation:=mem.alloc_bytes(37,8,resources.allocator);assert(allocation==nil)
 info,known:=charged.allocation_info(resources.allocator,raw_data(bytes));assert(known)
 testing.expect_value(t,ownership_usage(root).used.bytes,info.backing_bytes)
 testing.expect_value(t,ownership_usage(child).used.bytes,info.backing_bytes)
 testing.expect_value(t,charged.stats(binding).allocations,u64(1))
 scopes.release(&lease);resources_destroy(&resources)
 delete(bytes,managed)
 testing.expect_value(t,ownership_usage(root).used,scopes.Usage{})
 for invalid in ([2]scopes.Scope{sibling,foreign_scope}) {
  failure:=resources_init(&resources,invalid,managed)
  testing.expect(t,failure.kind==.Invalid_Config && resources.self==nil)
 }
 // A root-bound allocator cannot claim child coverage; the child-bound view can
 // cover an ancestor. These directions are intentionally different.
 ancestor,ae:=charged.create(root,{backing=a,metadata_allocator=a});assert(ae.kind==.None)
 failure:=resources_init(&resources,child,charged.allocator(ancestor))
 testing.expect(t,failure.kind==.Invalid_Config && resources.self==nil)
 charged.release(&ancestor)
 assert(resources_init(&resources,{},managed).kind==.None)
 charged.release(&binding)
 // Scope0 still retains the existing Binding's allocator view.
 bytes,allocation=mem.alloc_bytes(11,8,resources.allocator);assert(allocation==nil)
 delete(bytes,resources.allocator);resources_destroy(&resources)
 binding,be=charged.create(child,{backing=a,metadata_allocator=a});assert(be.kind==.None)
 assert(scopes.close(child)==.None)
 for configured in ([3]scopes.Scope{child,root,{}}) {
  failure=resources_init(&resources,configured,charged.allocator(binding))
  testing.expect(t,failure.kind==.Budget_Rejected && failure.http.budget==.Closed && resources.self==nil)
  resources_destroy(&resources)
 }
 charged.release(&binding)
 scopes.release_scope(&child);scopes.release_scope(&sibling);scopes.release_scope(&foreign_scope);scopes.release_scope(&root)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
}


@(test)
ownership_managed_constructor_and_clone_preserve_typed_budget_causes :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 profile:Profile;assert(profile_init(&profile,ownership_config(),a).kind==.None)
 for closed in ([2]bool{false,true}) {
  limit:u64=0;if closed {limit=1<<20}
  scope,error:=scopes.create_root({bytes=limit,streams=1},a);assert(error==.None)
  resources:Kernel_Resources;assert(resources_init(&resources,scope,a).kind==.None)
  kernel:Kernel
  if closed {
   assert(kernel_init(&kernel,&profile,&resources).kind==.None)
   assert(kernel_destroy(&kernel).kind==.None)
   assert(scopes.close(scope)==.None)
  }
  baseline:=track.current_memory_allocated
  want:=scopes.Error.Closed if closed else scopes.Error.Limit_Exceeded
  failure:=kernel_init(&kernel,&profile,&resources)
  testing.expect(t,failure.kind==.Budget_Rejected && failure.http.budget==want && kernel.self==nil)
  owner,cause:=request_clone({method=.GET,url="https://example.test"},resources.allocator)
  testing.expect(t,cause.kind==.Budget_Rejected && cause.http.budget==want && owner.storage==nil)
  snapshot:=ownership_usage(scope)
  testing.expect(t,snapshot.used==(scopes.Usage{}) && snapshot.rejected>0 && track.current_memory_allocated==baseline)
  resources_destroy(&resources);scopes.release_scope(&scope)
 }
 profile_destroy(&profile)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
}

Ownership_Probe :: struct {kernel:^Kernel,request:^Request_Owner,allocator:mem.Allocator,scope:scopes.Scope,calls:int,physical_header:bool}
ownership_free_probe :: proc(data:rawptr) {
 p:=cast(^Ownership_Probe)data;p.calls+=1
 if p.kernel!=nil {
  if p.physical_header {
   assert(p.kernel.self==nil)
   assert(kernel_destroy(p.kernel).kind!=.None)
   free(p.kernel,p.allocator);p.kernel=nil
  } else {
   assert(sync.try_lock(&p.kernel.mu));sync.unlock(&p.kernel.mu)
   assert(p.kernel.references>1 && kernel_destroy(p.kernel).kind!=.None)
  }
 }
 if p.request!=nil {
  assert(p.request.storage==nil)
  request_owner_destroy(p.request)
  free(p.request,p.allocator);p.request=nil
 }
 if p.scope!=(scopes.Scope{}) {
  usage:=ownership_usage(p.scope)
  assert(usage.used.bytes>0 && usage.used.streams==1)
 }
}

@(test)
ownership_kernel_stable_cells_and_origin_physical_retirement :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 profile:Profile;resources:Kernel_Resources;kernel:Kernel
 assert(profile_init(&profile,ownership_config(),a).kind==.None)
 assert(resources_init(&resources,{},a).kind==.None)
 assert(kernel_init(&kernel,&profile,&resources).kind==.None)
 testing.expect(t,kernel.self==&kernel && kernel.owner_id!=0 && kernel.references==1)
 testing.expect(t,kernel.request_free_count==2 && kernel.origin_free_count==2 && kernel.session_free_count==2)
 for slot in kernel.requests {testing.expect(t,slot.state==.Free && slot.generation==1)}
 for slot in kernel.origins {testing.expect(t,slot.state==.Free && slot.generation==1)}
 for slot in kernel.sessions {testing.expect(t,slot.state==.Free && slot.generation==1)}
 requests,origins,sessions:=raw_data(kernel.requests),raw_data(kernel.origins),raw_data(kernel.sessions)
 testing.expect(t,kernel_init(&kernel,&profile,&resources).kind!=.None && raw_data(kernel.requests)==requests && raw_data(kernel.origins)==origins && raw_data(kernel.sessions)==sessions)
 copied:=kernel;testing.expect(t,kernel_destroy(&copied).kind!=.None && kernel.self==&kernel)
 for exhausted in ([2]bool{false,true}) {
  // Seed one legitimate Occupied origin to isolate the shared retain/release
  // module before later admission/pool writers exist. No request is fabricated.
  index:=kernel.origin_free[kernel.origin_free_count-1];kernel.origin_free_count-=1;kernel.origin_free[kernel.origin_free_count]=0
  generation:=kernel.origins[index-1].generation
  if exhausted {generation=max(u64)}
  f:=Ownership_Fault{backing=a}
  origin,error:=origin_prepare(&profile,"https://example.test",{ownership_allocate,&f});assert(error.kind==.None)
  kernel.origins[index-1]={generation=generation,state=.Occupied,owner=origin,requests=1};origin={}
  kernel.counters.origins+=1
  handle:=Cell_Handle{index,generation}
  sync.lock(&kernel.mu)
  for reference in ([3]Origin_Reference{.Session,.Preparing,.Waiter}) {assert(kernel_origin_retain_locked(&kernel,handle,reference).kind==.None)}
  for reference in ([3]Origin_Reference{.Request,.Session,.Preparing}) {
   disposal,error:=kernel_origin_release_locked(&kernel,handle,reference);assert(error.kind==.None && disposal.owner.storage==nil)
  }
  disposal,release_error:=kernel_origin_release_locked(&kernel,handle,.Waiter);assert(release_error.kind==.None)
  sync.unlock(&kernel.mu)
  testing.expect(t,kernel.origins[index-1].state==.Returning && kernel.origins[index-1].owner.storage==nil && kernel.references==2)
  testing.expect(t,kernel_destroy(&kernel).kind!=.None)
  probe:=Ownership_Probe{kernel=&kernel};f.on_free=ownership_free_probe;f.user=&probe
  origin_disposal_destroy(&disposal)
  testing.expect(t,disposal.owner.storage==nil && probe.calls==1)
  assert(kernel_origin_cleanup_finish(&kernel,handle).kind==.None)
  testing.expect_value(t,kernel.references,1)
  if exhausted {testing.expect_value(t,kernel.origins[index-1].state,.Retired)} else {testing.expect(t,kernel.origins[index-1].state==.Free && kernel.origins[index-1].generation==generation+1)}
  testing.expect(t,kernel_origin_cleanup_finish(&kernel,handle).kind!=.None)
 }
 assert(kernel_destroy(&kernel).kind==.None);profile_destroy(&profile);resources_destroy(&resources)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
}

@(test)
ownership_response_disposal_outlives_resources_and_scope :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 root,error:=scopes.create_root({bytes=1<<20,streams=1},a);assert(error==.None)
 monitor,me:=scopes.retain_scope(root);assert(me==.None)
 f:=Ownership_Fault{backing=a};resources:Kernel_Resources
 assert(resources_init(&resources,root,{ownership_allocate,&f}).kind==.None)
 lease,le:=resources_request_lease(&resources);assert(le.kind==.None)
 body:=make([dynamic]u8,3,64,resources.allocator);copy(body[:],[]u8{'o','l','d'})
 disposal:=Request_Disposal{response=surf.Response{allocator=resources.allocator,body_storage=body,body=body[:]},lease=lease}
 body=nil;lease={}
 resources_destroy(&resources);scopes.release_scope(&root)
 testing.expect_value(t,string(disposal.response.body),"old")
 testing.expect(t,ownership_usage(monitor).used.bytes>0 && ownership_usage(monitor).used.streams==1)
 probe:=Ownership_Probe{scope=monitor};f.on_free=ownership_free_probe;f.user=&probe
 request_disposal_destroy(&disposal);request_disposal_destroy(&disposal)
 testing.expect(t,probe.calls==1 && disposal.response.body==nil && disposal.lease==(scopes.Lease{}))
 testing.expect_value(t,ownership_usage(monitor).used,scopes.Usage{})
 scopes.release_scope(&monitor)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
}

@(test)
ownership_reentrant_free_can_destroy_physical_owner_headers :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());defer mem.tracking_allocator_destroy(&track)
 a:=mem.tracking_allocator(&track)
 f:=Ownership_Fault{backing=a}
 owner,ae:=new(Request_Owner,a);assert(ae==nil)
 cloned,error:=request_clone({method=.GET,url="https://example.test"},{ownership_allocate,&f});assert(error.kind==.None)
 owner^=cloned;cloned={}
 probe:=Ownership_Probe{request=owner,allocator=a};f.on_free=ownership_free_probe;f.user=&probe
 request_owner_destroy(owner)
 testing.expect(t,probe.calls==1 && probe.request==nil && track.current_memory_allocated==0)
 profile:Profile;resources:Kernel_Resources
 assert(profile_init(&profile,ownership_config(),a).kind==.None)
 f={backing=a};assert(resources_init(&resources,{},{ownership_allocate,&f}).kind==.None)
 kernel,ke:=new(Kernel,a);assert(ke==nil);assert(kernel_init(kernel,&profile,&resources).kind==.None)
 probe={kernel=kernel,allocator=a,physical_header=true};f.on_free=ownership_free_probe;f.user=&probe
 assert(kernel_destroy(kernel).kind==.None)
 testing.expect(t,probe.calls==1 && probe.kernel==nil)
 profile_destroy(&profile);resources_destroy(&resources)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
}
