package surf_async

import surf ".."
import http "../../http"
import rt "base:runtime"
import "core:bytes"
import "core:fmt"
import "core:mem"
import charged "core:mem/budget"
import "core:net"
import scopes "core:sync/budget"
import "core:testing"

Prepare_Fault :: struct {
 backing:mem.Allocator,
 calls,at,mode,returned:int,
 alignments:[16]int,
 whole,reported:[]u8,
 triggered:bool,
 hook:proc(rawptr),user:rawptr,hook_mode:mem.Allocator_Mode,
}
prepare_fault :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 f:=cast(^Prepare_Fault)data
 if mode==f.hook_mode && f.hook!=nil {hook:=f.hook;f.hook=nil;hook(f.user)}
 if mode==.Free && old_memory!=nil && old_memory==raw_data(f.reported) {
  assert(old_size==len(f.reported));whole:=f.whole;f.whole=nil;f.reported=nil;f.returned+=1
  return f.backing.procedure(f.backing.data,.Free,0,alignment,raw_data(whole),len(whole),location)
 }
 if mode==.Alloc || mode==.Alloc_Non_Zeroed {
  assert(f.calls<len(f.alignments));f.alignments[f.calls]=alignment;f.calls+=1
  if f.at>0 && f.calls==f.at {
   f.triggered=true
   if f.mode==0 {return nil,.Out_Of_Memory}
   if f.mode==1 {return nil,nil}
   requested:=size
   if f.mode==3 {requested-=1}
   if f.mode==4 {requested+=1}
   if f.mode==5 {requested+=alignment}
   grant,error:=f.backing.procedure(f.backing.data,mode,requested,alignment,nil,0,location);assert(error==nil && raw_data(grant)!=nil)
   f.whole,f.reported=grant,grant
   if f.mode==5 {f.reported=grant[1:size+1]}
   return f.reported,.Out_Of_Memory if f.mode==2 else nil
  }
 }
 return f.backing.procedure(f.backing.data,mode,size,alignment,old_memory,old_size,location)
}
Prepare_Wire :: struct {wire:string,at:int}
prepare_read :: proc(data:rawptr,dst:[]u8)->(int,net.Connection_Error) {
 f:=cast(^Prepare_Wire)data
 if f.at==len(f.wire) {return 0,{kind=.Peer_Closed}}
 n:=copy(dst,f.wire[f.at:]);f.at+=n;return n,{}
}
prepare_write :: proc(_:rawptr,src:[]u8)->(int,net.Connection_Error) {return len(src),{}}
prepare_close :: proc(_:rawptr)->net.Connection_Error {return {}}
prepare_response :: proc(status:int,location:string,allocator:mem.Allocator,duplicate:bool=false)->surf.Response {
 extra:="";if duplicate {extra="Location: /other\r\n"}
 wire:=fmt.aprintf("HTTP/1.1 %d Redirect\r\nContent-Length: 4\r\nLocation: %s\r\n%sX-Old: yes\r\n\r\nbody",status,location,extra,allocator=allocator)
 fixture:=Prepare_Wire{wire=wire}
 response,error:=surf.exchange({data=&fixture,read=prepare_read,write=prepare_write,close=prepare_close}, {method=.GET,url="https://example.test/a/b?old=1"},8,allocator)
 delete(wire,allocator);assert(error.kind==.None)
 return response
}
prepare_profile :: proc(p:^Profile,allocator:mem.Allocator,scope:scopes.Scope={},redirects:int=5) {
 config,error:=config_normalize({http={allow_http=true,scope=scope,max_redirects=redirects}});assert(error.kind==.None)
 assert(profile_init(p,config,allocator).kind==.None)
}
prepare_handle :: proc()->Request_Handle {return {owner_id=71,slot=1,generation=3}}

@(test)
redirect_prepare_literal_methods_origins_and_relative_policy :: proc(t:^testing.T) {
 profile:Profile;prepare_profile(&profile,context.allocator);defer profile_destroy(&profile)
 vectors:=[?]struct {method:http.Method,status:int,location,want:string,error:http.Error_Kind,headers:[]http.Header}{
  {.GET,301,"/next","https://example.test/next",.None,nil},
  {.GET,302,"../next?x=2","https://example.test/next?x=2",.None,nil},
  {.GET,303,"?x=2","https://example.test/a/b?x=2",.None,nil},
  {.GET,307,"//EXAMPLE.TEST:443/next","https://EXAMPLE.TEST:443/next",.None,nil},
  {.GET,308,"/a/./b/../next","https://example.test/a/next",.None,nil},
  {.HEAD,301,"/next","",.Unsafe_Redirect,nil},
  {.HEAD,302,"/next","",.Unsafe_Redirect,nil},
  {.HEAD,303,"/next","",.Unsafe_Redirect,nil},
  {.HEAD,307,"/next","https://example.test/next",.None,nil},
  {.HEAD,308,"/next","https://example.test/next",.None,nil},
  {.POST,301,"/next","",.Unsafe_Redirect,nil},
  {.POST,302,"/next","",.Unsafe_Redirect,nil},
  {.POST,303,"/next","",.Unsafe_Redirect,nil},
  {.POST,307,"/next","https://example.test/next",.None,nil},
  {.POST,308,"/next","https://example.test/next",.None,nil},
  {.GET,302,"https://other.test/next","https://other.test/next",.None,{{"Accept","text/plain"},{"User-Agent","owned-test"}}},
  {.GET,302,"https://other.test/next","",.Unsafe_Redirect,{{"Authorization","Bearer opaque"}}},
  {.GET,302,"https://other.test/next","",.Unsafe_Redirect,{{"Cookie","opaque=value"}}},
  {.GET,302,"https://other.test/next","",.Unsafe_Redirect,{{"X-Private","opaque"}}},
  {.POST,307,"https://other.test/next","",.Unsafe_Redirect,nil},
  {.HEAD,307,"https://other.test/next","",.Unsafe_Redirect,nil},
  {.GET,302,"http://example.test/next","",.Insecure_URL,nil},
  {.GET,302,"https://other.test/#fragment","",.Invalid_Redirect,nil},
  {.GET,302,"","",.Invalid_Redirect,nil},
 }
 for sample in vectors {
  response:=prepare_response(sample.status,sample.location,context.allocator)
  target:Redirect_Handoff
  body:[]u8;if sample.method==.POST {body=[]u8{'p',0,255}}
  current:=http.Request{method=sample.method,url="https://example.test/a/b?old=1",headers=sample.headers,body=body}
  error:=redirect_prepare(&target,&profile,prepare_handle(),current,&response,0,17,context.allocator)
  testing.expect_value(t,error.http.kind,sample.error)
  testing.expect(t,response.status==0 && response.header_storage==nil && response.body_storage==nil)
  if sample.error==.None {
   testing.expect(t,error.kind==.None && target.phase==.Ready)
   testing.expect_value(t,target.input.request.url,sample.want)
   testing.expect_value(t,target.input.request.method,sample.method)
   testing.expect(t,bytes.equal(target.input.request.body,body))
   testing.expect_value(t,target.next_hop,1);testing.expect_value(t,target.queries_remaining,17)
   testing.expect_value(t,target.last_status,sample.status);testing.expect_value(t,target.request,prepare_handle())
   testing.expect(t,target.input.allocator.procedure==context.allocator.procedure && target.origin.allocator.procedure==context.allocator.procedure)
  } else {testing.expect(t,target.phase==.Empty && error.kind!=.None && error.http.status==sample.status && error.http.write_effect==.Response_Received)}
  redirect_handoff_destroy(&target)
 }
 for hops in ([2]int{4,5}) {
  response:=prepare_response(307,"/next",context.allocator)
  target:Redirect_Handoff
  error:=redirect_prepare(&target,&profile,prepare_handle(),{method=.GET,url="https://example.test"},&response,hops,0,context.allocator)
  testing.expect_value(t,error.http.kind,http.Error_Kind.None if hops==4 else http.Error_Kind.Redirect_Limit)
  if hops==4 {testing.expect_value(t,target.next_hop,5);testing.expect_value(t,target.queries_remaining,0)}
  redirect_handoff_destroy(&target)
 }
 response:=prepare_response(302,"/one",context.allocator,true);target:Redirect_Handoff
 error:=redirect_prepare(&target,&profile,prepare_handle(),{method=.GET,url="https://example.test"},&response,0,32,context.allocator)
 testing.expect_value(t,error.http.kind,.Invalid_Redirect)
 redirect_handoff_destroy(&target)
 fmt.printf("REDIRECT_PREPARE policy_literal_vectors=%d boundary_vectors=3 memory_codec_only=true\n",len(vectors))
}

@(test)
redirect_prepare_all_new_grant_failures_and_valid_byte_interior_grants :: proc(t:^testing.T) {
 for managed in ([2]bool{false,true}) {
  track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
  backing:=mem.tracking_allocator(&track)
  fault:=Prepare_Fault{backing=backing}
  allocator:=mem.Allocator{prepare_fault,&fault}
  scope:scopes.Scope;binding:charged.Binding
  if managed {
   owner_scope,error:=scopes.create_root({bytes=16<<20,streams=1},backing);assert(error==.None);scope=owner_scope
   owner,cause:=charged.create(scope,{backing=allocator,metadata_allocator=backing});assert(cause.kind==.None);binding=owner
   allocator=charged.allocator(binding)
  }
  profile:Profile;prepare_profile(&profile,backing,scope)
  baseline:=track.current_memory_allocated
  response:=prepare_response(307,"/a/../next",backing);target:Redirect_Handoff
  error:=redirect_prepare(&target,&profile,prepare_handle(),{method=.POST,url="https://example.test/a/b",body=[]u8{'p',0,255}},&response,0,1,allocator)
  assert(error.kind==.None);points:=fault.calls;alignments:=fault.alignments;assert(points>0 && points<16)
  testing.expect(t,target.input.allocator.procedure==allocator.procedure && target.input.allocator.data==allocator.data)
  testing.expect(t,target.origin.allocator.procedure==allocator.procedure && target.origin.allocator.data==allocator.data)
  redirect_handoff_destroy(&target);assert(track.current_memory_allocated==baseline)
  failed_cells,valid_interiors:=0,0
  for at in 1..=points {for mode in 0..<6 {
   fault={backing=backing,at=at,mode=mode}
   response=prepare_response(307,"/a/../next",backing)
   error=redirect_prepare(&target,&profile,prepare_handle(),{method=.POST,url="https://example.test/a/b",body=[]u8{'p',0,255}},&response,0,1,allocator)
   valid:=mode==5 && alignments[at-1]==1
   if valid {testing.expect(t,error.kind==.None && target.phase==.Ready);valid_interiors+=1} else {
    testing.expect(t,error.kind!=.None && error.http.kind==.Allocation_Failed && target.phase==.Empty)
    testing.expect(t,error.http.allocation==.Out_Of_Memory && error.http.status==307 && error.http.write_effect==.Response_Received)
    failed_cells+=1
   }
   testing.expect(t,fault.triggered && response.status==0 && response.headers==nil)
   redirect_handoff_destroy(&target)
   testing.expect(t,fault.whole==nil && fault.returned==(0 if mode<2 else 1))
   testing.expect(t,track.current_memory_allocated==baseline && len(track.bad_free_array)==0)
   if managed {snapshot,_:=scopes.snapshot(scope);testing.expect_value(t,snapshot.used,scopes.Usage{})}
  }}
  fmt.printf("REDIRECT_PREPARE managed=%v allocation_points=%d malformed_cells=%d valid_align1_interior_cells=%d\n",managed,points,failed_cells,valid_interiors)
  profile_destroy(&profile)
  if managed {charged.release(&binding);scopes.release_scope(&scope)}
  testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
  mem.tracking_allocator_destroy(&track)
 }
}

Prepare_Reentry :: struct {
 target:^Redirect_Handoff,profile:^Profile,outer,inner:^surf.Response,
 allocator:mem.Allocator,called:int,guarded,source_preserved,outer_cleared:bool,
}
prepare_reenter :: proc(data:rawptr) {
 c:=cast(^Prepare_Reentry)data;c.called+=1
 before:=c.inner^
 c.outer_cleared=c.outer.status==0 && c.outer.headers==nil && c.outer.header_storage==nil
 error:=redirect_prepare(c.target,c.profile,prepare_handle(),{method=.GET,url="https://example.test/"},c.inner,0,32,c.allocator)
 c.source_preserved=error.kind==.Invalid_State && c.inner.status==before.status &&
  raw_data(c.inner.headers)==raw_data(before.headers) && raw_data(c.inner.header_storage)==raw_data(before.header_storage) &&
  raw_data(c.inner.body_storage)==raw_data(before.body_storage) && len(c.inner.body_storage)==len(before.body_storage)
 redirect_handoff_destroy(c.target)
 c.guarded=c.target.phase==.Preparing
}
Prepare_Header_Free :: struct {target:^Redirect_Handoff,backing:mem.Allocator,cleared,recursive_empty:bool,called:int}
prepare_free_cleared_header :: proc(data:rawptr) {
 c:=cast(^Prepare_Header_Free)data;c.called+=1
 h:=c.target
 c.cleared=h.phase==.Empty && h.request==(Request_Handle{}) && raw_data(h.input.storage)==nil && raw_data(h.origin.storage)==nil
 redirect_handoff_destroy(h)
 c.recursive_empty=h.phase==.Empty
 c.target=nil
 free(h,c.backing)
}

@(test)
redirect_prepare_guards_constructor_callbacks_and_destroy_clears_heap_header :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 backing:=mem.tracking_allocator(&track)
 profile:Profile;prepare_profile(&profile,backing)
 baseline:=track.current_memory_allocated
 for mode in ([3]mem.Allocator_Mode{.Query_Features,.Alloc,.Free}) {
  fault:=Prepare_Fault{backing=backing}
  allocator:=mem.Allocator{prepare_fault,&fault}
  outer:=prepare_response(307,"/next",allocator)
  inner:=prepare_response(302,"/independent",backing)
  target:Redirect_Handoff
  c:=Prepare_Reentry{target=&target,profile=&profile,outer=&outer,inner=&inner,allocator=backing}
  fault.calls=0;fault.hook=prepare_reenter;fault.user=&c;fault.hook_mode=mode
  error:=redirect_prepare(&target,&profile,prepare_handle(),{method=.GET,url="https://example.test/"},&outer,0,32,allocator)
  testing.expect_value(t,error.kind,.None)
  testing.expect(t,c.called==1 && c.guarded && c.source_preserved && c.outer_cleared && target.phase==.Ready)
  redirect_handoff_destroy(&target);surf.response_destroy(&inner)
  testing.expect(t,track.current_memory_allocated==baseline && len(track.bad_free_array)==0)
 }
 fault:=Prepare_Fault{backing=backing};allocator:=mem.Allocator{prepare_fault,&fault}
 h:=new(Redirect_Handoff,backing)
 response:=prepare_response(307,"/next",backing)
 assert(redirect_prepare(h,&profile,prepare_handle(),{method=.GET,url="https://example.test/"},&response,0,32,allocator).kind==.None)
 c:=Prepare_Header_Free{target=h,backing=backing}
 fault.hook=prepare_free_cleared_header;fault.user=&c;fault.hook_mode=.Free
 redirect_handoff_destroy(h) // The callback physically frees h; no later h access.
 testing.expect(t,c.target==nil && c.called==1 && c.cleared && c.recursive_empty)
 testing.expect(t,track.current_memory_allocated==baseline && len(track.bad_free_array)==0)
 profile_destroy(&profile)
 testing.expect_value(t,track.current_memory_allocated,0)
 mem.tracking_allocator_destroy(&track)
 fmt.println("REDIRECT_PREPARE constructor_reentry_modes=3 cleared_heap_header_free=true")
}

@(test)
redirect_prepare_rejects_borrowed_response_aliases_before_consumption :: proc(t:^testing.T) {
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&track)
 profile:Profile;prepare_profile(&profile,allocator)
 for mode in 0..<2 {
  response:=prepare_response(307,"/next",allocator)
  before:=response
  field:=[1]http.Header{{name="X-Borrow",value=response.headers[0].value}}
  current:=http.Request{method=.POST,url="https://example.test/"}
  if mode==0 {current.body=response.body} else {current.headers=field[:]}
  target:Redirect_Handoff
  allocations,allocated:=track.total_allocation_count,track.current_memory_allocated
  error:=redirect_prepare(&target,&profile,prepare_handle(),current,&response,0,32,allocator)
  testing.expect_value(t,error.http.kind,.Overlapping_Buffers)
  testing.expect(t,target.phase==.Empty && response.status==before.status &&
   raw_data(response.headers)==raw_data(before.headers) && raw_data(response.header_storage)==raw_data(before.header_storage) &&
   raw_data(response.body_storage)==raw_data(before.body_storage) && string(response.body)=="body")
  testing.expect(t,track.total_allocation_count==allocations && track.current_memory_allocated==allocated)
  surf.response_destroy(&response)
 }
 profile_destroy(&profile)
 testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&track)
 fmt.println("REDIRECT_PREPARE borrowed_response_alias_rejections=2 source_preserved=true")
}

@(test)
redirect_prepare_preserves_managed_limit_and_closed_scope_causes :: proc(t:^testing.T) {
 for closed in ([2]bool{false,true}) {
  track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
  backing:=mem.tracking_allocator(&track)
  scope,cause:=scopes.create_root({bytes=0,streams=1},backing);assert(cause==.None)
  binding,error:=charged.create(scope,{backing=backing,metadata_allocator=backing});assert(error.kind==.None)
  allocator:=charged.allocator(binding)
  profile:Profile;prepare_profile(&profile,backing,scope)
  baseline:=track.current_memory_allocated
  response:=prepare_response(307,"/next",backing)
  if closed {assert(scopes.close(scope)==.None)}
  target:Redirect_Handoff
  failure:=redirect_prepare(&target,&profile,prepare_handle(),{method=.GET,url="https://example.test/"},&response,0,32,allocator)
  testing.expect(t,failure.kind==.Budget_Rejected && failure.http.kind==.Allocation_Failed)
  testing.expect_value(t,failure.http.budget,scopes.Error.Closed if closed else scopes.Error.Limit_Exceeded)
  testing.expect(t,failure.http.status==307 && failure.http.write_effect==.Response_Received && response.status==0 && target.phase==.Empty)
  snapshot,snapshot_error:=scopes.snapshot(scope)
  testing.expect(t,snapshot_error==.None && snapshot.used==(scopes.Usage{}))
  testing.expect_value(t,track.current_memory_allocated,baseline)
  profile_destroy(&profile);charged.release(&binding);scopes.release_scope(&scope)
  testing.expect(t,track.current_memory_allocated==0 && len(track.bad_free_array)==0)
  mem.tracking_allocator_destroy(&track)
 }
 fmt.println("REDIRECT_PREPARE typed_managed_budget_causes=2 consumed_once=true")
}
