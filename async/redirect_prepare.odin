package surf_async

import surf ".."
import http "../../http"
import h1 "../../http/v1"
import "core:mem"

@(private)
redirect_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return (av<=bv && bv-av<uintptr(an)) || (bv<av && av-bv<uintptr(bn))
}
@(private)
redirect_empty :: proc(h:^Redirect_Handoff)->bool {
 return h.phase==.Empty && h.request==(Request_Handle{}) && raw_data(h.input.storage)==nil && h.input.allocator.procedure==nil &&
  raw_data(h.input.request.url)==nil && raw_data(h.input.request.headers)==nil && raw_data(h.input.request.body)==nil &&
  raw_data(h.origin.storage)==nil && h.origin.allocator.procedure==nil && raw_data(h.origin.key.host)==nil &&
  len(h.input.storage)==0 && len(h.input.request.url)==0 && len(h.input.request.headers)==0 && len(h.input.request.body)==0 &&
  len(h.origin.storage)==0 && len(h.origin.key.host)==0 && h.origin.key.profile_id==0 && h.origin.key.port==0 && !h.origin.key.secure &&
  h.next_hop==0 && h.queries_remaining==0 && h.last_status==0
}
@(private)
redirect_request_shape :: proc(request:http.Request)->bool {
 if len(request.url)<0 || len(request.body)<0 || len(request.headers)<0 || len(request.headers)>http.MAX_HEADERS ||
  len(request.url)>0 && raw_data(request.url)==nil || len(request.body)>0 && raw_data(request.body)==nil ||
  len(request.headers)>0 && raw_data(request.headers)==nil {return false}
 for field in request.headers {
  if len(field.name)<0 || len(field.value)<0 || len(field.name)>0 && raw_data(field.name)==nil || len(field.value)>0 && raw_data(field.value)==nil {return false}
 }
 return true
}
@(private)
redirect_request_overlaps :: proc(request:http.Request,p:rawptr,n:int)->bool {
 if redirect_overlap(raw_data(request.url),len(request.url),p,n) || redirect_overlap(raw_data(request.body),len(request.body),p,n) ||
  redirect_overlap(raw_data(request.headers),len(request.headers)*size_of(http.Header),p,n) {return true}
 for field in request.headers {
  if redirect_overlap(raw_data(field.name),len(field.name),p,n) || redirect_overlap(raw_data(field.value),len(field.value),p,n) {return true}
 }
 return false
}
@(private)
redirect_preparation_error :: proc(error:Client_Error,status:int)->Client_Error {
 result:=error
 result.http=surf.http_error_classify(result.http,.Protocol,.Response_Received,status)
 return result
}

// Caller keeps Profile/current immutable and independently alive through this
// synchronous borrowed call, outside all State/Kernel locks. Before Preparing,
// malformed/reentrant/alias rejection preserves the caller's Response. Once
// Preparing is installed, the Response is moved+cleared and consumed on EVERY
// subsequent policy/allocation outcome. No intermediate bytes escape to Ready.
// This function does not sample time; its caller rechecks the original cutoff
// and cancellation after all preparation and physical cleanup have returned.
redirect_prepare :: proc(target:^Redirect_Handoff,profile:^Profile,handle:Request_Handle,current:http.Request,response:^surf.Response,redirects,queries_remaining:int,allocator:mem.Allocator)->Client_Error {
 if target==nil || !redirect_empty(target) {return {kind=.Invalid_State}}
 if !profile_valid(profile) || response==nil || handle.owner_id==0 || handle.slot==0 || handle.generation==0 ||
  redirects<0 || redirects>http.MAX_REDIRECTS || queries_remaining<0 || queries_remaining>DNS_TOTAL_QUERY_LIMIT || allocator.procedure==nil {return {kind=.Invalid_Config}}
 status:=response.status
 if status!=301 && status!=302 && status!=303 && status!=307 && status!=308 {return {kind=.Invalid_Config}}
 if !redirect_request_shape(current) {return {kind=.Invalid_Config}}
 if len(response.headers)<0 || len(response.headers)>http.MAX_HEADERS || len(response.headers)>0 && raw_data(response.headers)==nil ||
  len(response.header_storage)<0 || len(response.body)<0 || len(response.body_storage)<0 || cap(response.body_storage)<len(response.body_storage) {return {kind=.Invalid_Config}}
 for field in response.headers {
  if len(field.name)<0 || len(field.value)<0 || len(field.name)>0 && raw_data(field.name)==nil || len(field.value)>0 && raw_data(field.value)==nil {return {kind=.Invalid_Config}}
 }
 if redirect_overlap(target,size_of(Redirect_Handoff),response,size_of(surf.Response)) ||
  redirect_overlap(target,size_of(Redirect_Handoff),profile,size_of(Profile)) ||
  redirect_overlap(target,size_of(Redirect_Handoff),raw_data(profile.storage),len(profile.storage)) ||
  redirect_request_overlaps(current,target,size_of(Redirect_Handoff)) ||
  redirect_request_overlaps({headers=response.headers},target,size_of(Redirect_Handoff)) ||
  redirect_overlap(target,size_of(Redirect_Handoff),raw_data(response.body),len(response.body)) ||
  redirect_overlap(target,size_of(Redirect_Handoff),raw_data(response.header_storage),len(response.header_storage)) ||
  redirect_overlap(target,size_of(Redirect_Handoff),raw_data(response.body_storage),cap(response.body_storage)) {
  return {kind=.Invalid_Config,http={kind=.Overlapping_Buffers}}
 }
 // Root execute_redirect consumes response storage before target cloning, so
// current input must not borrow any of that independently disposed backing.
 if redirect_request_overlaps(current,raw_data(response.headers),len(response.headers)*size_of(http.Header)) ||
  redirect_request_overlaps(current,raw_data(response.header_storage),len(response.header_storage)) ||
  redirect_request_overlaps(current,raw_data(response.body_storage),cap(response.body_storage)) {
  return {kind=.Invalid_Config,http={kind=.Overlapping_Buffers}}
 }
 header:[http.MAX_HEADER_SIZE]u8
 if _,error:=h1.request_encode_profile(header[:],current,.Keep_Alive);error.kind!=.None {return {kind=.Request_Error,http={kind=error.kind}}}
 base,parse_error:=http.url_parse(current.url)
 if parse_error.kind!=.None {return {kind=.Request_Error,http={kind=parse_error.kind}}}
 target.phase=.Preparing
 consumed:=response^;response^={}
 checked:Redirect_Allocator
 input:Request_Owner
 origin:Prepared_Origin
 success:=false
 // Keep the Preparing guard through every arbitrary prefix destructor. The
// final commit/reset follows all callbacks; no allocator pointer outlives us.
 defer {
  if !success {request_owner_destroy(&input);origin_destroy(&origin)}
  redirect_allocator_destroy(&checked)
  surf.response_destroy(&consumed)
  if success {
   target^={phase=.Ready,request=handle,input=input,origin=origin,next_hop=redirects+1,queries_remaining=queries_remaining,last_status=status}
  }else{target^={}}
 }
 if error:=redirect_allocator_init(&checked,allocator);error.kind!=.None {return redirect_preparation_error(error,status)}
 temporary:=mem.Allocator{redirect_allocator_proc,&checked}
 url,error:=surf.execute_redirect(&consumed,current,base,profile.config.http,redirects,temporary)
 if checked.failure.kind!=.None {return redirect_preparation_error(checked.failure,status)}
 if error.kind!=.None {return redirect_preparation_error({kind=.Request_Error,http=error},status)}
 next:=current;next.url=url
 cloned,clone_error:=request_clone(next,allocator)
 if clone_error.kind!=.None {return redirect_preparation_error(clone_error,status)}
 input=cloned
 prepared,origin_error:=origin_prepare(profile,url,temporary)
 if checked.failure.kind!=.None {return redirect_preparation_error(checked.failure,status)}
 if origin_error.kind!=.None {return redirect_preparation_error(origin_error,status)}
 // origin_prepare used the checked stack adapter for typed allocation causes.
// Detach the exact whole grant before replacing its allocator with permanent
// provenance. Temporary cleanup then owns only the helper's surviving URL.
 assert(redirect_allocator_detach(&checked,prepared.storage,1))
 prepared.allocator=allocator;origin=prepared
 success=true
 return {}
}

// Preparing is an outstanding borrowed construction, so reentrant destruction
// rejects by doing nothing. Ready destruction clears before the first physical
// free; that callback may destroy/free the public handoff header itself.
redirect_handoff_destroy :: proc(target:^Redirect_Handoff) {
 if target==nil || target.phase==.Preparing {return}
 old:=target^;target^={}
 request_owner_destroy(&old.input)
 origin_destroy(&old.origin)
}
