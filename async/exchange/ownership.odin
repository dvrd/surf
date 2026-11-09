package surf_exchange

import surf "../.."
import http "../../../http"
import h1 "../../../http/v1"
import "core:mem"

@(private)
exchange_grant :: proc(size,alignment:int,allocator:mem.Allocator)->([]u8,surf.HTTP_Error) {
 if size<0 || allocator.procedure==nil {return nil,{kind=.Invalid_Config}}
 if size==0 {return nil,{}}
 grant,cause:=allocator.procedure(allocator.data,.Alloc,size,alignment,nil,0)
 if cause!=nil || len(grant)!=size || raw_data(grant)==nil || uintptr(raw_data(grant))%uintptr(alignment)!=0 {
  if raw_data(grant)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(grant),len(grant))}
  if cause==nil {cause=.Out_Of_Memory}
  return nil,{kind=.Allocation_Failed,allocation=cause}
 }
 for &byte in grant {byte=0}
 return grant,{}
}
@(private)
exchange_free :: proc(grant:[]u8,alignment:int,allocator:mem.Allocator) {
 if raw_data(grant)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(grant),len(grant))}
}
@(private)
exchange_response_empty :: proc(r:^surf.Response)->bool {
 return r!=nil && r.status==0 && raw_data(r.headers)==nil && raw_data(r.header_storage)==nil &&
        raw_data(r.body)==nil && raw_data(r.body_storage)==nil && cap(r.body_storage)==0 &&
        r.allocator.procedure==nil && r._allocator_scope=={}
}
@(private)
exchange_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return (av<=bv && bv-av<uintptr(an)) || (bv<av && av-bv<uintptr(bn))
}
@(private)
exchange_aliases :: proc(x:^Exchange,request:http.Request)->bool {
 if exchange_overlap(x,size_of(Exchange),raw_data(request.url),len(request.url)) ||
    exchange_overlap(x,size_of(Exchange),raw_data(request.body),len(request.body)) {return true}
 if len(request.headers)>http.MAX_HEADERS {return false} // Encoder reports the bound before dereference.
 if exchange_overlap(x,size_of(Exchange),raw_data(request.headers),len(request.headers)*size_of(http.Header)) {return true}
 for field in request.headers {
  if exchange_overlap(x,size_of(Exchange),raw_data(field.name),len(field.name)) ||
     exchange_overlap(x,size_of(Exchange),raw_data(field.value),len(field.value)) {return true}
 }
 return false
}

@(private)
exchange_copy_head :: proc(x:^Exchange)->surf.HTTP_Error {
 storage,error:=exchange_grant(x._response_head_used,1,x._allocator)
 if error.kind!=.None {return error}
 x._response.header_storage=storage;x._response.allocator=x._allocator
 copy(storage,x._response_head[:x._response_head_used])
 head,_,decoded:=h1.response_header_decode(storage)
 if decoded.kind!=.None {return surf.http_protocol_error(decoded)}
 descriptors,allocation:=exchange_grant(head.header_count*size_of(http.Header),align_of(http.Header),x._allocator)
 if allocation.kind!=.None {return allocation}
 if head.header_count>0 {
  headers:=(cast([^]http.Header)raw_data(descriptors))[:head.header_count]
  copy(headers,head.headers[:head.header_count]);x._response.headers=headers
 }
 x._response.status=head.status
 x._response.body_storage.allocator=x._allocator
 return {}
}

// Growth publishes the new owner before freeing old storage. _busy excludes
// reentrant public mutation until the caller returns a fresh-clock barrier.
@(private)
exchange_grow_body :: proc(x:^Exchange,needed:int)->(bool,surf.HTTP_Error) {
 body:=x._response.body_storage
 if needed<=cap(body) {return false,{}}
 if needed>x._options.body_limit {return false,{kind=.Body_Oversized}}
 capacity:=min(x._options.body_limit,max(needed,4096,2*cap(body)))
 storage,error:=exchange_grant(capacity,1,x._allocator)
 if error.kind!=.None {return false,error}
 copy(storage,body[:])
 replacement:=transmute([dynamic]u8)mem.Raw_Dynamic_Array{data=raw_data(storage),len=len(body),cap=len(storage),allocator=x._allocator}
 x._response.body_storage=replacement
 if raw_data(body)!=nil {exchange_free((cast([^]u8)raw_data(body))[:cap(body)],1,body.allocator)}
 return true,{}
}
@(private)
exchange_append_body :: proc(x:^Exchange,source:[]u8)->(bool,surf.HTTP_Error) {
 length:=len(x._response.body_storage)
 if len(source)>x._options.body_limit-length {return false,{kind=.Body_Oversized}}
 grew,error:=exchange_grow_body(x,length+len(source))
 if error.kind!=.None || grew {return grew,error}
 raw:=cast(^mem.Raw_Dynamic_Array)&x._response.body_storage
 copy((cast([^]u8)raw.data)[length:length+len(source)],source)
 raw.len+=len(source)
 return false,{}
}
