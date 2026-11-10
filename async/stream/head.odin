package surf_stream

import surf "../.."
import http "../../../http"
import "core:sync"

head_empty :: proc(head:^Head)->bool {
 return head!=nil && head._owner==nil && head.response.status==0 &&
  raw_data(head.response.header_storage)==nil && raw_data(head.response.headers)==nil &&
  raw_data(head.response.body_storage)==nil && cap(head.response.body_storage)==0 &&
  raw_data(head.response.body)==nil && head.response.allocator.procedure==nil &&
  head.response.allocator.data==nil && head.response._allocator_scope=={} &&
  head.response.body_storage.allocator.procedure==nil &&
  head.response.body_storage.allocator.data==nil
}

publish_head :: proc(cell:^Channel,response:^surf.Response,length:i64,encoding:Encoding)->bool {
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if cell.closed || cell.head_ready || cell.head_taken {return false}
 cell.header_bytes=len(response.header_storage)+len(response.headers)*size_of(http.Header)
 cell.head=response^;response^={}
 cell.wire_length=length;cell.encoding=encoding;cell.head_ready=true
 return true
}

take_head :: proc(cell:^Channel,destination:^Head)->Error {
 if destination==nil || aliases(cell,destination,size_of(Head)) || !head_empty(destination) {return {kind=.Invalid}}
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if cell.head_ready {
  if cell.references==max(int) {return {kind=.Capacity}}
  cell.references+=1
  destination^={response=cell.head,wire_content_length=cell.wire_length,
    delivery=cell.encoding,_owner=cell}
  cell.head={};cell.head_ready=false;cell.head_taken=true
  return {}
 }
 if cell.head_taken {return {kind=.Invalid}}
 if cell.error.kind!=.None {return {http=cell.error}}
 if cell.closed {return {kind=.Closed}}
 return {kind=.Pending}
}

head_destroy :: proc(head:^Head) {
 if head==nil {return}
 old:=head^;head^={}
 surf.response_destroy(&old.response)
 if old._owner!=nil {sync.lock(&old._owner.mu);old._owner.header_bytes=0;sync.unlock(&old._owner.mu)}
 release(old._owner)
}
