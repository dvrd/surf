package surf_exchange

import surf "../.."
import http "../../../http"
import h1 "../../../http/v1"
import "core:mem"
import "core:net"

@(private)
exchange_fill :: proc(x:^Exchange)->Exchange_Step {
 if x._read_at<x._read_used {return .Continue}
 if x._read.accepted {return .Waiting}
 if x._read.ready {
  x._read.ready=false
  result:=x._read.result
  if result.count<0 || result.count>len(x._read_buffer) {exchange_fail(x,{kind=.IO_Failed,transport={kind=.Invalid_Count},phase=.Read});return .Continue}
  x._read_at=0;x._read_used=result.count
  if result.err.kind==.Peer_Closed {x._peer_eof=true}
  if result.count>0 {return .Continue}
  if result.err.kind==.None {exchange_fail(x,{kind=.No_Progress,phase=.Read});return .Continue}
 }
 error:=x._read.result.err
 if error.kind!=.None {
  if error.kind==.Peer_Closed {
   if x._phase==.Reading_Body && x._head.framing==.EOF {x._phase=.Draining;return .Barrier}
   exchange_fail(x,{kind=.Unexpected_EOF,transport=error,phase=.Read})
  } else {exchange_fail(x,{kind=.IO_Failed,transport=error,phase=.Read})}
  return .Continue
 }
 x._read.result={};x._read.cancel_requested=false;x._read.accepted=true
 error=net.async_read(x._stream,&x._read.operation,x._read_buffer[:],x._budget.wall)
 if error.kind!=.None {x._read.accepted=false;exchange_fail(x,{kind=.IO_Failed,transport=error,phase=.Read});return .Continue}
 return .Waiting
}
@(private)
exchange_head_step :: proc(x:^Exchange)->Exchange_Step {
 if x._response_head_used==HEAD_BUFFER_SIZE {exchange_fail(x,{kind=.Header_Oversized,phase=.Protocol});return .Continue}
 if x._read_at==x._read_used {
  step:=exchange_fill(x)
  if step!=.Continue || x._phase==.Draining {return step}
 }
 for x._read_at<x._read_used {
  if x._response_head_used==len(x._response_head) {exchange_fail(x,{kind=.Header_Oversized,phase=.Protocol});return .Continue}
  x._response_head[x._response_head_used]=x._read_buffer[x._read_at]
  x._response_head_used+=1;x._read_at+=1
  n:=x._response_head_used
  if n<4 || x._response_head[n-4]!=13 || x._response_head[n-3]!=10 || x._response_head[n-2]!=13 || x._response_head[n-1]!=10 {continue}
  head,_,error:=h1.response_header_decode(x._response_head[:n])
  if error.kind!=.None {exchange_fail(x,surf.http_protocol_error(error));return .Continue}
  x._response.status=head.status
  if head.status<200 {
   if head.status==101 {exchange_fail(x,{kind=.Invalid_Status,phase=.Protocol});return .Continue}
   x._informational+=1
   if x._informational>x._options.informational_limit {exchange_fail(x,{kind=.Too_Many_Informational,phase=.Protocol});return .Continue}
   x._response_head_used=0;continue
  }
  h1.response_apply_method(&head,x._method)
  allowed,reuse_error:=h1.response_reuse_allowed(&head,http.method_text(x._method))
  if reuse_error.kind!=.None {exchange_fail(x,surf.http_protocol_error(reuse_error));return .Continue}
  if head.framing==.Length && head.content_length>u64(x._options.body_limit) {exchange_fail(x,{kind=.Body_Oversized,phase=.Body_Limit});return .Continue}
  x._head=head;x._reuse_eligible=allowed;x._phase=.Copying_Head
  return .Continue
 }
 return .Continue
}
@(private)
exchange_body_finished :: proc(x:^Exchange)->Exchange_Step {
 // Surplus belongs to the retiring stream, never to a future request. The
 // completed HTTP response is still valid, but its connection is not reusable.
 if x._read_at!=x._read_used || x._peer_eof || x._read.result.err.kind!=.None {x._reuse_eligible=false}
 x._phase=.Draining
 return .Barrier // Fresh caller monotonic sample before publishing success.
}
@(private)
exchange_body_step :: proc(x:^Exchange)->Exchange_Step {
 if x._head.framing==.None || x._head.framing==.Length && x._body_remaining==0 {return exchange_body_finished(x)}
 if x._read_at==x._read_used {
  step:=exchange_fill(x)
  if step!=.Continue || x._phase==.Draining {return step}
 }
 source:=x._read_buffer[x._read_at:x._read_used]
 if x._head.framing==.Chunked {
  body:=x._response.body_storage
  storage:[]u8
  if cap(body)>0 {storage=(cast([^]u8)raw_data(body))[:cap(body)]}
  consumed,written,done,error:=h1.chunk_decoder_feed(&x._chunk,source,storage[len(body):])
  raw:=cast(^mem.Raw_Dynamic_Array)&x._response.body_storage
  raw.len+=written;x._read_at+=consumed
  if error.kind!=.None {exchange_fail(x,surf.http_protocol_error(error));return .Continue}
  if done {return exchange_body_finished(x)}
  if consumed==0 && written==0 && len(source)>0 {
   if len(body)==x._options.body_limit {exchange_fail(x,{kind=.Body_Oversized,phase=.Body_Limit});return .Continue}
   grew,allocation:=exchange_grow_body(x,len(body)+min(READ_BUFFER_SIZE,x._options.body_limit-len(body)))
   if allocation.kind!=.None {exchange_fail(x,allocation);return .Continue}
   if grew {return .Barrier}
  }
  return .Continue
 }
 count:=len(source)
 if x._head.framing==.Length {count=int(min(u64(count),x._body_remaining))}
 grew,error:=exchange_append_body(x,source[:count])
 if error.kind!=.None {exchange_fail(x,error);return .Continue}
 if grew {return .Barrier}
 x._read_at+=count
 if x._head.framing==.Length {x._body_remaining-=u64(count)}
 return .Continue
}
