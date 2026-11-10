package surf_exchange

import surf "../.."
import channel "../stream"
import http "../../../http"
import h1 "../../../http/v1"
import "core:mem"
import "core:compress/gzip"
import "core:net"
import "core:strings"

stream_exchange_begin :: proc(x:^Stream_Exchange,stream:net.Async_Connection,
 request:http.Request,budget:Budget,notify:Notify,cell:^channel.Channel,
 redirects:bool,allocator:mem.Allocator)->surf.HTTP_Error {
 if x==nil || cell==nil {return {kind=.Invalid_Config}}
 if x.base._self!=nil || x.channel!=nil {return exchange_pending_error()}
 options:=cell.options
 length:=i64(-1)
 if size,upload:=options.upload_length.?;upload {length=size}
 encoding:=h1.Request_Accept_Encoding.Identity
 if options.decoding==.Gzip {encoding=.Gzip}
 head:[HEAD_BUFFER_SIZE]u8
 count,error:=h1.request_encode_content(head[:],request,.Keep_Alive,encoding,length)
 if error.kind!=.None {return surf.http_protocol_error(error)}
 x^={channel=cell,tx=.Head,redirects=redirects}
 if error:=exchange_init(&x.base,{body_limit=int(options.max_encoded_bytes)},allocator);error.kind!=.None {return error}
 if error:=exchange_begin(&x.base,stream,request,budget,notify);error.kind!=.None {return error}
 copy(x.base._request_head[:],head[:count]);x.base._request_head_used=count
 // RX is enabled after the independent TX head finishes.
 x.base._phase=.Reading_Head
 return {}
}

@(private)
stream_encoding :: proc(x:^Stream_Exchange)->surf.HTTP_Error {
 x.decoded=false
 if x.channel.options.decoding==.Identity {return {}}
 coding:=""
 count:=0
 for field in x.base._response.headers {
  if strings.equal_fold(field.name,"Content-Encoding") {
   coding=strings.trim(field.value," \t");count+=1
  }
 }
 if count==0 || count==1 && strings.equal_fold(coding,"identity") {return {}}
 if count!=1 || !strings.equal_fold(coding,"gzip") {
  return {kind=.Unsupported_Content_Encoding,phase=.Decode}
 }
 if x.base._head.framing==.None {return {}}
 options:=x.channel.options
 error:=gzip.decoder_init(&x.decoder,{max_encoded_bytes=options.max_encoded_bytes,
  max_decoded_bytes=options.max_decoded_bytes,max_header_bytes=8192,max_members=1})
 if error!=.None {return {kind=.Content_Decoding_Failed,decoding=error,phase=.Decode}}
 x.decoded=true
 return {}
}

@(private)
stream_copy_head :: proc(x:^Stream_Exchange)->Exchange_Step {
 if error:=exchange_copy_head(&x.base);error.kind!=.None {exchange_fail(&x.base,error);return .Continue}
 x.status=x.base._response.status
 if error:=stream_encoding(x);error.kind!=.None {exchange_fail(&x.base,error);return .Continue}
 x.private_response=x.redirects && (x.status==301 || x.status==302 || x.status==303 || x.status==307 || x.status==308)
 x.base._body_remaining=x.base._head.content_length
 if x.base._head.framing==.Chunked {
  error:=h1.chunk_decoder_init(&x.base._chunk,x.channel.options.max_encoded_bytes)
  if error.kind!=.None {exchange_fail(&x.base,surf.http_protocol_error(error));return .Continue}
 }
 x.base._phase=.Reading_Body;x.head_pending=true
 if x.tx!=.Done && x.tx!=.Stopped {
  x.early_response=true;x.base._reuse_eligible=false
 }
 return .Barrier // Header allocations require a fresh owner clock before publication.
}
