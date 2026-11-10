package surf_exchange

import surf "../.."
import channel "../stream"
import h1 "../../../http/v1"
import "core:compress/gzip"
import "core:strings"

@(private)
stream_entity_step :: proc(x:^Stream_Exchange)->Exchange_Step {
 if x.encoded_at<x.encoded_used || x.entity_done {return .Continue}
 base:=&x.base
 x.encoded_at=0;x.encoded_used=0
 if base._head.framing==.None || base._head.framing==.Length && base._body_remaining==0 {
  x.entity_done=true;return .Continue
 }
 if base._read_at==base._read_used {
  step:=exchange_fill(base)
  if base._phase==.Draining && base._failure.kind==.None {
   x.entity_done=true;base._phase=.Reading_Body;return .Continue
  }
  if step!=.Continue || base._failure.kind!=.None {return step}
 }
 source:=base._read_buffer[base._read_at:base._read_used]
 consumed,produced:=0,0
 if base._head.framing==.Chunked {
  done:bool
  n,written,finished,cause:=h1.chunk_decoder_feed(&base._chunk,source,x.encoded[:])
  consumed,produced,done=n,written,finished
  if cause.kind!=.None {exchange_fail(base,surf.http_protocol_error(cause));return .Continue}
  x.entity_done=done
 } else {
  count:=min(len(source),len(x.encoded))
  if base._head.framing==.Length {count=int(min(u64(count),base._body_remaining))}
  consumed,produced=count,count
  copy(x.encoded[:],source[:count])
  if base._head.framing==.Length {base._body_remaining-=u64(count);x.entity_done=base._body_remaining==0}
 }
 base._read_at+=consumed
 if u64(produced)>x.channel.options.max_encoded_bytes-x.encoded_total {
  exchange_fail(base,{kind=.Body_Oversized,phase=.Body_Limit});return .Continue
 }
 x.encoded_total+=u64(produced);x.encoded_used=produced
 return .Continue
}

@(private)
stream_publish_head :: proc(x:^Stream_Exchange)->Exchange_Step {
 if !x.head_pending {return .Continue}
 x.head_pending=false
 if x.private_response {return .Continue}
 length:=i64(-1)
 for field in x.base._response.headers {
  if strings.equal_fold(field.name,"Content-Length") {
   if x.base._head.content_length>u64(max(i64)) {
    exchange_fail(&x.base,{kind=.Invalid_Content_Length,phase=.Protocol});return .Continue
   }
   length=i64(x.base._head.content_length)
  }
 }
 encoding:=channel.Encoding.Decoded_Gzip if x.decoded else channel.Encoding.Wire
 if !channel.publish_head(x.channel,&x.base._response,length,encoding) {
  exchange_fail(&x.base,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation});return .Continue
 }
 x.base._response.status=x.status
 return .Continue
}

@(private)
stream_body_step :: proc(x:^Stream_Exchange,work:^int)->Exchange_Step {
 if x.rx_done {return .Waiting}
 stream_publish_head(x)
 if x.base._failure.kind!=.None {return .Continue}
 // Advance bounded entity metadata/lookahead before demanding payload credit.
 // stream_entity_step stops immediately while any payload remains staged.
 step:=stream_entity_step(x)
 if step!=.Continue || x.base._failure.kind!=.None {return step}
 source:=x.encoded[x.encoded_at:x.encoded_used]
 if len(source)==0 && !x.entity_done {return .Continue}
 output:^channel.Output
 destination:[]u8
 if x.private_response {destination=x.discard[:]}
 else {
  output,destination=channel.reserve_output(x.channel)
  // With all payload slots held, the decoder may still validate a trailer.
  // A zero-length output advances metadata only and stops at Need_Output.
  if output==nil && !x.decoded && len(source)>0 {return .Waiting}
 }
 published:=false
 defer if output!=nil && !published {channel.abandon_output(output)}
 produced:=0
 if x.decoded {
  decoded:=gzip.decoder_step(&x.decoder,source,destination,x.entity_done,max(1,work^))
  work^=max(0,work^-decoded.work)
  if decoded.err!=.None {
   exchange_fail(&x.base,{kind=.Content_Decoding_Failed,decoding=decoded.err,phase=.Decode});return .Continue
  }
  x.encoded_at+=decoded.consumed;produced=decoded.produced
  if decoded.status==.Done {x.rx_done=true}
  if output==nil && !x.private_response && decoded.status==.Need_Output {return .Waiting}
 } else {
  produced=min(len(source),len(destination))
  if u64(produced)>x.channel.options.max_decoded_bytes-x.delivered_total {
   exchange_fail(&x.base,{kind=.Body_Oversized,phase=.Body_Limit});return .Continue
  }
  copy(destination[:produced],source[:produced]);x.encoded_at+=produced
  if x.entity_done && x.encoded_at==x.encoded_used {x.rx_done=true}
 }
 x.delivered_total+=u64(produced)
 if output!=nil && produced>0 {
  accepted:=channel.publish_output(output,produced)
  // Publish consumes the reservation even when concurrent closure rejects it.
  published=true
  if !accepted {exchange_fail(&x.base,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation});return .Continue}
 }
 if x.rx_done {
  if x.base._read_at!=x.base._read_used || x.base._peer_eof || x.base._read.result.err.kind!=.None {
   x.base._reuse_eligible=false
  }
  return .Barrier
 }
 return .Continue
}
