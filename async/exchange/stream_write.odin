package surf_exchange

import channel "../stream"
import "core:net"

@(private)
stream_write_ready :: proc(x:^Stream_Exchange)->Exchange_Step {
 base:=&x.base
 result:=base._write.result;base._write.ready=false
 if result.count<0 || result.count>x.write_requested {
  exchange_fail(base,{kind=.IO_Failed,transport={kind=.Invalid_Count},phase=.Write});return .Continue
 }
 base._written+=u64(result.count)
 if x.tx==.Head {base._request_head_at+=result.count}
 else if x.tx==.Body {base._request_body_at+=result.count}
 else if x.tx==.Upload {x.upload_at+=result.count}
 if result.err.kind!=.None && !(x.early_response && result.err.kind==.Cancelled) {
  exchange_fail(base,{kind=.IO_Failed,transport=result.err,phase=.Write});return .Continue
 }
 if result.count==0 && result.err.kind==.None {
  exchange_fail(base,{kind=.No_Progress,phase=.Write});return .Continue
 }
 return .Continue
}

@(private)
stream_stop_upload :: proc(x:^Stream_Exchange)->Exchange_Step {
 base:=&x.base
 if !x.upload_released {
  x.upload_released=true
  channel.stop_upload(x.channel)
  return .Barrier // Arbitrary source release callbacks require fresh now.
 }
 if base._write.accepted {
  if !base._write.cancel_requested {
   base._write.cancel_requested=true
   _=net.async_cancel(base._stream,&base._write.operation)
  }
  return .Waiting
 }
 if x.upload.release!=nil || x.upload.allocator.procedure!=nil {
  channel.upload_release(x.channel,&x.upload)
  x.upload_at=0
  return .Barrier
 }
 x.tx=.Stopped
 return .Continue
}

@(private)
stream_write_step :: proc(x:^Stream_Exchange)->Exchange_Step {
 base:=&x.base
 if base._write.ready {stream_write_ready(x);if base._failure.kind!=.None {return .Continue}}
 if x.early_response {return stream_stop_upload(x)}
 if base._write.accepted {return .Waiting}
 if x.tx==.Head && base._request_head_at==base._request_head_used {
  _,upload:=x.channel.options.upload_length.?
  x.tx=.Upload if upload else .Body
 }
 if x.tx==.Body && base._request_body_at==len(base._request_body) {x.tx=.Done;return .Continue}
 if x.tx==.Upload && x.upload_at==len(x.upload.data) {
  if x.upload.release!=nil || x.upload.allocator.procedure!=nil {
   channel.upload_release(x.channel,&x.upload);x.upload_at=0;return .Barrier
  }
  taken,finished,error:=channel.upload_take(x.channel,&x.upload)
  if error.kind!=.None {exchange_fail(base,error);return .Continue}
  if !taken {
   if finished {x.tx=.Done;return .Continue}
   return .Waiting
  }
 }
 if x.tx==.Done || x.tx==.Stopped {return .Waiting}
 source:[]u8
 switch x.tx {
 case .Head:source=base._request_head[base._request_head_at:base._request_head_used]
 case .Body:source=base._request_body[base._request_body_at:]
 case .Upload:source=x.upload.data[x.upload_at:]
 case .Done,.Stopped:return .Waiting
 }
 source=source[:min(len(source),READ_BUFFER_SIZE)]
 x.write_requested=len(source)
 base._write.result={};base._write.cancel_requested=false;base._write.accepted=true
 error:=net.async_write(base._stream,&base._write.operation,source,base._budget.wall)
 if error.kind!=.None {base._write.accepted=false;exchange_fail(base,{kind=.IO_Failed,transport=error,phase=.Write});return .Continue}
 return .Waiting
}
