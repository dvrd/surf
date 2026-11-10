package surf_exchange

import surf "../.."
import channel "../stream"

stream_exchange_drive :: proc(x:^Stream_Exchange,now:i64,cancelled:bool,work:int)->Drive_Result {
 if x==nil || !exchange_valid(&x.base) || work<1 || work>MAX_WORK_PER_DRIVE || now<0 {
  return {status=.Done,error={kind=.Invalid_Config}}
 }
 base:=&x.base
 if base._busy {return {status=.Waiting,error=exchange_pending_error()}}
 if base._phase==.Done {return {status=.Done,error=base._failure,reuse_eligible=base._reuse_eligible}}
 base._busy=true
 used:=0
 for used<work {
  exchange_check_budget(base,now,cancelled || channel.is_closed(x.channel))
  if base._failure.kind==.None && base._response.status<200 {
   source:=channel.upload_failure(x.channel)
   if source.kind!=.None {exchange_fail(base,source)}
  }
  used+=1
  if base._failure.kind!=.None {
   if base._write.ready {stream_write_ready(x)}
   if !exchange_drain(base) {base._busy=false;return {status=.Waiting,work_used=used,error=exchange_error(base)}}
   if x.upload.release!=nil || x.upload.allocator.procedure!=nil {
    channel.upload_release(x.channel,&x.upload)
    base._busy=false;return {status=.Progress,work_used=used,error=exchange_error(base)}
   }
   base._failure=exchange_error(base);base._phase=.Done
   base._busy=false
   return {status=.Done,work_used=used,error=base._failure}
  }
  tx:=stream_write_step(x)
  if tx==.Barrier {base._busy=false;return {status=.Progress,work_used=used}}
  if base._failure.kind!=.None {continue}
  rx:=Exchange_Step.Waiting
  if x.tx!=.Head && !x.rx_done {
   switch base._phase {
   case .Reading_Head:rx=exchange_head_step(base)
   case .Copying_Head:rx=stream_copy_head(x)
   case .Reading_Body:
    remaining:=work-used
    rx=stream_body_step(x,&remaining)
    used=work-remaining
   case .Draining,.Done,.Idle,.Writing_Head,.Writing_Body:
    exchange_fail(base,{kind=.Invalid_Config})
   }
  }
  if rx==.Barrier {base._busy=false;return {status=.Progress,work_used=used}}
  if base._failure.kind!=.None {continue}
  if x.rx_done && (x.tx==.Done || x.tx==.Stopped) && !base._read.accepted && !base._write.accepted {
   base._phase=.Done;base._busy=false
   return {status=.Done,work_used=used,reuse_eligible=base._reuse_eligible}
  }
  if tx==.Waiting && rx==.Waiting {
   base._busy=false;return {status=.Waiting,work_used=used}
  }
 }
 base._busy=false
 return {status=.Progress,work_used=used}
}

stream_exchange_quiescent :: proc(x:^Stream_Exchange)->bool {
 return x!=nil && exchange_quiescent(&x.base)
}

stream_exchange_destroy :: proc(x:^Stream_Exchange)->surf.HTTP_Error {
 if !stream_exchange_quiescent(x) {return exchange_pending_error()}
 channel.stop_upload(x.channel)
 return exchange_destroy(&x.base)
}

stream_exchange_take_redirect :: proc(x:^Stream_Exchange,destination:^surf.Response)->bool {
 if !stream_exchange_quiescent(x) || !x.private_response || x.base._failure.kind!=.None ||
    !exchange_response_empty(destination) {return false}
 destination^=x.base._response;x.base._response={}
 return true
}

stream_exchange_status :: proc(x:^Stream_Exchange)->int {return x.status}
