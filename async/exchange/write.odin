package surf_exchange

import surf "../.."
import "core:net"

@(private)
exchange_operation_done :: proc(op:^net.Async_Operation) {
 state:=cast(^Operation_State)op.user_data
 x:=state.owner
 state.result=op.result;state.accepted=false;state.ready=true
 notify:=x._notify
 if notify.wake!=nil {notify.wake(notify.data)}
 // Notification may reenter its owner; no operation/Exchange access follows.
}
@(private)
exchange_write_result :: proc(x:^Exchange)->surf.HTTP_Error {
 if !x._write.ready {return {}}
 result:=x._write.result;x._write.ready=false
 head:=x._request_head_at<x._request_head_used
 expected:=x._request_head_used-x._request_head_at if head else min(READ_BUFFER_SIZE,len(x._request_body)-x._request_body_at)
 if result.count<0 || result.count>expected {return {kind=.IO_Failed,transport={kind=.Invalid_Count},phase=.Write}}
 x._written+=u64(result.count)
 if head {x._request_head_at+=result.count} else {x._request_body_at+=result.count}
 if result.err.kind!=.None {return {kind=.IO_Failed,transport=result.err,phase=.Write}}
 if result.count!=expected {return {kind=.IO_Failed,transport={kind=.Invalid_Count},phase=.Write}}
 return {}
}
@(private)
exchange_write_step :: proc(x:^Exchange)->Exchange_Step {
 if x._write.accepted {return .Waiting}
 if x._write.ready {
  if error:=exchange_write_result(x);error.kind!=.None {exchange_fail(x,error);return .Continue}
 }
 if x._phase==.Writing_Head && x._request_head_at==x._request_head_used {x._phase=.Writing_Body}
 if x._phase==.Writing_Body && x._request_body_at==len(x._request_body) {
  x._request_body=nil;x._phase=.Reading_Head;return .Continue
 }
 source:[]u8
 if x._phase==.Writing_Head {source=x._request_head[x._request_head_at:x._request_head_used]} else {
  start:=x._request_body_at;source=x._request_body[start:start+min(READ_BUFFER_SIZE,len(x._request_body)-start)]
 }
 x._write.result={};x._write.cancel_requested=false;x._write.accepted=true
 error:=net.async_write(x._stream,&x._write.operation,source,x._budget.wall)
 if error.kind!=.None {
  x._write.accepted=false;exchange_fail(x,{kind=.IO_Failed,transport=error,phase=.Write});return .Continue
 }
 return .Waiting
}
