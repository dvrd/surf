package surf_exchange

import surf "../.."
import http "../../../http"
import h1 "../../../http/v1"
import "core:mem"
import "core:net"

@(private) Exchange_Step :: enum {Continue, Waiting, Barrier}
@(private)
exchange_valid :: proc(x:^Exchange)->bool {return x!=nil && x._self==x}
@(private)
exchange_pending_error :: proc()->surf.HTTP_Error {return {kind=.Invalid_Config,transport={kind=.Operation_Pending},phase=.Configuration}}

exchange_init :: proc(x:^Exchange,options:Options,allocator:mem.Allocator)->surf.HTTP_Error {
 if x==nil || x._self!=nil {return {kind=.Invalid_Config}}
 normalized,error:=options_normalize(options)
 if error.kind!=.None {return error}
 if allocator.procedure==nil {return {kind=.Invalid_Config}}
 // Query is arbitrary allocator code too: reject reentry until construction
 // commits or rolls back, and require individual frees for every owned grant.
 x^={_self=x,_busy=true,_phase=.Idle}
 if .Free not_in mem.query_features(allocator) {x^={};return {kind=.Invalid_Config}}
 x^={_self=x,_options=normalized,_allocator=allocator,_phase=.Idle}
 return {}
}

exchange_begin :: proc(x:^Exchange,stream:net.Async_Connection,request:http.Request,budget:Budget,notify:Notify)->surf.HTTP_Error {
 if !exchange_valid(x) {return {kind=.Invalid_Config}}
 if x._busy || x._phase!=.Idle {return exchange_pending_error()}
 if stream.submit==nil || stream.cancel==nil || notify.wake==nil {return {kind=.Invalid_Config}}
 if error:=budget_validate(budget);error.kind!=.None {return error}
 if len(request.url)<0 || len(request.url)>0 && raw_data(request.url)==nil {return {kind=.Invalid_URL}}
 if len(request.body)<0 || len(request.body)>0 && raw_data(request.body)==nil {return {kind=.Invalid_Config}}
 if len(request.headers)<0 || len(request.headers)>http.MAX_HEADERS {return {kind=.Header_Limit}}
 if len(request.headers)>0 && raw_data(request.headers)==nil {return {kind=.Invalid_Header}}
 // Descriptor shape must precede alias traversal and the shared encoder.
 for field in request.headers {
  if len(field.name)<0 || len(field.value)<0 || len(field.name)>0 && raw_data(field.name)==nil ||
     len(field.value)>0 && raw_data(field.value)==nil {return {kind=.Invalid_Header}}
 }
 if exchange_aliases(x,request) {return {kind=.Overlapping_Buffers}}
 // All rejection paths preserve the complete Exchange and caller inputs.
 header:[HEAD_BUFFER_SIZE]u8
 count,error:=h1.request_encode_profile(header[:],request,.Keep_Alive)
 if error.kind!=.None {return surf.http_protocol_error(error)}
 options,allocator:=x._options,x._allocator
 x^={_self=x,_options=options,_allocator=allocator,_phase=.Writing_Head,
     _stream=stream,_budget=budget,_notify=notify,_method=request.method,
     _request_head_used=count,_request_body=request.body}
 copy(x._request_head[:count],header[:count])
 x._read.owner=x;x._write.owner=x
 x._read.operation={callback=exchange_operation_done,user_data=&x._read}
 x._write.operation={callback=exchange_operation_done,user_data=&x._write}
 return {}
}

@(private)
exchange_fail :: proc(x:^Exchange,error:surf.HTTP_Error) {
 if x._failure.kind==.None {x._failure=error}
 x._reuse_eligible=false;x._phase=.Draining
}
@(private)
exchange_error :: proc(x:^Exchange)->surf.HTTP_Error {
 effect:surf.HTTP_Write_Effect=.Unknown
 if x._response.status>0 {effect=.Response_Received} else if x._written==0 && !x._write.accepted {effect=.Not_Sent}
 return surf.http_error_classify(x._failure,.Read,effect,x._response.status)
}
@(private)
exchange_check_budget :: proc(x:^Exchange,now:i64,cancelled:bool) {
 if x._failure.kind!=.None {return}
 if cancelled {
  x._cancelled=true
  exchange_fail(x,{kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation})
 } else if x._budget.at!=0 && now>=x._budget.at {
  exchange_fail(x,{kind=.Deadline_Failed,transport={kind=.Timeout},phase=.Deadline})
 }
}
@(private)
exchange_drain :: proc(x:^Exchange)->bool {
 if x._write.ready {
  error:=exchange_write_result(x)
  if error.kind!=.None && x._failure.kind==.None {exchange_fail(x,error)}
 }
 if x._read.ready {
  x._read.ready=false
  if x._read.result.count<0 || x._read.result.count>READ_BUFFER_SIZE {
   exchange_fail(x,{kind=.IO_Failed,transport={kind=.Invalid_Count},phase=.Read})
  }
 }
 if x._read.accepted && !x._read.cancel_requested {
  x._read.cancel_requested=true
  _=net.async_cancel(x._stream,&x._read.operation)
 }
 if x._write.accepted && !x._write.cancel_requested {
  x._write.cancel_requested=true
  _=net.async_cancel(x._stream,&x._write.operation)
 }
 return !x._read.accepted && !x._write.accepted
}

// Fresh now is required on every drive call. A physical allocation/free or HTTP
// end boundary returns Progress before success, so the next call can gate its
// completion using a clock sampled AFTER that synchronous work. Work counts
// finite steps: protocol scans/copies use fixed read/head buffers. Physical
// allocation and body growth/copy are additionally bounded by body_limit (up to
//64MiB), not preempted or represented as per-byte work. No CPU deadline or
// preemption guarantee is made for allocators, owned growth or protocol crypto.
exchange_drive :: proc(x:^Exchange,now:i64,cancelled:bool,work:int)->Drive_Result {
 if !exchange_valid(x) || now<0 || work<1 || work>MAX_WORK_PER_DRIVE {return {status=.Done,error={kind=.Invalid_Config}}}
 if x._busy {return {status=.Waiting,error=exchange_pending_error()}}
 if x._phase==.Idle {return {status=.Done,error={kind=.Invalid_Config}}}
 if x._phase==.Done {return {status=.Done,error=x._failure,reuse_eligible=x._reuse_eligible}}
 x._busy=true
 used:=0
 for used<work {
  exchange_check_budget(x,now,cancelled)
  used+=1
  step:Exchange_Step
  switch x._phase {
  case .Writing_Head, .Writing_Body:step=exchange_write_step(x)
  case .Reading_Head:step=exchange_head_step(x)
  case .Copying_Head:
   error:=exchange_copy_head(x)
   if error.kind!=.None {exchange_fail(x,error)} else {
    x._body_remaining=x._head.content_length
    if x._head.framing==.Chunked {
     error=surf.http_protocol_error(h1.chunk_decoder_init(&x._chunk,u64(x._options.body_limit)))
     if error.kind!=.None {exchange_fail(x,error)}
    }
    if x._phase!=.Draining {x._phase=.Reading_Body}
   }
   step=.Barrier
  case .Reading_Body:step=exchange_body_step(x)
  case .Draining:
   if !exchange_drain(x) {step=.Waiting;break}
   // Commit before disposal: arbitrary frees may destroy the public owner.
   error:=exchange_error(x)
   x._failure=error;x._phase=.Done;x._request_body=nil
   disposal:surf.Response
   if error.kind!=.None {disposal=x._response;x._response={}} else {
    x._response.body=x._response.body_storage[:]
   }
   result:=Drive_Result{status=.Done,work_used=used,error=error,reuse_eligible=x._reuse_eligible}
   x._busy=false
   surf.response_destroy(&disposal)
   return result // Locals only: x may have been physically freed.
  case .Idle,.Done:panic("invalid exchange drive transition")
  }
  if step==.Barrier {
   result:=Drive_Result{status=.Progress,work_used=used,error=exchange_error(x)}
   x._busy=false;return result
  }
  if step==.Waiting {
   result:=Drive_Result{status=.Waiting,work_used=used,error=exchange_error(x)}
   x._busy=false;return result
  }
 }
 result:=Drive_Result{status=.Progress,work_used=used,error=exchange_error(x)}
 x._busy=false
 return result
}

exchange_quiescent :: proc(x:^Exchange)->bool {
 return exchange_valid(x) && !x._busy && (x._phase==.Idle || x._phase==.Done) &&
        !x._read.accepted && !x._write.accepted && !x._read.ready && !x._write.ready
}
exchange_take :: proc(x:^Exchange,destination:^surf.Response)->surf.HTTP_Error {
 if !exchange_valid(x) || destination==nil {return {kind=.Invalid_Config}}
 if exchange_overlap(x,size_of(Exchange),destination,size_of(surf.Response)) {return {kind=.Overlapping_Buffers}}
 if !exchange_quiescent(x) || x._phase!=.Done {return exchange_pending_error()}
 if x._failure.kind!=.None {return x._failure}
 if x._result_taken || !exchange_response_empty(destination) {return {kind=.Invalid_Config}}
 destination^=x._response;x._response={};x._result_taken=true
 return {}
}
exchange_reset :: proc(x:^Exchange)->surf.HTTP_Error {
 if !exchange_valid(x) {return {kind=.Invalid_Config}}
 if !exchange_quiescent(x) {return exchange_pending_error()}
 if !exchange_response_empty(&x._response) {return exchange_pending_error()}
 options,allocator:=x._options,x._allocator
 x^={_self=x,_options=options,_allocator=allocator,_phase=.Idle}
 return {}
}
exchange_destroy :: proc(x:^Exchange)->surf.HTTP_Error {
 if !exchange_valid(x) {return {kind=.Invalid_Config}}
 if !exchange_quiescent(x) {return exchange_pending_error()}
 response:=x._response
 x^={}
 surf.response_destroy(&response)
 return {} // No owner access after an arbitrary physical free.
}
