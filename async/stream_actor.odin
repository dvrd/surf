package surf_async

import surf ".."
import stream_api "stream"
import exchange_api "exchange"
import http "../../http"
import runtime_async "../../async"
import adapter "../../async/connection"
import tls_api "core:crypto/tls"
import "core:net"
import "core:sync"

@(private)
session_stream_channel :: proc(a:^Session_Actor)->^stream_api.Channel {
 sync.lock(&a.owner.kernel.mu);defer sync.unlock(&a.owner.kernel.mu)
 request:=admission_request_locked(&a.owner.kernel,a.request)
 if request==nil || request.stream==nil {return nil}
 assert(stream_api.retain(request.stream))
 return request.stream
}

@(private)
session_stream_begin :: proc(a:^Session_Actor,cell:^stream_api.Channel,
 stream:net.Async_Connection,request:http.Request,budget:exchange_api.Budget)->surf.HTTP_Error {
 storage,cause:=kernel_grant(size_of(exchange_api.Stream_Exchange),align_of(exchange_api.Stream_Exchange),a.owner.resources.allocator)
 if cause.kind!=.None {stream_api.release(cell);return cause.http}
 engine:=cast(^exchange_api.Stream_Exchange)raw_data(storage)
 now,clock:=network_clock(a.owner)
 if clock.kind!=.None || !session_before_http(a,now) {
  kernel_free(storage,align_of(exchange_api.Stream_Exchange),a.owner.resources.allocator)
  stream_api.release(cell)
  return a.error
 }
 error:=exchange_api.stream_exchange_begin(engine,stream,request,budget,
  {data=a,wake=session_notify},cell,a.owner.config.config.http.max_redirects>0,a.owner.resources.allocator)
 if error.kind!=.None {
  kernel_free(storage,align_of(exchange_api.Stream_Exchange),a.owner.resources.allocator)
  stream_api.release(cell)
  return error
 }
 a.stream_exchange=engine
 stream_api.set_notify(cell,a.wake)
 return {}
}

@(private)
session_stream_dispose :: proc(a:^Session_Actor) {
 engine:=a.stream_exchange
 if engine==nil {return}
 assert(exchange_api.stream_exchange_destroy(engine).kind==.None)
 cell:=engine.channel
 a.stream_exchange=nil
 storage:=(cast([^]u8)engine)[:size_of(exchange_api.Stream_Exchange)]
 kernel_free(storage,align_of(exchange_api.Stream_Exchange),a.owner.resources.allocator)
 stream_api.release(cell)
}

@(private)
session_engine_quiescent :: proc(a:^Session_Actor)->bool {
 if a.stream_exchange!=nil {return exchange_api.stream_exchange_quiescent(a.stream_exchange)}
 return exchange_api.exchange_quiescent(&a.exchange)
}

@(private)
session_engine_drive :: proc(a:^Session_Actor,now:i64,cancelled:bool)->exchange_api.Drive_Result {
 if a.stream_exchange!=nil {
  return exchange_api.stream_exchange_drive(a.stream_exchange,now,cancelled,a.owner.config.config.capacities.work_per_resume)
 }
 return exchange_api.exchange_drive(&a.exchange,now,cancelled,a.owner.config.config.capacities.work_per_resume)
}

@(private)
session_stream_step :: proc(a:^Session_Actor,now:runtime_async.Deadline)->runtime_async.Resume_Result {
 engine:=a.stream_exchange
 cancelled:=(session_cancelled(a) || runtime_async.cancelled(&a.task)) && now.at<a.cutoff.at
 result:=exchange_api.stream_exchange_drive(engine,now.at,cancelled,a.owner.config.config.capacities.work_per_resume)
 if result.error.kind!=.None {
  error:=result.error
  if a.tls_initialized {error.tls_io=tls_api.async_failure(&a.tls)}
  session_error(a,error);return .Yield
 }
 if result.status!=.Done {
  if result.status!=.Waiting {return .Yield}
  sleep:=runtime_async.sleep_until_earlier(a.owner.runtime,a.cutoff)
  if sleep.kind==.None {return .Yield}
  if sleep.kind!=.Pending {
   session_error(a,{kind=.IO_Failed,phase=.Cancellation,transport={kind=.Cancelled}});return .Yield
  }
  return .Waiting
 }
 response:surf.Response
 if exchange_api.stream_exchange_take_redirect(engine,&response) {
  if redirect_response(a,&response) {return .Yield}
  surf.response_destroy(&response)
  session_error(a,{kind=.Invalid_Config,phase=.Protocol});return .Yield
 }
 fresh,clock:=network_clock(a.owner)
 failure:surf.HTTP_Error
 if clock.kind!=.None {failure={kind=.Invalid_Config,phase=.Configuration}}
 else if session_cancelled(a) || runtime_async.cancelled(&a.task) {
  failure={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}
 } else if fresh.at>=a.cutoff.at {failure={kind=.Deadline_Failed,phase=.Deadline}}
 else if budget:=adapter.budget_error(&a.executor);budget.kind!=.None {
  failure={kind=.IO_Failed,transport=budget,phase=.Read}
 }
 response.status=engine.status
 if failure.kind!=.None {
  failure.status=engine.status;failure.write_effect=.Response_Received
  session_error(a,failure);return .Yield
 }
 if error:=network_assignment_finish(a,&response,{});error.kind!=.None {
  if error.kind!=.Pending {session_error(a,{kind=.Invalid_Config,phase=.Configuration})}
  return .Yield
 }
 stream_api.complete(engine.channel,{})
 session_stream_dispose(a)
 return session_finish_reuse(a,result.reuse_eligible)
}
