package surf_async

import runtime_async "../../async"
import "core:mem/owned"
import "core:testing"
import "core:time"

@(test)
stream_upload_preserves_source_after_deadline_or_cancel_before_actor_observation :: proc(t:^testing.T) {
 for expired in ([]bool{false,true}) {
  runtime:runtime_async.Runtime
  client20_runtime(&runtime,context.allocator)
  client:Client
  config:=client20_config()
  config.streaming=Stream_Client_Limits{streams=1,response_chunks=1,upload_chunks=1,
   max_chunk_bytes=16,max_retained_bytes_per_stream=32}
  assert(client_init(&client,&runtime,config,context.allocator).kind==.None)
  cutoff:=runtime_async.deadline_after(&runtime,100*time.Millisecond)
  handle,error:=client_submit_stream(&client,{method=.POST,url="http://127.0.0.1:1/upload"},
   {upload_length=i64(1)},cutoff)
  assert(error.kind==.None)
  if expired {time.sleep(150*time.Millisecond)} else {assert(client_cancel(&client,handle).kind==.None)}
  stage,stage_error:=client_request_stage(&client,handle)
  assert(stage_error.kind==.None && stage==.Queued)
  chunk,allocation:=owned.allocate(1,context.allocator)
  assert(allocation.kind==.None)
  original:=raw_data(chunk.storage)
  status,rejected:=client_upload_submit(&client,handle,&chunk)
  testing.expect_value(t,status,.Closed)
  testing.expect_value(t,rejected.kind,.Request_Error)
  testing.expect_value(t,rejected.http.kind,.Deadline_Failed if expired else .IO_Failed)
  testing.expect_value(t,rejected.http.phase,.Deadline if expired else .Cancellation)
  testing.expect_value(t,raw_data(chunk.storage),original)
  testing.expect(t,owned.valid(&chunk))
  testing.expect_value(t,client_upload_finish(&client,handle).kind,.Request_Error)
  assert(client_close(&client).kind==.None)
  assert(client_release(&client,handle).kind==.None)
  assert(client_destroy(&client).kind==.None)
  assert(runtime_async.destroy(&runtime).kind==.None)
  owned.destroy(&chunk)
 }
}
