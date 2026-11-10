package surf_async

import runtime_async "../../async"
import "core:mem"
import "core:mem/owned"
import "core:testing"

Stream_Negative_Owner_Probe :: struct {
 actual:[]u8,
 allocator:mem.Allocator,
 releases:int,
}

@(test)
stream_upload_rejects_negative_owner_lengths_without_moving_or_charging :: proc(t:^testing.T) {
 for lengths in ([5][2]int{{-1,1},{1,-1},{-1,-1},{0,-1},{1,1}}) {
  runtime:runtime_async.Runtime
  client20_runtime(&runtime,context.allocator)
  client:Client
  config:=client20_config()
  config.streaming=Stream_Client_Limits{streams=1,response_chunks=1,upload_chunks=1,
   max_chunk_bytes=16,max_retained_bytes_per_stream=32}
  assert(client_init(&client,&runtime,config,context.allocator).kind==.None)
  handle,error:=client_submit_stream(&client,{method=.POST,url="http://127.0.0.1:1/upload"},
   {upload_length=i64(1)})
  assert(error.kind==.None)
  probe:=Stream_Negative_Owner_Probe{allocator=context.allocator}
  probe.actual=make([]u8,1,context.allocator)
  data:=transmute([]u8)mem.Raw_Slice{data=raw_data(probe.actual),len=lengths[0]}
  storage:=transmute([]u8)mem.Raw_Slice{data=raw_data(probe.actual),len=lengths[1]}
  source:=owned.Chunk{data=data,storage=storage,user_data=&probe,
   release=proc(_:[]u8,data:rawptr){
    owner:=cast(^Stream_Negative_Owner_Probe)data
    owner.releases+=1
    // Cleanup always uses the real allocation, never the malformed view.
    delete(owner.actual,owner.allocator);owner.actual=nil
   }}
  status,rejected:=client_upload_submit(&client,handle,&source)
  valid:=lengths==([2]int{1,1})
  testing.expect_value(t,status,.Accepted if valid else .Invalid)
  testing.expect_value(t,rejected.kind,.None if valid else .Invalid_State)
  stats,snapshot:=client_stats(&client);assert(snapshot)
  testing.expect_value(t,stats.streaming.upload_bytes,1 if valid else 0)
  testing.expect_value(t,stats.streaming.upload_chunks,1 if valid else 0)
  testing.expect_value(t,probe.releases,0)
  if !valid {
   testing.expect_value(t,raw_data(source.data),raw_data(probe.actual))
   testing.expect_value(t,raw_data(source.storage),raw_data(probe.actual))
   testing.expect_value(t,len(source.data),lengths[0])
   testing.expect_value(t,len(source.storage),lengths[1])
   testing.expect(t,source.release!=nil)
  }
  assert(client_close(&client).kind==.None)
  assert(client_release(&client,handle).kind==.None)
  assert(client_destroy(&client).kind==.None)
  assert(runtime_async.destroy(&runtime).kind==.None)
  owned.destroy(&source)
  testing.expect_value(t,probe.releases,1)
 }
}
