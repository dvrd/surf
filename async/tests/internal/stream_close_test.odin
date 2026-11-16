package surf_async

import runtime_async "../../async"
import adapter "../../async/connection"
import exchange_api "exchange"
import channel "stream"
import rt "base:runtime"
import "core:mem"
import "core:mem/owned"
import "core:testing"
import "core:sync"
import "core:time"

// Layered actor/exchange unit: no sockets, TLS or native I/O. The executor is
// task-owned, and its bound/no-active state models an already-retired transport.
// The first close still has one active upload owner to dispose. No callback,
// socket readiness or timer can wake it after that disposal barrier.
Stream_Close_Probe :: struct {
 runtime:^runtime_async.Runtime,
 done:sync.Wait_Group,
 owner:Client_State,
 actor:Session_Actor,
 bank:^channel.Bank,
 cell:^channel.Channel,
 backing:[16]u8,
 drops,bytes,steps:int,
 callback_quiescent:bool,
 first,second:runtime_async.Resume_Result,
 first_engine_pending,first_owner_empty,first_credit_returned:bool,
}

stream_close_drop :: proc(storage:[]u8,data:rawptr) {
 p:=cast(^Stream_Close_Probe)data
 p.drops+=1;p.bytes+=len(storage)
 engine:=p.actor.stream_exchange
 p.callback_quiescent=p.actor.close_done&&adapter.quiescent(&p.actor.executor)&&
  !engine.base._read.accepted&&!engine.base._write.accepted&&
  !engine.base._read.ready&&!engine.base._write.ready&&
  channel.bank_stats(p.bank).upload_bytes==len(storage)
}

stream_close_resume :: proc(data:rawptr)->runtime_async.Resume_Result {
 p:=cast(^Stream_Close_Probe)data
 a:=&p.actor
 if p.steps==0 {
  assert(adapter.init_executor(&a.executor,p.runtime,&a.task).kind==.None)
  // This is the adapter's state after its final close callback; no fabricated
  // socket or callback is submitted and no readiness/timer is registered.
  a.executor._bound=true
 }
 result:=session_close_step(a)
 p.steps+=1
 if p.steps==1 {
  p.first=result
  p.first_engine_pending=!exchange_api.stream_exchange_quiescent(a.stream_exchange)
  p.first_owner_empty=a.stream_exchange!=nil&&a.stream_exchange.upload.release==nil&&
   a.stream_exchange.upload.allocator.procedure==nil
  p.first_credit_returned=channel.bank_stats(p.bank).upload_bytes==0
  // Force the second observation even on the old Waiting bug, so the negative
  // control terminates and reports the bad result without stranding a worker.
  return .Yield
 }
 p.second=result
 return .Done
}
stream_close_done :: proc(data:rawptr) {
 p:=cast(^Stream_Close_Probe)data
 runtime_async.shutdown(p.runtime)
 sync.wait_group_done(&p.done)
}

@(test)
stream_close_upload_destructor_barrier_yields_then_finishes_without_io_wake :: proc(t:^testing.T) {
 tracker:mem.Tracking_Allocator
 mem.tracking_allocator_init(&tracker,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&tracker)
 runtime:runtime_async.Runtime
 assert(runtime_async.init(&runtime,{workers=1,task_capacity=1,io_capacity=0,allocator=allocator}).kind==.None)
 p:=new(Stream_Close_Probe,allocator) or_else panic("test allocation")
 p.runtime=&runtime
 p.owner={self=&p.owner,phase=.Closing,runtime=&runtime,registered_tasks=1,
  resources={allocator=allocator}}
 now:=runtime_async.deadline_after(&runtime,0)
 p.owner.runtime_epoch=now.epoch
 p.owner.config.config.capacities.work_per_resume=1
 bank,bank_error:=channel.bank_create({streams=1,response_chunks=1,upload_chunks=1,
  max_chunk_bytes=16,max_retained_bytes_per_stream=32},allocator)
 assert(bank_error.kind==.None);p.bank=bank
 cell,cell_error:=channel.channel_create(bank,{upload_length=i64(1)})
 assert(cell_error.kind==.None);p.cell=cell
 source:=owned.Chunk{data=p.backing[:1],storage=p.backing[:],release=stream_close_drop,user_data=p}
 status,_:=channel.upload_submit(cell,&source);assert(status==.Accepted)
 storage,allocation:=kernel_grant(size_of(exchange_api.Stream_Exchange),align_of(exchange_api.Stream_Exchange),allocator)
 assert(allocation.kind==.None)
 engine:=cast(^exchange_api.Stream_Exchange)raw_data(storage)
 engine^={channel=cell}
 assert(exchange_api.exchange_init(&engine.base,{},allocator).kind==.None)
 engine.base._phase=.Draining
 engine.base._failure={kind=.IO_Failed,transport={kind=.Cancelled},phase=.Cancellation}
 taken,_,take_error:=channel.upload_take(cell,&engine.upload);assert(taken&&take_error.kind==.None)
 assert(channel.retain(cell)) // Actor owns the engine's Cell reference.
 a:=&p.actor
 a^={owner=&p.owner,stream_exchange=engine,phase=.Retiring,transport_initialized=true,
  executor_initialized=true,close_started=true,close_done=true,error=engine.base._failure}
 assert(exchange_api.exchange_init(&a.exchange,{},allocator).kind==.None)
 a.task={data=p,resume=stream_close_resume,on_cancel=stream_close_resume,on_done=stream_close_done}
 assert(runtime_async.register(&runtime,&a.task).kind==.None)
 assert(runtime_async.wake(&runtime,&a.task))
 sync.wait_group_add(&p.done,1)
 assert(runtime_async.start(&runtime).kind==.None)
 finished:=sync.wait_group_wait_with_timeout(&p.done,5*time.Second)
 if !finished {runtime_async.shutdown(&runtime)}
 assert(runtime_async.join(&runtime).kind==.None)
 testing.expect(t,finished)
 testing.expect_value(t,p.first,.Yield)
 testing.expect_value(t,p.second,.Done)
 testing.expect(t,p.steps==2&&p.drops==1&&p.bytes==16&&p.callback_quiescent)
 testing.expect(t,p.first_engine_pending&&p.first_owner_empty&&p.first_credit_returned)
 testing.expect(t,a.stream_exchange==nil&&a.owner_drained&&a.phase==.Done)
 assert(exchange_api.exchange_destroy(&a.exchange).kind==.None)
 channel.release_request(cell);channel.bank_close(&bank)
 assert(runtime_async.destroy(&runtime).kind==.None)
 free(p,allocator)
 testing.expect_value(t,tracker.current_memory_allocated,0)
 testing.expect_value(t,len(tracker.bad_free_array),0)
 mem.tracking_allocator_destroy(&tracker)
}
