package main
import exchange "shared:surf/async/exchange"
import surf "shared:surf"
import async "shared:async"
import adapter "shared:async/connection"
import "base:intrinsics"
import rt "base:runtime"
import "core:crypto/tls"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:thread"
import "core:time"

State :: struct {
 runtime:async.Runtime,task:async.Task,
 endpoint:net.Endpoint,connect:async.Connecting_Socket,socket:async.Socket,
 loop:adapter.Executor,transport:adapter.Transport,secure:tls.Async_Conn,
 hs:tls.Async_Handshake_Operation,close:net.Async_Operation,
 x:exchange.Exchange,roots:tls.Root_Pool,
 allocator:mem.Allocator,
 cap_a:async.Deadline,
 started,connected,wrapped,handshaken,closing,closed,encrypted,begun,checked:bool,
 done,completed,release:int,
 reuse:bool,local_idle:tls.Async_Idle_State,probe:async.Stream_Probe,
 mode:string,
 close_error:net.Connection_Error_Kind,
 resumes,wakes:int,
}
wake :: proc(data:rawptr){s:=cast(^State)data;s.wakes+=1;assert(async.wake(&s.runtime,&s.task))}
hs_done :: proc(op:^tls.Async_Handshake_Operation){s:=cast(^State)op.user_data;assert(op.err.kind==.None&&op.result.kind==.None);s.handshaken=true;wake(s)}
close_done :: proc(op:^net.Async_Operation){s:=cast(^State)op.user_data;s.close_error=op.result.err.kind;s.closed=true;wake(s)}
stream :: proc(s:^State)->net.Async_Connection {return tls.async_connection(&s.secure) if s.encrypted else adapter.stream(&s.transport)}
submit_close :: proc(s:^State){if !s.closing {assert(net.async_close(stream(s),&s.close).kind==.None);s.closing=true}}
begin :: proc(s:^State,second:bool){
 budget:=async.deadline_after(&s.runtime,2*time.Second if second else 250*time.Millisecond)
 assert(adapter.set_request_budget(&s.loop,budget).kind==.None)
 if !second {s.cap_a=budget}
 path:="http://localhost/B" if second else "http://localhost/A"
 assert(exchange.exchange_begin(&s.x,stream(s),{method=.GET,url=path},{budget.at,adapter.wall_budget(&s.loop)},{s,wake}).kind==.None)
 s.begun=true
}
resume :: proc(data:rawptr)->async.Resume_Result {
 s:=cast(^State)data;s.resumes+=1
 if !s.started {
  assert(adapter.init_executor(&s.loop,&s.runtime,&s.task).kind==.None)
  s.connect,_=async.begin_connect(&s.runtime,&s.task,s.endpoint,async.deadline_after(&s.runtime,5*time.Second))
  s.started=true
 }
 if !s.connected {
  socket,error:=async.finish_connect(s.connect,async.deadline_after(&s.runtime,5*time.Second))
  if error.kind==.Pending{return .Waiting};assert(error.kind==.None)
  s.socket=socket;s.connected=true
  assert(adapter.init_transport(&s.transport,&s.loop,s.socket).kind==.None)
 }
 if !s.wrapped {
  s.wrapped=true
  s.close={callback=close_done,user_data=s}
  assert(exchange.exchange_init(&s.x,{},s.allocator).kind==.None)
  if s.encrypted {
   assert(tls.async_client(&s.secure,adapter.stream(&s.transport),adapter.executor(&s.loop),{server_name="localhost",root_cas=s.roots.roots[:s.roots.count]},s.allocator)==.None)
   s.hs={callback=hs_done,user_data=s}
   assert(tls.async_handshake(&s.secure,&s.hs,{}).kind==.None)
  }else{s.handshaken=true}
 }
 if s.closed {assert(adapter.quiescent(&s.loop));assert(exchange.exchange_destroy(&s.x).kind==.None);return .Done}
 if s.closing{return adapter.drive(&s.loop)}
 if !s.handshaken{return adapter.drive(&s.loop)}
 if intrinsics.atomic_load(&s.completed)==1 && !s.checked {
  if intrinsics.atomic_load(&s.release)==0{return adapter.drive(&s.loop)}
  now:=async.deadline_after(&s.runtime,0)
  if now.at<=s.cap_a.at+20*i64(time.Millisecond) {
   error:=async.sleep_until(&s.runtime,{epoch=now.epoch,at=s.cap_a.at+20*i64(time.Millisecond)})
   assert(error.kind==.Pending||error.kind==.None);return .Waiting
  }
  s.local_idle=.Ready
  if s.encrypted{s.local_idle=tls.async_idle_state(&s.secure)}
  // Checked-out request B has its own cap. The old A cutoff is now expired.
  // No old budget_error call is used to veto this genuinely idle generation.
  if s.reuse && s.local_idle==.Ready {
   next:=async.deadline_after(&s.runtime,2*time.Second)
   assert(adapter.set_request_budget(&s.loop,next).kind==.None)
   probe,error:=async.probe_stream(s.socket);assert(error.kind==.None);s.probe=probe
  }else{s.probe=.Invalid}
  s.checked=true
  healthy:=s.mode=="healthy"||s.mode=="fragmented"||s.mode=="keyupdate-inline"
  if healthy {assert(s.reuse&&s.local_idle==.Ready&&s.probe==.Empty);begin(s,true)}else{
   assert(!s.reuse||s.local_idle!=.Ready||s.probe!=.Empty)
   submit_close(s);return .Yield
  }
 }
 if !s.begun {begin(s,false)}
 result:=exchange.exchange_drive(&s.x,async.deadline_after(&s.runtime,0).at,false,1)
 assert(result.work_used>=0&&result.work_used<=1)
 if result.error.kind!=.None {fmt.eprintf("exchange error %v\n",result.error)}
 assert(result.error.kind==.None)
 if result.status==.Done {
  response:surf.Response
  assert(exchange.exchange_take(&s.x,&response).kind==.None)
  expected:="A" if intrinsics.atomic_load(&s.completed)==0 else "B"
  assert(response.status==200&&string(response.body)==expected)
  surf.response_destroy(&response)
  assert(exchange.exchange_quiescent(&s.x))
  assert(exchange.exchange_reset(&s.x).kind==.None)
  s.reuse=result.reuse_eligible
  count:=intrinsics.atomic_add(&s.completed,1)+1
  if count==2 {submit_close(s);return .Yield}
  return adapter.drive(&s.loop)
 }
 return .Yield if result.status==.Progress else adapter.drive(&s.loop)
}
cancel :: proc(data:rawptr)->async.Resume_Result {s:=cast(^State)data;assert(false,"fixture watchdog cancellation");return .Done}
main :: proc(){
 assert(len(os.args)==5)
 endpoint,ok:=net.parse_endpoint(os.args[1]);assert(ok)
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&track)
 s:=new(State,allocator);s.endpoint=endpoint;s.mode=os.args[2];s.encrypted=os.args[3]=="tls";s.allocator=allocator
 dir:=os.args[4]
 if s.encrypted {
  path:=fmt.tprintf("%s/root.pem",dir)
  root,error:=os.read_entire_file(path,allocator);assert(error==nil)
  assert(tls.root_pool_parse(&s.roots,root,allocator).kind==.None);delete(root,allocator)
 }
 assert(async.init(&s.runtime,{workers=1,task_capacity=1,io_capacity=1,allocator=allocator}).kind==.None)
 s.task={data=s,resume=resume,on_cancel=cancel,on_done=proc(data:rawptr){intrinsics.atomic_store(&(cast(^State)data).done,1)}}
 assert(async.spawn(&s.runtime,&s.task).kind==.None)
 assert(async.start(&s.runtime).kind==.None)
 start:=time.tick_now();notified:=false
 for intrinsics.atomic_load(&s.done)==0 {
  assert(time.tick_since(start)<12*time.Second)
  if intrinsics.atomic_load(&s.completed)==1 && !notified {
   path:=fmt.tprintf("%s/A.done",dir);assert(os.write_entire_file(path,"done")==nil);notified=true
  }
  if notified&&intrinsics.atomic_load(&s.release)==0 {
   path:=fmt.tprintf("%s/staged",dir)
   if os.exists(path){intrinsics.atomic_store(&s.release,1);assert(async.wake(&s.runtime,&s.task))}
  }
  thread.yield()
 }
 assert(async.wait_idle(&s.runtime).kind==.None)
 assert(async.destroy(&s.runtime).kind==.None)
 tls.root_pool_destroy(&s.roots)
 fmt.print("{")
 fmt.printf("\"completed\":%d,\"tls\":%v,\"idle\":\"%v\",\"probe\":\"%v\",\"resumes\":%d,\"wakes\":%d,\"close_error\":\"%v\",\"old_cutoff_expired\":true}\n",intrinsics.atomic_load(&s.completed),s.encrypted,s.local_idle,s.probe,s.resumes,s.wakes,s.close_error)
 free(s,allocator)
 assert(track.current_memory_allocated==0&&len(track.allocation_map)==0&&len(track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&track)
 fmt.println("{\"heap_zero\":true}")
}
