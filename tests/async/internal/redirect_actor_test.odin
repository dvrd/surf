package surf_async

import runtime_async "../../async"
import "core:testing"
import "core:time"

// Public lifecycle only: the protocol runner supplies actual accepted-hop IO.
// This pins all enabled redirect caps without constructing a private Kernel.
@(test)
redirect28_public_config_and_prestart_handle_lifecycle :: proc(t:^testing.T) {
 for redirects in 0..=5 {
  runtime:runtime_async.Runtime
  assert(runtime_async.init(&runtime,{workers=1,task_capacity=2,io_capacity=1,allocator=context.allocator}).kind==.None)
  c:Client
  config:=Client_Config{http={allow_http=true,max_redirects=redirects,timeout=time.Second},capacities=Capacities{requests=1,origins=1,connections=1,connections_per_origin=1,waiters_per_origin=0,dns_ids=0,work_per_resume=1}}
  testing.expect_value(t,client_init(&c,&runtime,config,context.allocator).kind,.None)
  handle,error:=client_submit(&c,{method=.GET,url="http://127.0.0.1:1/no-network-before-start"})
  testing.expect_value(t,error.kind,.None)
  testing.expect(t,handle.owner_id!=0&&handle.slot!=0&&handle.generation!=0)
  closed:=client_close(&c);testing.expect(t,closed.kind==.None||closed.kind==.Pending)
  testing.expect(t,client_quiescent(&c))
  completion,available:=client_poll(&c)
  testing.expect(t,available);testing.expect_value(t,completion.request,handle)
  testing.expect(t,completion.error.kind!=.None)
  testing.expect_value(t,client_release(&c,handle).kind,.None)
  _,again:=client_poll(&c);testing.expect(t,!again)
  testing.expect_value(t,client_destroy(&c).kind,.None)
  testing.expect_value(t,runtime_async.destroy(&runtime).kind,.None)
 }
}
