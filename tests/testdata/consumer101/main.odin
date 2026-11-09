package main
import client "shared:surf/async"
import surf "shared:surf"
import async "shared:async"
import h1 "shared:http/v1"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"

Fixture :: struct {at,written:int}
read :: proc(data:rawptr,dst:[]u8)->(int,net.Connection_Error) {
 f:=cast(^Fixture)data
 wire:="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
 if f.at==len(wire) {return 0,{kind=.Peer_Closed}}
 n:=copy(dst,wire[f.at:]);f.at+=n;return n,{}
}
write :: proc(data:rawptr,src:[]u8)->(int,net.Connection_Error) {f:=cast(^Fixture)data;f.written+=len(src);return len(src),{}}
close :: proc(_:rawptr)->net.Connection_Error {return {}}
main :: proc() {
 tracker:mem.Tracking_Allocator
 mem.tracking_allocator_init(&tracker,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&tracker)
 // Execute the unchanged blocking facade and HTTP/1 encoder in the same binary.
 fixture:Fixture
 response,error:=surf.exchange({data=&fixture,read=read,write=write,close=close},
  {method=.GET,url="https://fixture.invalid/"},8,allocator)
 assert(error.kind==.None && response.status==200 && string(response.body)=="ok" && fixture.written>0)
 surf.response_destroy(&response)
 buffer:[256]u8
 n,encoded:=h1.request_encode_profile(buffer[:],{method=.GET,url="http://example.test/"},.Keep_Alive)
 assert(encoded.kind==.None && string(buffer[:n])=="GET / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n")
 // Real public registration/admission/prestart ownership return. Protocol I/O
 // is independently exercised by client101; this consumer does not claim it.
 runtime:async.Runtime
 assert(async.init(&runtime,{workers=1,task_capacity=2,io_capacity=2,allocator=allocator}).kind==.None)
 c:client.Client
 config:=client.Client_Config{http={allow_http=true},capacities=client.Capacities{
  requests=2,origins=2,connections=1,connections_per_origin=1,waiters_per_origin=2,dns_ids=0,work_per_resume=1}}
 assert(client.client_init(&c,&runtime,config,allocator).kind==.None)
 request,admitted:=client.client_submit(&c,{method=.GET,url="http://127.0.0.1:1/prestart"})
 assert(admitted.kind==.None)
 assert(client.client_close(&c).kind==.None && client.client_quiescent(&c))
 completion,found:=client.client_poll(&c)
 assert(found && completion.request==request && completion.error.phase==.Cancellation && completion.error.write_effect==.Not_Sent)
 assert(client.client_release(&c,request).kind==.None)
 assert(client.client_destroy(&c).kind==.None)
 assert(async.destroy(&runtime).kind==.None)
 assert(tracker.current_memory_allocated==0 && len(tracker.allocation_map)==0 && len(tracker.bad_free_array)==0)
 mem.tracking_allocator_destroy(&tracker)
 fmt.println("CONSUMER101 public_client_prestart=true unchanged_facade=true http1=true heap_zero=true")
}
