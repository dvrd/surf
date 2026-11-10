package main
import client "shared:surf/async"
import runtime_async "shared:async"
import surf "shared:surf"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import scopes "core:sync/budget"
import "core:strconv"
import "core:sync"
import "core:thread"
import "core:time"
import "core:sys/posix"
fd_count :: proc()->int {n:=0;for fd in 0..<1024{if posix.fcntl(posix.FD(fd),.GETFD)>=0{n+=1}};return n}

Grant :: struct {raw,view:[]u8,alignment:int}
Backing :: struct {
 mu:sync.Mutex,
 allocator:mem.Allocator,
 grants:[128]Grant,
 live,calls,armed_calls,point,mode,bad_frees,hits:int,
 sizes,alignments:[64]int,
 armed,destroying,header_freed:bool,
 first:rawptr,
 c:^client.Client,
 handle:client.Request_Handle,
 scope:scopes.Scope,
}
allocate :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error){
 p:=cast(^Backing)data
 switch mode {
 case .Alloc,.Alloc_Non_Zeroed:
  sync.lock(&p.mu);p.calls+=1;selected:=0
  if p.armed {p.armed_calls+=1;assert(p.armed_calls<=len(p.sizes));p.sizes[p.armed_calls-1]=size;p.alignments[p.armed_calls-1]=alignment;if p.armed_calls==p.point{selected=p.mode;p.hits+=1}}
  if selected==1 {sync.unlock(&p.mu);return nil,.Out_Of_Memory}
  if selected==3 {sync.unlock(&p.mu);return nil,nil}
  sync.unlock(&p.mu)
  if selected>=7 {stats,valid:=client.client_stats(p.c);assert(valid&&stats.active_requests+stats.preparing_requests>0);if selected==7{assert(scopes.close(p.scope)==.None)};if selected==8{assert(client.client_cancel(p.c,p.handle).kind==.None)};if selected==9{closed:=client.client_close(p.c);assert(closed.kind==.None||closed.kind==.Pending)}}
  sync.lock(&p.mu)
  actual:=size;if selected==4{actual=max(0,size-1)};if selected==5||selected==6{actual=size+1}
  raw,error:=p.allocator.procedure(p.allocator.data,mode,actual,max(16,alignment),nil,0,location);assert(error==nil)
  view:=raw;if selected==6{view=raw[1:]}
  stored:=false;for &grant in p.grants{if raw_data(grant.raw)==nil{grant={raw,view,max(16,alignment)};stored=true;break}};assert(stored)
  p.live+=len(raw);if p.first==nil{p.first=raw_data(view)};sync.unlock(&p.mu)
  if selected==2{return view,.Out_Of_Memory};return view,nil
 case .Free:
  if old_memory==nil{return nil,nil}
  sync.lock(&p.mu);old:=Grant{};for &grant in p.grants{if raw_data(grant.view)==old_memory{old=grant;grant={};break}}
  if raw_data(old.raw)==nil{p.bad_frees+=1;sync.unlock(&p.mu);return nil,.Invalid_Pointer}
  if old_size!=0&&old_size!=len(old.view){p.bad_frees+=1}
  free_header:=p.destroying&&old_memory==p.first&&!p.header_freed
  if free_header{p.header_freed=true}
  sync.unlock(&p.mu)
  // The whole State backing's physical Free happens after the public header
  // was cleared. Reentry and physical header disposal must not invalidate the
  // outer client_destroy's detached locals.
  if free_header{assert(client.client_destroy(p.c).kind==.Invalid_State);free(p.c,p.allocator);p.c=nil}
  result,error:=p.allocator.procedure(p.allocator.data,.Free,0,old.alignment,raw_data(old.raw),len(old.raw),location)
  sync.lock(&p.mu);p.live-=len(old.raw);sync.unlock(&p.mu);return result,error
 case .Query_Features:(cast(^mem.Allocator_Mode_Set)old_memory)^={.Alloc,.Alloc_Non_Zeroed,.Free,.Query_Features};return nil,nil
 case .Free_All,.Resize,.Resize_Non_Zeroed,.Query_Info:return nil,.Mode_Not_Implemented
 }
 return nil,.Mode_Not_Implemented
}
main :: proc(){
 assert(len(os.args)==5);endpoint,ok:=net.parse_endpoint(os.args[1]);assert(ok);dir:=os.args[2]
 point,valid:=strconv.parse_int(os.args[3]);assert(valid);mode,valid2:=strconv.parse_int(os.args[4]);assert(valid2)
 before_fd:=fd_count()
 track:mem.Tracking_Allocator;mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator());allocator:=mem.tracking_allocator(&track)
 scope,cause:=scopes.create_root({bytes=32<<20,streams=1,jobs=8},allocator);assert(cause==.None)
 r:runtime_async.Runtime;assert(runtime_async.init(&r,{workers=1,task_capacity=2,io_capacity=2,allocator=allocator}).kind==.None)
 p:=Backing{allocator=allocator,point=point,mode=mode,scope=scope};c:=new(client.Client,allocator);p.c=c
 config:=client.Client_Config{http={allow_http=true,timeout=3*time.Second,max_redirects=1,scope=scope},capacities=client.Capacities{requests=1,origins=1,connections=1,connections_per_origin=1,waiters_per_origin=0,dns_ids=0,work_per_resume=1}}
 assert(client.client_init(c,&r,config,{allocate,&p}).kind==.None);assert(runtime_async.start(&r).kind==.None)
 body:="fixed-owned-payload";url:=fmt.tprintf("http://127.0.0.1:%d/A",endpoint.port)
 handle,error:=client.client_submit(c,{method=.POST,url=url,body=transmute([]u8)body});assert(error.kind==.None)
 start:=time.tick_now();for !os.exists(fmt.tprintf("%s/A.received",dir)){assert(time.tick_since(start)<5*time.Second);time.sleep(time.Millisecond)}
 sync.lock(&p.mu);p.handle=handle;p.armed=true;sync.unlock(&p.mu)
 assert(os.write_entire_file(fmt.tprintf("%s/release",dir),"go")==nil)
 completion:=client.Completion{}
 for{item,available:=client.client_poll(c);if available{completion=item;break};assert(time.tick_since(start)<8*time.Second);thread.yield()}
 assert(completion.request==handle)
 response:surf.Response
 if completion.error.kind==.None{assert(client.client_take(c,handle,&response).kind==.None);assert(response.status==200&&string(response.body)=="response")}else{if mode<=6{assert(completion.error.kind==.Allocation_Failed)};assert(client.client_release(c,handle).kind==.None)}
 sync.lock(&p.mu);p.armed=false;count,hits:=p.armed_calls,p.hits;sizes,alignments:=p.sizes,p.alignments;sync.unlock(&p.mu)
 if point>0{assert(hits==1)}
 closed:=client.client_close(c);assert(closed.kind==.None||closed.kind==.Pending)
 for !client.client_quiescent(c){assert(time.tick_since(start)<8*time.Second);thread.yield()}
 sync.lock(&p.mu);p.destroying=true;sync.unlock(&p.mu);assert(client.client_destroy(c).kind==.None);assert(p.header_freed&&p.c==nil)
 assert(runtime_async.wait_idle(&r).kind==.None);assert(runtime_async.destroy(&r).kind==.None)
 usage,_:=scopes.snapshot(scope)
 // The taken whole-backed response keeps its own charged allocator alive,
 // including after the public Client header and Runtime were physically freed.
 if completion.error.kind==.None{assert(usage.used.bytes>0&&string(response.body)=="response")}
 assert(usage.used.streams==0&&usage.used.jobs==0);assert(usage.used.bytes==u64(p.live))
 surf.response_destroy(&response);usage,_=scopes.snapshot(scope);assert(usage.used==(scopes.Usage{}));scopes.release_scope(&scope)
 assert(fd_count()==before_fd);assert(p.live==0&&p.bad_frees==0);assert(track.current_memory_allocated==0&&len(track.bad_free_array)==0);mem.tracking_allocator_destroy(&track)
 assert(os.write_entire_file(fmt.tprintf("%s/done",dir),"done")==nil)
 fmt.print("{");fmt.printf("\"point\":%d,\"mode\":%d,\"calls\":%d,\"hits\":%d,\"error\":\"%v\",\"budget\":\"%v\",\"transport\":\"%v\",\"phase\":\"%v\",\"fd_zero\":true,\"header_freed\":true,\"heap_zero\":true,\"scope_zero\":true,\"sizes\":[",point,mode,count,hits,completion.error.kind,completion.error.budget,completion.error.transport.kind,completion.error.phase)
 for n in 0..<count{if n>0{fmt.print(",")};fmt.printf("%d",sizes[n])};fmt.print("],\"alignments\":[");for n in 0..<count{if n>0{fmt.print(",")};fmt.printf("%d",alignments[n])};fmt.println("]}")
}
