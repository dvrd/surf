package main

import api "shared:surf/async"
import runtime_async "shared:async"
import surf "shared:surf"
import http "shared:http"
import rt "base:runtime"
import "core:crypto/sha2"
import "core:crypto/tls"
import "core:encoding/json"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:mem/owned"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import scopes "core:sync/budget"
import "core:sys/posix"
import "core:thread"
import "core:time"
import "base:intrinsics"

Evidence :: struct {
 mode: string,
 tls: bool,
 bytes: u64,
 sha256: string,
 chunks, max_held_chunks, max_response_backing, max_upload_bytes: int,
 ended, head_received, first_chunk_barrier, intermediate_hidden: bool,
 status: int,
 wire_content_length: i64,
 delivery, error_kind, http_kind, phase, decoding, write_effect, source_io, transport: string,
 source_created, source_accepted, source_rejected, source_released, source_reentries: int,
 source_accepted_bytes, upload_blocked_after_bytes, upload_stall_ns: u64,
 late_owner, credit_preserved, chunk_credit_held, credit_reopened, occupied_preserved: bool,
 deadline_without_poll, cancel_without_poll: bool,
 cheap_before_release: bool,
 baseline_bytes, peak_bytes: i64,
 retained_after_teardown_bytes: u64,
 heap_zero, scope_zero, fd_zero: bool,
 allocation_calls, allocation_hits: int,
 allocation_sizes: [4]int,
 elapsed_ns: u64,
 source_error_completed_ns: u64,
}
Failure :: struct {
 mu: sync.Mutex,
 backing: mem.Allocator,
 armed: bool,
 point, calls, hits: int,
 sizes: [4]int,
}
Upload_Counter :: struct {
 allocator: mem.Allocator,
 client: ^api.Client,
 released: int,
 reentries: int,
}
Fixture :: struct {
 mode, directory: string,
 encrypted: bool,
 size: int,
 allocator: mem.Allocator,
 track: mem.Tracking_Allocator,
 runtime: ^runtime_async.Runtime,
 client: ^api.Client,
 scope: scopes.Scope,
 roots: tls.Root_Pool,
 head: api.Stream_Head,
 held: [2]owned.Chunk,
 held_offset: [2]u64,
 upload: Upload_Counter,
 evidence: Evidence,
 hash: sha2.Context_256,
 fd_before: int,
 request_taken: bool,
 failure: Failure,
 started: time.Tick,
 source_error_at: time.Tick,
}

fd_count :: proc()->int {
 count:=0
 for fd in 0..<1024 {if posix.fcntl(posix.FD(fd),.GETFD)>=0 {count+=1}}
 return count
}
marker :: proc(f:^Fixture,name:string) {
 assert(os.write_entire_file(fmt.tprintf("%s/%s",f.directory,name),name)==nil)
}
marked :: proc(f:^Fixture,name:string)->bool {
 return os.exists(fmt.tprintf("%s/%s",f.directory,name))
}
pattern_byte :: proc(offset:u64)->u8 {return u8((offset*31+offset/251+17)%256)}
is_upload :: proc(mode:string)->bool {return strings.has_prefix(mode,"upload") || strings.has_prefix(mode,"early-final")}
large_gzip :: proc(f:^Fixture)->bool {
 return strings.has_prefix(f.mode,"gzip") && f.size>=4<<20 && f.mode!="gzip-amplification"
}
extended_correctness_budget :: proc(f:^Fixture)->bool {
 return large_gzip(f) || f.mode=="fragmented" && f.encrypted
}
is_error :: proc(mode:string)->bool {
 return strings.has_prefix(mode,"chunk-") || mode=="conflicting-framing" || mode=="short-length" ||
  strings.has_prefix(mode,"coding-") ||
  mode=="gzip-crc" || mode=="gzip-crc-held" || mode=="gzip-size" || mode=="gzip-truncated" || mode=="gzip-trailing" ||
  mode=="gzip-members" || mode=="gzip-fhcrc-invalid" || mode=="gzip-encoded-limit" ||
  mode=="gzip-decoded-limit" || mode=="gzip-amplification" || mode=="encoded-limit" ||
  mode=="decoded-limit" || mode=="timeout" || mode=="cancel" || mode=="upload-short" ||
  mode=="upload-cancel" || mode=="upload-source-error" || mode=="upload-source-error-blocked" || mode=="redirect-malformed" ||
  mode=="redirect-gzip-invalid" || mode=="redirect-loop" || mode=="redirect-downgrade" ||
  mode=="redirect-deadline" || mode=="redirect-cross-auth" || mode=="buffered-short" ||
  strings.has_prefix(mode,"allocation-") || mode=="fairness"
}
hex_digest :: proc(destination:[]u8,digest:[]u8) {
 digits:="0123456789abcdef";assert(len(destination)==2*len(digest))
 for value,index in digest {destination[2*index]=digits[value>>4];destination[2*index+1]=digits[value&15]}
}
upload_release :: proc(storage:[]u8,data:rawptr) {
 counter:=cast(^Upload_Counter)data
 if counter.client!=nil {
  // Final disposal may have already cleared the public header. Reentry must
  // return normally even when the public capability has become invalid.
  _,_=api.client_stats(counter.client)
  intrinsics.atomic_add(&counter.reentries,1)
 }
 for &value in storage {value=0xdd}
 delete(storage,counter.allocator)
 intrinsics.atomic_add(&counter.released,1)
}
failure_allocator :: proc(data:rawptr,mode:mem.Allocator_Mode,size,alignment:int,
 old_memory:rawptr,old_size:int,location:=#caller_location)->([]u8,mem.Allocator_Error) {
 failure:=cast(^Failure)data
 if mode==.Alloc || mode==.Alloc_Non_Zeroed {
  sync.lock(&failure.mu)
  selected:=false
  if failure.armed {
   assert(failure.calls<len(failure.sizes));failure.sizes[failure.calls]=size;failure.calls+=1
   selected=failure.calls==failure.point
   if selected {failure.hits+=1}
  }
  sync.unlock(&failure.mu)
  if selected {return nil,.Out_Of_Memory}
 }
 return failure.backing.procedure(failure.backing.data,mode,size,alignment,old_memory,old_size,location)
}
arm_failure :: proc(f:^Fixture,point:int) {
 sync.lock(&f.failure.mu);defer sync.unlock(&f.failure.mu)
 assert(!f.failure.armed && point>0 && point<=len(f.failure.sizes))
 f.failure.point=point;f.failure.armed=true
}
upload_chunk :: proc(f:^Fixture,size:int,offset:int)->owned.Chunk {
 bytes:=make([]u8,size,f.allocator)
 for &value,index in bytes {value=pattern_byte(u64(offset+index))}
 result,error:=owned.take_custom(&bytes,len(bytes),upload_release,&f.upload)
 assert(error.kind==.None && bytes==nil)
 f.evidence.source_created+=1
 return result
}

initialize :: proc(f:^Fixture,endpoint:net.Endpoint) {
 mem.tracking_allocator_init(&f.track,rt.heap_allocator(),rt.heap_allocator())
 f.allocator=mem.tracking_allocator(&f.track)
 scope,cause:=scopes.create_root({bytes=256<<20,streams=8,jobs=16},f.allocator)
 assert(cause==.None);f.scope=scope
 f.runtime=new(runtime_async.Runtime,f.allocator);f.client=new(api.Client,f.allocator)
 assert(runtime_async.init(f.runtime,{workers=1,task_capacity=4,io_capacity=2,allocator=f.allocator}).kind==.None)
 if f.encrypted {
  bytes,error:=os.read_entire_file(fmt.tprintf("%s/root.pem",f.directory),f.allocator)
  assert(error==nil);assert(tls.root_pool_parse(&f.roots,bytes,f.allocator).kind==.None);delete(bytes,f.allocator)
 }
 config:=api.Client_Config{
  http={allow_http=true,timeout=10*time.Second,max_body_size=64<<20,scope=f.scope},
  capacities=api.Capacities{requests=3,origins=2,connections=2,connections_per_origin=1,waiters_per_origin=2,dns_ids=0,work_per_resume=128},
  streaming=api.Stream_Client_Limits{streams=1,response_chunks=2,upload_chunks=2,max_chunk_bytes=16384,max_retained_bytes_per_stream=65536},
 }
 if extended_correctness_budget(f) {config.http.timeout=30*time.Second}
 if strings.has_prefix(f.mode,"redirect") {config.http.max_redirects=2}
 if f.mode=="upload-backing" {
  limits,enabled:=config.streaming.?;assert(enabled);limits.upload_chunks=4;config.streaming=limits
 }
 if f.mode=="fairness" {limits,_:=config.capacities.?;limits.work_per_resume=1;config.capacities=limits}
 protocols:=[1]string{"http/1.1"}
 if f.encrypted {config.http.tls.root_cas=f.roots.roots[:f.roots.count];config.http.tls.alpn_protocols=protocols[:]}
 f.failure.backing=f.allocator
 assert(api.client_init(f.client,f.runtime,config,{failure_allocator,&f.failure}).kind==.None)
 f.upload={allocator=f.allocator,client=f.client}
 sync.lock(&f.track.mutex);f.evidence.baseline_bytes=f.track.current_memory_allocated;sync.unlock(&f.track.mutex)
 f.evidence.mode=f.mode;f.evidence.tls=f.encrypted
 sha2.init_256(&f.hash)
 _=endpoint
}

observe_stats :: proc(f:^Fixture) {
 stats,valid:=api.client_stats(f.client);assert(valid)
 assert(stats.streaming.held_response_chunks<=2)
 assert(stats.streaming.response_backing_bytes<=32768)
 assert(stats.streaming.upload_bytes<=65536)
 f.evidence.max_held_chunks=max(f.evidence.max_held_chunks,stats.streaming.held_response_chunks)
 f.evidence.max_response_backing=max(f.evidence.max_response_backing,stats.streaming.response_backing_bytes)
 f.evidence.max_upload_bytes=max(f.evidence.max_upload_bytes,stats.streaming.upload_bytes)
}
remember_error :: proc(f:^Fixture,error:api.Client_Error) {
 if error.kind==.None || error.kind==.Pending {return}
 if f.evidence.error_kind!="" {return}
 f.evidence.error_kind=fmt.aprintf("%v",error.kind)
 f.evidence.http_kind=fmt.aprintf("%v",error.http.kind)
 f.evidence.phase=fmt.aprintf("%v",error.http.phase)
 f.evidence.decoding=fmt.aprintf("%v",error.http.decoding)
 f.evidence.write_effect=fmt.aprintf("%v",error.http.write_effect)
 f.evidence.source_io=fmt.aprintf("%v",error.http.source_io)
 f.evidence.transport=fmt.aprintf("%v",error.http.transport)
 if f.evidence.status==0 {f.evidence.status=error.http.status}
}
check_payload :: proc(f:^Fixture,bytes:[]u8) {
 for value,index in bytes {
  offset:=f.evidence.bytes+u64(index)
  expected:=pattern_byte(offset)
  if f.mode=="gzip-amplification" {expected='A'}
  if is_upload(f.mode) || strings.has_prefix(f.mode,"redirect") {
   text:="no!" if strings.has_prefix(f.mode,"early-final") else "ok"
   assert(offset<u64(len(text)));expected=text[int(offset)]
  }
  if f.mode=="chunk-invalid-crlf" || f.mode=="chunk-missing-terminal" || f.mode=="chunk-truncated" {
   text:="partial" if f.mode=="chunk-truncated" else "abc"
   assert(offset<u64(len(text)));expected=text[int(offset)]
  }
  assert(value==expected)
 }
 sha2.update(&f.hash,bytes);f.evidence.bytes+=u64(len(bytes));f.evidence.chunks+=1
}

options :: proc(f:^Fixture)->api.Stream_Options {
 result:=api.Stream_Options{max_encoded_bytes=64<<20,max_decoded_bytes=64<<20}
 if is_upload(f.mode) {result.upload_length=i64(f.size)}
 if strings.has_prefix(f.mode,"gzip") || f.mode=="redirect-gzip-invalid" ||
    strings.has_prefix(f.mode,"coding-") || strings.has_suffix(f.mode,"-gzip") {result.decoding=.Gzip}
 if f.mode=="encoded-limit" {result.max_encoded_bytes=u64(f.size-1)}
 if f.mode=="decoded-limit" || f.mode=="gzip-decoded-limit" {result.max_decoded_bytes=u64(f.size-1)}
 if f.mode=="gzip-amplification" {result.max_decoded_bytes=65536}
 if f.mode=="gzip-encoded-limit" {result.max_encoded_bytes=16}
 if f.mode=="gzip-encoded-exact" {
  bytes,error:=os.read_entire_file(fmt.tprintf("%s/encoded-length",f.directory),context.allocator);assert(error==nil)
  value,valid:=strconv.parse_u64(string(bytes));assert(valid);result.max_encoded_bytes=value;delete(bytes)
 }
 if f.mode=="decoded-exact" || f.mode=="gzip-decoded-exact" {result.max_decoded_bytes=u64(f.size)}
 if f.mode=="head-gzip" || f.mode=="no-content-gzip" || f.mode=="not-modified-gzip" {
  result.max_encoded_bytes=1;result.max_decoded_bytes=1
 }
 return result
}

submit :: proc(f:^Fixture,endpoint:net.Endpoint)->api.Request_Handle {
 scheme:="https" if f.encrypted else "http"
 url:=fmt.tprintf("%s://127.0.0.1:%d/start",scheme,endpoint.port)
 fields:=[1]http.Header{{name="Authorization",value="Bearer owned-fixture"}}
 request:=http.Request{method=.POST if is_upload(f.mode) else .GET,url=url}
 if f.mode=="head-gzip" {request.method=.HEAD}
 if f.mode=="redirect-cross-auth" {request.headers=fields[:]}
 duration:=250*time.Millisecond if f.mode=="redirect-deadline" else 10*time.Second
 if extended_correctness_budget(f) {duration=30*time.Second}
 if f.mode=="timeout" {duration=300*time.Millisecond}
 handle,error:=api.client_submit_stream(f.client,request,options(f),runtime_async.deadline_after(f.runtime,duration))
 assert(error.kind==.None)
 response:surf.Response
 assert(api.client_take(f.client,handle,&response).kind!=.None && response.body==nil)
 if f.mode=="allocation-engine" {arm_failure(f,1)}
 if f.mode!="upload-backing" {assert(runtime_async.start(f.runtime).kind==.None)}
 if f.mode=="allocation-head-fields" {
  started:=time.tick_now()
  for !marked(f,"allocation-ready") {assert(time.tick_since(started)<5*time.Second);time.sleep(time.Millisecond)}
  arm_failure(f,2);marker(f,"allocation-release")
 }
 return handle
}

produce :: proc(f:^Fixture,handle:api.Request_Handle) {
 if !is_upload(f.mode) {return}
 if f.mode=="early-final" {return}
 if f.mode=="upload-backing" {
  assert(f.size==3)
  chunks:[3]owned.Chunk
  for &chunk,index in chunks {
   chunk=upload_chunk(f,16384,index);chunk.data=chunk.data[:1]
  }
  for index in 0..<2 {
   status,error:=api.client_upload_submit(f.client,handle,&chunks[index])
   assert(status==.Accepted && error.kind==.None && !owned.valid(&chunks[index]))
   f.evidence.source_accepted+=1
   f.evidence.source_accepted_bytes+=1
  }
  stats,valid:=api.client_stats(f.client);assert(valid && stats.streaming.upload_bytes==32768)
  status,error:=api.client_upload_submit(f.client,handle,&chunks[2])
  assert(status==.Backpressure && error.kind==.None && owned.valid(&chunks[2]))
  f.evidence.source_rejected+=1;f.evidence.credit_preserved=true
  observe_stats(f)
  assert(runtime_async.start(f.runtime).kind==.None)
  started:=time.tick_now()
  for {
   status,error=api.client_upload_submit(f.client,handle,&chunks[2])
   if status==.Accepted {assert(error.kind==.None);f.evidence.source_accepted+=1;f.evidence.source_accepted_bytes+=1;break}
   assert(status==.Backpressure && owned.valid(&chunks[2]) && time.tick_since(started)<5*time.Second)
   thread.yield()
  }
  assert(api.client_upload_finish(f.client,handle).kind==.None);return
 }
 if f.mode=="upload-oversize" || f.mode=="upload-overrun" || f.mode=="upload-empty" {
  size:=16385 if f.mode=="upload-oversize" else f.size+1 if f.mode=="upload-overrun" else 0
  rejected:=upload_chunk(f,size,0)
  if f.mode=="upload-oversize" {rejected.data=rejected.data[:1]}
  before:=rejected
  status,error:=api.client_upload_submit(f.client,handle,&rejected)
  _=error
  assert(status==.Invalid if f.mode=="upload-empty" else status==.Limit_Exceeded)
  assert(owned.valid(&rejected) && raw_data(rejected.storage)==raw_data(before.storage) && len(rejected.storage)==len(before.storage) && rejected.release==before.release)
  f.evidence.source_rejected+=1;f.evidence.occupied_preserved=true;owned.destroy(&rejected)
 }
 offset:=0
 started:=time.tick_now()
 stalled:time.Tick
 stalled_releases:=0
 for offset<f.size {
  chunk:=upload_chunk(f,min(16384,f.size-offset),offset)
  for {
   assert(time.tick_since(started)<13*time.Second)
   status,error:=api.client_upload_submit(f.client,handle,&chunk)
   observe_stats(f)
   if status==.Accepted {
    assert(error.kind==.None && !owned.valid(&chunk));f.evidence.source_accepted+=1
    f.evidence.source_accepted_bytes+=u64(min(16384,f.size-offset))
    offset+=min(16384,f.size-offset);stalled={};break
   }
   assert(owned.valid(&chunk));f.evidence.source_rejected+=1
   if status==.Closed {owned.destroy(&chunk);return}
   assert(status==.Backpressure && (error.kind==.None || error.kind==.Pending))
   if (f.mode=="early-final-blocked" || f.mode=="upload-source-error-blocked") && marked(f,"head-received") && !marked(f,"upload-blocked") {
    released:=intrinsics.atomic_load(&f.upload.released)
    if stalled==(time.Tick{}) || released!=stalled_releases {stalled=time.tick_now();stalled_releases=released}
    if time.tick_since(stalled)>100*time.Millisecond {
     f.evidence.upload_blocked_after_bytes=u64(offset)
     f.evidence.upload_stall_ns=u64(time.tick_since(stalled));marker(f,"upload-blocked")
     if f.mode=="upload-source-error-blocked" {
      f.source_error_at=time.tick_now()
      assert(api.client_upload_finish(f.client,handle,.Unexpected_EOF).kind==.None)
      owned.destroy(&chunk);return
     }
    }
   }
   thread.yield()
  }
  if f.mode=="early-final-prefix" && offset>=1<<20 {return}
  if (f.mode=="upload-short" || f.mode=="upload-source-error") && offset>=f.size/2 {break}
  if f.mode=="upload-cancel" && offset>=f.size/2 {assert(api.client_cancel(f.client,handle).kind==.None);return}
 }
 cause:io.Error
 if f.mode=="upload-source-error" {cause=.Unexpected_EOF}
 finish:=api.client_upload_finish(f.client,handle,cause)
 assert(finish.kind==.None || f.mode=="upload-short" || f.mode=="upload-source-error")
}

consume :: proc(f:^Fixture,handle:api.Request_Handle) {
 started:=time.tick_now();head_seen:=false;held:=0;credit_started:time.Tick
 limit:=40*time.Second if extended_correctness_budget(f) else 14*time.Second
 for {
  assert(time.tick_since(started)<limit)
  observe_stats(f)
  if !head_seen {
   error:=api.client_stream_take_head(f.client,handle,&f.head)
   if error.kind==.None {
    head_seen=true;f.evidence.head_received=true;f.evidence.status=f.head.response.status
    f.evidence.wire_content_length=f.head.wire_content_length
    f.evidence.delivery=fmt.aprintf("%v",f.head.delivery)
    assert(f.head.response.body==nil)
    if strings.has_prefix(f.mode,"redirect") {assert(f.head.response.status==200)}
   } else if error.kind!=.Pending {remember_error(f,error);return}
   if !head_seen && marked(f,"intermediate-written") && !f.evidence.intermediate_hidden {
    assert(error.kind==.Pending);f.evidence.intermediate_hidden=true;marker(f,"intermediate-hidden")
   }
  }
  if !head_seen {thread.yield();continue}
  chunk:owned.Chunk
  state,error:=api.client_stream_next(f.client,handle,&chunk)
  if error.kind!=.None {assert(!owned.valid(&chunk));remember_error(f,error);return}
  if state==.End {f.evidence.ended=true;return}
  if state==.Pending {
   if f.mode=="credit" && held==2 && !f.evidence.chunk_credit_held {
    if credit_started==(time.Tick{}) {credit_started=time.tick_now()}
    if time.tick_since(credit_started)>100*time.Millisecond {
     assert(owned.valid(&f.held[0]) && owned.valid(&f.held[1]))
     owned.destroy(&f.held[0]);f.evidence.chunk_credit_held=true
    }
   }
   thread.yield();continue
  }
  assert(state==.Chunk && owned.valid(&chunk) && len(chunk.data)>0)
  if f.mode=="credit" && held==2 {assert(f.evidence.chunk_credit_held)}
  offset:=f.evidence.bytes;check_payload(f,chunk.data)
  if f.evidence.chunks==1 {marker(f,"first-taken");f.evidence.first_chunk_barrier=marked(f,"first-written")}
  keep:=(strings.has_prefix(f.mode,"late") && f.mode!="late-head" || f.mode=="gzip-crc-held") && held==0 ||
   (f.mode=="credit" || f.mode=="timeout" || f.mode=="cancel" || f.mode=="fairness") && held<2
  if keep {
   assert(owned.move(&f.held[held],&chunk));f.held_offset[held]=offset;held+=1
   if (f.mode=="timeout" || f.mode=="cancel") && held==2 {
    if f.mode=="cancel" {assert(api.client_cancel(f.client,handle).kind==.None)}
    // No Client API calls can drive the actor here. The independent blocked
    // peer must observe physical transport retirement on the autonomous wake.
    waiting:=time.tick_now()
    for !marked(f,"transport-retired") {
     assert(time.tick_since(waiting)<2*time.Second);time.sleep(time.Millisecond)
    }
    if f.mode=="timeout" {f.evidence.deadline_without_poll=true}
    else {f.evidence.cancel_without_poll=true}
   }
   if f.mode=="fairness" && held==2 {fairness(f,handle)}
  } else {owned.destroy(&chunk)}
 }
}

fairness :: proc(f:^Fixture,held:api.Request_Handle) {
 bytes,error:=os.read_entire_file(fmt.tprintf("%s/cheap-endpoint",f.directory),f.allocator);assert(error==nil)
 endpoint,valid:=net.parse_endpoint(string(bytes));assert(valid);delete(bytes,f.allocator)
 cheap,cause:=api.client_submit(f.client,{method=.GET,url=fmt.tprintf("http://127.0.0.1:%d/cheap",endpoint.port)},runtime_async.deadline_after(f.runtime,2*time.Second))
 assert(cause.kind==.None)
 started:=time.tick_now()
 for {
  result,ready:=api.client_poll(f.client)
  if ready {assert(result.request==cheap && result.error.kind==.None);break}
  assert(time.tick_since(started)<3*time.Second);thread.yield()
 }
 response:surf.Response
 assert(api.client_take(f.client,cheap,&response).kind==.None && response.status==200 && string(response.body)=="ok")
 surf.response_destroy(&response)
 assert(!marked(f,"transport-retired"));f.evidence.cheap_before_release=true
 assert(api.client_cancel(f.client,held).kind==.None)
 for !marked(f,"transport-retired") {assert(time.tick_since(started)<5*time.Second);time.sleep(time.Millisecond)}
}

completion :: proc(f:^Fixture,handle:api.Request_Handle) {
 started:=time.tick_now()
 for {
  result,available:=api.client_poll(f.client)
  if available {
   assert(result.request==handle)
   if is_error(f.mode) {assert(result.error.kind!=.None)} else {assert(result.error.kind==.None)}
   if result.error.kind!=.None && f.evidence.error_kind=="" {remember_error(f,{kind=.Request_Error,http=result.error})}
   return
  }
  assert(time.tick_since(started)<12*time.Second);thread.yield()
 }
}

cleanup :: proc(f:^Fixture,handle:api.Request_Handle) {
 sync.lock(&f.failure.mu)
 f.failure.armed=false;f.evidence.allocation_calls=f.failure.calls
 f.evidence.allocation_hits=f.failure.hits;f.evidence.allocation_sizes=f.failure.sizes
 sync.unlock(&f.failure.mu)
 if strings.has_prefix(f.mode,"allocation-") {assert(f.evidence.allocation_hits==1)}
 if f.mode=="credit" || f.mode=="late-chunk" {api.stream_head_destroy(&f.head)}
 if !f.request_taken {assert(api.client_release(f.client,handle).kind==.None)}
 if strings.has_prefix(f.mode,"late") || f.mode=="credit" {
  // Head and taken chunks retain the stream admission cell after handle release.
  scheme:="https" if f.encrypted else "http"
  _,error:=api.client_submit_stream(f.client,{method=.GET,url=fmt.tprintf("%s://127.0.0.1:1/",scheme)},options(f))
  assert(error.kind==.Capacity);f.evidence.credit_preserved=true
 }
 if f.mode=="credit" {
  assert(f.evidence.chunk_credit_held)
  for &chunk in f.held {owned.destroy(&chunk)}
  scheme:="https" if f.encrypted else "http"
  next,error:=api.client_submit_stream(f.client,{method=.GET,url=fmt.tprintf("%s://127.0.0.1:1/",scheme)},options(f))
  assert(error.kind==.None);f.evidence.credit_reopened=true
  _=api.client_cancel(f.client,next)
  started:=time.tick_now()
  for {
   result,ready:=api.client_poll(f.client)
   if ready {assert(result.request==next && result.error.kind!=.None);break}
   assert(time.tick_since(started)<5*time.Second);thread.yield()
  }
  assert(api.client_release(f.client,next).kind==.None)
 }
 error:=api.client_close(f.client);assert(error.kind==.None || error.kind==.Pending)
 started:=time.tick_now()
 for !api.client_quiescent(f.client) {assert(time.tick_since(started)<8*time.Second);thread.yield()}
 assert(api.client_destroy(f.client).kind==.None)
 assert(runtime_async.destroy(f.runtime).kind==.None)
 f.upload.client=nil
 mem.free(f.client,f.allocator);mem.free(f.runtime,f.allocator);f.client=nil;f.runtime=nil
 tls.root_pool_destroy(&f.roots)
 if strings.has_prefix(f.mode,"late") || f.mode=="gzip-crc-held" {
  retained,cause:=scopes.snapshot(f.scope);assert(cause==.None && retained.used.bytes>0)
  f.evidence.retained_after_teardown_bytes=retained.used.bytes
 }
 for &chunk,index in f.held {
  if owned.valid(&chunk) {
   for value,at in chunk.data {assert(value==pattern_byte(f.held_offset[index]+u64(at)))}
   owned.destroy(&chunk);f.evidence.late_owner=true
  }
 }
 if f.mode=="buffered-gzip" {
  assert(len(f.head.response.body)>18 && f.head.response.body[0]==31 && f.head.response.body[1]==139)
  encoding,present:=surf.response_header(&f.head.response,"Content-Encoding")
  assert(present && encoding=="gzip");surf.response_destroy(&f.head.response)
 } else if f.head.response.status!=0 {
  assert(f.head.response.body==nil)
  if strings.has_prefix(f.mode,"late") {f.evidence.late_owner=true}
  api.stream_head_destroy(&f.head)
 }
 snapshot,cause:=scopes.snapshot(f.scope);assert(cause==.None && snapshot.used==(scopes.Usage{}))
 scopes.release_scope(&f.scope)
 assert(fd_count()==f.fd_before);f.evidence.fd_zero=true;f.evidence.scope_zero=true
 sync.lock(&f.track.mutex)
 f.evidence.peak_bytes=f.track.peak_memory_allocated
 assert(f.track.current_memory_allocated==0 && len(f.track.bad_free_array)==0)
 sync.unlock(&f.track.mutex)
 f.evidence.source_released=intrinsics.atomic_load(&f.upload.released)
 f.evidence.source_reentries=intrinsics.atomic_load(&f.upload.reentries)
 assert(f.evidence.source_released==f.evidence.source_created)
 f.evidence.heap_zero=true
 assert(f.evidence.peak_bytes<=f.evidence.baseline_bytes+(4<<20))
 mem.tracking_allocator_destroy(&f.track)
}

buffered :: proc(f:^Fixture,endpoint:net.Endpoint)->api.Request_Handle {
 scheme:="https" if f.encrypted else "http"
 handle,error:=api.client_submit(f.client,{method=.GET,url=fmt.tprintf("%s://127.0.0.1:%d/start",scheme,endpoint.port)})
 assert(error.kind==.None);assert(runtime_async.start(f.runtime).kind==.None)
 completion(f,handle)
 response:surf.Response
 error=api.client_take(f.client,handle,&response)
 if f.mode=="buffered-short" {
  assert(error.kind==.Request_Error && response.status==0 && response.body==nil && response.headers==nil && response.body_storage==nil)
  remember_error(f,error);return handle
 }
 assert(error.kind==.None);f.request_taken=true
 f.head.response=response
 f.evidence.head_received=true;f.evidence.status=response.status
 f.evidence.delivery=fmt.aprintf("Wire");f.evidence.bytes=u64(len(response.body));f.evidence.ended=true
 sha2.update(&f.hash,response.body)
 return handle
}

main :: proc() {
 assert(len(os.args)==6)
 endpoint,valid:=net.parse_endpoint(os.args[1]);assert(valid)
 size,valid_size:=strconv.parse_int(os.args[5]);assert(valid_size && size>0 && size<=64<<20)
 f:=Fixture{mode=os.args[2],encrypted=os.args[3]=="tls",directory=os.args[4],size=size,fd_before=fd_count()}
 initialize(&f,endpoint)
 f.started=time.tick_now()
 handle:api.Request_Handle
 if strings.has_prefix(f.mode,"buffered") {handle=buffered(&f,endpoint)}
 else {handle=submit(&f,endpoint);produce(&f,handle);consume(&f,handle)}
 f.evidence.elapsed_ns=u64(time.tick_since(f.started))
 if f.evidence.error_kind!="" {
  fmt.eprintf("STREAM104 outcome mode=%s bytes=%d kind=%s http=%s phase=%s decoding=%s status=%d transport=%s\n",f.mode,f.evidence.bytes,f.evidence.error_kind,f.evidence.http_kind,f.evidence.phase,f.evidence.decoding,f.evidence.status,f.evidence.transport)
 }
 if is_error(f.mode) {assert(!f.evidence.ended && f.evidence.error_kind!="")} else {assert(f.evidence.ended)}
 if !strings.has_prefix(f.mode,"buffered") {completion(&f,handle)}
 if f.mode=="upload-source-error-blocked" {
  f.evidence.source_error_completed_ns=u64(time.tick_since(f.source_error_at))
  marker(&f,"native-failed")
 }
 digest:[32]u8;sha2.final(&f.hash,digest[:]);hex:[64]u8;hex_digest(hex[:],digest[:])
 cleanup(&f,handle)
 f.evidence.sha256=string(hex[:])
 encoded,error:=json.marshal(f.evidence);assert(error==nil);defer delete(encoded)
 fmt.println(string(encoded))
 for text in ([8]string{f.evidence.delivery,f.evidence.error_kind,f.evidence.http_kind,f.evidence.phase,f.evidence.decoding,f.evidence.write_effect,f.evidence.source_io,f.evidence.transport}) {
  if text!="" {delete(text)}
 }
}
