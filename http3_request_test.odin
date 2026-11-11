package surf

import http "../http"
import http3 "../http/v3"
import "core:bytes"
import credentials "core:crypto/tls/credentials"
import store "core:crypto/tls/credentials/store"
import "core:crypto/tls"
import "core:fmt"
import "core:io"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

@(private)
Surf_H3_Fixture :: struct {
 listener: http3.Listener,
 stop: bool,
 calls: int,
 valid: bool,
 headers: [3]http3.Field,
}
@(private)
surf_h3_request_handler :: proc(data:rawptr, request:^http3.Server_Request, response:^http3.Server_Response)->http3.Response_Status {
 fixture:=cast(^Surf_H3_Fixture)data
 fixture.calls+=1
 valid:=request.method=="POST" && request.target=="/probe?one=two" && request.authority=="localhost:8443" && string(request.body)==("request-body" if fixture.calls<=2 else "")
 auth,cookie,kind,duplicates:=false,false,false,0
 for h in request.headers {
  if h.name=="authorization" {auth=h.value=="Bearer fixture"}
  if h.name=="cookie" {cookie=h.value=="session=fixture"}
  if h.name=="content-type" {kind=h.value=="application/json"}
  if h.name=="x-review" {duplicates+=1}
 }
 fixture.valid=fixture.valid && valid && auth && cookie && kind && duplicates==1
 fixture.headers={{name="www-authenticate",value="Bearer"},{name="set-cookie",value="a=1"},{name="set-cookie",value="b=2"}}
 response^={status=401,headers=fixture.headers[:],body=transmute([]u8)string("denied")}
 return .Ready
}
@(test)
surf_http3_preserves_request_upload_origin_and_response_headers :: proc(t:^testing.T) {
 testing.set_fail_timeout(t,40*time.Second)
 credential,ce:=credentials.create(#load("tests/http3/localhost.pem"),#load("../http/v3/testdata/rsa2048.pem"),{},context.allocator)
 if !testing.expect_value(t,ce,.None) {return}
 owner,se:=store.create({},context.allocator)
 if !testing.expect_value(t,se.kind,.None) {credentials.destroy(&credential);return}
 defer store.destroy(&owner)
 assert(store.replace(owner,&credential).kind==.None)
 fixture:=Surf_H3_Fixture{valid=true}
 fixture.listener.config={endpoint={net.IP4_Loopback,0},credentials=owner,on_request=surf_h3_request_handler,on_request_user=&fixture}
 port,ok:=http3.listener_listen(&fixture.listener)
 if !testing.expect(t,ok) {return}
 worker:=thread.create_and_start_with_poly_data(&fixture,proc(f:^Surf_H3_Fixture){for !sync.atomic_load(&f.stop) {if !http3.listener_step(&f.listener) {break}}})
 defer thread.destroy(worker)
 defer {sync.atomic_store(&fixture.stop,true);thread.join(worker);http3.listener_close(&fixture.listener)}
 roots:tls.Root_Pool
 assert(tls.root_pool_parse(&roots,#load("tests/http3/localhost.pem")).kind==.None)
 defer tls.root_pool_destroy(&roots)
 cache:Alt_Svc_Cache
 alt_buf:[80]u8
 assert(alt_svc_note(&cache,"localhost",fmt.bprintf(alt_buf[:],"h3=\":%d\"; ma=60",port),true,true,time.now(),8443))
 config:=Config{http3=true,alt_svc=&cache,timeout=8*time.Second,tls={root_cas=roots.roots[:roots.count]}}
 headers:=[]http.Header{{"Authorization","Bearer fixture"},{"Cookie","session=fixture"},{"Content-Type","application/json"},{"X-Review","one"}}
 request:=http.Request{method=.POST,url="https://localhost:8443/probe?one=two",headers=headers,body=transmute([]u8)string("request-body")}
 response,error:=execute(request,config)
 defer response_destroy(&response)
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,response.status,401)
 testing.expect_value(t,string(response.body),"denied")
 cookies:=0
 for h in response.headers {if h.name=="set-cookie" {cookies+=1}}
 testing.expect_value(t,cookies,2)
 // The second request consumes an io.Stream source rather than request.body.
 request.body=nil
 source:bytes.Buffer
 bytes.buffer_init_string(&source,"request-body")
 defer bytes.buffer_destroy(&source)
 uploaded,upload_error:=execute_upload(request,{stream=bytes.buffer_to_stream(&source),content_length=12},config)
 defer response_destroy(&uploaded)
 testing.expect_value(t,upload_error.kind,.None)
 testing.expect_value(t,uploaded.status,401)
 testing.expect_value(t,string(uploaded.body),"denied")
 config.max_body_size=3
 limited,limit_error:=execute_upload(request,{stream=bytes.buffer_to_stream(&source),content_length=0},config)
 defer response_destroy(&limited)
 testing.expect_value(t,limit_error.kind,.Body_Oversized)
 testing.expect_value(t,limit_error.phase,.Body_Limit)
 // A source callback can return after the total deadline. Preserve the
 // conservative sent state and source error instead of making it replay-safe.
 slow_reads:=0
 config.timeout=500*time.Millisecond;config.max_body_size=0
 late,late_error:=execute_upload(request,{stream={procedure=surf_h3_slow_source,data=&slow_reads},content_length=1},config)
 defer response_destroy(&late)
 testing.expect_value(t,slow_reads,1)
 testing.expect_value(t,late_error.kind,.Deadline_Failed)
 testing.expect_value(t,late_error.phase,.Deadline)
 testing.expect_value(t,late_error.write_effect,.Unknown)
 testing.expect_value(t,late_error.source_io,io.Error.No_Progress)
 sync.atomic_store(&fixture.stop,true);thread.join(worker)
 testing.expect_value(t,fixture.calls,3)
 // Only the first two requests carry the asserted body.
 testing.expect(t,fixture.valid)
}

@(private)
surf_h3_slow_source :: proc(data:rawptr,mode:io.Stream_Mode,p:[]u8,offset:i64,whence:io.Seek_From)->(i64,io.Error) {
 reads:=cast(^int)data
 reads^+=1
 time.sleep(time.Second)
 return 0,.No_Progress
}
