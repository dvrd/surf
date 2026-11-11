package surf
import http "../http"
import http3 "../http/v3"
import "core:mem"

@(private)
Http3_Body :: struct {body:[dynamic]u8,limit:int,allocation:mem.Allocator_Error}
@(private)
http3_body_write :: proc(data:rawptr,chunk:[]u8,final:bool)->(int,http3.Body_Status) {
 b:=cast(^Http3_Body)data
 if len(chunk)>b.limit-len(b.body){return 0,.Failed}
 n,e:=append(&b.body,..chunk);if e!=nil {b.allocation=e;return n,.Failed};return n,.Ready
}
@(private)
http3_body_init :: proc(b:^Http3_Body,config:Config,allocator:mem.Allocator)->HTTP_Error {
 b.limit=config.max_body_size;if b.limit==0{b.limit=http.DEFAULT_MAX_BODY_SIZE}
 if b.limit<0||b.limit>http.MAX_BODY_SIZE{return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 body,e:=make([dynamic]u8,0,allocator);if e!=nil{return {kind=.Allocation_Failed,phase=.Configuration,allocation=e,write_effect=.Not_Sent}};b.body=body;return {}
}
