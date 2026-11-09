package surf_async

import http "../../http"
import surf ".."
import "core:mem"
import "core:strings"

origin_prepare :: proc(profile:^Profile,url:string,allocator:mem.Allocator)->(Prepared_Origin,Client_Error) {
 if !profile_valid(profile) {return {},{kind=.Invalid_State}}
 if allocator.procedure==nil {return {},{kind=.Invalid_Config}}
 parsed,cause:=http.url_parse(url)
 if cause.kind!=.None {return {},{kind=.Request_Error,http=surf.http_protocol_error(cause)}}
 if !parsed.secure && !profile.config.http.allow_http {return {},{kind=.Request_Error,http={kind=.Insecure_URL}}}
 // Snapshot profile fields before the allocator can execute arbitrary callbacks.
 identity:=profile.owner_id
 storage,error:=profile_allocate(len(parsed.host),1,allocator)
 if error.kind!=.None {return {},error}
 copy(storage,parsed.host)
 // DNS ASCII case only; IPv6 spelling remains conservative textual identity.
 if !strings.contains(parsed.host,":") {
  for &byte in storage {if byte>='A' && byte<='Z' {byte+=32}}
 }
 return {key={profile_id=identity,secure=parsed.secure,host=string(storage),port=u16(parsed.port)},storage=storage,allocator=allocator},{}
}
origin_equal :: proc(a,b:Origin_Key)->bool {
 return a.profile_id==b.profile_id && a.secure==b.secure && a.port==b.port && a.host==b.host
}
origin_destroy :: proc(owner:^Prepared_Origin) {
 if owner==nil {return}
 storage,allocator:=owner.storage,owner.allocator
 owner^={}
 profile_free(storage,1,allocator)
}
