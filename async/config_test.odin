package surf_async

import surf ".."
import http "../../http"
import runtime_async "../../async"
import "core:mem"
import "core:net"
import resources "core:sync/budget"
import "core:testing"
import "core:time"

schema_caps :: proc() -> Capacities {
 return {requests=32,origins=16,connections=8,connections_per_origin=2,
         waiters_per_origin=32,dns_ids=256,work_per_resume=128}
}

schema_normalize :: proc(input:Client_Config) -> (Normalized_Config,Client_Error) {
 previous:=context
 context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous
 return config_normalize(input)
}

@(test)
schema_defaults_and_explicit_zero_are_distinct :: proc(t:^testing.T) {
 normalized,error:=schema_normalize({})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.capacities,schema_caps())
 testing.expect_value(t,normalized.request_timeout,30*time.Second)
 testing.expect_value(t,normalized.response_body_limit,8<<20)
 testing.expect_value(t,normalized.idle_timeout,30*time.Second)
 testing.expect_value(t,normalized.max_age,5*time.Minute)
 testing.expect_value(t,normalized.lifetime,runtime_async.Deadline{})
 caps:=schema_caps();caps.dns_ids=0;caps.waiters_per_origin=0
 normalized,error=schema_normalize({capacities=caps,idle_timeout=time.Nanosecond,max_age=time.Nanosecond,
  http={timeout=7*time.Second,max_body_size=17,setup_timeout=2*time.Second}})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.capacities,caps)
 testing.expect_value(t,normalized.idle_timeout,time.Nanosecond)
 testing.expect_value(t,normalized.max_age,time.Nanosecond)
 testing.expect_value(t,normalized.request_timeout,7*time.Second)
 testing.expect_value(t,normalized.response_body_limit,17)
 testing.expect_value(t,normalized.http.setup_timeout,2*time.Second)
 _,error=schema_normalize({capacities=Capacities{}})
 testing.expect_value(t,error.kind,.Invalid_Config)
}

@(test)
schema_capacity_hard_bounds_and_coupling :: proc(t:^testing.T) {
 // Independent published limits. Start at the complete maximum so each isolated
 // field boundary is not accidentally rejected by another field's dependency.
 maximum:=Capacities{requests=4096,origins=1024,connections=256,connections_per_origin=256,
  waiters_per_origin=4096,dns_ids=65536,work_per_resume=4096}
 normalized,error:=schema_normalize({capacities=maximum})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.capacities,maximum)
 lowers:=[7]int{1,1,1,1,0,0,1}
 uppers:=[7]int{4096,1024,256,256,4096,65536,4096}
 for field in 0..<7 {
  lower:=lowers[field]
  upper:=uppers[field]
  for value in ([6]int{lower,upper,lower-1,upper+1,min(int),max(int)}) {
   caps:=maximum
   fields:=([7]^int{&caps.requests,&caps.origins,&caps.connections,&caps.connections_per_origin,
    &caps.waiters_per_origin,&caps.dns_ids,&caps.work_per_resume})
   fields[field]^=value
   // Keep dependent fields legal when reducing their parent's capacity.
   if field==0 {caps.waiters_per_origin=0}
   if field==2 {caps.connections_per_origin=1}
   _,cause:=schema_normalize({capacities=caps})
   want:=Client_Error_Kind.None
   if value<lower || value>upper {want=.Invalid_Config}
   testing.expect_value(t,cause.kind,want)
  }
 }
 caps:=schema_caps();caps.connections_per_origin=caps.connections+1
 _,error=schema_normalize({capacities=caps});testing.expect_value(t,error.kind,.Invalid_Config)
 caps=schema_caps();caps.waiters_per_origin=caps.requests+1
 _,error=schema_normalize({capacities=caps});testing.expect_value(t,error.kind,.Invalid_Config)
 caps={requests=1,origins=1,connections=1,connections_per_origin=1,waiters_per_origin=0,dns_ids=0,work_per_resume=1}
 normalized,error=schema_normalize({capacities=caps})
 testing.expect_value(t,error.kind,.None);testing.expect_value(t,normalized.capacities,caps)
}

@(test)
schema_duration_and_lifetime_shape_without_runtime_claim :: proc(t:^testing.T) {
 for duration in ([3]time.Duration{-1,min(time.Duration),-time.Second}) {
  _,error:=schema_normalize({idle_timeout=duration});testing.expect_value(t,error.kind,.Invalid_Config)
  _,error=schema_normalize({max_age=duration});testing.expect_value(t,error.kind,.Invalid_Config)
 }
 for deadline in ([4]runtime_async.Deadline{{},{epoch=1,at=1},{epoch=max(u64),at=max(i64)},{epoch=1,at=max(i64)}}) {
  normalized,error:=schema_normalize({lifetime=deadline,idle_timeout=max(time.Duration),max_age=max(time.Duration)})
  testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,normalized.lifetime,deadline)
  testing.expect_value(t,normalized.idle_timeout,max(time.Duration))
 }
 for deadline in ([5]runtime_async.Deadline{{at=1},{at=-1},{epoch=1},{epoch=1,at=-1},{epoch=max(u64),at=min(i64)}}) {
  _,error:=schema_normalize({lifetime=deadline});testing.expect_value(t,error.kind,.Invalid_Config)
 }
 // Numeric epoch/time values above are intentionally not compared with a clock:
 // runtime identity and actual expiry admission belong to the network phase.
}

@(test)
schema_root_http_and_alpn_policy_preserved :: proc(t:^testing.T) {
 invalid:=[?]surf.Config{{max_body_size=-1},{max_body_size=http.MAX_BODY_SIZE+1},
  {max_redirects=-1},{max_redirects=http.MAX_REDIRECTS+1},{timeout=-1},{setup_timeout=-1}}
 for config in invalid {
  _,error:=schema_normalize({http=config})
  testing.expect_value(t,error.kind,.Invalid_Config)
  testing.expect_value(t,error.http.kind,surf.config_validate(config).kind)
 }
 normalized,error:=schema_normalize({http={max_body_size=http.MAX_BODY_SIZE,max_redirects=http.MAX_REDIRECTS,
  timeout=max(time.Duration),setup_timeout=max(time.Duration),allow_http=true}})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.response_body_limit,http.MAX_BODY_SIZE)
 testing.expect_value(t,normalized.request_timeout,max(time.Duration))
 testing.expect_value(t,normalized.http.allow_http,true)
 for offers in ([4][]string{{"h2"},{"h3"},{"http/1.1","h2"},{""}}) {
  _,error=schema_normalize({http={tls={alpn_protocols=offers}}})
  testing.expect_value(t,error.kind,.Invalid_Config)
 }
 offers:=[]string{"http/1.1"}
 normalized,error=schema_normalize({http={tls={alpn_protocols=offers}}})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,raw_data(normalized.http.tls.alpn_protocols),raw_data(offers))
 _,error=schema_normalize({http={tls={handshake_timeout=-1}}})
 testing.expect_value(t,error.kind,.Invalid_Config)
}

@(test)
schema_dns_snapshot_bounds_and_scalar_handles :: proc(t:^testing.T) {
 servers:[9]net.Endpoint
 for &server in servers {server={address=net.IP4_Address{127,0,0,1},port=53}}
 for count in ([3]int{0,1,8}) {
  normalized,error:=schema_normalize({http={resolver={name_servers=servers[:count]}}})
  testing.expect_value(t,error.kind,.None)
  testing.expect_value(t,len(normalized.http.resolver.name_servers),count)
  if count>0 do testing.expect_value(t,raw_data(normalized.http.resolver.name_servers),raw_data(servers[:count]))
 }
 _,error:=schema_normalize({http={resolver={name_servers=servers[:]}}})
 testing.expect_value(t,error.kind,.Invalid_Config)
 servers[0].port=0
 _,error=schema_normalize({http={resolver={name_servers=servers[:1]}}})
 testing.expect_value(t,error.kind,.Invalid_Config)
 handle:=Request_Handle{}
 testing.expect_value(t,handle.owner_id,u64(0));testing.expect_value(t,handle.slot,u32(0))
 testing.expect_value(t,handle.generation,u64(0))
 handle={owner_id=max(u64),slot=max(u32),generation=max(u64)}
 alias:=handle;testing.expect_value(t,alias,handle)
 // Scalar construction proves no validity/admission or lifetime behavior.
 completion:=Completion{request=handle}
 testing.expect_value(t,completion.request,handle)
}

@(test)
schema_scope_is_borrowed_without_admission :: proc(t:^testing.T) {
 owner,cause:=resources.create_root({bytes=0,streams=0,jobs=0},context.allocator)
 testing.expect_value(t,cause,.None)
 defer resources.release_scope(&owner)
 before,_:=resources.snapshot(owner)
 normalized,error:=schema_normalize({http={scope=owner}})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.http.scope,owner)
 after,_:=resources.snapshot(owner)
 testing.expect_value(t,after,before)
 testing.expect_value(t,resources.close(owner),.None)
 closed_before,_:=resources.snapshot(owner)
 normalized,error=schema_normalize({http={scope=owner}})
 testing.expect_value(t,error.kind,.None)
 testing.expect_value(t,normalized.http.scope,owner)
 closed_after,_:=resources.snapshot(owner)
 testing.expect_value(t,closed_after,closed_before)
 // Normalization borrows metadata only. No positive/closed resource admission
 // is inferred; the later resource constructor enforces that contract.
 _,error=schema_normalize({http={allocator_scope=owner}})
 testing.expect_value(t,error.kind,.Invalid_Config)
}
