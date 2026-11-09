package surf_async

import "core:mem"
import "core:net"
import "core:sync"
import "core:crypto/x509"

@(private) profile_identity_mu: sync.Mutex
@(private) profile_identity_serial: u64

// Counter ownership is explicit so exhaustion can be tested without mutating
// the shared identity namespace used by concurrently initialized profiles.
@(private)
profile_identity_next :: proc(serial:^u64,mu:^sync.Mutex)->(u64,bool) {
 sync.mutex_lock(mu)
 defer sync.mutex_unlock(mu)
 if serial^==max(u64) {return 0,false}
 serial^+=1
 return serial^,true
}

// Descriptor offsets are aligned before any cast. A single checked physical
// backing owns every copied descriptor/string, keeping rollback one-step.
@(private)
profile_region :: proc(total:^int,count,size,alignment:int)->(int,bool) {
 if count<0 || size<1 || count>max(int)/size {return 0,false}
 padding := (alignment-total^%alignment)%alignment
 bytes := count*size
 if total^>max(int)-padding || total^+padding>max(int)-bytes {return 0,false}
 offset := total^+padding
 total^=offset+bytes
 return offset,true
}
@(private)
profile_allocate :: proc(size,alignment:int,allocator:mem.Allocator)->([]u8,Client_Error) {
 if size<0 || allocator.procedure==nil {return nil,{kind=.Invalid_Config}}
 if size==0 {return nil,{}}
 storage,cause:=allocator.procedure(allocator.data,.Alloc,size,alignment,nil,0)
 if cause!=nil || len(storage)!=size || raw_data(storage)==nil || uintptr(raw_data(storage))%uintptr(alignment)!=0 {
  if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(storage),len(storage))}
  if cause==nil {cause=.Out_Of_Memory}
  return nil,{kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=cause}}
 }
 for &byte in storage {byte=0}
 return storage,{}
}
@(private)
profile_free :: proc(storage:[]u8,alignment:int,allocator:mem.Allocator) {
 if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,alignment,raw_data(storage),len(storage))}
}
@(private)
profile_valid :: proc(p:^Profile)->bool {return p!=nil && p.self==p && p.owner_id!=0}

profile_init :: proc(p:^Profile,config:Normalized_Config,allocator:mem.Allocator)->Client_Error {
 if p==nil || p.self!=nil || p.owner_id!=0 || raw_data(p.storage)!=nil {return {kind=.Invalid_State}}
 p^={}
 normalized,error:=config_normalize({http=config.http,capacities=config.capacities,
  idle_timeout=config.idle_timeout,max_age=config.max_age,lifetime=config.lifetime})
 if error.kind!=.None {return error}
 if allocator.procedure==nil || normalized.request_timeout!=config.request_timeout ||
    normalized.response_body_limit!=config.response_body_limit {return {kind=.Invalid_Config}}
 // The caller must keep Config's borrowed inputs immutable for this call.
 total:=0
 roots_at,roots_ok:=profile_region(&total,len(config.http.tls.root_cas),size_of(^x509.Certificate),align_of(^x509.Certificate))
 offers_at,offers_ok:=profile_region(&total,len(config.http.tls.alpn_protocols),size_of(string),align_of(string))
 servers_at,servers_ok:=profile_region(&total,len(config.http.resolver.name_servers),size_of(net.Endpoint),align_of(net.Endpoint))
 name_at,name_ok:=profile_region(&total,len(config.http.tls.server_name),1,1)
 if !roots_ok || !offers_ok || !servers_ok || !name_ok {return {kind=.Invalid_Config}}
 text_at:=total
 for offer in config.http.tls.alpn_protocols {
  if len(offer)>max(int)-total {return {kind=.Invalid_Config}}
  total+=len(offer)
 }
 alignment:=max(align_of(^x509.Certificate),align_of(string),align_of(net.Endpoint))
 storage,allocation:=profile_allocate(total,alignment,allocator)
 if allocation.kind!=.None {return allocation}
 snapshot:=normalized
 if len(config.http.tls.root_cas)>0 {
  roots:=(cast([^]^x509.Certificate)raw_data(storage[roots_at:]))[:len(config.http.tls.root_cas)]
  copy(roots,config.http.tls.root_cas);snapshot.http.tls.root_cas=roots
 } else {snapshot.http.tls.root_cas=nil}
 if len(config.http.resolver.name_servers)>0 {
  servers:=(cast([^]net.Endpoint)raw_data(storage[servers_at:]))[:len(config.http.resolver.name_servers)]
  copy(servers,config.http.resolver.name_servers);snapshot.http.resolver.name_servers=servers
 } else {snapshot.http.resolver.name_servers=nil}
 copy(storage[name_at:name_at+len(config.http.tls.server_name)],config.http.tls.server_name)
 snapshot.http.tls.server_name=string(storage[name_at:name_at+len(config.http.tls.server_name)])
 if len(config.http.tls.alpn_protocols)>0 {
  offers:=(cast([^]string)raw_data(storage[offers_at:]))[:len(config.http.tls.alpn_protocols)]
  at:=text_at
  for offer,i in config.http.tls.alpn_protocols {
   copy(storage[at:at+len(offer)],offer);offers[i]=string(storage[at:at+len(offer)]);at+=len(offer)
  }
  snapshot.http.tls.alpn_protocols=offers
 } else {snapshot.http.tls.alpn_protocols=nil}
 identity,available:=profile_identity_next(&profile_identity_serial,&profile_identity_mu)
 if !available {
  profile_free(storage,alignment,allocator)
  return {kind=.Capacity}
 }
 p^={self=p,owner_id=identity,config=snapshot,storage=storage,allocator=allocator}
 return {}
}

profile_destroy :: proc(p:^Profile) {
 if !profile_valid(p) {return}
 storage,allocator:=p.storage,p.allocator
 p^={}
 alignment:=max(align_of(^x509.Certificate),align_of(string),align_of(net.Endpoint))
 profile_free(storage,alignment,allocator)
}
