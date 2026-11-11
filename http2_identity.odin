package surf

import tls "core:crypto/tls"
import credential_store "core:crypto/tls/credentials/store"

@(private)
HTTP_Client_Identity :: struct {store:^credential_store.Store,lease:credential_store.Lease,generation:u64}
@(private)
http_identity_acquire :: proc(config:tls.Config)->(HTTP_Client_Identity,HTTP_Error) {
 identity:=HTTP_Client_Identity{store=config.client_credentials}
 if identity.store==nil {
  if config.client_credential_lease!=nil {return {},{kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
  return identity,{}
 }
 lease:credential_store.Lease;e:credential_store.Error
 if config.client_credential_lease!=nil {lease,e=credential_store.retain(identity.store,config.client_credential_lease^)} else {lease,e=credential_store.acquire(identity.store)}
 if e.kind!=.None {return {},{kind=.TLS_Failed,phase=.TLS,write_effect=.Not_Sent}}
 generation,ge:=credential_store.lease_generation(identity.store,lease)
 if ge.kind!=.None {_=credential_store.release(identity.store,&lease);return {},{kind=.TLS_Failed,phase=.TLS,write_effect=.Not_Sent}}
 identity.lease=lease;identity.generation=generation
 return identity,{}
}
@(private)
http_identity_release :: proc(identity:^HTTP_Client_Identity) {
 if identity.store!=nil {_=credential_store.release(identity.store,&identity.lease)}
 identity^={}
}
@(private)
http_tls_config_equal :: proc(a,b:tls.Config)->bool {
 if a.client_credentials!=b.client_credentials || a.session!=b.session || a.session_cache!=b.session_cache ||
  a.early_data!=b.early_data || a.remember_tickets!=b.remember_tickets || a.handshake_timeout!=b.handshake_timeout ||
  len(a.root_cas)!=len(b.root_cas) || len(a.alpn_protocols)!=len(b.alpn_protocols) {return false}
 for root,i in a.root_cas {if root!=b.root_cas[i] {return false}}
 for protocol,i in a.alpn_protocols {if protocol!=b.alpn_protocols[i] {return false}}
 return true
}
@(private)
http_lane_has_tunnels :: proc(lane:^HTTP_Lane)->bool {
 for tunnel in lane.tunnels {if tunnel!=nil {return true}};return false
}
