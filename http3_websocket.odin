package surf
import http "../http"
import h3 "../http/v3"
import "core:time"
import "core:strings"
import "base:intrinsics"

HTTP3_Tunnel :: struct {
 wire:h3.Client_Connect,
 client:^HTTP_Client,
 read_deadline,write_deadline:time.Time,
}
// HTTP3 WebSockets require an explicit persistent pool so ordinary requests can
// share the same authenticated QUIC connection while tunnels remain open.
websocket_http3_open :: proc(client:^HTTP_Client,tunnel:^HTTP3_Tunnel,connection:^WebSocket_Conn,url:string,config:WebSocket_Config,headers:[]http.Header=nil)->HTTP_Error {
 if client==nil || client._self!=client || tunnel==nil || tunnel.wire.owner!=nil || connection==nil || connection.phase!=.Uninitialized || client.config.http3_pool==nil {return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 slot:=-1;for entry,i in client.http3_tunnels {if entry==nil {slot=i;break}};if slot<0 {return {kind=.Invalid_Config,phase=.Admission,write_effect=.Not_Sent}}
 parsed,pe:=http.url_parse(url);if pe.kind!=.None || !parsed.secure {return {kind=.Invalid_URL,phase=.Configuration,write_effect=.Not_Sent}}
 options:=config;options.host=parsed.authority;options.target=parsed.target;if options.target=="" {options.target="/"}
 stream:=WebSocket_Stream{data=tunnel,read=h3_tunnel_read,write=h3_tunnel_write,close=h3_tunnel_close,abort=h3_tunnel_abort,set_read_deadline=h3_tunnel_read_deadline,set_write_deadline=h3_tunnel_write_deadline}
 if websocket_client(connection,stream,options)!=.None {return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 committed:=false;defer if !committed {connection^={};_=h3_tunnel_abort(tunnel)}
 deadline:=time.time_add(time.now(),effective_timeout(client.config));if options.handshake_timeout>0 {own:=time.time_add(time.now(),options.handshake_timeout);if time.diff(own,deadline)>0 {deadline=own}}
 fields:[59]h3.Field;count:=1;fields[0]={name="sec-websocket-version",value="13"}
 if options.origin!="" {fields[count]={name="origin",value=options.origin};count+=1}
 protocols:[1024]u8;pn:=0
 for protocol,i in options.subprotocols {if i>0 {if pn+2>len(protocols) {return {kind=.Header_Limit}};pn+=copy(protocols[pn:],", ")};if len(protocol)>len(protocols)-pn {return {kind=.Header_Limit}};pn+=copy(protocols[pn:],protocol)}
 if pn>0 {fields[count]={name="sec-websocket-protocol",value=string(protocols[:pn])};count+=1}
 names:[4096]u8;at:=0
 for header in headers {
  if count>=len(fields) || len(header.name)>len(names)-at {return {kind=.Header_Limit}}
  start:=at;for byte in transmute([]u8)header.name {value:=byte;if value>='A' && value<='Z' {value+=32};names[at]=value;at+=1}
  name:=string(names[start:at])
  if name=="sec-websocket-key" || name=="sec-websocket-accept" || name=="sec-websocket-version" || name=="sec-websocket-extensions" || name=="sec-websocket-protocol" || name=="origin" {return {kind=.Invalid_Header,phase=.Configuration,write_effect=.Not_Sent}}
  fields[count]={name=name,value=header.value,never_indexed=name=="authorization" || name=="cookie"};count+=1
 }
 port:=http3_dial_port(client.config.alt_svc,parsed.host,parsed.port,time.now())
 endpoint,re:=http3_resolve(parsed.host,port,deadline,client.config.resolver);if re.kind!=.None {return re}
 tunnel.client=client;intrinsics.atomic_store(&client.cancel,0)
 request:=h3.Client_Request{method="CONNECT",protocol="websocket",authority=parsed.authority,target=options.target,headers=fields[:count],qpack=client.config.http3_qpack,ecn=client.config.http3_ecn,client_credentials=client.config.tls.client_credentials,client_credential_lease=client.config.tls.client_credential_lease}
 e:=h3.pool_connect_open(client.config.http3_pool,endpoint,parsed.host,request,client.config.tls.root_cas,deadline,&tunnel.wire)
 if e!=.None {return http3_map_error(h3.Client_Result{error=e},deadline)}
 selected:="";seen:=false
 for field in tunnel.wire.headers[:tunnel.wire.header_count] {
  if strings.equal_fold(field.name,"sec-websocket-protocol") {if seen {return {kind=.Invalid_Header}};seen=true;selected=field.value}
  if strings.equal_fold(field.name,"sec-websocket-extensions") || strings.equal_fold(field.name,"sec-websocket-accept") {return {kind=.Invalid_Header}}
 }
 if seen {found:=false;for offered in options.subprotocols {if offered==selected {found=true}};if !found || len(selected)>len(connection.selected_protocol) {return {kind=.Invalid_Header}};connection.selected_protocol_size=copy(connection.selected_protocol[:],selected)}
 client.http3_tunnels[slot]=tunnel;connection.phase=.Open;committed=true;return {}
}
@(private)
h3_tunnel_deadline :: proc(t:^HTTP3_Tunnel,write:bool)->time.Time {
 deadline:=t.read_deadline;if write {deadline=t.write_deadline};if deadline==(time.Time{}) {deadline=time.time_add(time.now(),effective_timeout(t.client.config))};return deadline
}
@(private)
h3_tunnel_progress :: proc(t:^HTTP3_Tunnel,write:bool)->WebSocket_Stream_Error {
 if t.client==nil || t.wire.owner==nil {return {kind=.Invalid_Stream}}
 if h2_cancelled(&t.client.cancel) {h3.client_connect_abort(&t.wire);return {kind=.TCP_Failed,transport={kind=.Cancelled}}}
 e:=h3.client_connect_step(&t.wire,h3_tunnel_deadline(t,write))
 if e==.None {return {}};return {kind=.TCP_Failed,transport={kind=.Timeout if e==.Deadline else .Cancelled if e==.Cancelled else .Protocol_Failed}}
}
@(private)
h3_tunnel_read :: proc(data:rawptr,dst:[]u8)->(int,WebSocket_Stream_Error) {
 t:=cast(^HTTP3_Tunnel)data
 for {n,status:=h3.connect_read(&t.wire.stream,dst);switch status {case .None:return n,{};case .End:return n,{kind=.EOF};case .Pending:case .Cancelled,.Failed:return n,{kind=.TCP_Failed}}
  if e:=h3_tunnel_progress(t,false);e.kind!=.None {return 0,e}
 }
}
@(private)
h3_tunnel_write :: proc(data:rawptr,src:[]u8)->(int,WebSocket_Stream_Error) {
 t:=cast(^HTTP3_Tunnel)data
 for {n,status:=h3.connect_write(&t.wire.stream,src);if status==.None {if e:=h3_tunnel_progress(t,true);e.kind!=.None {return n,e};return n,{}}
  if status!=.Pending {return n,{kind=.TCP_Failed}};if e:=h3_tunnel_progress(t,true);e.kind!=.None {return 0,e}
 }
}
@(private)
h3_tunnel_abort :: proc(data:rawptr)->WebSocket_Stream_Error {t:=cast(^HTTP3_Tunnel)data;h3.client_connect_abort(&t.wire);h3_tunnel_unlink(t);return {}}
@(private)
h3_tunnel_unlink :: proc(t:^HTTP3_Tunnel) {if t.client!=nil {for &entry in t.client.http3_tunnels {if entry==t {entry=nil}}};t.client=nil}
@(private)
h3_tunnel_close :: proc(data:rawptr)->WebSocket_Stream_Error {
 t:=cast(^HTTP3_Tunnel)data;if t.wire.owner==nil {return {}}
 e:=h3.client_connect_finish(&t.wire,h3_tunnel_deadline(t,true));if e!=.None {_=h3_tunnel_abort(t);return {kind=.TCP_Failed}}
 // FIN is queued and the owning client retains its bounded stream state until
 // the peer FIN arrives; detach only this handle, never the QUIC connection.
 h3.client_connect_detach(&t.wire);h3_tunnel_unlink(t);return {}
}
@(private)
h3_tunnel_read_deadline :: proc(data:rawptr,deadline:time.Time)->WebSocket_Stream_Error {(cast(^HTTP3_Tunnel)data).read_deadline=deadline;return {}}
@(private)
h3_tunnel_write_deadline :: proc(data:rawptr,deadline:time.Time)->WebSocket_Stream_Error {(cast(^HTTP3_Tunnel)data).write_deadline=deadline;return {}}
