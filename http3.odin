package surf

import http "../http"
import http3 "../http/v3"
import "core:mem"
import "core:io"
import "core:net"
import "core:strings"
import "core:time"
import "base:intrinsics"

@(private)
Http3_Body :: struct {body:[dynamic]u8,limit:int,allocation:mem.Allocator_Error}
@(private)
http3_body_write :: proc(data:rawptr,chunk:[]u8,final:bool)->(int,http3.Body_Status) {
 b:=cast(^Http3_Body)data
 if len(chunk)>b.limit-len(b.body){return 0,.Failed}
 n,e:=append(&b.body,..chunk)

 if e!=nil {
  b.allocation=e
  return n,.Failed
 }

 return n,.Ready
}
@(private)
http3_body_init :: proc(b:^Http3_Body,config:Config,allocator:mem.Allocator)->HTTP_Error {
 b.limit=config.max_body_size
 if b.limit==0{b.limit=http.DEFAULT_MAX_BODY_SIZE}
 if b.limit<0||b.limit>http.MAX_BODY_SIZE{return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 body,e:=make([dynamic]u8,0,allocator)
 if e!=nil{return {kind=.Allocation_Failed,phase=.Configuration,allocation=e,write_effect=.Not_Sent}}
 b.body=body
 return {}
}

// Fixed discovery table. A full slot replaces the oldest entry.
ALT_SVC_SLOTS :: 4
ALT_SVC_MAX_AGE :: 7 * 24 * 60 * 60

Alt_Svc :: struct {
	used:     bool,
	host:     [256]u8,
	host_len: int,
	port:     int,
	origin_port: int,
	expires:  time.Time,
}

Alt_Svc_Cache :: struct {
	slots: [ALT_SVC_SLOTS]Alt_Svc,
	next:  int,
}

// GET and HEAD are the only methods retried after HTTP/3 fails before a send.
http3_fallback_allowed :: proc(method: http.Method) -> bool {
	return method == .GET || method == .HEAD
}

// Half of the remaining deadline is the HTTP/3 budget. A miss that has not
// transmitted falls back only for GET and HEAD. Early data requires the configured request predicate.
execute_http3 :: proc(
	url: http.URL,
	request: http.Request,
	config: Config,
	total_deadline: time.Time,
	allocator: mem.Allocator,
	upload: ^Upload_Source = nil,
) -> (
	Response,
	HTTP_Error,
) {
	remain := time.diff(time.now(), total_deadline)
	if remain <= 0 {
		return {}, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
	}
	budget := remain / 2
	if budget < 50 * time.Millisecond && remain >= 100 * time.Millisecond {
		budget = 50 * time.Millisecond
	}
	if budget <= 0 do budget = remain
	deadline := time.time_add(time.now(), budget)
	port := http3_dial_port(config.alt_svc, url.host, url.port, time.now())
	endpoint, resolve_error := http3_resolve(url.host, port, deadline, config.resolver)
	if resolve_error.kind != .None {
		return {}, resolve_error
	}
	path := url.target
	if len(path) == 0 do path = "/"
	fields: [http.MAX_HEADERS]http3.Field
	if len(request.headers) > len(fields) {
		return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
	}
	names: [http.MAX_HEADER_SIZE]u8
	names_n := 0
	for header, i in request.headers {
		name, fits := field_name_lower(names[:], &names_n, header.name)
		if !fits {return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}}
		fields[i] = {name = name, value = header.value}
	}
	wire := http3.Client_Request{
 session_cache=config.tls.session_cache,
 cancel=config._http3_cancel,cancel_data=config._http3_cancel_data,
		qpack = config.http3_qpack,
 ecn=config.http3_ecn,
		client_credentials=config.tls.client_credentials,
		client_credential_lease=config.tls.client_credential_lease,
		method = http.method_text(request.method), target = path, authority = url.authority,
		headers = fields[:len(request.headers)], body = request.body,
		max_response_bytes = config.max_body_size,
	}
 if config.http3_early_data!=nil {policy_request:=request;wire.early_data=config.http3_early_data(&policy_request)}
	trailer_fields: [32]http3.Field
	trailer_names: [4096]u8
	trailers, trailers_fit := http3_trailer_fields(&trailer_fields, &trailer_names, request.trailers)
	if !trailers_fit {return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}}
	wire.trailers = trailers
	source: HTTP3_Upload
	wire_source: http3.Upload_Source
	if upload != nil {
		source.source = upload
		wire_source = {data = &source, read = http3_upload_read, content_length = upload.content_length}
		wire.upload = &wire_source
	}
 aggregate:Http3_Body
 if e:=http3_body_init(&aggregate,config,allocator);e.kind!=.None{return {},e}
 defer delete(aggregate.body)
 sink:=http3.Body_Sink{data=&aggregate,write=http3_body_write}
 wire.body_sink=&sink
 wire.max_response_bytes=aggregate.limit
	result: http3.Client_Result
	if config.http3_pool != nil {
		result = http3.pool_exchange_request(config.http3_pool, endpoint, url.host, wire, config.tls.root_cas, deadline)
	} else {
		result = http3.client_exchange_request(endpoint, url.host, wire, config.tls.root_cas, deadline)
	}
	if result.error != .None {
        if aggregate.allocation!=nil{return {},{kind=.Allocation_Failed,phase=.Read,allocation=aggregate.allocation,write_effect=.Response_Received}}
		error := http3_map_error(result, total_deadline)
		error.source_io = source.error
		return {}, error
	}
 response,e:=http3_response(&result,allocator)
 if e.kind!=.None{return {},e}
 delete(response.body_storage)
 response.body_storage=aggregate.body
 aggregate.body={}
 response.body=response.body_storage[:]
 return response,{}
}

@(private)
HTTP3_Upload :: struct {source: ^Upload_Source, error: io.Error}

@(private)
http3_upload_read :: proc(data: rawptr, destination: []u8) -> (int, bool) {
	source := cast(^HTTP3_Upload)data
	n, error := io.read(source.source.stream, destination)
	if error != nil && error != io.Error.EOF {
		source.error = error
		return n, false
	}
	if n == 0 {source.error = io.Error.EOF; return 0, false}
	return n, true
}

// Alt-Svc wins only while the lookup is valid. Otherwise the URL port, or 443.
http3_dial_port :: proc(cache: ^Alt_Svc_Cache, host: string, url_port: int, now: time.Time) -> int {
	if port, ok := alt_svc_lookup(cache, host, now, url_port); ok && port > 0 {
		return port
	}
	if url_port > 0 do return url_port
	return 443
}

// An IP literal does not query a resolver. A hostname uses the caller's
// nameservers, or the platform resolver, and must finish inside deadline.
@(private)
http3_resolve :: proc(host: string, port: int, deadline: time.Time, options: net.Resolver_Options) -> (net.Endpoint, HTTP_Error) {
	endpoints, resolve_error := net.resolve_endpoints_until(host, port, deadline, options)
	if resolve_error != nil || endpoints.count == 0 {
		if resolve_error == nil {
			resolve_error = net.Resolve_Error.Unable_To_Resolve
		}
		return {}, http_error_classify({kind = .Dial_Failed, network = resolve_error}, .DNS, .Not_Sent)
	}
	return endpoints.items[0], {}
}

@(private)
http3_map_error :: proc(result: http3.Client_Result, total_deadline: time.Time) -> HTTP_Error {
	effect := HTTP_Write_Effect.Not_Sent
	if result.sent do effect = .Unknown
	if result.error == .Deadline && time.diff(time.now(), total_deadline) <= 0 {
		return {kind = .Deadline_Failed, phase = .Deadline, write_effect = effect}
	}
	if result.error==.Capacity {return {kind=.Invalid_Config,phase=.Admission,write_effect=effect}}
 if result.error==.Request_Rejected {return {kind=.IO_Failed,phase=.Protocol,write_effect=effect}}
	if result.error == .Invalid_Request {return {kind = .Invalid_Config, phase = .Configuration, write_effect = effect}}
	if result.error == .Body_Limit {return {kind = .Body_Oversized, phase = .Body_Limit, write_effect = effect}}
	if result.error == .Source {return {kind = .IO_Failed, phase = .Read, write_effect = effect}}
	if result.error == .Cancelled {return {kind = .IO_Failed, phase = .Cancellation, write_effect = effect, transport = {kind = .Cancelled}}}
	if result.error == .Certificate {
		return {kind = .IO_Failed, phase = .TLS, write_effect = effect}
	}
	return {kind = .IO_Failed, phase = .Protocol, write_effect = effect}
}

@(private)
http3_response :: proc(result: ^http3.Client_Result, allocator: mem.Allocator) -> (Response, HTTP_Error) {
	if result == nil {
		return {}, {kind = .IO_Failed, phase = .Protocol, write_effect = .Response_Received}
	}
	response := Response {
		allocator = allocator,
		status = result.status,
	}
	n := result.body_len
	if n < 0 do n = 0
	if n > len(result.body) do n = len(result.body)
	body, alloc_error := make([dynamic]u8, n, allocator)
	if alloc_error != nil {
		return {}, {kind = .Allocation_Failed, allocation = alloc_error, phase = .Configuration, write_effect = .Response_Received}
	}
	if n > 0 do copy(body[:n], result.body[:n])
	response.body_storage = body
	response.body = response.body_storage[:]
	bytes := 0
	for i in 0..<result.header_count {
		field, ok := http3.client_result_header(result, i)
		if !ok {response_destroy(&response); return {}, {kind = .IO_Failed, phase = .Protocol, write_effect = .Response_Received}}
		bytes += len(field.name) + len(field.value)
	}
	storage, storage_error := make([]u8, bytes, allocator)
	if storage_error != nil {response_destroy(&response); return {}, {kind = .Allocation_Failed, allocation = storage_error, phase = .Configuration, write_effect = .Response_Received}}
	response.header_storage = storage
	headers, header_error := make([]http.Header, result.header_count, allocator)
	if header_error != nil {response_destroy(&response); return {}, {kind = .Allocation_Failed, allocation = header_error, phase = .Configuration, write_effect = .Response_Received}}
	response.headers = headers
	at := 0
	for i in 0..<result.header_count {
		field, _ := http3.client_result_header(result, i)
		copied := copy(storage[at:], field.name)
		headers[i].name = string(storage[at:at+copied])
		at += copied
		copied = copy(storage[at:], field.value)
		headers[i].value = string(storage[at:at+copied])
		at += copied
	}
 if trailer_error:=http3_response_trailers(&response,result,allocator);trailer_error.kind!=.None {response_destroy(&response);return {},trailer_error}
 return response, {}
}

// Stores h3=":port"; ma=seconds only for an authenticated HTTPS origin.
// ma is required. Zero, expired, cleartext, and unauthenticated inputs do not write.
alt_svc_note :: proc(
	cache: ^Alt_Svc_Cache,
	host, value: string,
	authenticated, secure: bool,
	now: time.Time,
	origin_port: int = 443,
) -> bool {
	if cache == nil || !authenticated || !secure || len(host) == 0 || len(host) > 256 {
		return false
	}
	effective_port := origin_port
	if effective_port == 0 {effective_port = 443}
	port, ma, parsed := alt_svc_h3(value)
	if !parsed || ma <= 0 {
		return false
	}
	if ma > ALT_SVC_MAX_AGE do ma = ALT_SVC_MAX_AGE
	index := cache.next % ALT_SVC_SLOTS
	replaced := false
	for i in 0 ..< ALT_SVC_SLOTS {
		if cache.slots[i].used && cache.slots[i].origin_port == effective_port && string(cache.slots[i].host[:cache.slots[i].host_len]) == host {
			index = i
			replaced = true
			break
		}
	}
	slot := &cache.slots[index]
	copy(slot.host[:], host)
	slot.host_len = len(host)
	slot.port = port
	slot.origin_port = effective_port
	slot.expires = time.time_add(now, time.Duration(ma) * time.Second)
	slot.used = true
	if !replaced do cache.next += 1
	return true
}

alt_svc_lookup :: proc(cache: ^Alt_Svc_Cache, host: string, now: time.Time, origin_port: int = 443) -> (port: int, ok: bool) {
	effective_port := origin_port
	if effective_port == 0 {effective_port = 443}
	if cache == nil do return 0, false
	for i in 0 ..< ALT_SVC_SLOTS {
		slot := &cache.slots[i]
		if !slot.used || slot.origin_port != effective_port || string(slot.host[:slot.host_len]) != host do continue
		if time.diff(now, slot.expires) <= 0 {
			slot^ = {}
			return 0, false
		}
		return slot.port, true
	}
	return 0, false
}

@(private)
is_digit :: proc(c: rune) -> bool {
	return c >= '0' && c <= '9'
}

@(private)
alt_svc_h3 :: proc(value: string) -> (port, ma: int, ok: bool) {
	at := strings.index(value, "h3=\"")
	if at < 0 do return
	rest := value[at + 4:]
	end := strings.index(rest, "\"")
	if end <= 0 do return
	token := rest[:end]
	if len(token) > 1 && token[0] == ':' {
		token = token[1:]
	}
	if len(token) == 0 do return
	for rune in token {
		if !is_digit(rune) do return
		port = port * 10 + int(rune - '0')
		if port > 65535 do return 0, 0, false
	}
	if port == 0 do return
	tail := rest[end + 1:]
	loc := strings.index(tail, "ma=")
	if loc < 0 do return
	for rune in tail[loc + 3:] {
		if !is_digit(rune) do break
		ma = ma * 10 + int(rune - '0')
		if ma > ALT_SVC_MAX_AGE {
			ma = ALT_SVC_MAX_AGE
			break
		}
	}
	ok = ma > 0
	return
}

response_trailer :: proc(response: ^Response, name: string) -> (string, bool) {
	if response == nil {return "", false}
	for field in response.trailers {if strings.equal_fold(field.name,name) {return field.value,true}}
	return "",false
}

@(private)
http3_response_trailers :: proc(response: ^Response, result: ^http3.Client_Result, allocator: mem.Allocator) -> HTTP_Error {
	bytes:=0
	for i in 0..<result.trailer_count {
		field,ok:=http3.client_result_trailer(result,i)
		if !ok {return {kind=.IO_Failed,phase=.Protocol,write_effect=.Response_Received}}
		bytes+=len(field.name)+len(field.value)
	}
	storage,storage_error:=make([]u8,bytes,allocator)
	if storage_error!=nil {return {kind=.Allocation_Failed,allocation=storage_error,phase=.Configuration,write_effect=.Response_Received}}
	response.trailer_storage=storage
	fields,fields_error:=make([]http.Header,result.trailer_count,allocator)
	if fields_error!=nil {return {kind=.Allocation_Failed,allocation=fields_error,phase=.Configuration,write_effect=.Response_Received}}
	response.trailers=fields
	at:=0
	for i in 0..<result.trailer_count {
		field,_:=http3.client_result_trailer(result,i)
		n:=copy(storage[at:],field.name)
		fields[i].name=string(storage[at:at+n])
		at+=n
		n=copy(storage[at:],field.value)
		fields[i].value=string(storage[at:at+n])
		at+=n
	}
	return {}
}

@(private)
http3_request_trailers_valid :: proc(headers: []http.Header) -> bool {
	fields: [32]http3.Field
	names: [4096]u8
	lowered, fits := http3_trailer_fields(&fields, &names, headers)
	return fits && http3.trailers_check(lowered).kind == .None
}

// Lowercased trailer fields in caller storage; false when they do not fit.
@(private)
http3_trailer_fields :: proc(fields: ^[32]http3.Field, names: ^[4096]u8, trailers: []http.Header) -> (lowered: []http3.Field, ok: bool) {
	if len(trailers) > len(fields) {return nil, false}
	used := 0
	for field, i in trailers {
		name := field_name_lower(names[:], &used, field.name) or_return
		fields[i] = {name = name, value = field.value}
	}
	return fields[:len(trailers)], true
}

HTTP3_Tunnel :: struct {
 wire:http3.Client_Connect,
 client:^HTTP_Client,
 read_deadline,write_deadline:time.Time,
}
// HTTP3 WebSockets require an explicit persistent pool so ordinary requests can
// share the same authenticated QUIC connection while tunnels remain open.
websocket_http3_open :: proc(client:^HTTP_Client,tunnel:^HTTP3_Tunnel,connection:^WebSocket_Conn,url:string,config:WebSocket_Config,headers:[]http.Header=nil)->HTTP_Error {
 if client==nil || client._self!=client || tunnel==nil || tunnel.wire.owner!=nil || connection==nil || connection.phase!=.Uninitialized || client.config.http3_pool==nil {return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 slot:=-1

 for entry,i in client.http3_tunnels {
  if entry==nil {
   slot=i
   break
  }
 }

 if slot<0 {
  return {kind=.Invalid_Config,phase=.Admission,write_effect=.Not_Sent}
 }

 parsed,pe:=http.url_parse(url)

 if pe.kind!=.None || !parsed.secure {
  return {kind=.Invalid_URL,phase=.Configuration,write_effect=.Not_Sent}
 }

 options:=config
 options.host=parsed.authority
 options.target=parsed.target

 if options.target=="" {
  options.target="/"
 }
 stream:=WebSocket_Stream{data=tunnel,read=h3_tunnel_read,write=h3_tunnel_write,close=h3_tunnel_close,abort=h3_tunnel_abort,set_read_deadline=h3_tunnel_read_deadline,set_write_deadline=h3_tunnel_write_deadline}
 if websocket_client(connection,stream,options)!=.None {return {kind=.Invalid_Config,phase=.Configuration,write_effect=.Not_Sent}}
 committed:=false
 defer if !committed {
  connection^={}
  _=h3_tunnel_abort(tunnel)
 }
 deadline:=websocket_tunnel_deadline(client.config,options.handshake_timeout)
 fields:[59]http3.Field
 count:=1
 fields[0]={name="sec-websocket-version",value="13"}
 if options.origin!="" {fields[count]={name="origin",value=options.origin};count+=1}
 protocols:[1024]u8
 offered,offered_fits:=websocket_protocols_join(protocols[:],options.subprotocols)
 if !offered_fits {return {kind=.Header_Limit}}
 if offered!="" {fields[count]={name="sec-websocket-protocol",value=offered};count+=1}
 names:[4096]u8
 at:=0
 for header in headers {
  if count>=len(fields) {return {kind=.Header_Limit}}
  name,fits:=field_name_lower(names[:],&at,header.name)
  if !fits {return {kind=.Header_Limit}}
  if name=="sec-websocket-key" || name=="sec-websocket-accept" || name=="sec-websocket-version" || name=="sec-websocket-extensions" || name=="sec-websocket-protocol" || name=="origin" {return {kind=.Invalid_Header,phase=.Configuration,write_effect=.Not_Sent}}
  fields[count]={name=name,value=header.value,never_indexed=name=="authorization" || name=="cookie"}
  count+=1
 }
 port:=http3_dial_port(client.config.alt_svc,parsed.host,parsed.port,time.now())
 endpoint,re:=http3_resolve(parsed.host,port,deadline,client.config.resolver)

 if re.kind!=.None {
  return re
 }

 tunnel.client=client
 intrinsics.atomic_store(&client.cancel,0)
 request:=http3.Client_Request{method="CONNECT",protocol="websocket",authority=parsed.authority,target=options.target,headers=fields[:count],qpack=client.config.http3_qpack,ecn=client.config.http3_ecn,client_credentials=client.config.tls.client_credentials,client_credential_lease=client.config.tls.client_credential_lease}
 e:=http3.pool_connect_open(client.config.http3_pool,endpoint,parsed.host,request,client.config.tls.root_cas,deadline,&tunnel.wire)
 if e!=.None {return http3_map_error(http3.Client_Result{error=e},deadline)}
 selected:=""
 seen:=false
 for field in tunnel.wire.headers[:tunnel.wire.header_count] {
  if strings.equal_fold(field.name,"sec-websocket-protocol") {if seen {return {kind=.Invalid_Header}};seen=true;selected=field.value}
  if strings.equal_fold(field.name,"sec-websocket-extensions") || strings.equal_fold(field.name,"sec-websocket-accept") {return {kind=.Invalid_Header}}
 }
 if seen && !websocket_subprotocol_accept(connection,options.subprotocols,selected) {return {kind=.Invalid_Header}}
 client.http3_tunnels[slot]=tunnel
 connection.phase=.Open
 committed=true
 return {}
}
@(private)
h3_tunnel_deadline :: proc(t:^HTTP3_Tunnel,write:bool)->time.Time {
 deadline:=t.read_deadline

 if write {
  deadline=t.write_deadline
 }

 if deadline==(time.Time{}) {
  deadline=time.time_add(time.now(),effective_timeout(t.client.config))
 }

 return deadline
}
@(private)
h3_tunnel_progress :: proc(t:^HTTP3_Tunnel,write:bool)->WebSocket_Stream_Error {
 if t.client==nil || t.wire.owner==nil {return {kind=.Invalid_Stream}}
 if h2_cancelled(&t.client.cancel) {http3.client_connect_abort(&t.wire);return {kind=.TCP_Failed,transport={kind=.Cancelled}}}
 e:=http3.client_connect_step(&t.wire,h3_tunnel_deadline(t,write))
 if e==.None {
  return {}
 }

 return {kind=.TCP_Failed,transport={kind=.Timeout if e==.Deadline else .Cancelled if e==.Cancelled else .Protocol_Failed}}
}
@(private)
h3_tunnel_read :: proc(data:rawptr,dst:[]u8)->(int,WebSocket_Stream_Error) {
 t:=cast(^HTTP3_Tunnel)data
 for {n,status:=http3.connect_read(&t.wire.stream,dst);switch status {case .None:return n,{};case .End:return n,{kind=.EOF};case .Pending:case .Cancelled,.Failed:return n,{kind=.TCP_Failed}}
  if e:=h3_tunnel_progress(t,false);e.kind!=.None {return 0,e}
 }
}
@(private)
h3_tunnel_write :: proc(data:rawptr,src:[]u8)->(int,WebSocket_Stream_Error) {
 t:=cast(^HTTP3_Tunnel)data
 for {n,status:=http3.connect_write(&t.wire.stream,src);if status==.None {if e:=h3_tunnel_progress(t,true);e.kind!=.None {return n,e};return n,{}}
  if status!=.Pending {
   return n,{kind=.TCP_Failed}
  }

  if e:=h3_tunnel_progress(t,true);e.kind!=.None {
   return 0,e
  }
 }
}
@(private)
h3_tunnel_abort :: proc(data:rawptr)->WebSocket_Stream_Error {t:=cast(^HTTP3_Tunnel)data;http3.client_connect_abort(&t.wire);h3_tunnel_unlink(t);return {}}
@(private)
h3_tunnel_unlink :: proc(t:^HTTP3_Tunnel) {if t.client!=nil {for &entry in t.client.http3_tunnels {if entry==t {entry=nil}}};t.client=nil}
@(private)
h3_tunnel_close :: proc(data:rawptr)->WebSocket_Stream_Error {
 t:=cast(^HTTP3_Tunnel)data

 if t.wire.owner==nil {
  return {}
 }

 e:=http3.client_connect_finish(&t.wire,h3_tunnel_deadline(t,true))

 if e!=.None {
  _=h3_tunnel_abort(t)
  return {kind=.TCP_Failed}
 }
 // FIN is queued and the owning client retains its bounded stream state until
 // the peer FIN arrives; detach only this handle, never the QUIC connection.
 http3.client_connect_detach(&t.wire)
 h3_tunnel_unlink(t)
 return {}
}
@(private)
h3_tunnel_read_deadline :: proc(data:rawptr,deadline:time.Time)->WebSocket_Stream_Error {(cast(^HTTP3_Tunnel)data).read_deadline=deadline;return {}}
@(private)
h3_tunnel_write_deadline :: proc(data:rawptr,deadline:time.Time)->WebSocket_Stream_Error {(cast(^HTTP3_Tunnel)data).write_deadline=deadline;return {}}
