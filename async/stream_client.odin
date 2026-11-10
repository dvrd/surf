package surf_async

import stream_api "stream"
import http "../../http"
import runtime_async "../../async"
import "core:io"
import "core:mem/owned"
import "core:sync"

@(private)
stream_client_error :: proc(cause:stream_api.Error)->Client_Error {
 if cause.kind==.Allocation_Failed {return {kind=.Allocation_Failed,http=cause.http}}
 if cause.http.kind!=.None {return {kind=.Request_Error,http=cause.http}}
 switch cause.kind {
 case .None:return {}
 case .Invalid:return {kind=.Invalid_State}
 case .Closed:return {kind=.Closed}
 case .Pending:return {kind=.Pending}
 case .Capacity:return {kind=.Capacity}
 case .Allocation_Failed:return {kind=.Allocation_Failed,http=cause.http}
 }
 unreachable()
}

client_submit_stream :: proc(c:^Client,request:http.Request,options:Stream_Options,
 deadline:runtime_async.Deadline={})->(Request_Handle,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return {},error};defer client_leave(s)
 selected,selection:=submission_budget(s,deadline)
 if selection.kind!=.None {return {},selection}
 if s.stream_bank==nil {return {},{kind=.Invalid_Config}}
 normalized,valid:=stream_api.options_normalize(options,s.config.config.response_body_limit)
 if !valid {return {},{kind=.Invalid_Config}}
 if length,upload:=normalized.upload_length.?;upload {
  limits,_:=s.config.config.streaming.?
  if length>0 && limits.max_retained_bytes_per_stream<=limits.response_chunks*limits.max_chunk_bytes {return {},{kind=.Invalid_Config}}
  if len(request.body)!=0 || s.config.config.http.max_redirects>0 {return {},{kind=.Invalid_Config}}
 }
 cell,cause:=stream_api.channel_create(s.stream_bank,normalized)
 if cause.kind!=.None {return {},stream_client_error(cause)}
 return client_submit_state(s,request,selected,cell)
}

@(private)
client_stream_ref :: proc(s:^Client_State,handle:Request_Handle)->(^stream_api.Channel,Client_Error) {
 sync.lock(&s.kernel.mu);defer sync.unlock(&s.kernel.mu)
 request:=admission_request_locked(&s.kernel,handle)
 if request==nil {return nil,{kind=.Invalid_Handle}}
 if request.stream==nil || !stream_api.retain(request.stream) {return nil,{kind=.Invalid_State}}
 return request.stream,{}
}

client_stream_take_head :: proc(c:^Client,handle:Request_Handle,destination:^Stream_Head)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 if destination==nil || client_stream_destination_alias(s,c,destination,size_of(Stream_Head)) {return {kind=.Invalid_State}}
 cell,cause:=client_stream_ref(s,handle);if cause.kind!=.None {return cause}
 defer stream_api.release(cell)
 return stream_client_error(stream_api.take_head(cell,destination))
}

client_stream_next :: proc(c:^Client,handle:Request_Handle,destination:^owned.Chunk)->(Stream_Read_Status,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return .Pending,error};defer client_leave(s)
 if destination==nil || client_stream_destination_alias(s,c,destination,size_of(owned.Chunk)) {return .Pending,{kind=.Invalid_State}}
 cell,cause:=client_stream_ref(s,handle);if cause.kind!=.None {return .Pending,cause}
 defer stream_api.release(cell)
 status,next:=stream_api.next(cell,destination)
 return status,stream_client_error(next)
}

client_upload_submit :: proc(c:^Client,handle:Request_Handle,source:^owned.Chunk)->(Upload_Submit_Status,Client_Error) {
 s,error:=client_enter(c);if error.kind!=.None {return .Closed,error};defer client_leave(s)
 if source==nil || client_stream_destination_alias(s,c,source,size_of(owned.Chunk)) {return .Invalid,{kind=.Invalid_State}}
 if gate:=client_upload_gate(s,handle);gate.kind!=.None {return .Closed,gate}
 cell,cause:=client_stream_ref(s,handle);if cause.kind!=.None {return .Invalid,cause}
 defer stream_api.release(cell)
 status,next:=stream_api.upload_submit(cell,source)
 return status,stream_client_error(next)
}

client_upload_finish :: proc(c:^Client,handle:Request_Handle,source_error:io.Error=nil)->Client_Error {
 s,error:=client_enter(c);if error.kind!=.None {return error};defer client_leave(s)
 if gate:=client_upload_gate(s,handle);gate.kind!=.None {return gate}
 cell,cause:=client_stream_ref(s,handle);if cause.kind!=.None {return cause}
 defer stream_api.release(cell)
 return stream_client_error(stream_api.upload_finish(cell,source_error))
}

@(private)
client_stream_destination_alias :: proc(s:^Client_State,c:^Client,destination:rawptr,size:int)->bool {
 if client_ranges_overlap(destination,size,c,size_of(Client)) ||
  client_ranges_overlap(destination,size,s,size_of(Client_State)) ||
  client_ranges_overlap(destination,size,raw_data(s.actors),len(s.actors)*size_of(Session_Actor)) ||
  client_ranges_overlap(destination,size,raw_data(s.requests),len(s.requests)*size_of(Request_Network)) ||
  client_ranges_overlap(destination,size,raw_data(s.task_index),len(s.task_index)*size_of(^runtime_async.Task)) ||
  client_ranges_overlap(destination,size,raw_data(s.dns_ids),len(s.dns_ids)*size_of(u16)) ||
  client_ranges_overlap(destination,size,raw_data(s.profile.storage),len(s.profile.storage)) {return true}
 k:=&s.kernel
 return client_ranges_overlap(destination,size,raw_data(k.requests),len(k.requests)*size_of(Request_Slot)) ||
  client_ranges_overlap(destination,size,raw_data(k.sessions),len(k.sessions)*size_of(Session_Model)) ||
  client_ranges_overlap(destination,size,raw_data(k.origins),len(k.origins)*size_of(Origin_Slot))
}
