package surf

import http "../http"
import http3 "../http/v3"
import "core:mem"
import "core:strings"

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
		n:=copy(storage[at:],field.name);fields[i].name=string(storage[at:at+n]);at+=n
		n=copy(storage[at:],field.value);fields[i].value=string(storage[at:at+n]);at+=n
	}
	return {}
}

@(private)
http3_request_trailers_valid :: proc(headers:[]http.Header)->bool {
 if len(headers)>32 {return false}
 fields:[32]http3.Field;names:[4096]u8;at:=0
 for field,i in headers {
  if len(field.name)>len(names)-at {return false}
  start:=at
  for character,j in field.name {lower:=character;if lower>='A'&&lower<='Z' {lower+=32};names[start+j]=u8(lower)}
  at+=len(field.name);fields[i]={name=string(names[start:at]),value=field.value}
 }
 return http3.trailers_check(fields[:len(headers)]).kind==.None
}
