package surf
import http "../http"
import h3 "../http/v3"
import "core:testing"

@(test)
http3_websocket_invalid_owners_and_missing_pool_preflight :: proc(t:^testing.T) {
 client:HTTP_Client;tunnel:HTTP3_Tunnel;connection:WebSocket_Conn
 testing.expect_value(t,websocket_http3_open(nil,&tunnel,&connection,"https://example.invalid/",{}).kind,.Invalid_Config)
 testing.expect_value(t,http_client_init(&client,{http3=true},{},context.allocator).kind,.None);defer http_client_close(&client)
 testing.expect_value(t,websocket_http3_open(&client,&tunnel,&connection,"https://example.invalid/",{}).kind,.Invalid_Config)
 testing.expect_value(t,connection.phase,.Uninitialized)
}
@(test)
http3_http_client_batch_is_rejected_without_tcp_fallback :: proc(t:^testing.T) {
 pool:h3.Pool;client:HTTP_Client
 testing.expect_value(t,http_client_init(&client,{http3=true,http3_pool=&pool},{},context.allocator).kind,.None);defer http_client_close(&client)
 requests:=[2]http.Request{{method=.GET,url="https://example.invalid/"},{method=.GET,url="https://example.invalid/"}};results:[2]HTTP_Result
 error:=http_client_multiplex(&client,requests[:],results[:])
 testing.expect_value(t,error.kind,.Invalid_Config);testing.expect_value(t,http_client_dials(&client),0)
}
