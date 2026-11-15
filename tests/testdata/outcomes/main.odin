package main

import surf "../../.."
import "core:crypto/tls"
import "core:fmt"
import "core:os"
import "core:net"
import "core:time"

main :: proc() {
	http_url := os.get_env("SURF_OUTCOME_HTTP", context.allocator)
	tls_url := os.get_env("SURF_OUTCOME_TLS", context.allocator)
	refused_url := os.get_env("SURF_OUTCOME_REFUSED", context.allocator)
	wrong_root := os.get_env("SURF_OUTCOME_WRONG_ROOT", context.allocator)
	defer delete(http_url)
	defer delete(tls_url)
	defer delete(refused_url)
	defer delete(wrong_root)
	assert(http_url != "" && tls_url != "" && refused_url != "" && wrong_root != "")
	empty_resolver := os.get_env("SURF_OUTCOME_EMPTY_RESOLVER", context.allocator)
	defer delete(empty_resolver)
	saved_dns := net.dns_configuration
	net.dns_configuration.resolv_conf = empty_resolver
	dns_response, dns_error := surf.execute({method = .POST, url = "http://offline-fixture.test/"}, {allow_http = true})
	net.dns_configuration = saved_dns
	surf.response_destroy(&dns_response)
	assert(dns_error.phase == .DNS && dns_error.write_effect == .Not_Sent)
	config := surf.Config{allow_http = true, max_body_size = 8, timeout = 200 * time.Millisecond}
	for sample in ([]struct{path: string, phase: surf.HTTP_Phase, status: int, effect: surf.HTTP_Write_Effect}{
		{"/native-reset", .Read, 0, .Unknown},
		{"/native-large", .Body_Limit, 200, .Response_Received},
		{"/native-malformed", .Protocol, 0, .Unknown},
		{"/native-slow", .Deadline, 0, .Unknown},
	}) {
		url := fmt.aprintf("%s%s", http_url, sample.path)
		response, error := surf.execute({method = .POST, url = url, body = []u8{'x'}}, config)
		assert(error.kind != .None)
		assert(error.phase == sample.phase)
		assert(error.status == sample.status)
		assert(error.write_effect == sample.effect)
		surf.response_destroy(&response)
		delete(url)
	}
	redirect_config := config
	redirect_config.max_redirects = 1
	redirect_url := fmt.aprintf("%s/native-redirect", http_url)
	defer delete(redirect_url)
	redirect_response, redirect_error := surf.execute({method = .POST, url = redirect_url, body = []u8{'x'}}, redirect_config)
	surf.response_destroy(&redirect_response)
	assert(redirect_error.phase == .Read && redirect_error.status == 307 && redirect_error.write_effect == .Unknown)
	unsafe_url := fmt.aprintf("%s/native-unsafe-redirect", http_url)
	defer delete(unsafe_url)
	unsafe_response, unsafe_error := surf.execute({method = .POST, url = unsafe_url, body = []u8{'x'}}, redirect_config)
	surf.response_destroy(&unsafe_response)
	assert(unsafe_error.phase == .Protocol && unsafe_error.status == 302 && unsafe_error.write_effect == .Response_Received)
	response, refused := surf.execute({method = .POST, url = refused_url}, config)
	surf.response_destroy(&response)
	assert((refused.phase == .Connect || refused.phase == .Deadline) && refused.write_effect == .Not_Sent)
	for sample in ([]struct{path: string, phase: surf.HTTP_Phase, status: int, effect: surf.HTTP_Write_Effect}{
		{"/curl-reset", .Read, 0, .Unknown},
		{"/curl-large", .Body_Limit, 200, .Response_Received},
		{"/curl-malformed", .Protocol, 0, .Unknown},
		{"/curl-slow", .Deadline, 0, .Unknown},
	}) {
		url := fmt.aprintf("%s%s", http_url, sample.path)
		_, result := surf.buffered_http_execute("POST", url, []u8{'x'}, nil, "", allow_http = true, timeout_ms = 200)
		assert(!result.transport_ok && !result.ok && result.error.kind != .None)
		if sample.path == "/curl-malformed" && result.error.provider_code == 1 {
			assert(result.error.phase == .Protocol || result.error.phase == .Unknown)
		} else {
			assert(result.error.phase == sample.phase)
		}
		assert(result.status == sample.status && result.error.status == sample.status)
		assert(result.error.write_effect == sample.effect)
		delete(url)
	}
	_, curl_refused := surf.buffered_http_execute("POST", refused_url, nil, nil, "", allow_http = true)
    fmt.printf("REFUSED kind=%v phase=%v effect=%v status=%d provider=%d network=%v transport=%v\n",
        curl_refused.error.kind, curl_refused.error.phase, curl_refused.error.write_effect,
        curl_refused.status, curl_refused.error.provider_code, curl_refused.error.network,
        curl_refused.error.transport.kind)
    os.flush(os.stdout)
    assert((curl_refused.error.phase == .Connect || curl_refused.error.phase == .Deadline) &&
        curl_refused.error.write_effect == .Not_Sent)
	status_url := fmt.aprintf("%s/status", http_url)
	defer delete(status_url)
	_, status_result := surf.buffered_http_execute("POST", status_url, nil, nil, "", allow_http = true)
	assert(status_result.transport_ok && !status_result.ok && status_result.status == 503 && status_result.error.kind == .None)
	pool := new(tls.Root_Pool)
	defer free(pool)
	defer tls.root_pool_destroy(pool)
	assert(tls.root_pool_load_file(pool, wrong_root).kind == .None)
	tls_config := surf.Config{tls = {root_cas = pool.roots[:pool.count], handshake_timeout = time.Second}}
	tls_response, tls_error := surf.execute({method = .POST, url = tls_url}, tls_config)
	surf.response_destroy(&tls_response)
	assert(tls_error.kind == .TLS_Failed && tls_error.phase == .TLS && tls_error.write_effect == .Not_Sent)
	_, curl_tls := surf.buffered_http_execute("POST", tls_url, nil, nil, wrong_root)
	assert(curl_tls.error.kind == .TLS_Failed && curl_tls.error.phase == .TLS && curl_tls.error.write_effect == .Not_Sent)
	fmt.println("16 public native/curl outcome fixtures passed")
}
