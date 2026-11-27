package main

import "core:fmt"
import "core:net"
import "core:os"
import "core:time"
import "shared:surf"

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
	dns_response, dns_error := surf.execute(
		{method = .POST, url = "http://offline-fixture.test/"},
		{allow_http = true},
	)
	net.dns_configuration = saved_dns
	surf.response_destroy(&dns_response)
	assert(dns_error.phase == .DNS && dns_error.write_effect == .Not_Sent)

	config := surf.Config {
		allow_http    = true,
		max_body_size = 8,
		timeout       = 200 * time.Millisecond,
	}
	for sample in ([]struct {
			path:   string,
			phase:  surf.HTTP_Phase,
			status: int,
			effect: surf.HTTP_Write_Effect,
		} {
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
	redirect_response, redirect_error := surf.execute(
		{method = .POST, url = redirect_url, body = []u8{'x'}},
		redirect_config,
	)
	surf.response_destroy(&redirect_response)
	assert(
		redirect_error.phase == .Read &&
		redirect_error.status == 307 &&
		redirect_error.write_effect == .Unknown,
	)

	unsafe_url := fmt.aprintf("%s/native-unsafe-redirect", http_url)
	defer delete(unsafe_url)
	unsafe_response, unsafe_error := surf.execute(
		{method = .POST, url = unsafe_url, body = []u8{'x'}},
		redirect_config,
	)
	surf.response_destroy(&unsafe_response)
	assert(
		unsafe_error.phase == .Protocol &&
		unsafe_error.status == 302 &&
		unsafe_error.write_effect == .Response_Received,
	)

	response, refused := surf.execute({method = .POST, url = refused_url}, config)
	surf.response_destroy(&response)
	assert(
		(refused.phase == .Connect || refused.phase == .Deadline) &&
		refused.write_effect == .Not_Sent,
	)

	pool := new(surf.Trust_Roots)
	defer free(pool)
	defer surf.trust_roots_destroy(pool)
	assert(surf.trust_roots_load_file(pool, wrong_root) == .None)

	tls_config := surf.Config {
		tls = {roots = pool},
		setup_timeout = time.Second,
	}
	tls_response, tls_error := surf.execute({method = .POST, url = tls_url}, tls_config)
	surf.response_destroy(&tls_response)
	assert(
		tls_error.kind == .TLS_Failed &&
		tls_error.phase == .TLS &&
		tls_error.write_effect == .Not_Sent,
	)


	fmt.println("public outcome fixtures passed")
}
