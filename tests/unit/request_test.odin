package surf

import "core:testing"

@(test)
request_validate_refuses_framing_and_bad_input_before_send :: proc(t: ^testing.T) {
	config := Config{}
	url := "https://example.com/upload"
	body := []u8{1, 2, 3, 4}

	for name in ([]string {
			"Transfer-Encoding",
			"Content-Length",
			"Connection",
			"Host",
			"TE",
			"Expect",
		}) {
		headers := []Header{{name = name, value = "x"}}
		error := request_validate(
			config,
			{method = .POST, url = url, headers = headers, body = body},
			{},
		)
		testing.expect_value(t, error.kind, .Reserved_Header)
		testing.expect_value(t, error.phase, .Configuration)
		testing.expect_value(t, error.write_effect, .Not_Sent)
	}

	bad := []Header{{name = "X-Test", value = "a\r\nb"}}
	testing.expect_value(
		t,
		request_validate(config, {method = .GET, url = url, headers = bad}, {}).kind,
		.Invalid_Header,
	)
	testing.expect_value(
		t,
		request_validate(config, {method = .GET, url = "ftp://x"}, {}).kind,
		.Invalid_URL,
	)
	testing.expect_value(
		t,
		request_validate(config, {method = .GET, url = "http://example.com/"}, {}).kind,
		.Insecure_URL,
	)
	testing.expect_value(
		t,
		request_validate(config, {method = .GET, url = url, body = body}, {}).kind,
		.Invalid_Method,
	)

	upload := Submit_Options {
		upload        = .Queue,
		upload_length = 4,
	}
	follow := Config {
		max_redirects = 1,
	}
	testing.expect_value(
		t,
		request_validate(follow, {method = .PUT, url = url}, upload).kind,
		.Invalid_Config,
	)
	testing.expect_value(
		t,
		request_validate(config, {method = .PUT, url = url}, upload).kind,
		.None,
	)

	allowed := []Header {
		{name = "Authorization", value = "Bearer x"},
		{name = "Content-Type", value = "a/b"},
	}
	testing.expect_value(
		t,
		request_validate(config, {method = .POST, url = url, headers = allowed, body = body}, {}).kind,
		.None,
	)
}
