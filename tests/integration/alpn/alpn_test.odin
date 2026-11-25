package tests

import surf "shared:surf"
import "core:io"
import "core:testing"

// Local stand-in so this suite does not share the upload suite's package.
Upload_Producer :: struct {
	bytes:         []u8,
	reads, closes: int,
}

upload_producer :: proc(
	data: rawptr,
	mode: io.Stream_Mode,
	dst: []u8,
	_: i64,
	_: io.Seek_From,
) -> (
	i64,
	io.Error,
) {
	state := cast(^Upload_Producer)data
	#partial switch mode {
	case .Query:
		return io.query_utility({.Read, .Close})
	case .Close:
		state.closes += 1
		return 0, {}
	case .Read:
		state.reads += 1
		if len(state.bytes) == 0 {
			return 0, .EOF
		}
		n := copy(dst, state.bytes)
		state.bytes = state.bytes[n:]
		if n == 0 {
			return 0, .EOF
		}
		return i64(n), {}
	}
	return 0, .Unsupported
}

source_for :: proc(state: ^Upload_Producer, length: i64) -> surf.Upload_Source {
	return {stream = {procedure = upload_producer, data = state}, content_length = length}
}

@(test)
alpn_surf_rejects_unsupported_protocol_before_connection_setup :: proc(t: ^testing.T) {
	for protocols in ([?][]string{{"h3"}, {"http/1.1", "h3"}, {"h2", "h3"}, {""}, {"http/2"}, {"H2"}, {"H3"}}) {
		// A syntactically invalid zero-port URL cannot mask configuration failure;
		// it also prevents DNS/socket I/O if this guard regresses.
		response, error := surf.execute(
			{method = .GET, url = "http://127.0.0.1:0/"},
			{allow_http = true, tls = {alpn_protocols = protocols}},
		)
		surf.response_destroy(&response)
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, error.phase, .Configuration)
		testing.expect_value(t, error.write_effect, .Not_Sent)
	}
}

@(test)
alpn_surf_tcp_accepts_http1_and_h2_without_implicit_offer :: proc(t: ^testing.T) {
	bare := surf.Config{}
	testing.expect_value(t, surf.config_validate(bare).kind, .None)
	testing.expect_value(t, len(bare.tls.alpn_protocols), 0)

	for protocols in ([?][]string{{"http/1.1"}, {"h2"}, {"http/1.1", "h2"}, {"h2", "http/1.1"}}) {
		testing.expect_value(t, surf.config_validate({tls = {alpn_protocols = protocols}}).kind, .None)
	}
}

@(test)
alpn_surf_rejects_before_reading_upload_source :: proc(t: ^testing.T) {
	producer := Upload_Producer {
		bytes = {1},
	}

	response, error := surf.execute_upload(
		{method = .POST, url = "http://127.0.0.1:0/"},
		source_for(&producer, 1),
		{allow_http = true, tls = {alpn_protocols = {"h3"}}},
	)
	surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, producer.reads, 0)
	testing.expect_value(t, producer.closes, 0)
}
