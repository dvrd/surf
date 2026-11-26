package tests

import "../../support/loopback"
import "core:fmt"
import "core:net"
import "core:testing"
import "core:time"
import "shared:surf"

Address_Witness :: struct {
	calls:     int,
	localhost: bool,
	loopback:  bool,
	port:      int,
}

address_note :: proc(witness: ^Address_Witness, host: string, addresses: []net.Endpoint) {
	witness.calls += 1
	if host == "localhost" {
		witness.localhost = true
	}
	for address in addresses {
		witness.port = address.port
		switch ip in address.address {
		case net.IP4_Address:
			if ip == net.IP4_Loopback {
				witness.loopback = true
			}
		case net.IP6_Address:
			if ip == net.IP6_Loopback {
				witness.loopback = true
			}
		}
	}
}

address_reject_loopback :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	witness := cast(^Address_Witness)user
	address_note(witness, host, addresses)
	for address in addresses {
		switch ip in address.address {
		case net.IP4_Address:
			if ip == net.IP4_Loopback {
				return false
			}
		case net.IP6_Address:
			if ip == net.IP6_Loopback {
				return false
			}
		}
	}
	return true
}

address_allow :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	address_note(cast(^Address_Witness)user, host, addresses)
	return true
}

address_reject_localhost :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	witness := cast(^Address_Witness)user
	address_note(witness, host, addresses)
	return host != "localhost"
}

address_count_named :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	address_note(cast(^Address_Witness)user, host, addresses)
	return true
}

@(test)
address_policy_rejects_resolved_loopback_before_dial :: proc(t: ^testing.T) {
	witness: Address_Witness
	response, error := surf.execute(
		{method = .GET, url = "http://127.0.0.1:1/secret"},
		{
			allow_http = true,
			timeout = 2 * time.Second,
			address_policy = address_reject_loopback,
			address_policy_data = &witness,
		},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, error.status, 0)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, witness.loopback)
	testing.expect_value(t, witness.port, 1)
}

@(test)
address_policy_allows_the_checked_address_to_be_dialed :: proc(t: ^testing.T) {
	witness: Address_Witness
	response, error := surf.execute(
		{method = .GET, url = "http://127.0.0.1:1/secret"},
		{
			allow_http = true,
			timeout = 2 * time.Second,
			address_policy = address_allow,
			address_policy_data = &witness,
		},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Dial_Failed)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, witness.loopback)
	testing.expect_value(t, witness.port, 1)
}

Address_Hops :: struct {
	first:  loopback.Server,
	second: loopback.Server,
}

// first answers every request with a redirect to location; second answers 200.
address_hops_start :: proc(t: ^testing.T, hops: ^Address_Hops, location: string) -> bool {
	hops.second.answer = {wire = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"}

	if !testing.expect(t, loopback.server_start(&hops.second)) {
		return false
	}

	target := fmt.tprintf(location, hops.second.port)
	hops.first.answer = {
		wire = fmt.aprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n", target),
	}

	if !testing.expect(t, loopback.server_start(&hops.first)) {
		delete(hops.first.answer.wire)
		loopback.server_stop(&hops.second)
		return false
	}

	return true
}

address_hops_stop :: proc(hops: ^Address_Hops) {
	loopback.server_stop(&hops.first)
	loopback.server_stop(&hops.second)
	delete(hops.first.answer.wire)
}

// Refuses an IP-literal host; a name is allowed whatever it resolves to.
address_reject_literal :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
	address_note(cast(^Address_Witness)user, host, addresses)

	return net.parse_address(host) == nil
}

@(test)
address_policy_rejects_ip_redirect_before_the_hop :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 8 * time.Second)
	hops: Address_Hops

	if !address_hops_start(t, &hops, "http://127.0.0.1:%d/secret") {
		return
	}
	defer address_hops_stop(&hops)

	witness: Address_Witness
	response, error := surf.execute(
		{method = .GET, url = fmt.tprintf("http://localhost:%d/start", hops.first.port)},
		{
			allow_http = true,
			timeout = 3 * time.Second,
			max_redirects = 1,
			address_policy = address_reject_literal,
			address_policy_data = &witness,
		},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Response_Received)
	testing.expect_value(t, error.status, 302)
	testing.expect_value(t, witness.calls, 2)
	testing.expect(t, witness.localhost && witness.loopback)
	testing.expect_value(t, witness.port, hops.second.port)
	testing.expect_value(t, loopback.server_requests(&hops.first), 1)
	testing.expect_value(t, loopback.server_accepts(&hops.second), 0)
}

// A named hop is not checked when the redirect is read, only once it resolved:
// one check per hop, and the hop is followed.
@(test)
address_policy_defers_a_named_redirect_until_resolution :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 8 * time.Second)
	hops: Address_Hops

	if !address_hops_start(t, &hops, "http://localhost:%d/next") {
		return
	}
	defer address_hops_stop(&hops)

	witness: Address_Witness
	response, error := surf.execute(
		{method = .GET, url = fmt.tprintf("http://127.0.0.1:%d/start", hops.first.port)},
		{
			allow_http = true,
			timeout = 3 * time.Second,
			max_redirects = 1,
			address_policy = address_count_named,
			address_policy_data = &witness,
		},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "ok")
	testing.expect_value(t, witness.calls, 2)
	testing.expect(t, witness.localhost && witness.loopback)
	testing.expect_value(t, witness.port, hops.second.port)
	testing.expect_value(t, loopback.server_requests(&hops.second), 1)
}

@(test)
address_policy_checks_a_redirect_hostname_after_resolution :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 8 * time.Second)
	hops: Address_Hops

	if !address_hops_start(t, &hops, "http://localhost:%d/secret") {
		return
	}
	defer address_hops_stop(&hops)

	witness: Address_Witness
	response, error := surf.execute(
		{method = .GET, url = fmt.tprintf("http://127.0.0.1:%d/start", hops.first.port)},
		{
			allow_http = true,
			timeout = 3 * time.Second,
			max_redirects = 1,
			address_policy = address_reject_localhost,
			address_policy_data = &witness,
		},
	)
	defer surf.response_destroy(&response)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Response_Received)
	testing.expect_value(t, error.status, 302)
	testing.expect(t, witness.localhost)
	testing.expect(t, witness.loopback)
	testing.expect_value(t, witness.port, hops.second.port)
	testing.expect_value(t, witness.calls, 2)
	testing.expect_value(t, loopback.server_accepts(&hops.second), 0)
}
