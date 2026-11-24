package tests

import surf "shared:surf"
import http "shared:http"
import tls "core:crypto/tls"
import "core:fmt"
import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

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

address_reject_redirect_ip :: proc(host: string, addresses: []net.Endpoint, user: rawptr) -> bool {
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

@(test)
address_policy_rejects_ip_redirect_before_the_hop :: proc(t: ^testing.T) {
	witness: Address_Witness
	headers := [1]http.Header{{name = "Location", value = "http://127.0.0.1:1/secret"}}
	response := surf.Response {
		status  = 302,
		headers = headers[:],
	}
	base := http.URL {
		scheme    = "http",
		host      = "public.test",
		authority = "public.test",
		target    = "/",
		port      = 80,
	}
	url, error := surf.execute_redirect(
		&response,
		{method = .GET, url = "http://public.test/"},
		base,
		{
			allow_http = true,
			max_redirects = 1,
			address_policy = address_reject_redirect_ip,
			address_policy_data = &witness,
		},
		0,
		context.allocator,
	)
	defer delete(url)
	testing.expect_value(t, error.kind, .Address_Rejected)
	testing.expect_value(t, error.phase, .Connect)
	testing.expect_value(t, error.write_effect, .Not_Sent)
	testing.expect_value(t, len(url), 0)
	testing.expect_value(t, witness.calls, 1)
	testing.expect(t, witness.loopback)
	testing.expect_value(t, witness.port, 1)
}

@(test)
address_policy_defers_a_named_redirect_until_resolution :: proc(t: ^testing.T) {
	witness: Address_Witness
	headers := [1]http.Header{{name = "Location", value = "http://localhost:1/secret"}}
	response := surf.Response {
		status  = 302,
		headers = headers[:],
	}
	base := http.URL {
		scheme    = "http",
		host      = "public.test",
		authority = "public.test",
		target    = "/",
		port      = 80,
	}
	url, error := surf.execute_redirect(
		&response,
		{method = .GET, url = "http://public.test/"},
		base,
		{
			allow_http = true,
			max_redirects = 1,
			address_policy = address_count_named,
			address_policy_data = &witness,
		},
		0,
		context.allocator,
	)
	defer delete(url)
	testing.expect_value(t, error.kind, .None)
	testing.expect(t, len(url) > 0)
	testing.expect_value(t, witness.calls, 0)
}

Redirect_Peer :: struct {
	listener: net.TCP_Socket,
}

redirect_peer_serve :: proc(peer: ^Redirect_Peer) {
	client, _, accept_error := net.accept_tcp(peer.listener)
	if accept_error != nil {
		return
	}
	defer net.close(client)
	buffer: [512]u8
	_, _ = net.recv_tcp(client, buffer[:])
	message := "HTTP/1.1 302 Found\r\nLocation: http://localhost:1/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	_, _ = net.send_tcp(client, transmute([]u8)message)
}

@(test)
address_policy_checks_a_redirect_hostname_after_resolution :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 8 * time.Second)
	witness: Address_Witness
	listener, listen_error := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	testing.expect(t, listen_error == nil)
	if listen_error != nil {
		return
	}
	peer := Redirect_Peer {
		listener = listener,
	}
	worker := thread.create_and_start_with_poly_data(&peer, redirect_peer_serve)
	defer {
		net.close(listener)
		if worker != nil {
			thread.destroy(worker)
		}
	}
	testing.expect(t, worker != nil)
	if worker == nil {
		return
	}
	endpoint, bound_error := net.bound_endpoint(listener)
	testing.expect_value(t, bound_error, .None)
	if bound_error != .None {
		return
	}
	url := fmt.aprintf("http://127.0.0.1:%d/start", endpoint.port)
	defer delete(url)
	response, error := surf.execute(
		{method = .GET, url = url},
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
	testing.expect_value(t, witness.port, 1)
	testing.expect(t, witness.calls >= 2)
}
