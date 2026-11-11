package surf

import "core:net"
import "core:time"
import http "shared:http"

@(private)
connection_setup_deadline :: proc(config: Config, total: time.Time) -> time.Time {
	if config.setup_timeout <= 0 {return total}
	now := time.now()
	budget := min(config.setup_timeout, max(time.Duration(0), time.diff(now, total)))
	return time.time_add(now, budget)
}

@(private)
bounded_socket :: proc(url: http.URL, config: Config, deadline: time.Time) -> (net.TCP_Socket, HTTP_Error) {
	endpoints, resolve_error := net.resolve_endpoints_until(url.host, url.port, deadline, config.resolver)
	if resolve_error != nil {
		return 0, http_error_classify({kind = .Dial_Failed, network = resolve_error}, .DNS, .Not_Sent)
	}
	socket, connect_error := net.dial_tcp_candidates_until(endpoints, deadline)
	if connect_error != nil {
		return 0, http_error_classify({kind = .Dial_Failed, network = connect_error}, .Connect, .Not_Sent)
	}
	return socket, {}
}
