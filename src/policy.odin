package surf

import "core:net"

// Nil policy allows the dial. An empty set or a false result refuses every
// address before connect. The slice is the exact set the dial will walk.
address_policy_check :: proc(
	config: Config,
	host: string,
	addresses: []net.Endpoint,
) -> HTTP_Error {
	if config.address_policy == nil {
		return {}
	}
	if len(addresses) == 0 || !config.address_policy(host, addresses, config.address_policy_data) {
		return {kind = .Address_Rejected, phase = .Connect, write_effect = .Not_Sent}
	}
	return {}
}

// Refuses an empty set and any address that is not global unicast. IPv4:
// loopback, RFC 1918, shared address space 100.64.0.0/10, link-local
// 169.254.0.0/16 (including 169.254.169.254), 0.0.0.0/8, 224.0.0.0/4, and
// 240.0.0.0/4. IPv6: ::1, fe80::/10, fc00::/7, ::, ff00::/8, and the NAT64
// well-known prefix 64:ff9b::/96. An IPv4-mapped address is refused when its
// IPv4 form is. One refused address refuses the whole set.
address_policy_public_only :: proc(_: string, addresses: []net.Endpoint, _: rawptr) -> bool {
	ip4_refused :: proc(ip: net.IP4_Address) -> bool {
		if ip[0] == 0 || ip[0] == 10 || ip[0] == 127 {
			return true
		}

		if ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 {
			return true
		}

		if ip[0] == 169 && ip[1] == 254 {
			return true
		}

		if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
			return true
		}

		if ip[0] == 192 && ip[1] == 168 {
			return true
		}

		if ip[0] >= 224 {
			return true
		}

		return false
	}

	ip6_refused :: proc(ip: net.IP6_Address) -> bool {
		if ip == {} || ip == net.IP6_Loopback {
			return true
		}

		first := u16(ip[0])

		if first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00 || first & 0xff00 == 0xff00 {
			return true
		}

		if u16(ip[0]) == 0x0064 &&
		   u16(ip[1]) == 0xff9b &&
		   u16(ip[2]) == 0 &&
		   u16(ip[3]) == 0 &&
		   u16(ip[4]) == 0 &&
		   u16(ip[5]) == 0 {
			return true
		}

		mapped :=
			u16(ip[0]) == 0 &&
			u16(ip[1]) == 0 &&
			u16(ip[2]) == 0 &&
			u16(ip[3]) == 0 &&
			u16(ip[4]) == 0 &&
			u16(ip[5]) == 0xffff

		if mapped {
			hi := u16(ip[6])
			lo := u16(ip[7])

			return ip4_refused({u8(hi >> 8), u8(hi), u8(lo >> 8), u8(lo)})
		}

		return false
	}

	if len(addresses) == 0 {
		return false
	}

	for address in addresses {
		refused := false

		switch ip in address.address {
		case net.IP4_Address:
			refused = ip4_refused(ip)
		case net.IP6_Address:
			refused = ip6_refused(ip)
		}

		if refused {
			return false
		}
	}

	return true
}

