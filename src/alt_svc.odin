package surf

import "core:strings"
import "core:time"

// Fixed discovery table. A full slot replaces the oldest entry.
ALT_SVC_SLOTS :: 4
ALT_SVC_MAX_AGE :: 7 * 24 * 60 * 60

Alt_Svc :: struct {
	used:        bool,
	host:        [256]u8,
	host_len:    int,
	port:        int,
	origin_port: int,
	expires:     time.Time,
}

Alt_Svc_Cache :: struct {
	slots: [ALT_SVC_SLOTS]Alt_Svc,
	next:  int,
}

// Stores h3=":port"; ma=seconds only for an authenticated HTTPS origin.
// ma is required. Zero, expired, cleartext, and unauthenticated inputs do not write.
alt_svc_note :: proc(
	cache: ^Alt_Svc_Cache,
	host, value: string,
	authenticated, secure: bool,
	now: time.Time,
	origin_port: int = 443,
) -> bool {
	if cache == nil || !authenticated || !secure || len(host) == 0 || len(host) > 256 {
		return false
	}
	effective_port := origin_port
	if effective_port == 0 {
		effective_port = 443
	}
	port, ma, parsed := alt_svc_h3(value)
	if !parsed || ma <= 0 {
		return false
	}
	if ma > ALT_SVC_MAX_AGE {
		ma = ALT_SVC_MAX_AGE
	}
	index := cache.next % ALT_SVC_SLOTS
	replaced := false
	for i in 0 ..< ALT_SVC_SLOTS {
		if cache.slots[i].used &&
		   cache.slots[i].origin_port == effective_port &&
		   string(cache.slots[i].host[:cache.slots[i].host_len]) == host {
			index = i
			replaced = true
			break
		}
	}
	slot := &cache.slots[index]
	copy(slot.host[:], host)
	slot.host_len = len(host)
	slot.port = port
	slot.origin_port = effective_port
	slot.expires = time.time_add(now, time.Duration(ma) * time.Second)
	slot.used = true
	if !replaced {
		cache.next += 1
	}
	return true
}

alt_svc_lookup :: proc(
	cache: ^Alt_Svc_Cache,
	host: string,
	now: time.Time,
	origin_port: int = 443,
) -> (
	port: int,
	ok: bool,
) {
	effective_port := origin_port
	if effective_port == 0 {
		effective_port = 443
	}
	if cache == nil {
		return 0, false
	}
	for i in 0 ..< ALT_SVC_SLOTS {
		slot := &cache.slots[i]
		if !slot.used ||
		   slot.origin_port != effective_port ||
		   string(slot.host[:slot.host_len]) != host {
			continue
		}

		if time.diff(now, slot.expires) <= 0 {
			slot^ = {}
			return 0, false
		}

		return slot.port, true
	}
	return 0, false
}

is_digit :: proc(c: rune) -> bool {
	return c >= '0' && c <= '9'
}

alt_svc_h3 :: proc(value: string) -> (port, ma: int, ok: bool) {
	at := strings.index(value, "h3=\"")
	if at < 0 {
		return
	}
	rest := value[at + 4:]
	end := strings.index(rest, "\"")
	if end <= 0 {
		return
	}
	token := rest[:end]

	if len(token) > 1 && token[0] == ':' {
		token = token[1:]
	}

	if len(token) == 0 {
		return
	}

	for rune in token {
		if !is_digit(rune) {
			return
		}
		port = port * 10 + int(rune - '0')
		if port > 65535 {
			return 0, 0, false
		}
	}

	if port == 0 {
		return
	}
	tail := rest[end + 1:]
	loc := strings.index(tail, "ma=")
	if loc < 0 {
		return
	}

	for rune in tail[loc + 3:] {
		if !is_digit(rune) {
			break
		}
		ma = ma * 10 + int(rune - '0')

		if ma > ALT_SVC_MAX_AGE {
			ma = ALT_SVC_MAX_AGE
			break
		}
	}

	ok = ma > 0

	return
}
