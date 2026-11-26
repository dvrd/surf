package surf

import "core:testing"
import "core:time"

@(test)
alt_svc_is_noted_only_for_an_authenticated_https_origin :: proc(t: ^testing.T) {
	cache: Alt_Svc_Cache
	now := time.now()
	value := "h3=\":443\"; ma=60"

	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", value, false, true, now))
	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", value, true, false, now))
	testing.expect(t, !alt_svc_note(&cache, "synthetic.invalid", "h3=\":443\"; ma=0", true, true, now))
	testing.expect(t, !alt_svc_note(nil, "synthetic.invalid", value, true, true, now))
	testing.expect(t, alt_svc_note(&cache, "synthetic.invalid", value, true, true, now))

	port, ok := alt_svc_lookup(&cache, "synthetic.invalid", now)
	testing.expect(t, ok && port == 443)

	later := time.time_add(now, 61 * time.Second)
	port, ok = alt_svc_lookup(&cache, "synthetic.invalid", later)
	testing.expect(t, !ok && port == 0)

	_, still := alt_svc_lookup(&cache, "synthetic.invalid", now)
	testing.expect(t, !still)
}

@(test)
alt_svc_is_kept_per_origin_port :: proc(t: ^testing.T) {
	cache: Alt_Svc_Cache
	now := time.now()

	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9443\"; ma=60", true, true, now, 8443))
	testing.expect(t, alt_svc_note(&cache, "localhost", "h3=\":9444\"; ma=60", true, true, now, 443))

	port, ok := alt_svc_lookup(&cache, "localhost", now, 8443)
	testing.expect(t, ok && port == 9443)
	port, ok = alt_svc_lookup(&cache, "localhost", now, 443)
	testing.expect(t, ok && port == 9444)
}
