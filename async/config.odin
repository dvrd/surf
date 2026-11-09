package surf_async

import surf ".."
import http "../../http"
import scopes "core:sync/budget"
import "core:time"

// Shape/bounds only. No allocation, scope admission/retention, clock, resolver,
// entropy or runtime access. The returned configuration still borrows all inputs.
config_normalize :: proc(input:Client_Config) -> (Normalized_Config,Client_Error) {
 cause := surf.config_validate(input.http)
 if cause.kind != .None do return {}, {kind=.Invalid_Config,http=cause}
 if input.idle_timeout < 0 || input.max_age < 0 ||
    input.http.tls.handshake_timeout < 0 || input.http.allocator_scope != (scopes.Scope{}) {
  return {}, {kind=.Invalid_Config}
 }
 lifetime := input.lifetime
 if (lifetime.epoch == 0 && lifetime.at != 0) ||
    (lifetime.epoch != 0 && lifetime.at <= 0) { return {}, {kind=.Invalid_Config} }
 capacities := DEFAULT_CAPACITIES
 if explicit,ok := input.capacities.?; ok do capacities = explicit
 if capacities.requests < 1 || capacities.requests > MAX_REQUESTS ||
    capacities.origins < 1 || capacities.origins > MAX_ORIGINS ||
    capacities.connections < 1 || capacities.connections > MAX_CONNECTIONS ||
    capacities.connections_per_origin < 1 || capacities.connections_per_origin > capacities.connections ||
    capacities.waiters_per_origin < 0 || capacities.waiters_per_origin > capacities.requests ||
    capacities.dns_ids < 0 || capacities.dns_ids > MAX_DNS_IDS ||
    capacities.work_per_resume < 1 || capacities.work_per_resume > MAX_WORK_PER_RESUME {
  return {}, {kind=.Invalid_Config}
 }
 if len(input.http.resolver.name_servers) > MAX_NAME_SERVERS do return {}, {kind=.Invalid_Config}
 for endpoint in input.http.resolver.name_servers {
  if endpoint.port == 0 do return {}, {kind=.Invalid_Config}
 }
 result := Normalized_Config{
  http=input.http, capacities=capacities, idle_timeout=input.idle_timeout,
  max_age=input.max_age, request_timeout=surf.effective_timeout(input.http),
  response_body_limit=input.http.max_body_size, lifetime=lifetime,
 }
 if result.idle_timeout == 0 do result.idle_timeout = 30*time.Second
 if result.max_age == 0 do result.max_age = 5*time.Minute
 if result.response_body_limit == 0 do result.response_body_limit = http.DEFAULT_MAX_BODY_SIZE
 return result, {}
}
