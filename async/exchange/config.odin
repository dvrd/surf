package surf_exchange

import surf "../.."
import http "../../../http"
import "core:time"

// Pure bounds/default selection. No allocator, clock, retention, callbacks or
// network calls. On rejection no partially normalized result is returned.
options_normalize :: proc(input:Options)->(Resolved_Options,surf.HTTP_Error) {
 if input.body_limit<0 || input.body_limit>http.MAX_BODY_SIZE ||
    input.informational_limit<0 || input.informational_limit>MAX_INFORMATIONAL_RESPONSES {
  return {},{kind=.Invalid_Config}
 }
 result:=Resolved_Options{body_limit=input.body_limit,informational_limit=input.informational_limit}
 if result.body_limit==0 {result.body_limit=http.DEFAULT_MAX_BODY_SIZE}
 if result.informational_limit==0 {result.informational_limit=MAX_INFORMATIONAL_RESPONSES}
 return result,{}
}

// Structural clock-pair validation only. Negative/nonzero wall times are legal
// absolute times; no source of current time or Runtime epoch is consulted here.
budget_validate :: proc(input:Budget)->surf.HTTP_Error {
 if input.at<0 || (input.at==0 && input.wall!=(time.Time{})) ||
    (input.at>0 && input.wall==(time.Time{})) {return {kind=.Invalid_Config}}
 return {}
}
