# Optional managed resource budgets

Set `Config.scope` on `execute` / `execute_upload` to an operation scope below
host connection and global scopes from `core:sync/budget`. Limits are immutable;
metadata capacity does not increase them. The host owns hierarchy policy. A zero
scope preserves existing behavior. `exchange_scoped` and `exchange_upload_scoped`
provide the same opt-in behavior for supplied transports. Original `exchange`,
`exchange_upload`, and `buffered_http_execute` procedure types remain compatible.

Each blocking operation reserves one stream until it returns. Output headers,
body capacity, allocation headers, alignment, temporary arena blocks and their
bookkeeping consume requested backing bytes. Reallocation admits the complete
old/new overlap before changing the owner. Failure preserves retained owners.
Snapshots report current, peak, rejection and stream counters at every ancestor.
These counters describe requested backing, not RSS or allocator metadata.
Binding and scope metadata have separate counters in their respective modules.

An ordinary allocator supporting individual Free receives an owned charged
binding. A direct managed allocator is reused only when its default scope covers
the requested scope; its binding is retained. Incompatible or foreign managed
allocators fail admission before transport activity. No callback executes under
the hierarchy lock. Standard allocator OOM cannot distinguish backing exhaustion
from budget denial: `HTTP_Error.allocation` reports that OOM without inventing a
budget cause. Explicit reservation errors also report `HTTP_Error.budget`,
`phase=Admission`, and `write_effect=Not_Sent`. Later failures preserve the actual
write effect and must not be treated as automatically safe to retry.

For a host-managed arena, set `Config.allocator_scope` to its charged backing
scope. This is a trusted host assertion that **both** the arena block allocator
and array/bookkeeping allocator are charged. The annotation must cover the
requested scope; merely sharing a root is insufficient. Surf retains that scope
through the Response but cannot extend arena storage lifetime. The caller must
keep the arena alive until every Response and moved Chunk has been destroyed.
Unannotated allocators without individual Free support are rejected. Arbitrary
custom pointers are never interpreted as managed allocation headers.

`response_take_body` moves the complete backing capacity into a standard owned
Chunk. Destroying the Response releases only its remaining storage. An independent
managed heap body's allocation retains its binding and scope after caller owner
handles retire, including an empty body's harmless nil free. A same-root transfer
into `http/exchange` atomically rebinds its one charge; shared ancestors are not
charged twice. Foreign-root rejection leaves the source owner intact. Borrowed
arena storage retains the caller's original arena lifetime requirement.

## Native TLS and curl

Managed native operations install the charged allocator and a charged temporary
arena in the call context, including TLS's 1 MiB certificate flight and chain
verification allocations. They retire call temporaries before returning. TLS
requires explicit trust roots; it does not lazily load or cache system roots.
Load `tls.Root_Pool` at host startup with a host allocator and keep it stable
until all clients finish. Roots, profiles, caller inputs, protocol stack scratch,
and independently owned transport state are outside the operation's heap budget.

`buffered_http_execute_owned` returns a Response with independent owned output;
its trailing allocator/scope/allocator_scope options use the same rules above.
`buffered_http_execute_managed` selects budgeting for the original borrowed curl
result. That mode requires a host coverage annotation for `context.temp_allocator`;
its output remains valid only until that arena resets. Freeing the logical result
does not release arena blocks. The original nine-argument curl procedure remains
usable as an AWS HTTP_Execute callback.

Managed curl additionally reserves its fixed 64 KiB response scratch until output
copying finishes. Setup strings use a charged call arena; header inputs are
limited to HTTP's header count and 16 KiB aggregate header text. Curl's opaque
internal allocations and process caches use curl's allocator and are not claimed
as scope-controlled heap. The output/body and known scratch bounds are enforced;
this interface does not claim an RSS or complete foreign-library memory ceiling.

## Validation

`tests/budget_test.odin` exercises retained full backing, hierarchy admission,
covered arenas, stream rejection, Surf-to-exchange transfer and a reentrant free
that releases the Response frame. `tests/budgets_loopback.py` runs independent
native HTTP, curl and TLS peers under ASan/TSan. It checks global retained-body
pressure, oversized responses, borrowed arena recovery, empty owner retirement,
TLS temporary admission/rejection, zero final charges and stable descriptor
counts. Existing setup, upload and outcome harnesses remain regression gates.
