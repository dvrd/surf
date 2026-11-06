package surf

import owned "core:mem/owned"

// Moves the response's complete body allocation into a separately releasable
// owner. Headers remain with response; response_destroy stays safe afterward.
// The allocator backing body_storage must survive until the chunk is released.
// Borrowed/manually constructed bodies are rejected without changing response.
response_take_body :: proc(response: ^Response) -> (chunk: owned.Chunk, error: owned.Error) {
	if response == nil || len(response.body) != len(response.body_storage) ||
	   raw_data(response.body) != raw_data(response.body_storage) {
		return {}, {kind=.Invalid_Input}
	}
	chunk, error = owned.take_dynamic(&response.body_storage)
	if error.kind == .None {response.body = nil}
	return
}
