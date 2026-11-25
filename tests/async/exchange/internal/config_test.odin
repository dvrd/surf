package surf_exchange

import surf "../.."
import "shared:async/tls"
import "core:mem"
import "core:testing"
import "core:time"

// Panic allocators make this boundary usable before any charged owner exists.
config_test_normalize :: proc(input: Options) -> (Resolved_Options, surf.HTTP_Error) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous

	return options_normalize(input)
}

@(test)
exchange_options_defaults_and_independent_exact_bounds :: proc(t: ^testing.T) {
	result, error := config_test_normalize({})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{8 << 20, 7})

	for body in ([4]int{1, 17, (64 << 20) - 1, 64 << 20}) {
		for interim in ([3]int{1, 6, 7}) {
			input := Options{body, interim}
			before := input
			result, error = config_test_normalize(input)
			testing.expect_value(t, error.kind, .None)
			testing.expect_value(t, result, Resolved_Options{body, interim})
			testing.expect_value(t, input, before)
		}
	}

	result, error = config_test_normalize({body_limit = 23})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{23, 7})
	result, error = config_test_normalize({informational_limit = 1})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, result, Resolved_Options{8 << 20, 1})
}

@(test)
exchange_options_reject_without_partial_normalization :: proc(t: ^testing.T) {
	for bad in ([4]int{-1, min(int), (64 << 20) + 1, max(int)}) {
		input := Options {
			body_limit          = bad,
			informational_limit = 1,
		}

		before := input
		result, error := config_test_normalize(input)
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, result, Resolved_Options{})
		testing.expect_value(t, input, before)
	}

	// Seven is the legacy maximum number of interim heads, not eight.
	for bad in ([4]int{-1, min(int), 8, max(int)}) {
		result, error := config_test_normalize({body_limit = 17, informational_limit = bad})
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, result, Resolved_Options{})
	}
}

@(test)
exchange_budget_requires_paired_clocks_without_sampling_or_extending :: proc(t: ^testing.T) {
	previous := context
	context.allocator, context.temp_allocator = mem.panic_allocator(), mem.panic_allocator()
	defer context = previous
	testing.expect_value(t, budget_validate({}).kind, .None)

	for cutoff in ([3]i64{1, 37, max(i64)}) {
		for wall in ([4]time.Time {
				time.Time{_nsec = 1},
				time.Time{_nsec = -1},
				time.Time{_nsec = min(i64)},
				time.Time{_nsec = max(i64)},
			}) {
			input := Budget{cutoff, wall}
			before := input
			testing.expect_value(t, budget_validate(input).kind, .None)
			testing.expect_value(t, input, before)
		}
	}

	for input in ([6]Budget{{-1, {}}, {min(i64), {}}, {1, {}}, {max(i64), {}}, {0, {_nsec = 1}}, {0, {_nsec = -1}}}) {
		testing.expect_value(t, budget_validate(input).kind, .Invalid_Config)
	}
}

@(test)
exchange_state_has_stable_full_record_and_separate_head_storage :: proc(t: ^testing.T) {
	x: Exchange
	testing.expect(t, len(x._read_buffer) >= tls.MAX_PLAINTEXT_SIZE)
	testing.expect_value(t, len(x._read_buffer), 16 << 10)
	testing.expect_value(t, len(x._request_head), 16 << 10)
	testing.expect_value(t, len(x._response_head), 16 << 10)
	testing.expect(t, raw_data(x._request_head[:]) != raw_data(x._response_head[:]))
	testing.expect_value(t, x._read.operation.pending, false)
	testing.expect_value(t, x._write.operation.pending, false)
	testing.expect_value(t, x._read.accepted, false)
	testing.expect_value(t, x._write.accepted, false)
	testing.expect_value(t, x._self, nil)
	testing.expect_value(t, x._response.status, 0)
	testing.expect_value(t, len(x._response.body), 0)
	testing.expect_value(t, len(x._response.headers), 0)
	testing.expect_value(t, x._response.allocator.procedure, nil)
	testing.expect_value(t, x._phase, .Idle)
}
