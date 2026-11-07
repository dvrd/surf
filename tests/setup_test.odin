package tests

import surf ".."
import "core:mem"
import "core:testing"
import "core:time"

@(test)
setup_negative_timeout_rejected_before_io :: proc(t: ^testing.T) {
	response, error := surf.execute({method=.POST,url="https://fixture.invalid/"},{setup_timeout=-time.Second})
	defer surf.response_destroy(&response)
	testing.expect_value(t,error.kind,.Invalid_Config)
	testing.expect_value(t,error.phase,.Configuration)
	testing.expect_value(t,error.write_effect,.Not_Sent)
}

@(test)
setup_nil_connection_allocation_is_typed :: proc(t: ^testing.T) {
	response, error := surf.execute({method=.POST,url="https://fixture.invalid/"},{},mem.nil_allocator())
	defer surf.response_destroy(&response)
	testing.expect_value(t,error.kind,.Allocation_Failed)
	testing.expect_value(t,error.allocation,.Out_Of_Memory)
	testing.expect_value(t,error.write_effect,.Not_Sent)
}
