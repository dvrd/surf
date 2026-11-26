// A minimal consumer of the public API. The fixture prints one marker line.

package main

import "support"
import "core:fmt"
import "core:strings"
import "core:time"

MARKER :: "CONSUMER execute=true client_start=true client_init=true requests=4 heap_zero=true"

run_consumer :: proc() {
	gate_label = "consumer"

	g := support.begin("consumer")
	defer support.end(&g)
	binary := support.path(&g, "fixture")
	defer delete(binary)
	if !support.build(&g, "tests/support/consumer", binary, true) {
		support.fail(&g, "fixture build")
	}
	command := [1]string{binary}
	child, started := support.spawn(command[:], nil)
	if !started {
		support.fail(&g, "fixture start")
	}
	defer support.stop(&child)
	if !support.reap(&child, 60 * time.Second) || child.code != 0 {
		fmt.eprintf("fixture: %s\n", support.tail(&child))
		support.stop(&child)
		support.fail(&g, "fixture")
	}
	if strings.trim_space(support.stdout(&child)) != MARKER {
		support.stop(&child)
		support.fail(&g, "marker")
	}
	support.passed(&g, "{\"passed\":true,\"marker\":true}\n")
	fmt.println("consumer marker passed")
}
