// Public Client prestart consumer. The fixture prints one marker line.
package main

import support "../support"

import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

MARKER :: "CONSUMER101 public_client_prestart=true unchanged_facade=true http1=true heap_zero=true"

main :: proc() {
	g := support.begin("consumer101")
	defer support.end(&g)
	binary := support.path(&g, "fixture")
	defer delete(binary)
	if !support.build(&g, "tests/testdata/consumer101", binary, true) {
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
	fmt.println("consumer101 marker passed")
}
