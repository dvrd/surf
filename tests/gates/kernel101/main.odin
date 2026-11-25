// Kernel and memory codec fixture. One JSON line, no socket and no unit census.
package main

import support "../support"

import "core:encoding/json"
import "core:fmt"
import "core:time"

main :: proc() {
	g := support.begin("kernel101")
	defer support.end(&g)
	binary := support.path(&g, "fixture")
	defer delete(binary)
	if !support.build(&g, "tests/testdata/kernel101", binary, true) {
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
	native, ok := support.only(support.stdout(&child))
	if !ok {
		support.stop(&child)
		support.fail(&g, "json")
	}
	defer json.destroy_value(native)
	if !support.is_true(native, "passed") || !support.eq_string(native, "scope", "kernel-and-memory-codec-only") {
		support.fail(&g, "scope")
	}
	if !support.eq_int(native, "model_completions", 2) || !support.eq_int(native, "memory_exchanges", 2) {
		support.fail(&g, "counts")
	}
	if !support.eq_int(native, "model_idle_reuses", 1) || !support.eq_int(native, "foreign_owner_checks", 2) {
		support.fail(&g, "counts")
	}
	if !support.eq_int(native, "close_rejections", 2) || !support.gt_int(native, "work1_calls", 2) {
		support.fail(&g, "counts")
	}
	if !support.is_true(native, "scope_zero") || !support.is_true(native, "heap_zero") {
		support.fail(&g, "cleanup")
	}
	support.passed(&g, "{\"passed\":true}\n")
	fmt.println("kernel101 codec fixture passed")
}
