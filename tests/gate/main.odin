package main

import "core:fmt"
import "core:os"

// One acceptance binary. The first argument is the gate name. The flags after
// it are the ones that gate already understood.
gate_label: string

main :: proc() {
	if len(os.args) < 2 {
		usage()
	}

	switch os.args[1] {
	case "budgets":
		run_budgets()
	case "cancel":
		run_cancel()
	case "client":
		run_client()
	case "concurrency":
		run_concurrency()
	case "consumer":
		run_consumer()
	case "failure":
		run_failure()
	case "outcomes":
		run_outcomes()
	case "pool":
		run_pool()
	case "redirect":
		run_redirect()
	case "setup":
		run_setup()
	case "stream":
		run_stream()
	case "uploads":
		run_uploads()
	case:
		usage()
	}
}

usage :: proc() {
	fmt.eprintf("usage: task gate [GATE=name] [VERBOSE=1]\n")
	fmt.eprintf("       gate <name> --odin <compiler> --shared <collection> --report <path>\n")
	fmt.eprintf(
		"names: budgets cancel client concurrency consumer failure outcomes pool redirect setup stream uploads\n",
	)
	os.exit(2)
}

fail :: proc(reason: string) {
	fmt.eprintf("%s: %s\n", gate_label, reason)
	_ = os.flush(os.stderr)
	os.exit(1)
}
