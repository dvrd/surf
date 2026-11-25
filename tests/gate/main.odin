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
	case "compatibility":
		run_compatibility()
	case "concurrency":
		run_concurrency()
	case "consumer":
		run_consumer()
	case "exchange":
		run_exchange()
	case "failure":
		run_failure()
	case "kernel":
		run_kernel()
	case "outcomes":
		run_outcomes()
	case "pool":
		run_pool()
	case "redirect":
		run_redirect()
	case "redirect_foundations":
		run_redirect_foundations()
	case "session":
		run_session()
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
	fmt.eprintf("usage: gate <name> --odin <compiler> --shared <collection> --report <path>\n")
	fmt.eprintf("names: budgets cancel client compatibility concurrency consumer exchange failure kernel outcomes pool redirect redirect_foundations session setup stream uploads\n")
	os.exit(2)
}

fail :: proc(reason: string) {
	fmt.eprintf("%s: %s\n", gate_label, reason)
	_ = os.flush(os.stderr)
	os.exit(1)
}
