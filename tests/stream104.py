#!/usr/bin/env python3
"""Owned independent Surf104 streaming, upload, gzip and lifetime wire gate."""
from staging import copy_closure, test_run, test_files
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time


CASES = [
    ("known", 32 << 20), ("chunked", 32 << 20), ("eof", 32 << 20),
    ("fragmented", 4096), ("short-length", 65536),
    ("buffered-gzip", 65536), ("buffered-short", 65536),
    ("allocation-engine", 2), ("allocation-head-fields", 2),
    ("head-gzip", 12345), ("no-content-gzip", 12345), ("not-modified-gzip", 12345),
    ("coding-unsupported", 3), ("coding-chain", 3), ("coding-repeated", 3),
    ("chunk-invalid-size", 65536), ("chunk-invalid-crlf", 65536),
    ("chunk-truncated", 65536), ("chunk-missing-terminal", 65536),
    ("chunk-trailer-invalid", 65536), ("conflicting-framing", 65536),
    ("credit", 131072), ("late-head", 131072), ("late-chunk", 131072),
    ("late-both", 131072), ("timeout", 32 << 20), ("cancel", 32 << 20),
    ("fairness", 32 << 20),
    ("upload", 4 << 20), ("upload-backing", 3), ("upload-empty", 4096),
    ("upload-oversize", 4096), ("upload-overrun", 4096),
    ("upload-short", 131072), ("upload-source-error", 131072),
    ("upload-source-error-blocked", 32 << 20),
    ("upload-cancel", 131072), ("early-final", 32 << 20),
    ("early-final-prefix", 32 << 20), ("early-final-blocked", 32 << 20),
    ("gzip", 4 << 20), ("gzip-chunked", 4 << 20), ("gzip-eof", 4 << 20),
    ("gzip-fragmented", 65536), ("gzip-metadata", 65536),
    ("gzip-fhcrc", 65536), ("gzip-fhcrc-invalid", 65536),
    ("gzip-crc", 65536), ("gzip-crc-held", 65536), ("gzip-size", 65536),
    ("gzip-truncated", 65536), ("gzip-trailing", 65536),
    ("gzip-members", 65536), ("gzip-encoded-exact", 65536),
    ("gzip-decoded-exact", 65536), ("decoded-exact", 65536),
    ("gzip-encoded-limit", 65536), ("gzip-decoded-limit", 65536),
    ("gzip-amplification", 4 << 20),
    ("encoded-limit", 65536), ("decoded-limit", 65536),
    ("redirect", 2), ("redirect-cross", 2), ("redirect-cross-auth", 2), ("redirect-loop", 2),
    ("redirect-malformed", 2), ("redirect-gzip-invalid", 2),
    ("redirect-deadline", 2), ("redirect-downgrade", 2),
]
ERRORS = {
    "short-length", "buffered-short", "chunk-invalid-size", "chunk-invalid-crlf", "chunk-truncated",
    "allocation-engine", "allocation-head-fields",
    "chunk-missing-terminal", "chunk-trailer-invalid", "conflicting-framing",
    "timeout", "cancel", "upload-short", "upload-source-error", "upload-cancel",
    "upload-source-error-blocked",
    "fairness",
    "gzip-fhcrc-invalid", "gzip-crc", "gzip-crc-held", "gzip-size", "gzip-truncated", "gzip-trailing",
    "gzip-members", "gzip-encoded-limit", "gzip-decoded-limit", "gzip-amplification",
    "encoded-limit", "decoded-limit", "redirect-loop", "redirect-malformed",
    "coding-unsupported", "coding-chain", "coding-repeated",
    "redirect-gzip-invalid", "redirect-deadline", "redirect-downgrade", "redirect-cross-auth",
}
DECODER_ERRORS = {
    "gzip-fhcrc-invalid": "Checksum_Mismatch", "gzip-crc": "Checksum_Mismatch", "gzip-crc-held": "Checksum_Mismatch",
    "gzip-size": "Size_Mismatch", "gzip-truncated": "Truncated",
    "gzip-trailing": "Trailing_Data", "gzip-members": "Member_Limit",
    "gzip-decoded-limit": "Decoded_Limit", "gzip-amplification": "Decoded_Limit",
    "redirect-gzip-invalid": "Checksum_Mismatch",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(root):
    return {str(p.resolve()): sha(p) for p in sorted(Path(root).rglob("*"))
            if p.is_file() and not p.is_symlink()
            and ".git" not in p.parts and "__pycache__" not in p.parts}


def validate(mode, size, encrypted, native, peer):
    require(native["mode"] == peer["mode"] == mode, "case identity")
    require(native["tls"] == peer["tls"] == encrypted, "transport identity")
    require(peer["alpn"] == ("http/1.1" if encrypted else ""), "actual ALPN")
    for field in ("heap_zero", "scope_zero", "fd_zero"):
        require(native[field] is True, field)
    require(native["peak_bytes"] <= native["baseline_bytes"] + (4 << 20), "flat backing ceiling")
    require(native["max_held_chunks"] <= 2, "held output slot bound")
    require(native["max_response_backing"] <= 32768, "output backing bound")
    require(native["max_upload_bytes"] <= 65536, "upload backing bound")
    require(native["source_created"] == native["source_released"], "exact source disposal")
    if mode in ERRORS:
        require(native["ended"] is False and native["error_kind"], "typed failure, not End")
        if mode in DECODER_ERRORS:
            require(native["http_kind"] == "Content_Decoding_Failed", "decoder failure kind")
            require(native["decoding"] == DECODER_ERRORS[mode], "exact decoder detail")
        if mode == "gzip-crc-held":
            require(native["late_owner"] and native["retained_after_teardown_bytes"] > 0,
                    "already transferred prefix remains owned after checksum failure and Client teardown")
        if mode in ("timeout", "redirect-deadline"):
            require(native["phase"] == "Deadline", "deadline while backpressured")
            if mode == "timeout":
                require(native["deadline_without_poll"], "autonomous timeout before caller polls")
            else:
                require(200_000_000 <= native["elapsed_ns"] <= 800_000_000,
                        "redirect keeps original250ms cutoff rather than a fresh hop budget")
        if mode in ("cancel", "upload-cancel", "fairness"):
            require(native["phase"] == "Cancellation", "cancellation outcome")
            if mode == "cancel":
                require(native["cancel_without_poll"], "physical cancellation before caller polls")
        if mode in ("upload-source-error", "upload-source-error-blocked"):
            require(native["source_io"] == "Unexpected_EOF", "producer source diagnostic")
            require(native["phase"] == "Write", "producer source error phase")
        if mode == "upload-source-error-blocked":
            require(native["upload_stall_ns"] >= 100_000_000 and native["upload_blocked_after_bytes"] > 0,
                    "producer failed with stable upload credit hold")
            require(0 < native["source_error_completed_ns"] < 2_000_000_000,
                    "source error cancels held write before total request cutoff")
            require(peer["requests"] == 1 and peer["upload_bytes"] < size and not native["head_received"],
                    "source failure completes before peer drains incomplete upload")
        if mode == "fairness":
            require(native["cheap_before_release"] and peer["cheap_before_release"] and peer["requests"] == 2,
                    "one-worker cheap origin progresses while response credits are held")
        if mode.startswith("allocation-"):
            require(native["http_kind"] == "Allocation_Failed" and native["allocation_hits"] == 1,
                    "injected actor allocation failure")
            require(not native["head_received"] and native["bytes"] == 0, "no partial successful response")
            point = 1 if mode == "allocation-engine" else 2
            require(native["allocation_calls"] == point and native["allocation_sizes"][point - 1] > 0,
                    "exact allocation boundary recorded")
            require(peer["requests"] == (0 if mode == "allocation-engine" else 1),
                    "independent request-side fault boundary")
        if mode.startswith("coding-"):
            require(native["http_kind"] == "Unsupported_Content_Encoding" and not native["head_received"],
                    "unsupported coding rejected before head publication")
        if mode == "redirect-cross-auth":
            require(native["http_kind"] == "Unsafe_Redirect" and native["status"] == 302,
                    "existing unsafe cross-origin policy")
            require(peer["requests"] == 1 and peer["authorization_gone"], "no second-origin contact")
        if mode.startswith("redirect"):
            require(not native["head_received"] and native["status"] == 302,
                    "failed redirect preserves status without exposing intermediate head")
        if mode == "gzip-amplification":
            require(native["bytes"] <= 65536, "amplification ceiling before publication")
        if mode in ("decoded-limit", "gzip-decoded-limit", "encoded-limit"):
            require(native["bytes"] <= size - 1, "byte ceiling before publication")
        if mode == "gzip-encoded-limit":
            require(native["bytes"] == 0, "encoded Content-Length rejected before decoded publication")
        return
    require(native["ended"] is True and not native["error_kind"], "successful terminal End")
    require(native["head_received"] is True, "owned head delivery")
    if mode == "buffered-gzip":
        require(native["delivery"] == "Wire" and peer["accept_encoding"] == "identity",
                "buffered identity behavior is unchanged")
        require(native["bytes"] == peer["wire_body_bytes"] and native["sha256"] == peer["body_sha256"],
                "buffered response retains raw gzip bytes")
    elif mode in ("head-gzip", "no-content-gzip", "not-modified-gzip"):
        status = {"head-gzip": 200, "no-content-gzip": 204, "not-modified-gzip": 304}[mode]
        require(native["status"] == status and native["bytes"] == native["chunks"] == 0,
                "bodyless response does not consume representation bytes")
        require(native["delivery"] == "Wire" and native["wire_content_length"] == size,
                "bodyless wire metadata preserved without gzip decoder")
    elif mode.startswith("upload") or mode.startswith("early-final"):
        expected = b"no!" if mode.startswith("early-final") else b"ok"
        require(native["bytes"] == len(expected), "upload response byte count")
        require(native["sha256"] == hashlib.sha256(expected).hexdigest(), "upload response digest")
        if mode.startswith("early-final"):
            require(peer["early_final"] and peer["upload_bytes"] < size, "early response before upload EOF")
            require(native["status"] == 413, "early final status")
            if mode == "early-final-blocked":
                require(native["upload_blocked_after_bytes"] > 0 and native["upload_stall_ns"] >= 100_000_000,
                        "early response unblocks stable owned-upload backpressure")
        else:
            require(peer["upload_complete"] and peer["upload_bytes"] == size, "complete upload bytes")
            require(native["source_accepted"] > 0, "owned upload accepted")
            require(native["source_reentries"] > 0, "release callback safely reenters Client API")
        if mode == "upload-backing":
            require(native["credit_preserved"] and native["max_upload_bytes"] == 32768,
                    "whole storage, not payload, uses byte credit")
        if mode in ("upload-empty", "upload-oversize", "upload-overrun"):
            require(native["occupied_preserved"] and native["source_rejected"] > 0,
                    "rejected upload owner preserved")
    elif mode.startswith("redirect"):
        require(native["bytes"] == 2 and native["status"] == 200, "only final redirect response")
        require(peer["requests"] == 2 and peer["intermediate_sent"], "redirect peer count")
        require(native["intermediate_hidden"], "intermediate head withheld")
        require(native["sha256"] == peer["body_sha256"], "final redirect body")
        if mode == "redirect-cross":
            require(peer["authorization_gone"], "cross-origin authorization stripping")
    else:
        require(native["bytes"] == size and native["sha256"] == peer["body_sha256"],
                "independent response count and digest")
        expected = "Decoded_Gzip" if mode.startswith("gzip") else "Wire"
        require(native["delivery"] == expected, "explicit delivery representation")
        if mode in ("known", "chunked", "eof"):
            require(peer["first_chunk_barrier"] and native["first_chunk_barrier"],
                    "chunk delivery before remaining entity exists")
    if mode == "credit":
        require(native["chunk_credit_held"] and native["credit_preserved"] and native["credit_reopened"],
                "take and request release retain credits until final destruction")
    if mode.startswith("late"):
        require(native["late_owner"] and native["credit_preserved"], "late independent owner")
        require(native["retained_after_teardown_bytes"] > 0, "late backing remains charged")


def self_test():
    native = dict(mode="known", tls=False, heap_zero=True, scope_zero=True, fd_zero=True,
                  peak_bytes=65536, baseline_bytes=32768, max_held_chunks=2,
                  max_response_backing=32768, max_upload_bytes=0, source_created=0,
                  source_released=0, ended=True, error_kind="", head_received=True,
                  bytes=3, sha256=hashlib.sha256(b"abc").hexdigest(), delivery="Wire",
                  first_chunk_barrier=True)
    peer = dict(mode="known", tls=False, alpn="", body_sha256=native["sha256"],
                first_chunk_barrier=True)
    validate("known", 3, False, native, peer)
    controls = [dict(sha256="00" * 32), dict(ended=False), dict(heap_zero=False),
                dict(peak_bytes=8 << 20), dict(first_chunk_barrier=False),
                dict(source_created=1), dict(max_held_chunks=3)]
    for change in controls:
        altered = copy.deepcopy(native)
        altered.update(change)
        try:
            validate("known", 3, False, altered, peer)
        except RuntimeError:
            continue
        raise RuntimeError("Oracle accepted corrupt evidence: " + str(change))
    return len(controls)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--odin", type=Path, required=True)
    parser.add_argument("--core-root", type=Path, required=True)
    parser.add_argument("--shared-root", type=Path, required=True)
    parser.add_argument("--go", type=Path, default=Path("/opt/homebrew/bin/go"))
    parser.add_argument("--go-root", type=Path, default=Path("/opt/homebrew/Cellar/go/1.27.3/libexec"))
    parser.add_argument("--sanitizers", nargs="+", choices=("address", "thread"), default=["address", "thread"])
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--final", action="store_true", help="require frozen source and complete selected matrix")
    args = parser.parse_args()
    require(len(set(args.sanitizers)) == len(args.sanitizers), "Duplicate sanitizer selection")
    require(len({name for name, _ in CASES}) == len(CASES), "Duplicate matrix case name")
    compiler, core, shared = (p.resolve() for p in (args.odin, args.core_root, args.shared_root))
    evidence, report = args.evidence_dir.resolve(), args.report.resolve()
    require(not evidence.exists(), "Fresh evidence directory required")
    evidence.mkdir(parents=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    state = {"passed": False, "acceptance": args.final, "scope": "owned Surf104 HTTP1/TLS13 streaming cells; no Mesa or cross-platform claim",
             "cases": [], "commands": [], "oracle_controls": self_test()}
    env = dict(os.environ, ODIN_ROOT=str(core), GOROOT=str(args.go_root), GOTOOLCHAIN="local",
               GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0", GOCACHE=str(evidence / "go-cache"))
    env["PATH"] = "/opt/homebrew/opt/llvm@22/bin:" + env.get("PATH", "")
    for key in list(env):
        if key.startswith(("AWS_", "GOOGLE_", "GCLOUD_", "AZURE_")):
            del env[key]

    def run(label, command, timeout=180):
        command = [str(x) for x in command]
        start = time.monotonic()
        try:
            result = test_run(command, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            log = evidence / (label + ".log")
            log.write_text(stdout + stderr + "\nFIXTURE process timeout\n")
            state["commands"].append(dict(label=label, command=command, returncode=None,
                                          seconds=time.monotonic() - start, log=str(log),
                                          log_sha256=sha(log), error="TimeoutExpired"))
            raise RuntimeError(label + " timed out: " + str(log)) from error
        log = evidence / (label + ".log")
        log.write_text(result.stdout + result.stderr)
        state["commands"].append(dict(label=label, command=command, returncode=result.returncode,
                                      seconds=time.monotonic() - start, log=str(log), log_sha256=sha(log)))
        require(result.returncode == 0, label + " failed: " + str(log))
        require("+++ leak" not in result.stderr and "+++ bad free" not in result.stderr,
                label + " ownership diagnostics")
        return result.stdout

    try:
        state["compiler"] = {"path": str(compiler), "sha256": sha(compiler),
                             "version": run("compiler-version", [compiler, "version"])}
        helper = core / "ci/webtools_consumer_gate.py"
        spec = importlib.util.spec_from_file_location("stream104_closure", helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        physical = evidence / "shared"
        physical.mkdir()
        state["closures"] = {name: copy_closure(gate, name, shared, physical)
                             for name in ("surf/async", "async/connection")}
        initial = files(physical)
        source_map = {str((shared / Path(p).relative_to(physical)).resolve()): digest
                      for p, digest in initial.items()}
        require(all(sha(p) == digest for p, digest in source_map.items()), "physical closure mismatch")
        inputs = dict(source_map)
        for directory in (core / "base", core / "core", core / "vendor"):
            inputs.update(files(directory))
        here = shared / "surf/tests/stream104"
        inputs.update(files(here))
        inputs[str(Path(__file__).resolve())] = sha(__file__)
        inputs[str(helper)] = sha(helper)
        state["input_sha256"] = inputs
        peer = evidence / "peer"
        run("peer-build", [args.go, "build", "-o", peer, here / "peer.go"])
        binaries = {str(peer): sha(peer)}
        state["binaries"] = binaries
        selected = [(name, size) for name, size in CASES
                    if not args.case or any(name == prefix for prefix in args.case)]
        require(selected, "No selected case")
        state["selected_case_names"] = [name for name, _ in selected]
        for sanitizer in args.sanitizers:
            native = evidence / ("native-" + sanitizer)
            run("native-build-" + sanitizer, [compiler, "build", here,
                "-collection:shared=" + str(physical), "-warnings-as-errors", "-vet", "-vet-packages:main", "-thread-count:1",
                "-sanitize:" + sanitizer, "-out:" + str(native)])
            binaries[str(native)] = sha(native)
            for encrypted in (False, True):
                for mode, size in selected:
                    if mode == "redirect-downgrade" and not encrypted:
                        continue
                    if mode.startswith("allocation-") and encrypted:
                        continue
                    label = sanitizer + "-" + ("tls" if encrypted else "tcp") + "-" + mode
                    directory = evidence / label
                    command = [str(peer), "-mode", mode, "-dir", str(directory), "-bytes", str(size)]
                    if encrypted:
                        command.append("-tls")
                    if mode in ("known", "chunked", "eof"):
                        command.append("-first-chunk-barrier")
                    proc = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, start_new_session=True)
                    try:
                        require(select.select([proc.stdout], [], [], 10)[0], label + " peer readiness")
                        endpoint = proc.stdout.readline().strip()
                        require(endpoint.startswith("127.0.0.1:"), label + " owned endpoint")
                        extended_budget = (mode.startswith("gzip") and size >= 4 << 20
                                           and mode != "gzip-amplification") or (mode == "fragmented" and encrypted)
                        native_timeout = 40 if extended_budget else 25
                        text = run(label, [native, endpoint, mode, "tls" if encrypted else "tcp", directory, size], native_timeout)
                        rows = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
                        require(len(rows) == 1, label + " native evidence row")
                        out, err = proc.communicate(timeout=5)
                        (evidence / (label + "-peer.log")).write_text(out + err)
                        require(proc.returncode == 0, label + " peer failed: " + out + err)
                        peer_rows = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
                        require(len(peer_rows) == 1, label + " peer evidence row")
                        validate(mode, size, encrypted, rows[0], peer_rows[0])
                        state["cases"].append(dict(name=label, native=rows[0], peer=peer_rows[0], passed=True))
                    finally:
                        peer_log = evidence / (label + "-peer.log")
                        if proc.poll() is None:
                            os.killpg(proc.pid, signal.SIGTERM)
                            try:
                                out, err = proc.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                os.killpg(proc.pid, signal.SIGKILL)
                                out, err = proc.communicate(timeout=5)
                        else:
                            out, err = proc.communicate(timeout=5)
                        if not peer_log.exists():
                            peer_log.write_text(out + err)
        state["binaries"] = binaries
        require(all(sha(p) == digest for p, digest in binaries.items()), "executable changed")
        state["inputs_unchanged"] = all(Path(p).is_file() and sha(p) == digest for p, digest in inputs.items())
        if args.final:
            require(state["inputs_unchanged"], "Frozen source inputs changed")
        require(files(physical) == initial, "physical closure changed")
        expected = len(args.sanitizers) * sum(1 if name == "redirect-downgrade" or name.startswith("allocation-") else 2 for name, _ in selected)
        require(len(state["cases"]) == expected, "missing native matrix cells")
        expected_names = {sanitizer + "-" + ("tls" if encrypted else "tcp") + "-" + mode
                          for sanitizer in args.sanitizers for encrypted in (False, True)
                          for mode, _ in selected
                          if not (mode == "redirect-downgrade" and not encrypted)
                          and not (mode.startswith("allocation-") and encrypted)}
        require({cell["name"] for cell in state["cases"]} == expected_names,
                "missing or duplicate selected case identity")
        state["expected_cases"] = expected
        state["passed"] = True
    except Exception as error:
        state["failure"] = str(error)
        raise
    finally:
        report.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(json.dumps(dict(passed=True, acceptance=args.final, cases=len(state["cases"]), report=str(report))))


if __name__ == "__main__":
    main()
