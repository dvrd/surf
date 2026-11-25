# Plan 003: Test private keys are minted in the process, not stored in git

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: Confirm the two files below still start with
> a PKCS#8 private-key header, and that `load_identity` still reads
> `key.pem`. Do not print the file bodies. Do not copy them into the plan,
> the commit message, or a log.
>
> ```
> git diff --stat 6209fc3..HEAD -- tests/testdata/credentials tests/http3 tests/loopback tests/internal/http3_request_test.odin tests/internal/http3_capacity_test.odin
> ```

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-tls-net-errors.md
- **Category**: security
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

Two tracked files are PKCS#8 private keys: `tests/testdata/credentials/key.pem`
and `tests/http3/rsa2048.pem`. Anyone who clones the repo has the keys that
match the test certificates beside them. Deleting the files later does not
remove them from history. Treat both keys as burned. Tests should mint a
key in memory the way `tests/loopback/cert.odin` `mint_p256` already does,
and the tree should no longer contain a private key.

## Current state

- `tests/testdata/credentials/key.pem` line 1 is a PKCS#8 private key.
  `tests/loopback/tls.odin` `load_identity` reads it and
  `tests/testdata/credentials/leaf.pem`, then takes an Ed25519 seed from the
  key. The comment in `mint_p256` says the core server engine can sign the
  P-256 key and cannot sign the Ed25519 fixture.
- `tests/http3/rsa2048.pem` line 1 is a PKCS#8 private key.
  `tests/internal/http3_request_test.odin:71` and
  `tests/internal/http3_capacity_test.odin` pass
  `#load("../tests/http3/localhost.pem")` and
  `#load("../tests/http3/rsa2048.pem")` to `credentials.create`. The same
  certificate bytes are parsed with `tls.root_pool_parse` as the trust
  anchor. `localhost.pem` is a certificate, not a private key.
- `tests/loopback/cert.odin` `mint_p256` generates a P-256 key in `peer_p256`,
  writes a certificate to `path`, and keeps the key in the process.
  Callers pass DNS names and IP bytes the client will check.
- Other PEM files under `tests/testdata/credentials/` (`leaf.pem`, `root.pem`,
  `wrong-root.pem`) and `tests/http3/localhost.pem` are certificates. Confirm
  each file's first line before deleting anything. A certificate stays if
  and only if some test still needs that exact trust anchor. A private key
  does not stay.
- Plan 001 changes `root_pool_parse(...).kind == .None` to `== nil`. Use the
  post-001 form.

Do not paste PEM contents, key bytes, or seeds into any file you write.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| No private keys tracked | `git grep -l "PRIVATE KEY" -- tests` | prints nothing |
| Suites | `task test` from the repo root | exit 0 |

## Scope

**In scope**

- `tests/loopback/tls.odin`
- `tests/loopback/cert.odin` only if `mint_p256` must learn to return PEM bytes in memory instead of only writing a file
- `tests/internal/http3_request_test.odin`
- `tests/internal/http3_capacity_test.odin`
- `tests/testdata/credentials/key.pem` (delete)
- `tests/http3/rsa2048.pem` (delete)
- A certificate file only when its matching private key was the one you deleted and no remaining test loads that certificate

**Out of scope**

- Generating a replacement key and committing it
- `/Users/kakurega/dev/oss/Odin`
- `src/**` unless a test cannot obtain a credential without a one-line test-only helper. If you believe `src/` must change, STOP.
- Rotating anything outside this repository. Say in the commit body that the two published test keys are burned and must not be trusted. One sentence. No key material.

## Git workflow

- Branch: `advisor/003-test-private-keys`
- Commit subject: `test: mint TLS fixture keys in the process`
- Do not push. Do not commit a new `*.pem` private key. `git grep -l "PRIVATE KEY"` must be empty before you commit.

## Steps

### Step 1: Stop using the Ed25519 file key in loopback

Find every caller of `load_identity`. Point those callers at `mint_p256`
with the DNS name and IP the client already checks (localhost and
`127.0.0.1` unless the caller passes something else).

If a caller needs the Ed25519 path specifically, STOP. The comment on
`mint_p256` says that fixture cannot be signed by the core server engine.
Do not invent a second Ed25519 generator and commit its key.

After the callers are moved, delete `load_identity`'s read of `key.pem` if
nothing else calls it. Delete `tests/testdata/credentials/key.pem`.

Keep `leaf.pem` only if a remaining reader still loads it. If the only
reader was `load_identity`, delete `leaf.pem` too.

**Verify**: `git grep -n "credentials/key.pem" -- tests` prints nothing.
`odin check tests/loopback -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` may not apply if `loopback` is not a standalone package. In that case build one gate that uses it after plan 004, or compile `tests/gates/outcomes` as in plan 004's verify command. A type error in `load_identity`'s old PEM decode is a failure of this step.

### Step 2: Mint the HTTP/3 credential in the test

`credentials.create` currently receives certificate PEM bytes and key PEM
bytes. Replace both `#load`s of `rsa2048.pem` with bytes produced in the
test process.

Use `mint_p256` if `credentials.create` accepts a P-256 PKCS#8 or SEC1 key.
If it accepts only RSA, STOP and report the parameter types. Do not commit
an RSA key to get past that.

The trust anchor passed to `root_pool_parse` must be the certificate just
minted, not the deleted file. Write the certificate to a temp path under
`/tmp` if `root_pool_parse` needs bytes you already have in memory: pass
those bytes. Do not leave the key on disk.

Delete `tests/http3/rsa2048.pem`. Delete `tests/http3/localhost.pem` if no
remaining `#load` or path refers to it.

**Verify**: `git grep -n "rsa2048.pem" -- .` prints nothing.
`git grep -l "PRIVATE KEY" -- tests` prints nothing.

### Step 3: Run the suites

**Verify**: `task test` from the repo root → exit 0.

If an assertion compares a certificate fingerprint, serial, or SPKI to a
constant from the old files, update it to the minted certificate's value
computed in the test. Do not hardcode the new key.

## Test plan

- No new test file. The existing HTTP/3 tests and the loopback callers are
  the regression: they must complete a handshake with the minted key.
- `task test` → exit 0.
- `git grep -l "PRIVATE KEY" -- tests` → no output.

## Done criteria

- [ ] `tests/testdata/credentials/key.pem` and `tests/http3/rsa2048.pem` are deleted
- [ ] `git grep -l "PRIVATE KEY" -- tests src` prints nothing
- [ ] `task test` exits 0
- [ ] No new private-key file is tracked (`git ls-files "*.pem"` lists only certificates; the first line of each remaining PEM is a certificate header, checked by you, not printed into the commit)
- [ ] `plans/README.md` status row updated

## STOP conditions

- `credentials.create` rejects a P-256 key and you would need to commit an RSA key. Report the error. Do not commit a key.
- A test asserts a fixed fingerprint of the old certificate and the expected bytes are not computed from the live cert. Report the test name. Do not paste the old certificate.
- `mint_p256` cannot express the name the client checks. Report the name.
- Plan 001 has not landed and the tests still use `.kind` on `root_pool_parse`. Finish 001 first. Do not reimplement it.

## Maintenance notes

- The published keys remain in git history. Do not reuse them as a trust anchor anywhere.
- A new test that needs a server identity calls `mint_p256` or the same in-memory path. It does not add a PEM.
- Reviewers should look at `git grep -l "PRIVATE KEY"` and at whether the cert written for the client is the one the server signed.
