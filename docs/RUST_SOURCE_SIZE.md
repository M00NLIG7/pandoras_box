# Rust source-size convention

Pandora treats the largest included hand-authored Rust source file in a source-pinned current stable Tokio release as a hard per-file limit. The committed policy metadata is [`reference/rust-source-size-policy.json`](reference/rust-source-size-policy.json); the deterministic reference inventory is [`reference/tokio-1.53.1-rust-source-lines.tsv`](reference/tokio-1.53.1-rust-source-lines.tsv).

## Pinned reference and measurement

On 2026-08-18, this authenticated lookup identified `tokio-1.53.1` as Tokio's latest non-draft, non-prerelease release:

```sh
gh-axi release list -R tokio-rs/tokio \
  --exclude-drafts --exclude-pre-releases --limit 20
gh-axi api /repos/tokio-rs/tokio/git/ref/tags/tokio-1.53.1
```

The authoritative tag resolves directly to commit `75fef53d0a8590c2d1dbb63672aa7b7d1ef51155`. The measured checkout was acquired through `gh-axi` and detached at that exact commit:

```sh
mkdir -p .reference
(cd .reference && gh-axi repo clone tokio-rs/tokio)
git -C .reference/tokio switch --detach \
  75fef53d0a8590c2d1dbb63672aa7b7d1ef51155
python3 scripts/inventory-tokio-rust-source.py \
  --tokio-checkout .reference/tokio \
  --check docs/reference/tokio-1.53.1-rust-source-lines.tsv
```

The inventory examines all 790 paths returned by `git ls-files '*.rs'` at the pin. A physical line is one LF byte, plus one final line when a non-empty file is not LF-terminated. This byte-based definition is encoding-independent and does not ignore blank or comment lines.

The absolute largest Rust file and the largest included hand-authored source are the same:

| Result | Physical lines | Path | Disposition |
| --- | ---: | --- | --- |
| Absolute maximum | **2699** | `tokio/src/net/windows/named_pipe.rs` | Included |
| Included hand-authored maximum | **2699** | `tokio/src/net/windows/named_pipe.rs` | Included; sets Pandora's hard limit |

The committed TSV has SHA-256 `b25c42461efddda2926129c8103f87885d99d05e29970f0a6451260d8b7c94a5`. The repository check verifies its digest, row count, deterministic ordering, classifications, maxima, and agreement with the metadata.

## Narrow exclusions

Tests, examples, benchmarks, build scripts, fuzz targets, and hand-authored test-support programs remain included. In particular, Pandora applies the 2699-line limit to production code and every Rust test/example.

Only Tokio's exact `tests-build/tests/fail/` and `tests-build/tests/pass/` trees are excluded as fixtures. The evidence is `tests-build/tests/macros.rs`, which passes those files directly to the `trybuild` compile-pass/compile-fail harness. All 11 excluded rows are explicit in the TSV; the largest is only 74 lines and therefore does not affect either maximum.

No other tracked Tokio `.rs` file was excluded at this pin:

- generated source: no generated/“do not edit” header or `linguist-generated` attribute was found;
- vendored source: no vendor tree or `vendored` attribute was found;
- build output: the reference starts from `git ls-files`, so untracked `target` or other build output cannot enter it;
- machine-produced tables: no tracked Rust source identified itself as one;
- lockfiles: they are not `.rs` files and cannot set a Rust source-file convention.

Pandora currently has **no excluded Rust files**. A future exception must name one exact `.rs` path with its category, reason, and reviewable evidence in the policy JSON. Broad path patterns are deliberately unsupported by the normal repository check.

## Pandora inventory and refactor

At the required integration commit `6801c9f2e9ddc9c0ce73a5988b7e4b0efa71ff28`, a whole-repository inventory found exactly two violations:

| Before path | Physical lines |
| --- | ---: |
| `pandoras_box/src/runtime/reporting.rs` | 3155 |
| `pandoras_box/src/runtime/runner.rs` | 3117 |

The refactor preserves the existing module paths and public behavior while assigning cohesive ownership:

- `runtime/reporting/pdf.rs` owns PDF layout, rendering, and byte assembly;
- `runtime/reporting/tests.rs` owns reporting tests;
- `runtime/runner/tests.rs` owns runner mission, credential, transport, cleanup, deadline, and reuse contract tests.

After the split there are no violations. The repository maximum is `pandoras_box/src/runtime/session_executor.rs` at 2354 physical lines; the former violations are 2298 (`reporting.rs`) and 2228 (`runner.rs`). No implementation was minified or moved outside Rust, and no generated/include indirection is used.

## Deterministic check

Run the same no-network check used by CI:

```sh
python3 scripts/check-rust-source-size.py
```

It fails when:

- the policy metadata or pinned TSV is missing, malformed, inconsistent, or has the wrong digest;
- the Tokio pin, tag, measurement, exclusions, maxima, or hard limit metadata is incomplete;
- an included, tracked or non-ignored working-tree `.rs` file exceeds 2699 physical lines; or
- a Pandora exclusion is not an exact existing Rust path with review evidence.

Normal checks never fetch or clone Tokio.

## Validation evidence

Validation was run locally from the isolated branch with Rust 1.94.1 on `aarch64-apple-darwin`; no live-host fixture or release operation was invoked.

- Pinned reference reproduction: `inventory-tokio-rust-source.py --check` passed against the clean detached Tokio commit and reported 790 tracked Rust files, 11 excluded fixtures, and matching absolute/included maxima of 2699.
- Repository enforcement: `check-rust-source-size.py` passed with 65 included Pandora Rust files, zero exclusions, and a 2354-line maximum. Negative checks rejected both a 2700-line Rust file and missing reference metadata.
- Formatting and lint: `cargo fmt --all -- --check` passed; strict locked/offline Clippy passed for the host workspace/all targets and `x86_64-pc-windows-gnu` workspace/all targets.
- Tests: `cargo test --locked --offline --workspace` and `cargo test --locked --offline -p rustrc --doc` passed. Controlled live-lab tests remained explicitly ignored as designed.
- Dependency policy: `cargo audit --no-fetch --stale -D warnings` and `cargo deny --locked --offline check advisories sources` passed.
- Script/workflow checks: `bash -n scripts/*.sh`, `shellcheck scripts/*.sh`, Python syntax/Ruff/Pyright checks, workflow YAML parsing, and `git diff --check` passed.

## Updating the reference

A bound update is an explicit review, not an automated dependency refresh:

1. Use the `gh-axi release list` and tag-ref commands above to identify the current stable release and authoritative commit.
2. Acquire a fresh checkout through `gh-axi repo clone`, detach at the resolved commit, and verify it is clean.
3. Review generated, vendored, build-output, machine-table, lockfile, and fixture evidence. Update only narrowly justified exclusion rules.
4. Update the tag, commit, lookup date, expected file count, and both expected maxima in the policy JSON.
5. Generate a candidate inventory with `inventory-tokio-rust-source.py --output <temporary-path>` and review the complete diff, including every excluded row.
6. Replace the committed TSV, update its SHA-256 and the hard limit in the same change, then run both inventory `--check` and `check-rust-source-size.py`.

This keeps any convention change source-pinned, reproducible, and visible in code review.
