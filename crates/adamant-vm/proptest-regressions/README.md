# proptest-regressions

This directory holds **failing-input regression seeds** automatically
written by [proptest] when a property test fails. Each seed records
the exact input that triggered a failure so the test can replay it
deterministically on every subsequent run.

## Policy

**Files in this directory are committed to git.** When a property
test ever fails (in CI or locally), proptest writes a `.txt` file
here containing the failing seed; that file is part of the audit
trail and travels with the repository so any developer or auditor
can replay the failure.

Do **not** add `proptest-regressions/` (or its contents) to
`.gitignore`. The seed-replay-on-clone property is load-bearing for
debugging consensus-critical wire-format failures.

## Reproducibility framing

Three pieces work together to make property-test failures replayable:

1. The `proptest` crate is exact-version-pinned at `1.6.0` in the
   workspace `Cargo.toml`.
2. Each `proptest!` macro invocation pins
   `rng_algorithm = RngAlgorithm::ChaCha` so the random generator
   is deterministic at the algorithm level.
3. Failing seeds are persisted to this directory and committed to
   git so the exact input that triggered a past failure is replayed
   on every run.

If any of the three is missing, the chain breaks: pinned algorithm
without a pinned version means version drift can change behaviour;
pinned version + algorithm without seed persistence means each new
test invocation generates new inputs and a previously-found failure
might not recur for many runs.

[proptest]: https://docs.rs/proptest/1.6.0/proptest/
