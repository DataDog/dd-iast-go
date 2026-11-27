# Design: fix staticcheck QF1008 in internal/spans/orchestrion.go

## Decisions

1. **Fix: remove the redundant `.Event` selector on line 33.** Change
   `ann.Event.Vulnerabilities` to `ann.Vulnerabilities`.
   - Reason: `Annotation` embeds `model.Event`, and no other field at the same
     depth is named `Vulnerabilities`. The promoted field is the same field, so
     the change has no effect on behavior.
   - Rejected: `//nolint:staticcheck` comment. It hides a valid finding and adds
     noise, while the real fix is the same size.
2. **Keep lines 35-36 as they are** (`&ann.Event` and `json.Marshal(ann.Event)`).
   - Reason: they use the whole embedded struct. The linter does not flag them,
     and removing `.Event` there would change the meaning (marshal the whole
     `Annotation`, including the mutex and other fields).
3. **Do not add golangci-lint to CI in this change.**
   - Reason: the CI `lint` job runs only gofmt, `checklocks`, and
     `go vet` for `benchmarks/overhead`. Adding golangci-lint needs a config
     file and a decision about which linters to enable for the full repository.
     That is a separate change with a different risk, and it can be merged
     and verified on its own.
4. **No new tests.**
   - Reason: the change does not change behavior. The existing tests in
     `internal/spans` (`annotation_test.go`) cover the package and must still
     pass.
5. **Review: standard Reviewer only. No Adversarial Reviewer.**
   - Reason: one-line change, compile-checked, no behavior change, no public
     API change.

## Proposed change

File: `internal/spans/orchestrion.go`, line 33.

    - ... ann.Event.Vulnerabilities ...
    + ... ann.Vulnerabilities ...

Only this line changes in production code.

## Constraints

- No behavior change.
- Do not change `internal/spans/orchestrion.go` lines 35-36.
- Do not change `internal/spans/orchestrion.yml`. Its rule only injects a
  `//go:linkname` call into `Span.Finish`. It does not touch the body of
  `Finished`.
- PR title in Conventional Commits format, for example:
  `chore(lint): remove redundant embedded field selector in spans`.
- PR description follows `CONTRIBUTING.md` ("Pull requests"): problem,
  approach, tests run.
- Remove this design file from the branch before the PR is marked ready.

## Acceptance criteria

- [ ] `lint`: `golangci-lint run ./internal/spans/...` reports 0 issues
      (golangci-lint v2.15.0 or later, default config, because the repo has
      no `.golangci.*` file).
- [ ] `lint/ci`: `gofmt -l .` prints nothing, and `go tool checklocks ./...`
      passes (same checks as the CI `lint` job).
- [ ] `unit/orchestrion`: `go tool orchestrion go test -shuffle=on ./internal/spans/...`
      passes (same mode as the CI `test` job, `orchestrion` matrix entry).
- [ ] `unit`: `go test ./internal/spans/...` passes.
- [ ] `scope`: the diff of production code is 1 line in
      `internal/spans/orchestrion.go`; lines 35-36 are not changed.
- [ ] `scope`: the final PR does not contain this design file.

## Risks

- **Wrong field resolves after the change.** Low. Go resolves the shallowest
  field. `Vulnerabilities` exists only in `model.Event`. If a future field
  with the same name is added at depth 0, the compiler picks it; that is out
  of scope here, and the build plus tests catch type errors now.
- **Orchestrion weaving conflict.** None found. The weaving rule does not
  touch this function. The `unit/orchestrion` criterion verifies it.

## Out of scope

- Adding golangci-lint (or a `.golangci.*` config) to CI.
- Other lint findings outside `internal/spans`.
