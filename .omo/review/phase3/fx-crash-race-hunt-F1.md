# fx-crash-race-hunt-F1: independent verification of crash-race-hunt-F1

## Verdict per finding
- **crash-race-hunt-F1: CONFIRMED.** The woven `(*http.Request).ParseForm` advice stores `r.Form`/`r.PostForm` on every call. A re-parse of an already-parsed request is read-only in plain Go 1.26.6, and the advice turns it into a racing write. I reproduced it through a woven build of a minimal customer module that enables only the `iast/net/http` integration. That build had no tracer, no IAST startup and no HTTP server, so the race needs no active IAST scope at all.

## Reproduction
My reproducer is a separate module (`evidence/fx-crash-race-hunt-F1/zzrepro/`) that stands in for a customer: `go.mod` with `tool github.com/DataDog/orchestrion` and `replace github.com/DataDog/dd-iast-go => ../`, and an `orchestrion.tool.go` that imports only `iast/net/http`. The test (`repro_test.go`) builds a request with `httptest.NewRequest(POST, "/?q=1", "id=x")` and parses it once. Goroutine A then loops `r.ParseForm()`, while goroutine B loops the plain map reads `r.Form["id"][0] + r.PostForm["id"][0]`. B does not go through any advised accessor. The test also asserts that the map identity is unchanged after the re-parses.

Commands, run in the private copy (`zzrepro` placed at the module root, `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4`):
- Plain control: `go test -race -count=3 -cpu=4,16 -v -run TestFxParseFormReparseRace .` passes 6/6 with `woven=false` and `ok example.com/fxrepro` (`plain_control.out`).
- Woven: `GORACE=halt_on_error=0 /usr/bin/time -l go tool orchestrion go test -race -count=3 -cpu=4,16 -v -run TestFxParseFormReparseRace .` fails with 2 `WARNING: DATA RACE`, one per field (`woven_repro.out`):
  ```
  Write at 0x00c000000450 by goroutine 9:
    net/http.(*Request).ParseForm.func1()   <generated>:4 +0xbc
    runtime.deferreturn()
    example.com/fxrepro.TestFxParseFormReparseRace.func1()  repro_test.go:34
  Previous read at 0x00c000000450 by goroutine 10:
    example.com/fxrepro.TestFxParseFormReparseRace.func2()  repro_test.go:41
  Write at 0x00c000000458 ... ParseForm.func1() <generated>:4 +0xf4   (PostForm)
  --- FAIL: TestFxParseFormReparseRace ... race detected during execution of test
  ```
  The build peaked at 280 MB RSS, well below the 4 GB threshold. The detector reports each address pair only once per process, so only the first iteration fails. The later iterations pass with `woven=true`, and the map identity and values were unchanged in every run.
- I did not re-run the finder's server-based reproducer, which covers IAST enabled and `config.Enabled=false`. Its captured logs (`evidence/crash-race-hunt/logs/woven_parseform_{woven,disabled}.out`) show the same `ParseForm.func1() <generated>:4` write against `FormValue` reads, which matches my trace.

## Reachability
- Mechanism at HEAD 2e23b46: `iast/net/http/orchestrion.yml:152-162` prepends `defer func() { if r != nil { r.Form, r.PostForm = iasthttpbridge.Form(r.Context(), r.Form, r.PostForm) } }()` to `ParseForm`. `httpbridge.Form` (`internal/taint/httpbridge/bridge.go:96-102`) returns the maps unchanged when no callback is registered. `request.ManageForm` (`internal/taint/request/lazy.go:49-57`) also returns them unchanged when there is no analysis, and `manageMap` returns the input when `!changed`. The store happens anyway. In Go 1.26.6, `request.go` `ParseForm` writes only under `r.PostForm == nil` / `r.Form == nil`, so a second call is pure reads. `FormValue` and `PostFormValue` also only read once `Form` is non-nil.
- Trigger: customer code that re-calls `ParseForm` (directly, or through helpers or middleware that call it defensively) while another goroutine of the same request reads `r.Form`, `r.PostForm`, `FormValue` or `PostFormValue`. Plain Go allows this without a race, since read/read is not a race. The race does not depend on configuration. It exists as soon as the net/http integration is woven, including when IAST is disabled, sampled out, or never started. Go 1.26.6 is a supported toolchain.
- Impact: every write stores the identical pointer, so on amd64/arm64 no value is corrupted and the maps do not change. Production behaviour is therefore unchanged in practice. It is still a Go memory-model data race inside a wrapped stdlib call, so a customer's `go test -race` or `-race` canary fails where it passed before instrumentation. That breaks product rule 1 (no behaviour change in wrapped stdlib calls).
- Documentation: the README, `phase1/01-design-intent.md` and `phase1/00-architecture.md` do not document this. The design-intent doc mentions no concurrency limitation for the form advice, so it is not a documented limitation.
- Frequency: the pattern (sharing a `*http.Request` across goroutines and re-parsing) is uncommon but legitimate, and it is the kind of code that `-race` CI exercises.

## Adjusted severity
**High** (finder: Critical). The race is real, it is in production-woven code, and it does not depend on configuration, which by the letter of the scale is Critical. I downgrade it one step because the racing write stores the same pointer value, so no customer-visible value, panic or corruption follows. The concrete damage is new `-race` failures and a formal memory-model violation. Only concurrent re-parse plus read within one request reaches it, and that pattern is uncommon. If the program owner applies the scale literally ("data race in production code"), Critical is defensible. Either way it is a must-fix before shipping.

Duplicates: only one item was under test. The `ParseMultipartForm` advice (`orchestrion.yml:177-186`, which unconditionally stores `r.MultipartForm.Value`; see life-lazy-reader-F1) is the same root-cause pattern at a distinct write site, and one fix pattern covers both.

## Root cause (file:line)
- `iast/net/http/orchestrion.yml:152-162`: an unconditional `{{ $req }}.Form, {{ $req }}.PostForm = iasthttpbridge.Form(...)` in a deferred closure that runs on every `ParseForm` call.
- Sibling: `iast/net/http/orchestrion.yml:177-186` (`MultipartForm.Value = iasthttpbridge.Multipart(...)`).

## Minimal fix
Only write when the call actually parsed something and the bridge actually replaced a map:
```go
__dd_iast_parsed := {{ $req }} != nil && {{ $req }}.Form != nil && {{ $req }}.PostForm != nil
defer func() {
  if {{ $req }} == nil || __dd_iast_parsed { return }   // re-parse: stdlib only read; do not write
  f, pf := iasthttpbridge.Form({{ $req }}.Context(), {{ $req }}.Form, {{ $req }}.PostForm)
  if !sameMap(f, {{ $req }}.Form) { {{ $req }}.Form = f }        // or have Form return changed bools
  if !sameMap(pf, {{ $req }}.PostForm) { {{ $req }}.PostForm = pf }
}()
```
Apply the same entry snapshot to `ParseMultipartForm` (skip when `MultipartForm` was already non-nil at entry). Add the woven `-race` regression from `zzrepro/repro_test.go` to `iast/integration/testapp`.
