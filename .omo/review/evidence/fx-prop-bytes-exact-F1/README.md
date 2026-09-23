# fx-prop-bytes-exact-F1 evidence (independent reproducers)

Replay in a fresh private copy of HEAD 2e23b46:
- `zz_fx_reslice_test.go` -> `internal/taint/propagation/`; run the command in `internal-repro-go1.26.6.txt` (exit 1 = bug).
- `zz_fx_reslice_woven_test.go` -> `iast/io/`; run the command in `woven-repro-go1.26.6.txt` (exit 1 = bug).
- `fix.patch` (bytesAlias len->cap) makes the internal reproducer pass while the existing propagation/store suites stay green (`fix-check-go1.26.6.txt`).
Every case uses a distinct root/key: an earlier identical (pointer,len) key masks the bug, because lookup matches exact keys.
