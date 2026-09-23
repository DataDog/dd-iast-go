fx-sink-e2e-truepos-F1 evidence (independent reproducers, HEAD 2e23b46, Go 1.26.6)
fx_comment_test.go   -> place in internal/taint/redaction/ (uses package test helpers compositeSnapshot/maskSensitive); output: unit-output.txt
fxrepro/             -> own woven module (go.mod/orchestrion.tool.go wiring copied from sink-e2e-truepos/demoapp; main.go is new);
                        place at <copy>/fxrepro (replace => ../), go.sum from sink-e2e-truepos/demoapp; output: woven-output.txt
fx_comment_verify_test.go, fx-unit-test-output.txt (16:05) predate this run (earlier attempt at the same node id);
                        consistent with the verdict but not relied on.
