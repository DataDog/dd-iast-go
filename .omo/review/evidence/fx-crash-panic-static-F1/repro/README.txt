Independent reproducer for crash-panic-static-F1 (node fx-crash-panic-static-F1).
Module github.com/acme/shop, placed at <private copy>/_repro/f1verify; go.sum copied from iast/integration/testapp.
orchestrion.tool.go = full integration set (same as the dd-iast-go root orchestrion.tool.go).
orchestrion.tool.go127 = same minus iast/encoding/json (the json aspect does not weave on go1.27.0: "dec.r undefined").
Each package's init-time weak crypto call is gated by REPRO=<variant> (os.Getenv), so one binary tests every variant
without changing import graph / init order.
  REPRO=sha1  -> digest: var Fingerprint = sha1.New()... hex...[:8]          (no regexp import)
  REPRO=des   -> legacy: init(){ des.NewCipher }  (no string ops => inits BEFORE internal/config => silently not reported)
  REPRO=des2  -> legacy2: var Probe = des.NewCipher ... hex.EncodeToString(dst)[:8]
  REPRO=early -> example.com/early: md5.Sum in init (inits before config => no crash, no report)
Note: legacy2 was first built WITHOUT the [:8] slice (no crash, inits before config) and then WITH it (crash):
the woven string-slice operator makes the package import iast/propagation -> internal/config, placing it in the window.
