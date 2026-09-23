import json,sys
r=json.load(sys.stdin); d=r["diag_owner"]
print(r["bytes_per_req"], "vulns", r["diag_vulns"], "ev", r["diag_event_json_bytes"], r["diag_span_tag"])
for k,v in sorted(d["stages"].items()): print(k, v["v"], v["values"], v["charged"], {a:b for a,b in v["drops"].items() if b})
print({a:b for a,b in d["owner_drop_counters"].items() if b}, d["owner_values"], d["owner_charged_bytes"])