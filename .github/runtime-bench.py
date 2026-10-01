# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026-present Datadog, Inc.
#
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
# Run: python3 .github/runtime-bench.py <outdir>
#
# The report of .github/runtime-bench.sh: it compares the results with the
# numeric gates of plan runtime-operator-hooks, section 9.3, writes the
# Markdown report to stdout, and writes the verdict to <outdir>/verdict:
#   PASS        every gate is measured and passes;
#   FAIL        one or more gates fail;
#   INCOMPLETE  no gate fails, but a gate has no complete data, and it is not
#               in RUNTIME_BENCH_OPTIONAL.
#
# RUNTIME_BENCH_OPTIONAL is a comma-separated list of gate keys (the "Key"
# column of the report) that can be "not measured", or "all" for a partial
# re-measure.
#
# Runtime rows: the gate value is the pooled median of hook - nohook over all
# the code placements, with a 95 % bootstrap interval. A runtime gate needs
# all its cases in at least MIN_PLACEMENTS placements, with the same number of
# runs for hook and nohook in each placement (>= MIN_RUNS). The worst single placement is
# reported, not gated. "woven - unwoven" is pooled hook - plain: the cost that
# a customer sees (it also has the GC cost of the linked tracer), not a gate.

import glob
import os
import random
import re
import statistics as st
import sys

LINE = re.compile(r"^Benchmark(\S+?)(?:-\d+)?\s+\d+\s+(.+)$")
PAIR = re.compile(r"([-+\d.eE]+)\s+(\S+)")

MIN_PLACEMENTS = 8
# The minimum number of runs: for each runtime case, side and placement (plan
# section 9.2: 8 runs); for each store and admission row; for each side of
# the HTTP benchmark.
MIN_RUNS = 8
MIN_HTTP_RUNS = 10

CONVERSIONS = ["b2s", "s2b", "r2s", "s2r"]
SHAPES = [f"concat{n}-{m}" for m in ("heap", "stack") for n in (2, 4, 6, 16)] + [
    f"{c}-{m}" for c in CONVERSIONS for m in ("heap", "stack")
]
# The cases of iast/runtime/bench_test.go.
EXPECTED_RUNTIME = (
    [f"RuntimeOff/{s}" for s in SHAPES]
    + [f"RuntimeClean/{s}" for s in SHAPES]
    + [f"RuntimeS2SOff/{c}-{m}" for c in ("s2b", "s2r") for m in ("heap", "stack")]
    + ["RuntimeCleanHit/s2b-stack", "RuntimeCleanHit/concat2-stack"]
    + [f"RuntimeTainted/{c}-stack" for c in ["concat2"] + CONVERSIONS]
)

# The exact size class of the one allocation of each tainted stack case
# (bench_test.go: "x" + "short-value" is 12 B, "short-bytes" and
# "short runes" are 11 B, []rune("short-value") is 11 x 4 = 44 B).
TAINTED_BYTES = {
    "concat2-stack": 16,
    "b2s-stack": 16,
    "s2b-stack": 16,
    "r2s-stack": 16,
    "s2r-stack": 48,
}

LOADS = ["sparse", "typical", "full"]
ADMISSION_APIS = ["TaintString", "TaintBytes", "TaintSourceString", "TaintSourceBytes", "AdoptSourceBytes"]
# The cases of internal/taint/store/admission_bench_test.go.
EXPECTED_ADMISSION = (
    [
        f"SourceAdmission/{w}/{load}/{api}"
        for w in ("params1000", "dense256", "span257")
        for api in ADMISSION_APIS
        for load in ("sparse", "stressed", "saturated")
    ]
    + [f"SourceAdmission/collide/{load}/AdoptSourceBytes" for load in ("sparse", "stressed", "saturated")]
    + ["SourceAdmission/retention/sparse/TaintString"]
)


def load(path):
    """Returns {case: [{unit: value}]} of one benchmark output file."""
    runs = {}
    if not os.path.exists(path):
        return runs
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = LINE.match(line.rstrip("\n"))
            if not m:
                continue
            values = {unit: float(v) for v, unit in PAIR.findall(m.group(2))}
            if "ns/op" in values:
                runs.setdefault(m.group(1), []).append(values)
    return runs


def merge(*loaded):
    out = {}
    for runs in loaded:
        for case, values in runs.items():
            out.setdefault(case, []).extend(values)
    return out


def col(runs, unit):
    return [r[unit] for r in runs if unit in r]


def med(runs, unit="ns/op"):
    values = col(runs, unit)
    return st.median(values) if values else None


def boot(a, b, n=2000):
    """95 % bootstrap interval of median(b) - median(a)."""
    r = random.Random(1)
    d = sorted(
        st.median(r.choices(b, k=len(b))) - st.median(r.choices(a, k=len(a)))
        for _ in range(n)
    )
    return d[int(0.025 * n)], d[int(0.975 * n) - 1]


def fmt(v, digits=2, sign=True):
    if v is None:
        return "-"
    return f"{v:+.{digits}f}" if sign else f"{v:.{digits}f}"


def operands(name):
    m = re.match(r"concat(\d+)-", name)
    return int(m.group(1)) if m else 1


def is_rune(name):
    return name.startswith(("r2s", "s2r"))


def runtime_limit(case):
    """Returns (limit ns, extra allocations, text) of plan section 9.3."""
    group, name = case.split("/", 1)
    if group in ("RuntimeOff", "RuntimeS2SOff"):
        return 2.0, 0, "<= +2 ns"
    if group == "RuntimeClean":
        if is_rune(name):
            return 6.0, 0, "<= +6 ns"
        limit = 3 + 1.5 * operands(name)
        return limit, 0, f"<= +{limit:g} ns"
    if group == "RuntimeCleanHit":
        # Each operand is a clean filter hit: <= +50 ns for each operand.
        limit = 50.0 * operands(name)
        return limit, 0, f"<= +{limit:g} ns"
    if group == "RuntimeTainted":
        return 1000.0, 1, "<= +1 us, +1 alloc"
    return None, None, "-"


def runtime_rows(out):
    """Returns (placements, rows, problems) of the hook - nohook results."""
    files = sorted(glob.glob(os.path.join(out, "runtime", "[hn][0-9][0-9].txt")))
    ks = sorted({os.path.basename(f)[1:3] for f in files})
    hook = {k: load(os.path.join(out, "runtime", f"h{k}.txt")) for k in ks}
    nohook = {k: load(os.path.join(out, "runtime", f"n{k}.txt")) for k in ks}
    plain = load(os.path.join(out, "runtime", "plain.txt"))
    rows, problems = {}, {}
    for case in EXPECTED_RUNTIME:
        paired = [
            k
            for k in ks
            if case in hook[k]
            and case in nohook[k]
            and len(hook[k][case]) == len(nohook[k][case]) >= MIN_RUNS
        ]
        if len(paired) < MIN_PLACEMENTS or len(paired) != len(ks):
            problems[case] = (
                f"{len(paired)} of {len(ks)} placements with the same number of hook and nohook runs, "
                f">= {MIN_RUNS} (need all, and >= {MIN_PLACEMENTS} placements)"
            )
            continue
        a = [x for k in paired for x in col(nohook[k][case], "ns/op")]
        b = [x for k in paired for x in col(hook[k][case], "ns/op")]
        runs_h = [r for k in paired for r in hook[k][case]]
        runs_n = [r for k in paired for r in nohook[k][case]]
        delta = st.median(b) - st.median(a)
        lo, hi = boot(a, b)
        per = [(med(hook[k][case]) - med(nohook[k][case]), k) for k in paired]
        extra_allocs = med(runs_h, "allocs/op") - med(runs_n, "allocs/op")
        extra_bytes = med(runs_h, "B/op") - med(runs_n, "B/op")
        woven = st.median(b) - med(plain[case]) if case in plain else None
        limit, allocs, text = runtime_limit(case)
        ok = delta <= limit and extra_allocs == allocs
        name = case.split("/", 1)[1]
        if case.startswith("RuntimeTainted/"):
            ok = ok and extra_bytes == TAINTED_BYTES[name]
        rows[case] = {
            "delta": delta,
            "ci": (lo, hi),
            "worst": max(per),
            "range": (min(per)[0], max(per)[0]),
            "allocs": extra_allocs,
            "bytes": extra_bytes,
            "woven": woven,
            "text": text,
            "ok": ok,
            "n": (len(a), len(b)),
        }
    return ks, rows, problems


def main():
    out = sys.argv[1]
    optional = {x.strip() for x in os.environ.get("RUNTIME_BENCH_OPTIONAL", "").split(",") if x.strip()}
    lines = []
    p = lines.append

    ks, rows, problems = runtime_rows(out)
    store = load(os.path.join(out, "store", "lookup-new.txt"))
    adm_new = load(os.path.join(out, "store", "admission-new.txt"))
    adm_old = load(os.path.join(out, "store", "admission-old.txt"))
    control = load(os.path.join(out, "http", "control.txt"))
    iast = load(os.path.join(out, "http", "iast.txt"))

    # (key, title, gate, measured, ok): ok is True, False or None (not measured).
    gates = []

    def missing(key, title, gate, why):
        gates.append((key, title, gate, f"not measured: {why}", None))

    def runtime_gate(key, title, gate, selected):
        absent = [c for c in selected if c not in rows]
        if absent:
            missing(key, title, gate, f"`{absent[0]}`: {problems.get(absent[0], 'no data')}")
            return
        worst = max(selected, key=lambda c: rows[c]["delta"] - runtime_limit(c)[0])
        r = rows[worst]
        value = f"worst margin: `{worst}` {fmt(r['delta'])} ns (gate {r['text']}), allocs {fmt(r['allocs'], 0)}"
        if worst.startswith("RuntimeTainted/"):
            value += f", {fmt(r['bytes'], 0)} B"
        gates.append((key, title, gate, value, all(rows[c]["ok"] for c in selected)))

    def store_values(names):
        """Returns [(median ns, name)], or None when a name has less than
        MIN_RUNS runs."""
        if any(len(store.get(n, [])) < MIN_RUNS for n in names):
            return None
        return [(med(store[n]), n) for n in names]

    def zero_allocs(names):
        return all(med(store[n], "allocs/op") == 0 for n in names)

    def select(group, test=lambda n: True):
        return [c for c in EXPECTED_RUNTIME if c.startswith(group + "/") and test(c.split("/", 1)[1])]

    runtime_gate("off", "Gate off, any concat or conversion", "0 extra allocations; <= +2 ns pooled", select("RuntimeOff"))
    runtime_gate(
        "clean-heap",
        "Gate on, clean, escaping (`buf == nil`)",
        "0 extra allocations; <= +3 ns + 1.5 ns for each operand",
        select("RuntimeClean", lambda n: n.endswith("-heap") and not is_rune(n)),
    )
    runtime_gate(
        "clean-stack",
        "Gate on, clean, stack buffer, filter miss",
        "0 extra allocations; <= +3 ns + 1.5 ns for each operand",
        select("RuntimeClean", lambda n: n.endswith("-stack") and not is_rune(n)),
    )

    # A filter hit. The woven case RuntimeCleanHit/s2b-stack (hook - nohook)
    # is the complete gate-on path of one clean operand that is a filter hit
    # (filter check, wrapper, pre-check with Confirm), with one root (sparse).
    # The store benchmark gives the extra cost of the pre-check at a larger
    # load: RuntimePre/<load>/one-clean-hit - RuntimePre/sparse/one-clean-hit,
    # at the worst load. The gate value is the sum.
    def woven_hit(key, title, gate, case, worst_names, sparse_name, limit):
        pre = store_values(worst_names + [sparse_name])
        woven = rows.get(case)
        if pre is None or woven is None:
            missing(key, title, gate, f"`{case}` or `{sparse_name}` and the other loads")
            return
        sparse = dict((n, v) for v, n in pre)[sparse_name]
        v, n = max(x for x in pre if x[1] != sparse_name)
        extra = max(0.0, v - sparse)
        total = woven["delta"] + extra
        gates.append(
            (
                key,
                title,
                gate,
                f"woven `{case}` {woven['delta']:.2f} ns + load (`{n}` - sparse) {extra:.2f} ns = {total:.2f} ns",
                total <= limit and zero_allocs([x for _, x in pre]) and woven["allocs"] == 0,
            )
        )

    woven_hit(
        "hit",
        "Gate on, clean, stack buffer, filter hit",
        "0 extra allocations; <= +50 ns for each operand that hits",
        "RuntimeCleanHit/s2b-stack",
        [f"RuntimePre/{x}/one-clean-hit" for x in LOADS if x != "sparse"],
        "RuntimePre/sparse/one-clean-hit",
        50,
    )
    woven_hit(
        "full2",
        "Gate on, clean, 2-operand stack concat, full index",
        "0 extra allocations; <= +100 ns (both operands can hit)",
        "RuntimeCleanHit/concat2-stack",
        ["RuntimePre/full/concat2-clean-hit", "RuntimePre/full/concat2-clean-random"],
        "RuntimePre/sparse/concat2-clean-hit",
        100,
    )

    runtime_gate(
        "tainted",
        "Gate on, tainted, stack buffer",
        "+1 allocation of the exact result size; <= +1 us",
        select("RuntimeTainted", lambda n: not is_rune(n)),
    )

    title, gate = "`MayContain` filter hit, clean", "<= 45 ns, 0 allocations"
    values = store_values([f"MayContain/clean-neighbor/{x}" for x in LOADS])
    if values is None:
        missing("maycontain-hit", title, gate, "`MayContain/clean-neighbor/*`")
    else:
        v, n = max(values)
        gates.append(("maycontain-hit", title, gate, f"worst `{n}` {v:.2f} ns", v <= 45 and zero_allocs([x for _, x in values])))

    title, gate = "`MayContain` clean, random pointers, sparse / typical / full", "<= 4 / 10 / 45 ns, 0 allocations"
    names = [f"MayContain/clean-random/{x}" for x in LOADS]
    values = store_values(names)
    if values is None:
        missing("maycontain-random", title, gate, "`MayContain/clean-random/*`")
    else:
        ok = all(v <= limit for (v, _), limit in zip(values, (4, 10, 45))) and zero_allocs(names)
        text = "; ".join(
            f"{x} {v:.2f} ns ({med(store[n], 'filter-hit%'):.1f} % hit)" for x, (v, n) in zip(LOADS, values)
        )
        gates.append(("maycontain-random", title, gate, text, ok))

    runtime_gate(
        "rune-clean",
        "Gate on, clean, rune conversion, escaping or stack",
        "0 extra allocations; <= +6 ns",
        select("RuntimeClean", is_rune),
    )
    runtime_gate("s2s-off", "Gate on, `[]byte(s)` / `[]rune(s)`, Q2 switch off", "0 extra allocations; <= +2 ns", select("RuntimeS2SOff"))
    runtime_gate(
        "tainted-rune",
        "Gate on, tainted rune conversion",
        "+1 allocation of the exact result size; <= +1 us",
        select("RuntimeTainted", is_rune),
    )

    # Only filter misses: the clean keys that the filter rejects, at each load.
    title, gate = "`MayContain` filter miss (any load)", "<= 3 ns, 0 allocations"
    names = [f"MayContain/clean-miss/{x}" for x in LOADS]
    values = store_values(names)
    if values is None:
        missing("maycontain-miss", title, gate, "`MayContain/clean-miss/*`")
    else:
        v, n = max(values)
        text = "; ".join(f"{x} {v:.2f} ns" for x, (v, _) in zip(LOADS, values))
        gates.append(("maycontain-miss", title, gate, text, v <= 3 and zero_allocs(names)))

    title, gate = "HTTP overhead benchmark (sampled out)", "<= +3.70 % (Phase 6: +2.70 %, + 1 point)"
    rt = "HTTPRoundTrip"
    if len(control.get(rt, [])) >= MIN_HTTP_RUNS and len(iast.get(rt, [])) >= MIN_HTTP_RUNS:
        c, i = med(control[rt]), med(iast[rt])
        pct = 100 * (i / c - 1)
        text = f"control {c / 1000:.2f} us, IAST {i / 1000:.2f} us: {pct:+.2f} % (n={len(control[rt])})"
        gates.append(("http", title, gate, text, pct <= 3.70))
    else:
        missing("http", title, gate, f"less than {MIN_HTTP_RUNS} `HTTPRoundTrip` runs for each side")

    title, gate = "Source-root admission loss (Q9), old - new", "sparse: 0 points; stressed: <= 1 point"
    adm_rows = []
    absent = [c for c in EXPECTED_ADMISSION if len(adm_new.get(c, [])) < MIN_RUNS or len(adm_old.get(c, [])) < MIN_RUNS]
    if absent:
        side = "old" if not adm_old else "new or old"
        missing(
            "admission",
            title,
            gate,
            f"`{absent[0]}` has less than {MIN_RUNS} {side} runs (old store: RUNTIME_BENCH_OLD_TREE)",
        )
    else:
        ok = True
        worst = {}
        for case in EXPECTED_ADMISSION:
            old, new = med(adm_old[case], "admitted%"), med(adm_new[case], "admitted%")
            if old is None or new is None:
                ok = None
                break
            loss = old - new
            load_name = case.split("/")[2]
            limit = {"sparse": 0.0, "stressed": 1.0}.get(load_name)
            row_ok = limit is None or loss <= limit
            ok = ok and row_ok
            if limit is not None and (load_name not in worst or loss > worst[load_name][0]):
                worst[load_name] = (loss, case)
            adm_rows.append((case, old, new, loss, limit, row_ok))
        if ok is None:
            missing("admission", title, gate, "no admitted% metric")
        else:
            text = "; ".join(f"{k} worst loss {v[0]:+.2f} points (`{v[1]}`)" for k, v in worst.items())
            gates.append(("admission", title, gate, text, ok))

    title, gate = "Zero-allocation check (`TestAllocs`, woven, each hook binary)", "0 allocations, gate on, clean"
    allocs_path = os.path.join(out, "runtime", "allocs.txt")
    if os.path.exists(allocs_path):
        with open(allocs_path, encoding="utf-8") as f:
            text = f.read()
        failed = sum(1 for x in text.splitlines() if x.startswith("FAIL"))
        passed = sum(1 for x in text.splitlines() if x.strip() == "PASS")
        gates.append(("allocs", title, gate, f"{passed} PASS, {failed} FAIL", failed == 0 and passed >= len(ks) > 0))
    else:
        missing("allocs", title, gate, "no `runtime/allocs.txt`")

    failed = [g for g in gates if g[4] is False]
    unmeasured = [g for g in gates if g[4] is None]
    required = [g for g in unmeasured if "all" not in optional and g[0] not in optional]
    verdict = "FAIL" if failed else ("INCOMPLETE" if required else "PASS")

    p(f"## Runtime hooks: plan section 9.3 gates ({os.environ.get('RUNTIME_BENCH_TAG', '')})")
    p("")
    counts = sorted({r["n"] for r in rows.values()})
    p(
        f"Placements: {len(ks)} ({', '.join(str(int(k)) for k in ks)}); runs for each side and case "
        f"(nohook, hook): {', '.join(f'{a}/{b}' for a, b in counts) or '-'} (interleaved rounds). "
        "Gate value: pooled median of hook - nohook."
    )
    p("")
    p("| Key | Case (9.3) | Gate | Measured | Result |")
    p("|---|---|---|---|---|")
    for key, title, gate, value, ok in gates:
        if ok is None:
            result = "optional, not measured" if g_optional(key, optional) else "NOT MEASURED"
        else:
            result = "PASS" if ok else "FAIL"
        p(f"| {key} | {title} | {gate} | {value} | {result} |")
    p("")
    p("### Runtime cases, hook - nohook (ns)")
    p("")
    p("| Case | Pooled [95 % CI] | Worst placement (k) | Range | Allocs | B | Woven - unwoven | Gate | Result |")
    p("|---|---:|---:|---:|---:|---:|---:|---|---|")
    for case in EXPECTED_RUNTIME:
        if case not in rows:
            p(f"| {case} | not measured: {problems[case]} | | | | | | | |")
            continue
        r = rows[case]
        p(
            f"| {case} | **{fmt(r['delta'])}** [{fmt(r['ci'][0])}, {fmt(r['ci'][1])}] "
            f"| {fmt(r['worst'][0])} ({int(r['worst'][1])}) "
            f"| {fmt(r['range'][0])}..{fmt(r['range'][1])} | {fmt(r['allocs'], 0)} | {fmt(r['bytes'], 0)} "
            f"| {fmt(r['woven'])} | {r['text']} | {'PASS' if r['ok'] else 'FAIL'} |"
        )
    if store:
        p("")
        p("### Store, bridge pre-check and sink (new store, median)")
        p("")
        p("| Case | ns/op | filter-hit % | probes/op | allocs/op |")
        p("|---|---:|---:|---:|---:|")
        for case, runs in store.items():
            probes = med(runs, "probes/op")
            if probes is None:
                probes = med(runs, "lookup-probes/op")
            p(
                f"| {case} | {med(runs):.2f} | {fmt(med(runs, 'filter-hit%'), 2, False)} "
                f"| {fmt(probes, 2, False)} | {fmt(med(runs, 'allocs/op'), 0, False)} |"
            )
    if adm_rows:
        p("")
        p("### Source-root admission, admitted % (median)")
        p("")
        p("| Case | Old | New | Loss (points) | Gate | Result |")
        p("|---|---:|---:|---:|---|---|")
        for case, old, new, loss, limit, row_ok in adm_rows:
            gate = "reported" if limit is None else f"<= {limit:g}"
            p(f"| {case} | {old:.2f} | {new:.2f} | {loss:+.2f} | {gate} | {'PASS' if row_ok else 'FAIL'} |")
    elif adm_new:
        p("")
        p("### Source-root admission, admitted % (new store only, median)")
        p("")
        p("| Case | New |")
        p("|---|---:|")
        for case, runs in adm_new.items():
            p(f"| {case} | {fmt(med(runs, 'admitted%'), 2, False)} |")
    p("")
    if failed:
        p("**Verdict: FAIL** (" + ", ".join(g[0] for g in failed) + ")")
    elif required:
        p("**Verdict: INCOMPLETE** (not measured: " + ", ".join(g[0] for g in required) + ")")
    else:
        p("**Verdict: PASS**")
    if unmeasured and not required and not failed:
        p("")
        p("Optional gates that are not measured: " + ", ".join(g[0] for g in unmeasured) + ".")
    print("\n".join(lines))
    with open(os.path.join(out, "verdict"), "w", encoding="utf-8") as f:
        f.write(verdict)


def g_optional(key, optional):
    return "all" in optional or key in optional


if __name__ == "__main__":
    main()
