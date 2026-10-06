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
# gates of group G-B of plan _docs/plans/heapbits-sqli-cmdi.md (section 10.1),
# writes the Markdown report to stdout, and writes the verdict to
# <outdir>/verdict:
#   PASS        every gate is measured and passes;
#   FAIL        one or more gates fail;
#   INCOMPLETE  no gate fails, but a gate has no complete data, and it is not
#               in RUNTIME_BENCH_OPTIONAL (or a smoke run lowered a minimum,
#               see RUNTIME_BENCH_MIN_PLACEMENTS).
#
# RUNTIME_BENCH_PROFILE selects the gate limits (see PROFILES): "local"
# (default, the darwin/arm64 gates of PR #39) or "ci" (the GitHub runners,
# linux/amd64 and linux/arm64). An unknown profile is an error (exit code 2).
#
# RUNTIME_BENCH_OPTIONAL is a comma-separated list of gate keys (the "Key"
# column of the report) that can be "not measured", or "all" for a partial
# re-measure.
#
# Runtime rows: the gate value is the pooled median of hook - nohook over all
# the code placements, with a 95 % bootstrap interval. A runtime gate needs
# all its cases in at least MIN_PLACEMENTS placements, with the same number of
# runs for hook and nohook in each placement (>= MIN_RUNS). The worst single
# placement is reported, not gated. "woven - unwoven" is pooled hook - plain:
# the cost that a customer sees (it also has the GC cost of the linked
# tracer), not a gate.
#
# The rows of PR #39 that measure its taint store (filter hit, full index,
# MayContain, source admission) do not exist in this tree: they are shown as
# N/A (NOT_APPLICABLE).

import glob
import os
import random
import re
import statistics as st
import sys

LINE = re.compile(r"^Benchmark(\S+?)(?:-\d+)?\s+\d+\s+(.+)$")
PAIR = re.compile(r"([-+\d.eE]+)\s+(\S+)")

MIN_PLACEMENTS = int(os.environ.get("RUNTIME_BENCH_MIN_PLACEMENTS", "") or 8)
# The minimum number of runs for each runtime case, side and placement.
MIN_RUNS = int(os.environ.get("RUNTIME_BENCH_MIN_RUNS", "") or 8)
MIN_HTTP_RUNS = 10
# A smoke run with lower minimums cannot give PASS.
SMOKE = MIN_PLACEMENTS < 8 or MIN_RUNS < 8

CONVERSIONS = ["b2s", "s2b", "r2s", "s2r"]
SHAPES = (
    [f"concat{n}-{m}" for m in ("heap", "stack") for n in (2, 4, 6, 16)]
    + [f"{c}-{m}" for c in CONVERSIONS for m in ("heap", "stack")]
    + ["grow-heap", "growbuf-stack"]
)
# The cases of iast/runtime/bench_test.go.
EXPECTED_RUNTIME = (
    [f"RuntimeOff/{s}" for s in SHAPES]
    + [f"RuntimeClean/{s}" for s in SHAPES]
    + [f"RuntimeCleanNear/{s}" for s in ("s2b-stack", "b2s-stack", "concat2-stack")]
    + [f"RuntimeS2SOff/{c}-{m}" for c in ("s2b", "s2r") for m in ("heap", "stack")]
    + [f"RuntimeTainted/{c}-stack" for c in ["concat2"] + CONVERSIONS]
    + ["RuntimeTainted/grow-heap"]
)

# The exact size class of the one extra allocation of each tainted stack case
# (bench_test.go: "x" + "short-value" is 12 B, "short-bytes" and
# "short runes" are 11 B, []rune("short-value") is 11 x 4 = 44 B). The tainted
# grow-heap case allocates in both builds: no extra allocation.
TAINTED_BYTES = {
    "concat2-stack": 16,
    "b2s-stack": 16,
    "s2b-stack": 16,
    "r2s-stack": 16,
    "s2r-stack": 48,
}

# Rows of PR #39 that measure its taint store: no equivalent here.
NOT_APPLICABLE = [
    ("hit", "Gate on, clean, stack buffer, filter hit"),
    ("full2", "Gate on, clean, 2-operand stack concat, full index"),
    ("maycontain-hit", "`MayContain` filter hit, clean"),
    ("maycontain-random", "`MayContain` clean, random pointers, sparse / typical / full"),
    ("maycontain-miss", "`MayContain` filter miss (any load)"),
    ("admission", "Source-root admission loss (Q9), old - new"),
]

# The gate limits of each profile (the limits of PR #39, section 9.3 of its
# plan runtime-operator-hooks.md). All ns values are the maximum pooled
# hook - nohook.
#   off, off_rune        gate off; off_rune is for r2s and s2r
#   clean_base, clean_operand
#                        gate on, clean, not rune: base + operand x operands
#   clean_rune           gate on, clean, rune conversion
#   tainted, tainted_rune
#                        gate on, tainted (+1 allocation of the exact size)
#   s2s_off              string-to-slice switch off
#   http, http_note      HTTP overhead in %, and the reason of the limit
# RuntimeCleanNear and the grow cases have no limit of PR #39: the grow cases
# use the limits of the other cases of their group, and RuntimeCleanNear is
# reported only.
PROFILES = {
    "local": {
        "title": "darwin/arm64",
        "off": 2.0,
        "off_rune": 2.0,
        "clean_base": 3.0,
        "clean_operand": 1.5,
        "clean_rune": 6.0,
        "tainted": 1000.0,
        "tainted_rune": 1000.0,
        "s2s_off": 2.0,
        "http": 3.70,
        "http_note": "PR #39 Phase 6: +2.70 %, + 1 point",
    },
    # PR #39, user decision after its CI run 36992589970: the worst value of
    # the two GitHub runners, plus a margin.
    "ci": {
        "title": "GitHub runners",
        "off": 8.0,
        "off_rune": 25.0,
        "clean_base": 4.0,
        "clean_operand": 2.0,
        "clean_rune": 25.0,
        "tainted": 1500.0,
        "tainted_rune": 1750.0,
        "s2s_off": 5.0,
        "http": 6.0,
        "http_note": "PR #39 CI run 36992589970: +5.17 %, + margin",
    },
}


def profile():
    """Returns (name, limits) of RUNTIME_BENCH_PROFILE."""
    name = os.environ.get("RUNTIME_BENCH_PROFILE", "") or "local"
    if name not in PROFILES:
        print(f"runtime-bench.py: unknown RUNTIME_BENCH_PROFILE {name!r} (use one of {', '.join(PROFILES)})", file=sys.stderr)
        sys.exit(2)
    return name, PROFILES[name]


def ns(v):
    return f"{v:g} ns"


def us(v):
    return f"{v / 1000:g} us"


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


def runtime_limit(case, g):
    """Returns (limit ns, extra allocations, text) of the case, with the
    limits g of the active profile."""
    group, name = case.split("/", 1)
    if group == "RuntimeOff":
        limit = g["off_rune"] if is_rune(name) else g["off"]
    elif group == "RuntimeS2SOff":
        limit = g["s2s_off"]
    elif group == "RuntimeClean":
        limit = g["clean_rune"] if is_rune(name) else g["clean_base"] + g["clean_operand"] * operands(name)
    elif group == "RuntimeTainted":
        limit = g["tainted_rune"] if is_rune(name) else g["tainted"]
        if name == "grow-heap":
            return limit, 0, f"<= +{us(limit)}, +0 alloc"
        return limit, 1, f"<= +{us(limit)}, +1 alloc"
    elif group == "RuntimeCleanNear":
        # Reported only.
        return None, None, "reported"
    else:
        return None, None, "-"
    return limit, 0, f"<= +{ns(limit)}"


def runtime_rows(out, g):
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
        limit, allocs, text = runtime_limit(case, g)
        name = case.split("/", 1)[1]
        if limit is None:
            ok = None  # reported only
        else:
            ok = delta <= limit and extra_allocs == allocs
            if case.startswith("RuntimeTainted/") and name in TAINTED_BYTES:
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
    profile_name, g = profile()
    optional = {x.strip() for x in os.environ.get("RUNTIME_BENCH_OPTIONAL", "").split(",") if x.strip()}
    lines = []
    p = lines.append

    ks, rows, problems = runtime_rows(out, g)
    control = load(os.path.join(out, "http", "control.txt"))
    iast = load(os.path.join(out, "http", "iast.txt"))

    # (key, title, gate, measured, ok): ok is True, False, None (not
    # measured), "NA" (no equivalent in this tree) or "INFO" (reported only).
    gates = []

    def missing(key, title, gate, why):
        gates.append((key, title, gate, f"not measured: {why}", None))

    def runtime_gate(key, title, gate, selected):
        absent = [c for c in selected if c not in rows]
        if absent:
            missing(key, title, gate, f"`{absent[0]}`: {problems.get(absent[0], 'no data')}")
            return
        worst = max(selected, key=lambda c: rows[c]["delta"] - runtime_limit(c, g)[0])
        r = rows[worst]
        value = f"worst margin: `{worst}` {fmt(r['delta'])} ns (gate {r['text']}), allocs {fmt(r['allocs'], 0)}"
        if worst.startswith("RuntimeTainted/"):
            value += f", {fmt(r['bytes'], 0)} B"
        gates.append((key, title, gate, value, all(rows[c]["ok"] for c in selected)))

    def select(group, test=lambda n: True):
        return [c for c in EXPECTED_RUNTIME if c.startswith(group + "/") and test(c.split("/", 1)[1])]

    off = f"0 extra allocations; <= +{ns(g['off'])} pooled"
    if g["off_rune"] != g["off"]:
        off += f" (rune conversion: <= +{ns(g['off_rune'])})"
    runtime_gate("off", "Gate off, any concat, conversion or grow", off, select("RuntimeOff"))
    clean = f"0 extra allocations; <= +{ns(g['clean_base'])} + {ns(g['clean_operand'])} for each operand"
    runtime_gate(
        "clean-heap",
        "Gate on, clean, escaping (`buf == nil`)",
        clean,
        select("RuntimeClean", lambda n: n.endswith("-heap") and not is_rune(n)),
    )
    runtime_gate(
        "clean-stack",
        "Gate on, clean, stack buffer",
        clean,
        select("RuntimeClean", lambda n: n.endswith("-stack") and not is_rune(n)),
    )
    runtime_gate(
        "tainted",
        "Gate on, tainted (stack buffer, or grow)",
        f"+1 allocation of the exact result size (grow: +0); <= +{us(g['tainted'])}",
        select("RuntimeTainted", lambda n: not is_rune(n)),
    )
    runtime_gate(
        "rune-clean",
        "Gate on, clean, rune conversion, escaping or stack",
        f"0 extra allocations; <= +{ns(g['clean_rune'])}",
        select("RuntimeClean", is_rune),
    )
    runtime_gate(
        "s2s-off",
        "Gate on, `[]byte(s)` / `[]rune(s)`, string-to-slice switch off",
        f"0 extra allocations; <= +{ns(g['s2s_off'])}",
        select("RuntimeS2SOff"),
    )
    runtime_gate(
        "tainted-rune",
        "Gate on, tainted rune conversion",
        f"+1 allocation of the exact result size; <= +{us(g['tainted_rune'])}",
        select("RuntimeTainted", is_rune),
    )

    # RuntimeCleanNear replaces the "filter hit" rows of PR #39: it has no
    # limit, so it is reported.
    near = select("RuntimeCleanNear")
    if all(c in rows for c in near):
        value = "; ".join(f"`{c.split('/', 1)[1]}` {fmt(rows[c]['delta'])} ns, allocs {fmt(rows[c]['allocs'], 0)}" for c in near)
        gates.append(("clean-near", "Gate on, clean operand next to tainted bytes (worst clean case of the bit check)", "reported, no limit", value, "INFO"))
    else:
        absent = next(c for c in near if c not in rows)
        gates.append(("clean-near", "Gate on, clean operand next to tainted bytes", "reported, no limit", f"not measured: `{absent}`: {problems.get(absent, 'no data')}", "INFO"))

    for key, title in NOT_APPLICABLE:
        gates.append((key, title, "-", "measures the taint store of PR #39", "NA"))

    title, gate = "G-A1 HTTP overhead benchmark (sampled out)", f"<= +{g['http']:.2f} % ({g['http_note']})"
    rt = "HTTPRoundTrip"
    if len(control.get(rt, [])) >= MIN_HTTP_RUNS and len(iast.get(rt, [])) >= MIN_HTTP_RUNS:
        c, i = med(control[rt]), med(iast[rt])
        pct = 100 * (i / c - 1)
        text = f"control {c / 1000:.2f} us, IAST {i / 1000:.2f} us: {pct:+.2f} % (n={len(control[rt])})"
        gates.append(("http", title, gate, text, pct <= g["http"]))
    else:
        missing("http", title, gate, f"less than {MIN_HTTP_RUNS} `HTTPRoundTrip` runs for each side")

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
    if failed:
        verdict = "FAIL"
    elif required or SMOKE:
        verdict = "INCOMPLETE"
    else:
        verdict = "PASS"

    p(
        f"## Runtime hooks: group G-B gates, profile `{profile_name}` ({g['title']}) "
        f"({os.environ.get('RUNTIME_BENCH_TAG', '')})"
    )
    p("")
    counts = sorted({r["n"] for r in rows.values()})
    p(
        f"Placements: {len(ks)} ({', '.join(str(int(k)) for k in ks)}); runs for each side and case "
        f"(nohook, hook): {', '.join(f'{a}/{b}' for a, b in counts) or '-'} (interleaved rounds). "
        "Gate value: pooled median of hook - nohook."
    )
    if SMOKE:
        p("")
        p(
            f"**Smoke run:** the minimums were lowered (placements {MIN_PLACEMENTS}, runs {MIN_RUNS}). "
            "The numbers are not a result and the verdict cannot be PASS."
        )
    p("")
    p("| Key | Case | Gate | Measured | Result |")
    p("|---|---|---|---|---|")
    for key, title, gate, value, ok in gates:
        if ok is None:
            result = "optional, not measured" if g_optional(key, optional) else "NOT MEASURED"
        elif ok == "NA":
            result = "N/A"
        elif ok == "INFO":
            result = "reported"
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
        result = "reported" if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
        p(
            f"| {case} | **{fmt(r['delta'])}** [{fmt(r['ci'][0])}, {fmt(r['ci'][1])}] "
            f"| {fmt(r['worst'][0])} ({int(r['worst'][1])}) "
            f"| {fmt(r['range'][0])}..{fmt(r['range'][1])} | {fmt(r['allocs'], 0)} | {fmt(r['bytes'], 0)} "
            f"| {fmt(r['woven'])} | {r['text']} | {result} |"
        )
    p("")
    if failed:
        p("**Verdict: FAIL** (" + ", ".join(g[0] for g in failed) + ")")
    elif required:
        p("**Verdict: INCOMPLETE** (not measured: " + ", ".join(g[0] for g in required) + ")")
    elif SMOKE:
        p("**Verdict: INCOMPLETE** (smoke run)")
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
