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
# RUNTIME_BENCH_PROFILE selects the gate limits (see PROFILES): "local"
# (default, the darwin/arm64 gates of plan section 9.3) or "ci" (the GitHub
# runners, linux/amd64 and linux/arm64). An unknown profile is an error (exit
# code 2).
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
# The maximum median drops/op of a hook RuntimeTainted row. A drop is a
# refused adoption: then the row measures the drop path, not the tainted path.
# bench_test.go starts a new request scope often, so that the owner quota
# does not refuse the new roots (runTainted): a hook run has approx. 0.
MAX_TAINTED_DROPS = 0.01
MIN_HTTP_RUNS = 10

CONVERSIONS = ["b2s", "s2b", "r2s", "s2r"]
# The rune conversions with 8 and 1 000 runes, ASCII and multi-byte ("mb").
# With 1 000 runes, the result is always on the heap: no stack case.
RUNE_SHAPES = [
    f"{c}{n}-{m}" for c in ("r2s", "s2r") for n, m in (("8", "heap"), ("8", "stack"), ("8mb", "heap"), ("8mb", "stack"))
] + [f"{c}{n}-heap" for c in ("r2s", "s2r") for n in ("1000", "1000mb")]
SHAPES = (
    [f"concat{n}-{m}" for m in ("heap", "stack") for n in (2, 4, 6, 16)]
    + [f"{c}-{m}" for c in CONVERSIONS for m in ("heap", "stack")]
    + RUNE_SHAPES
)

# The exact size class of the one allocation of each tainted stack case, and
# 0 for a tainted heap case (no extra allocation). bench_test.go: "x" +
# "short-value" is 12 B; the 4, 6 and 16 operand concats are 32, 30 and 32 B;
# "short-bytes" is 11 B; string(runes) allocates the UTF-8 size + 3 B (11 + 3,
# 8 + 3, 22 + 3); []rune("short-value") is 11 x 4 = 44 B; 8 runes are 32 B.
TAINTED_BYTES = {
    "concat2-stack": 16,
    "concat4-stack": 32,
    "concat6-stack": 32,
    "concat16-stack": 32,
    "concat2-heap": 0,
    "b2s-stack": 16,
    "s2b-stack": 16,
    "r2s-stack": 16,
    "s2r-stack": 48,
    "r2s8-stack": 16,
    "r2s8mb-stack": 32,
    "r2s1000-heap": 0,
    "r2s1000mb-heap": 0,
    "s2r8-stack": 32,
    "s2r8mb-stack": 32,
    "s2r1000-heap": 0,
    "s2r1000mb-heap": 0,
}

# The number of runes of each tainted rune case (bench_test.go): "short runes"
# and "short-value" have 11 runes.
TAINTED_RUNES = {
    "r2s-stack": 11,
    "s2r-stack": 11,
    "r2s8-stack": 8,
    "r2s8mb-stack": 8,
    "s2r8-stack": 8,
    "s2r8mb-stack": 8,
    "r2s1000-heap": 1000,
    "r2s1000mb-heap": 1000,
    "s2r1000-heap": 1000,
    "s2r1000mb-heap": 1000,
}

# The cases of iast/runtime/bench_test.go.
EXPECTED_RUNTIME = (
    [f"RuntimeOff/{s}" for s in SHAPES]
    + [f"RuntimeClean/{s}" for s in SHAPES]
    + [f"RuntimeS2SOff/{c}-{m}" for c in ("s2b", "s2r") for m in ("heap", "stack")]
    + ["RuntimeCleanHit/s2b-stack", "RuntimeCleanHit/concat2-stack"]
    + [f"RuntimeTainted/{name}" for name in TAINTED_BYTES]
)

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

# The gate limits of each profile (plan section 9.3). All ns values are the
# maximum pooled hook - nohook, or the maximum median for the store rows.
#   off, off_rune        gate off; off_rune is for r2s and s2r
#   clean_base, clean_operand
#                        gate on, clean, not rune: base + operand x operands
#   clean_rune           gate on, clean, rune conversion
#   hit                  filter hit, for each operand that hits
#   full2                2-operand stack concat, full index
#   tainted_base, tainted_operand
#                        gate on, tainted, not rune: base + operand x each
#                        operand above 2 (+1 allocation of the exact size in
#                        a stack case, 0 in a heap case)
#   tainted_rune_base, tainted_rune_per
#                        gate on, tainted rune conversion: base + per x runes
#   rune1000_rel         gate off and gate on clean, 1 000 runes: the maximum
#                        hook - nohook as a fraction of the nohook median;
#                        None: the time of the rows is record-only (in the
#                        table, with the result REPORTED, but it does not
#                        change the verdict); the 0 extra allocations rule
#                        stays a gate
#   maycontain_hit, maycontain_random (sparse, typical, full), maycontain_miss
#   s2s_off              Q2 switch off
#   http, http_note      HTTP overhead in %, and the reason of the limit
PROFILES = {
    "local": {
        "title": "darwin/arm64",
        "off": 2.0,
        "off_rune": 2.0,
        "clean_base": 3.0,
        "clean_operand": 1.5,
        "clean_rune": 6.0,
        "hit": 50.0,
        "full2": 100.0,
        # User decision after T11.2: the tainted cost scales with the size.
        "tainted_base": 900.0,
        "tainted_operand": 120.0,
        "tainted_rune_base": 1100.0,
        "tainted_rune_per": 4.0,
        "rune1000_rel": 0.01,
        "maycontain_hit": 45.0,
        "maycontain_random": (4.0, 10.0, 45.0),
        "maycontain_miss": 3.0,
        "s2s_off": 2.0,
        "http": 3.70,
        "http_note": "Phase 6: +2.70 %, + 1 point",
    },
    # User decision after CI run 36992589970: the worst value of the two
    # GitHub runners, plus a margin.
    "ci": {
        "title": "GitHub runners",
        "off": 8.0,
        "off_rune": 25.0,
        "clean_base": 4.0,
        "clean_operand": 2.0,
        "clean_rune": 25.0,
        "hit": 100.0,
        "full2": 200.0,
        # User decision after CI run 37750452315: 2 x the local tainted
        # gates.
        "tainted_base": 1800.0,
        "tainted_operand": 240.0,
        "tainted_rune_base": 2200.0,
        "tainted_rune_per": 8.0,
        # User decision after CI run 37750452315: on the GitHub runners, the
        # noise of a 1 000-rune conversion (gate off and clean) is larger
        # than 1 % (up to +322 ns). The time is record-only; the 0 extra
        # allocations rule stays a gate.
        "rune1000_rel": None,
        "maycontain_hit": 45.0,
        "maycontain_random": (5.0, 10.0, 45.0),
        "maycontain_miss": 5.0,
        "s2s_off": 5.0,
        "http": 6.0,
        "http_note": "CI run 36992589970: +5.17 %, + margin",
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


def is_rune1000(name):
    return is_rune(name) and "1000" in name


def runtime_limit(case, g, nohook):
    """Returns (limit ns, extra allocations, text) of the case, with the
    limits g of the active profile. nohook is the pooled nohook median (ns)."""
    group, name = case.split("/", 1)
    if group in ("RuntimeOff", "RuntimeClean") and is_rune1000(name):
        # 1 000 runes: the conversion costs microseconds, and the noise is
        # larger than a fixed ns gate.
        if g["rune1000_rel"] is None:
            return None, 0, "time reported, not gated; 0 extra allocations gated"
        limit = g["rune1000_rel"] * nohook
        return limit, 0, f"<= +{100 * g['rune1000_rel']:g} % of nohook (+{limit:.2f} ns)"
    if group == "RuntimeOff":
        limit = g["off_rune"] if is_rune(name) else g["off"]
    elif group == "RuntimeS2SOff":
        limit = g["s2s_off"]
    elif group == "RuntimeClean":
        limit = g["clean_rune"] if is_rune(name) else g["clean_base"] + g["clean_operand"] * operands(name)
    elif group == "RuntimeCleanHit":
        # Each operand is a clean filter hit.
        limit = g["hit"] * operands(name)
    elif group == "RuntimeTainted":
        if is_rune(name):
            limit = g["tainted_rune_base"] + g["tainted_rune_per"] * TAINTED_RUNES[name]
        else:
            limit = g["tainted_base"] + g["tainted_operand"] * max(0, operands(name) - 2)
        # A heap case already allocates its result: no extra allocation.
        if name.endswith("-heap"):
            return limit, 0, f"<= +{us(limit)}, +0 alloc"
        return limit, 1, f"<= +{us(limit)}, +1 alloc"
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
        limit, allocs, text = runtime_limit(case, g, st.median(a))
        # limit None: the time is record-only, but the allocations are gated.
        ok = extra_allocs == allocs and (limit is None or delta <= limit)
        name = case.split("/", 1)[1]
        dropped = None
        if case.startswith("RuntimeTainted/"):
            ok = ok and extra_bytes == TAINTED_BYTES[name]
            # An old binary (without "drops/op") or a drop path fails.
            drops = med(runs_h, "drops/op")
            if drops is None or drops > MAX_TAINTED_DROPS:
                ok = False
                dropped = "no drops/op" if drops is None else f"drops/op {drops:g} > {MAX_TAINTED_DROPS:g}"
                text += f"; {dropped}"
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
            "limit": limit,
            "dropped": dropped,
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
        # The time of a record-only row (limit None) does not change the
        # gate, but its allocations do.
        gated = [c for c in selected if rows[c]["limit"] is not None]
        bad = [c for c in selected if rows[c]["limit"] is None and not rows[c]["ok"]]
        if not gated:
            if bad:
                value = f"`{bad[0]}`: allocs {fmt(rows[bad[0]]['allocs'], 0)} (gate 0)"
                gates.append((key, title, gate, value, False))
            else:
                gates.append((key, title, gate, "time of all rows is record-only; 0 extra allocations", True))
            return
        worst = max(gated, key=lambda c: rows[c]["delta"] - rows[c]["limit"])
        r = rows[worst]
        value = f"worst margin: `{worst}` {fmt(r['delta'])} ns (gate {r['text']}), allocs {fmt(r['allocs'], 0)}"
        if worst.startswith("RuntimeTainted/"):
            value += f", {fmt(r['bytes'], 0)} B"
        dropped = [c for c in selected if rows[c]["dropped"]]
        if dropped:
            value += f"; drop path: `{dropped[0]}` ({rows[dropped[0]]['dropped']})"
        if bad:
            value += f"; record-only row with extra allocations: `{bad[0]}` (allocs {fmt(rows[bad[0]]['allocs'], 0)})"
        gates.append((key, title, gate, value, not bad and all(rows[c]["ok"] for c in gated)))

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

    off = f"0 extra allocations; <= +{ns(g['off'])} pooled"
    if g["off_rune"] != g["off"]:
        off += f" (rune conversion: <= +{ns(g['off_rune'])})"
    if g["rune1000_rel"] is None:
        rune1000 = "; 1 000 runes: time reported, not gated; 0 extra allocations gated"
    else:
        rune1000 = f"; 1 000 runes: <= +{100 * g['rune1000_rel']:g} % of nohook"
    off += rune1000
    runtime_gate("off", "Gate off, any concat or conversion", off, select("RuntimeOff"))
    clean = f"0 extra allocations; <= +{ns(g['clean_base'])} + {ns(g['clean_operand'])} for each operand"
    runtime_gate(
        "clean-heap",
        "Gate on, clean, escaping (`buf == nil`)",
        clean,
        select("RuntimeClean", lambda n: n.endswith("-heap") and not is_rune(n)),
    )
    runtime_gate(
        "clean-stack",
        "Gate on, clean, stack buffer, filter miss",
        clean,
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
        f"0 extra allocations; <= +{ns(g['hit'])} for each operand that hits",
        "RuntimeCleanHit/s2b-stack",
        [f"RuntimePre/{x}/one-clean-hit" for x in LOADS if x != "sparse"],
        "RuntimePre/sparse/one-clean-hit",
        g["hit"],
    )
    woven_hit(
        "full2",
        "Gate on, clean, 2-operand stack concat, full index",
        f"0 extra allocations; <= +{ns(g['full2'])} (both operands can hit)",
        "RuntimeCleanHit/concat2-stack",
        ["RuntimePre/full/concat2-clean-hit", "RuntimePre/full/concat2-clean-random"],
        "RuntimePre/sparse/concat2-clean-hit",
        g["full2"],
    )

    runtime_gate(
        "tainted",
        "Gate on, tainted, stack buffer",
        f"+1 allocation of the exact result size (stack), +0 (heap); "
        f"<= +{us(g['tainted_base'])} + {ns(g['tainted_operand'])} for each operand above 2",
        select("RuntimeTainted", lambda n: not is_rune(n)),
    )

    title, gate = "`MayContain` filter hit, clean", f"<= {ns(g['maycontain_hit'])}, 0 allocations"
    values = store_values([f"MayContain/clean-neighbor/{x}" for x in LOADS])
    if values is None:
        missing("maycontain-hit", title, gate, "`MayContain/clean-neighbor/*`")
    else:
        v, n = max(values)
        gates.append(("maycontain-hit", title, gate, f"worst `{n}` {v:.2f} ns", v <= g["maycontain_hit"] and zero_allocs([x for _, x in values])))

    title = "`MayContain` clean, random pointers, sparse / typical / full"
    gate = f"<= {' / '.join(f'{v:g}' for v in g['maycontain_random'])} ns, 0 allocations"
    names = [f"MayContain/clean-random/{x}" for x in LOADS]
    values = store_values(names)
    if values is None:
        missing("maycontain-random", title, gate, "`MayContain/clean-random/*`")
    else:
        ok = all(v <= limit for (v, _), limit in zip(values, g["maycontain_random"])) and zero_allocs(names)
        text = "; ".join(
            f"{x} {v:.2f} ns ({med(store[n], 'filter-hit%'):.1f} % hit)" for x, (v, n) in zip(LOADS, values)
        )
        gates.append(("maycontain-random", title, gate, text, ok))

    runtime_gate(
        "rune-clean",
        "Gate on, clean, rune conversion, escaping or stack",
        f"0 extra allocations; <= +{ns(g['clean_rune'])}{rune1000}",
        select("RuntimeClean", is_rune),
    )
    runtime_gate(
        "s2s-off",
        "Gate on, `[]byte(s)` / `[]rune(s)`, Q2 switch off",
        f"0 extra allocations; <= +{ns(g['s2s_off'])}",
        select("RuntimeS2SOff"),
    )
    runtime_gate(
        "tainted-rune",
        "Gate on, tainted rune conversion",
        f"+1 allocation of the exact result size (stack), +0 (heap); "
        f"<= +{us(g['tainted_rune_base'])} + {ns(g['tainted_rune_per'])} for each rune",
        select("RuntimeTainted", is_rune),
    )

    # Only filter misses: the clean keys that the filter rejects, at each load.
    title, gate = "`MayContain` filter miss (any load)", f"<= {ns(g['maycontain_miss'])}, 0 allocations"
    names = [f"MayContain/clean-miss/{x}" for x in LOADS]
    values = store_values(names)
    if values is None:
        missing("maycontain-miss", title, gate, "`MayContain/clean-miss/*`")
    else:
        v, n = max(values)
        text = "; ".join(f"{x} {v:.2f} ns" for x, (v, _) in zip(LOADS, values))
        gates.append(("maycontain-miss", title, gate, text, v <= g["maycontain_miss"] and zero_allocs(names)))

    title, gate = "HTTP overhead benchmark (sampled out)", f"<= +{g['http']:.2f} % ({g['http_note']})"
    rt = "HTTPRoundTrip"
    if len(control.get(rt, [])) >= MIN_HTTP_RUNS and len(iast.get(rt, [])) >= MIN_HTTP_RUNS:
        c, i = med(control[rt]), med(iast[rt])
        pct = 100 * (i / c - 1)
        text = f"control {c / 1000:.2f} us, IAST {i / 1000:.2f} us: {pct:+.2f} % (n={len(control[rt])})"
        gates.append(("http", title, gate, text, pct <= g["http"]))
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

    p(
        f"## Runtime hooks: plan section 9.3 gates, profile `{profile_name}` ({g['title']}) "
        f"({os.environ.get('RUNTIME_BENCH_TAG', '')})"
    )
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
            f"| {fmt(r['woven'])} | {r['text']} | {row_result(r)} |"
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


def row_result(r):
    if r["limit"] is None:
        return "REPORTED" if r["ok"] else "FAIL"
    return "PASS" if r["ok"] else "FAIL"


def g_optional(key, optional):
    return "all" in optional or key in optional


if __name__ == "__main__":
    main()
