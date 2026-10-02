#!/usr/bin/env bash
# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026-present Datadog, Inc.

# Escape comparison of the runtime hooks (plan runtime-operator-hooks, sections
# 3.8 and 9.4 item 1). It compiles the runtime with and without the hooks, and
# compares the escape analysis output of the hooked runtime functions and of
# concatstring2..5 and concatbyte2..5. The lines must be identical. A
# difference means that the wrapper calls the runtime function directly (not
# through its alias), and the escape tags of the runtime function changed.
#
# Usage: .github/runtime-escape-compare.sh <mode> <level> <outdir>
#   mode  = default | race | nol   (nol is -gcflags=all=-N -l)
#   level = m | m2                 (-m, or -m=2 written as -m -m)
# Run it from the repository root. It exits 1 when the lines are not identical.
# ORCHESTRION is the Orchestrion command (default: go tool orchestrion).
set -euo pipefail

# A string with spaces gives more than one word (for example "go run ...").
read -r -a orchestrion <<<"${ORCHESTRION:-go tool orchestrion}"

MODE=${1:?mode}
LEVEL=${2:?level}
OUT=${3:?outdir}
mkdir -p "$OUT"

case $LEVEL in
m) M=-m ;;
m2) M="-m -m" ;; # the compiler flag -m=2 is written as -m -m
*) echo "unknown level $LEVEL" >&2; exit 2 ;;
esac
case $MODE in
default) FLAGS=("-gcflags=runtime=$M") ;;
race) FLAGS=(-race "-gcflags=runtime=$M") ;;
# Use only one -gcflags flag. Orchestrion v1.13.1 keeps only the last value of
# a repeated build flag for its child builds (goflags.CommandFlags.Long is a
# map). With two -gcflags flags, the child builds do not use -N -l, and the
# link fails with "fingerprint mismatch". The extract function keeps only the
# runtime/string.go lines, so -m on all packages gives the same result.
nol) FLAGS=("-gcflags=all=-N -l $M") ;;
*) echo "unknown mode $MODE" >&2; exit 2 ;;
esac

TAG="$(go env GOVERSION)-$(go env GOOS)-$(go env GOARCH)-$MODE-$LEVEL"
RT="$(go env GOROOT)/src/runtime/string.go"
FUNCS='concatstrings|concatbytes|concatstring[2-5]|concatbyte[2-5]|slicebytetostring|stringtoslicebyte|slicerunetostring|stringtoslicerune'
ranges=$(awk -v f="^func ($FUNCS)\\\\(" '$0 ~ f {s=NR} s&&/^}/{print s":"NR; s=0}' "$RT" | tr '\n' ' ')
if [[ $(wc -w <<<"$ranges") -ne 14 ]]; then
	echo "expected 14 functions in $RT, got: $ranges" >&2
	exit 1
fi

# extract keeps the lines of string.go positions inside the functions, removes
# the GOROOT prefix and every column (the //line directives of Orchestrion
# have no column), and sorts them.
extract() {
	awk -v R="$ranges" 'BEGIN{n=split(R,a," "); for(i=1;i<=n;i++){split(a[i],b,":"); lo[i]=b[1]; hi[i]=b[2]}}
	/^[^ ]*\/src\/runtime\/string\.go:[0-9]+/ { split($0,p,":"); l=p[2]+0; for(i=1;i<=n;i++) if(l>=lo[i]&&l<=hi[i]){ gsub(/[^ ]*\/src\/runtime\//,""); print; break } }' "$1" |
		sed -E 's/(\.go:[0-9]+):[0-9]+/\1/g' | sort
}

"${orchestrion[@]}" go test -a -c -o /dev/null "${FLAGS[@]}" ./iast/runtime >"$OUT/$TAG.woven.raw" 2>&1
go test -a -c -o /dev/null "${FLAGS[@]}" ./iast/runtime >"$OUT/$TAG.plain.raw" 2>&1
# With default flags, the compiler reports the inlining of __dd_iast_ok. With
# -N -l, there is no inlining, and only the injected declarations of the
# runtime package have <generated> positions (go1.27 adds a directory prefix).
grep -q '__dd_iast_ok' "$OUT/$TAG.woven.raw" ||
	awk '/^# runtime$/ {r=1; next} /^# / {r=0} r && /(^|\/)<generated>:/ {w=1} END {exit !w}' "$OUT/$TAG.woven.raw" || {
	echo "the woven output has no hook wrapper: the runtime is not woven" >&2
	exit 1
}
extract "$OUT/$TAG.woven.raw" >"$OUT/$TAG.woven.full.txt"
extract "$OUT/$TAG.plain.raw" >"$OUT/$TAG.plain.full.txt"
# decisions keeps the escape decisions and the parameter tags. At -m=2 the
# compiler also prints explanations: the flow paths ("flow:", "from ...") and
# the inlining costs. The prepended code changes the inlining costs, and the
# flow paths of concatstring2..5 get one {temp} step more with the same
# derefs. These lines are not decisions, so they are not compared; the full
# diff is in $TAG.full-diff.txt.
decisions() {
	grep -v -e 'flow:' -e '^[^ ]*:[0-9]*:  *from ' -e 'inline .* cost [0-9]' "$1" | sed -E 's/autotmp_[0-9]+/autotmp/g' | sort || true
}
decisions "$OUT/$TAG.woven.full.txt" >"$OUT/$TAG.woven.txt"
decisions "$OUT/$TAG.plain.full.txt" >"$OUT/$TAG.plain.txt"
diff "$OUT/$TAG.plain.full.txt" "$OUT/$TAG.woven.full.txt" >"$OUT/$TAG.full-diff.txt" || true
nw=$(wc -l <"$OUT/$TAG.woven.txt")
np=$(wc -l <"$OUT/$TAG.plain.txt")
if [[ $np -gt 0 ]] && diff "$OUT/$TAG.plain.txt" "$OUT/$TAG.woven.txt" >"$OUT/$TAG.diff.txt"; then
	echo "escape $TAG: identical ($np lines)"
else
	echo "escape $TAG: DIFFERENT (plain $np lines, woven $nw lines, see $OUT/$TAG.diff.txt)"
	exit 1
fi
