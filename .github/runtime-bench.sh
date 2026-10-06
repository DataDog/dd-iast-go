#!/usr/bin/env bash
# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026-present Datadog, Inc.

# The benchmarks of the runtime hooks (gate group G-B of plan
# _docs/plans/heapbits-sqli-cmdi.md, section 10) and the check of their gates.
# A local run and a CI run use the same commands. This is the port of the
# harness of PR #39 (.github/runtime-bench.sh of that tree).
#
# Method:
#   - The hook cost is "hook - nohook". Both binaries are woven test binaries
#     of ./iast/runtime. The nohook binary is built from a copy of the module
#     where iast/runtime/orchestrion.yml has no hook aspect (the 8
#     prepend-statements aspects): the declarations stay, and the heap taint
#     bits (internal/taint/heapbits/orchestrion.yml) stay woven. An unwoven
#     binary is not the reference: the woven binary also links the tracer, and
#     its GC cost is not a hook cost.
#   - The code placement changes a case with a loop by some ns, with the same
#     instructions. Thus each placement k adds a padding function with k
#     stores to the injected runtime declarations (k = 0: no padding). The
#     gate value is the pooled median over all the placements. The worst
#     single placement is reported, not gated.
#   - Each round runs every binary once (a new process: the taint gate is
#     sticky and BenchmarkRuntimeOff needs it off), and the order rotates each
#     round.
#   - "woven - unwoven" (pooled hook - plain) is reported separately: it is
#     the cost that a customer sees, not a gate.
#   - The rows of PR #39 that measure its taint store (filter hit, full
#     index, MayContain, source admission) do not exist here: the report shows
#     them as N/A.
#
# Usage: .github/runtime-bench.sh <command> [args]
#   build [k...]  build the hook and nohook binaries of the placements k
#                 (default: RUNTIME_BENCH_PLACEMENTS)
#   prepare <k> <hook|nohook> <name>
#                 make the source copy of one build in $RUNTIME_BENCH_OUT/<name>,
#                 without the build
#   plain         build the unwoven binary
#   run           run the interleaved rounds of all the binaries of bin/
#   http          run the benchmarks/overhead HTTP round trip, sampled out
#   report        write the Markdown report (stdout) and the gate verdict
#                 (exit 0 only for PASS, or with RUNTIME_BENCH_REPORT_ONLY=1;
#                 see runtime-bench.py)
#   all           build (all placements), plain, run, http, report
#
# Environment:
#   RUNTIME_BENCH_OUT        output directory (default:
#                            ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/runtime-bench)
#   RUNTIME_BENCH_PLACEMENTS placements for "all" (default: 0 1 3 5 7 9 11 13)
#   RUNTIME_BENCH_ROUNDS     rounds of "run" (default: 10)
#   RUNTIME_BENCH_BENCHTIME  -test.benchtime of "run" (default: 300ms)
#   RUNTIME_BENCH_FILTER     -test.bench of "run" (default: ^BenchmarkRuntime),
#                            for a re-measure of some cases only
#   RUNTIME_BENCH_HTTP_COUNT -count of "http" (default: 10)
#   RUNTIME_BENCH_JOBS       parallel builds of "build" (default: 4)
#   RUNTIME_BENCH_OPTIONAL   gate keys that "report" accepts as not measured
#                            (comma-separated, or "all" for a partial run)
#   RUNTIME_BENCH_PROFILE    gate limits of "report": local (default,
#                            darwin/arm64) or ci (GitHub runners)
#   RUNTIME_BENCH_MIN_PLACEMENTS, RUNTIME_BENCH_MIN_RUNS
#                            smoke runs only: lower the minimum number of
#                            placements (8) and of runs (8) of a gate. The
#                            verdict is then INCOMPLETE, never PASS.
#   RUNTIME_BENCH_REPORT_ONLY 1: "report" exits 0 also for FAIL and
#                            INCOMPLETE (the verdict is in the report). An
#                            error of the script is still a failure.
#   ORCHESTRION              the Orchestrion command (default: go tool orchestrion)
#
# Run it from the repository root. RUNTIME_BENCH_OUT must be outside the
# repository. Each woven build has its own GOCACHE:
# Orchestrion v1.13.1 does not put the aspects or the build flags in the
# action IDs of the woven packages. Use only one -gcflags flag
# if you add build flags: Orchestrion keeps only the last one.
set -euo pipefail

COMMAND=${1:?command}
shift

# A string with spaces gives more than one word (for example "go run ...").
read -r -a orchestrion <<<"${ORCHESTRION:-go tool orchestrion}"

root=$(pwd -P)
out=${RUNTIME_BENCH_OUT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/runtime-bench}
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
# The source copies are in $out, and a copy of $root must not contain them.
# The commands remove directories in $out, thus "/" is refused.
if [[ $out == / ]]; then
	echo "RUNTIME_BENCH_OUT must not be /" >&2
	exit 2
fi
case "$out/" in
"$root/"*)
	echo "RUNTIME_BENCH_OUT ($out) must be outside the repository ($root)" >&2
	rmdir "$out" 2>/dev/null || true
	exit 2
	;;
esac
# The commands remove files in these directories: a symbolic link could send
# the removal out of $out. (bin can be a link: the commands only add files to
# it.)
for dir in src gocache runtime http log; do
	if [[ -L $out/$dir ]]; then
		echo "$out/$dir must not be a symbolic link" >&2
		exit 2
	fi
done
placements=${RUNTIME_BENCH_PLACEMENTS:-0 1 3 5 7 9 11 13}
rounds=${RUNTIME_BENCH_ROUNDS:-10}
benchtime=${RUNTIME_BENCH_BENCHTIME:-300ms}
http_count=${RUNTIME_BENCH_HTTP_COUNT:-10}
jobs=${RUNTIME_BENCH_JOBS:-4}
filter=${RUNTIME_BENCH_FILTER:-^BenchmarkRuntime}
tag="$(go env GOVERSION)-$(go env GOOS)-$(go env GOARCH)"
# benchstat is a tool of the module of the overhead benchmarks (no network).
benchstat=(go -C "$root/benchmarks/overhead" tool benchstat)

yaml=iast/runtime/orchestrion.yml
# The first hook aspect. The nohook file stops before this line.
first_hook='  - id: iast-concatstrings'

# source copies the module to $1, without the version control data.
source_copy() {
	local dst=$1
	rm -rf "$dst"
	mkdir -p "$dst"
	tar -C "$root" --exclude=.jj --exclude=.git -cf - . | tar -C "$dst" -xf -
}

# The aspects that nohook removes: the 8 hook aspects, in this order, at the
# end of the file.
hook_ids='iast-concatstrings iast-concatbytes iast-slicebytetostring iast-stringtoslicebyte iast-slicerunetostring iast-stringtoslicerune iast-growslice iast-growsliceBuf'

# nohook removes the hook aspects (prepend-statements) from the yaml file $1.
nohook() {
	local file=$1 ids
	ids=$(awk -v start="$first_hook" '$0 == start {on=1} on && /^  - id: / {printf "%s%s", sep, $3; sep=" "}' "$file")
	if [[ $ids != "$hook_ids" ]]; then
		echo "nohook: the aspects after the first hook aspect are not the 8 hook aspects: $ids" >&2
		exit 1
	fi
	awk -v stop="$first_hook" '$0 == stop {exit} {print}' "$file" >"$file.tmp"
	mv "$file.tmp" "$file"
	if grep -q '^ *- prepend-statements:' "$file" || ! grep -q 'id: iast-runtime-decls' "$file"; then
		echo "nohook: unexpected content in $file" >&2
		exit 1
	fi
}

# pad adds a padding function with $2 stores to the runtime declarations of
# the yaml file $1, before __dd_iast_ok. The runtime text after the padding
# function moves. The data addresses of the benchmark do not change.
pad() {
	local file=$1 stores=$2
	[[ $stores -eq 0 ]] && return 0
	awk -v k="$stores" '
		function block(  i) {
			print "            var __dd_iast_padv [32]uint32"
			print ""
			print "            //go:noinline"
			print "            func __dd_iast_pad() {"
			for (i = 0; i < k; i++) {
				printf "              __dd_iast_padv[%d] = %d\n", i, i + 1
			}
			print "            }"
			print ""
			print "            func init() { __dd_iast_pad() }"
			print ""
			found++
		}
		held != "" {
			if ($0 == "            func __dd_iast_ok() bool {") {
				block()
			}
			print held
			held = ""
		}
		$0 == "            //go:nosplit" { held = $0; next }
		{ print }
		END {
			if (held != "") {
				print held
			}
			if (found != 1) {
				exit 1
			}
		}' "$file" >"$file.tmp" || {
		echo "pad: no single __dd_iast_ok anchor in $file" >&2
		exit 1
	}
	mv "$file.tmp" "$file"
}

# placement_ok is true when $1 is a placement: a number from 0 to 31.
placement_ok() {
	[[ $1 =~ ^[0-9]{1,2}$ ]] && ((10#$1 <= 31))
}

# prepare makes the source copy $3 of placement $1 and variant $2 (hook or
# nohook).
prepare() {
	local k=$1 variant=$2 dst=$3
	source_copy "$dst"
	pad "$dst/$yaml" "$k"
	case $variant in
	hook) ;;
	nohook) nohook "$dst/$yaml" ;;
	*)
		echo "unknown variant $variant" >&2
		exit 2
		;;
	esac
}

# build_one builds the binary bin/<name>.test of one placement and one
# variant (hook or nohook). All the source copies have names of the same
# length.
build_one() {
	local k=$1 variant=$2 name src
	name=$(printf '%s%02d' "${variant:0:1}" "$k")
	src="$out/src/$name"
	prepare "$k" "$variant" "$src"
	mkdir -p "$out/bin" "$out/log"
	echo "build $name (placement $k, $variant)" >&2
	if ! (cd "$src" && GOCACHE="$out/gocache/$tag-$name" "${orchestrion[@]}" go test \
		-c -o "$out/bin/$name.test" ./iast/runtime) >"$out/log/build-$name.log" 2>&1; then
		cat "$out/log/build-$name.log" >&2
		echo "build $name failed" >&2
		return 1
	fi
	# Each GOCACHE is used for one build only, and it is approx. 2 GB.
	rm -rf "$src" "$out/gocache/$tag-$name"
}

# run_bin runs the benchmarks of one binary once, and adds the output to
# runtime/<name>.txt. DD_IAST_REQUIRE_WOVEN is removed: the benchmarks do
# not count bridge entries, so TestMain would fail.
run_bin() {
	local binary=$1 name
	name=$(basename "$binary" .test)
	env -u DD_IAST_REQUIRE_WOVEN "$binary" -test.run='^$' -test.bench="$filter" \
		-test.benchtime="$benchtime" -test.count=1 -test.benchmem >>"$out/runtime/$name.txt"
}

case $COMMAND in
build)
	if [[ $# -gt 0 ]]; then
		ks=("$@")
	else
		read -r -a ks <<<"$placements"
	fi
	# Two builds of one placement use the same paths.
	seen=" "
	for k in "${ks[@]}"; do
		if ! placement_ok "$k" || [[ $seen == *" $((10#$k)) "* ]]; then
			echo "build: placement $k is not a number from 0 to 31, or it is a duplicate" >&2
			exit 2
		fi
		seen+="$((10#$k)) "
	done
	# printf %02d reads 08 as an octal number: use base 10.
	for i in "${!ks[@]}"; do
		ks[i]=$((10#${ks[i]}))
	done
	# The builds run in parallel, $jobs at a time.
	pids=()
	for k in "${ks[@]}"; do
		for variant in hook nohook; do
			build_one "$k" "$variant" &
			pids+=($!)
			if [[ ${#pids[@]} -ge $jobs ]]; then
				wait "${pids[0]}"
				pids=("${pids[@]:1}")
			fi
		done
	done
	for pid in ${pids[@]+"${pids[@]}"}; do
		wait "$pid"
	done
	;;
prepare)
	# The source copy of one build, without the build (for a check of the
	# transforms): prepare <k> <hook|nohook> <name> makes $out/<name>.
	if [[ $# -ne 3 ]] || ! placement_ok "$1" || [[ ! $2 =~ ^(hook|nohook)$ || ! $3 =~ ^[A-Za-z0-9_-]+$ ]]; then
		echo "usage: prepare <k> <hook|nohook> <name> (k: 0 to 31)" >&2
		exit 2
	fi
	prepare "$((10#$1))" "$2" "$out/$3"
	;;
plain)
	mkdir -p "$out/bin"
	go test -c -o "$out/bin/plain.test" ./iast/runtime
	;;
run)
	mkdir -p "$out/runtime"
	binaries=("$out"/bin/*.test)
	count=${#binaries[@]}
	# A new run does not add to the results of an earlier run, and it keeps
	# no result of a binary that was removed.
	rm -f "$out"/runtime/*.txt
	# The zero-allocation check (TestAllocs, gate on and
	# clean, woven stdlib path), and a check that each hook binary is woven.
	: >"$out/runtime/allocs.txt"
	for binary in "${binaries[@]}"; do
		case $(basename "$binary") in
		h*.test)
			if ! DD_IAST_REQUIRE_WOVEN=1 "$binary" -test.run='^TestAllocs$' -test.count=1 \
				>>"$out/runtime/allocs.txt" 2>&1; then
				echo "TestAllocs failed in $binary" >&2
				echo "FAIL $(basename "$binary")" >>"$out/runtime/allocs.txt"
			fi
			;;
		esac
	done
	for ((round = 0; round < rounds; round++)); do
		for ((j = 0; j < count; j++)); do
			run_bin "${binaries[$(((j + round) % count))]}"
		done
		echo "round $((round + 1)) of $rounds" >&2
	done
	;;
http)
	# Gate G-A1: the sampled-out HTTP round trip, thus -sampling=0. The runner
	# records "unknown" as the revision in a jj workspace (no .git).
	mkdir -p "$out/http"
	go -C benchmarks/overhead run ./runner -outputdir="$out/http" -count="$http_count" \
		-benchtime=500ms -cpu=1 -sampling=0 -bench='^BenchmarkHTTPRoundTrip$' >"$out/log-http.txt" 2>&1 || {
		cat "$out/log-http.txt" >&2
		exit 1
	}
	;;
report)
	# The pooled files for benchstat.
	cat "$out"/runtime/h*.txt >"$out/runtime-hook-pooled.txt"
	cat "$out"/runtime/n*.txt >"$out/runtime-nohook-pooled.txt"
	{
		RUNTIME_BENCH_TAG=${RUNTIME_BENCH_TAG:-$tag} python3 .github/runtime-bench.py "$out"
		echo
		echo '<details><summary>benchstat: nohook vs hook, pooled over the placements</summary>'
		echo
		echo '```text'
		"${benchstat[@]}" "nohook=$out/runtime-nohook-pooled.txt" "hook=$out/runtime-hook-pooled.txt"
		echo '```'
		echo
		echo '</details>'
		if [[ -s $out/runtime/plain.txt ]]; then
			echo
			echo '<details><summary>benchstat: unwoven vs woven (hook), pooled</summary>'
			echo
			echo '```text'
			"${benchstat[@]}" "unwoven=$out/runtime/plain.txt" "woven=$out/runtime-hook-pooled.txt"
			echo '```'
			echo
			echo '</details>'
		fi
		if [[ -s $out/http/comparison.txt ]]; then
			echo
			echo '<details><summary>benchstat: HTTP overhead, sampled out</summary>'
			echo
			echo '```text'
			cat "$out/http/comparison.txt"
			echo '```'
			echo
			echo '</details>'
		fi
	} >"$out/report.md"
	cat "$out/report.md"
	# runtime-bench.py writes the verdict file. FAIL and INCOMPLETE are
	# exit 1, but not in report-only mode.
	verdict=$(cat "$out/verdict")
	if [[ ${RUNTIME_BENCH_REPORT_ONLY:-} == 1 ]]; then
		echo "Report only: the verdict $verdict does not fail the command." >&2
		exit 0
	fi
	[[ $verdict == PASS ]]
	;;
all)
	"$0" build
	"$0" plain
	"$0" run
	"$0" http
	"$0" report
	;;
*)
	echo "unknown command $COMMAND" >&2
	exit 2
	;;
esac
