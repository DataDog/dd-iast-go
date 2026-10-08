#!/usr/bin/env bash
# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026-present Datadog, Inc.

# Checks of one cell of the woven-runtime CI job (one Go version, runner and
# build mode). The CI job and a local run use the same commands.
#
# Usage: .github/woven-runtime.sh <mode> <check> [outdir]
#   mode   = default | race | nol   (nol is -gcflags=all=-N -l)
#   check  = test | g0 | link | linknames | escape | bench
#   outdir = the directory for the escape and bench output
#            (default: $WOVEN_CACHE_DIR/woven-runtime-out)
#
# Environment:
#   ORCHESTRION     the Orchestrion command (default: go tool orchestrion)
#   WOVEN_CACHE_DIR the directory of the GOCACHE directories
#                   (default: $RUNNER_TEMP, else $TMPDIR, else /tmp)
#   LOADER_GO       the linker loader.go for the linknames check
#                   (default: the file of the current toolchain)
#
# Run it from the repository root.
#
# Build cache: Orchestrion v1.13.1 adds dependency archives (for example
# iobridge for the std io package) that the Go action ID of the dependent
# package does not include, and its tool ID does not include the build flags.
# Thus two woven builds that use different flags must not use the same
# GOCACHE. Each woven build configuration of this script has its own GOCACHE,
# and its name contains the Go version, GOEXPERIMENT and the mode. If you
# change ORCHESTRION locally, also change WOVEN_CACHE_DIR.
#
# Use only one -gcflags flag. Orchestrion keeps only the last value of a
# repeated build flag (internal/goflags/flags.go). A second -gcflags flag gives
# a "fingerprint mismatch" at link time.
set -euo pipefail

MODE=${1:?mode}
CHECK=${2:?check}

# A string with spaces gives more than one word (for example "go run ...").
read -r -a orchestrion <<<"${ORCHESTRION:-go tool orchestrion}"

case $MODE in
default) flags=() ;;
race) flags=(-race) ;;
nol) flags=("-gcflags=all=-N -l") ;;
*)
	echo "unknown mode $MODE" >&2
	exit 2
	;;
esac

# The packages of the woven tests (root module only).
packages=(
	./iast/runtime/...
	./internal/taint/runtimebridge/...
	./internal/taint/store/...
	./internal/taint/propagation/...
)

experiment=$(go env GOEXPERIMENT)
tag="$(go env GOVERSION)-$(go env GOOS)-$(go env GOARCH)-${experiment:-noexp}-$MODE"
cache_root=${WOVEN_CACHE_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}
cache_root=${cache_root%/}
out=${3:-$cache_root/woven-runtime-out}

# woven runs Orchestrion with the GOCACHE of one build configuration. The
# bash 3.2 of macOS refuses "${a[@]}" of an empty array with set -u, thus the
# ${a[@]+...} form.
woven() {
	local cache=$1
	shift
	GOCACHE="$cache_root/gocache-$cache-$tag" "${orchestrion[@]}" "$@"
}

case $CHECK in
test)
	# The link of each test binary is also the link check of the bridge
	# symbols (defined in runtimebridge with a push linkname) and of the
	# self-linkname aliases __dd_iast_orig_<fn> of the runtime.
	woven woven go test ${flags[@]+"${flags[@]}"} -ldflags=-checklinkname=1 \
		-count=1 -shuffle=on "${packages[@]}"
	;;
g0)
	# The system-stack test pulls runtime.systemstack with a test-only
	# linkname. Only this package uses -checklinkname=0: all other packages
	# keep the default link check.
	# A tag that selects no file gives "[no test files]" and exit 0. Thus
	# require the pass line of the test in the output.
	mkdir -p "$out"
	log="$out/g0-$tag.log"
	woven woven go test ${flags[@]+"${flags[@]}"} -tags iast_g0test \
		-ldflags=-checklinkname=0 -count=1 -v -run '^TestSystemStackSkipsHook$' \
		./iast/runtime/internal/g0test 2>&1 | tee "$log"
	if ! grep -q -- '--- PASS: TestSystemStackSkipsHook' "$log"; then
		echo "the system-stack test did not run" >&2
		exit 1
	fi
	;;
link)
	# The link check of each toolchain: build the two fixtures of the
	# runtime-only test application with -checklinkname=1, run them, and
	# find the expected symbols. The fixture module has other aspects, thus
	# it has its own GOCACHE.
	dir=./iast/runtime/testapp
	bin="$out/link-$tag"
	mkdir -p "$bin"
	for fixture in bootstrap nohook; do
		(cd "$dir" && woven testapp go build ${flags[@]+"${flags[@]}"} \
			-ldflags=-checklinkname=1 -o "$bin/$fixture" "./cmd/$fixture")
		"$bin/$fixture" >/dev/null
		go tool nm "$bin/$fixture" >"$bin/$fixture.nm"
	done
	symbols=$(cat "$dir/cmd/bootstrap/symbols.txt")
	symbols+=$'\n'runtime.__dd_iast_concatstrings
	missing=0
	while IFS= read -r symbol; do
		[[ -z "$symbol" ]] && continue
		for fixture in bootstrap nohook; do
			# nohook imports nothing from dd-iast-go: it has only the
			# runtime symbol.
			if [[ $fixture == nohook && $symbol != runtime.* ]]; then
				continue
			fi
			if ! awk -v s="$symbol" '$NF == s {f=1} END {exit !f}' "$bin/$fixture.nm"; then
				echo "link: $fixture has no symbol $symbol" >&2
				missing=1
			fi
		done
	done <<<"$symbols"
	if [[ $missing -ne 0 ]]; then
		exit 1
	fi
	echo "link $tag: bootstrap and nohook link with -checklinkname=1 and run"
	;;
linknames)
	# No hook name (no __dd_iast name, and none of the 6 runtime functions of
	# the aliases) is in the blockedLinknames list of the linker. The mode has no effect on this check.
	loader=${LOADER_GO:-$(go env GOROOT)/src/cmd/link/internal/loader/loader.go}
	block=$(awk '/^var blockedLinknames = map\[string\]\[\]string\{/ {b=1} b {print} b && /^\}/ {exit}' "$loader")
	if [[ $(grep -c '^[[:space:]]*"' <<<"$block" || true) -eq 0 ]]; then
		echo "linknames: no blockedLinknames entries in $loader: the list moved" >&2
		exit 1
	fi
	names='"(__dd_iast[^"]*|runtime\.(concatstrings|concatbytes|slicebytetostring|stringtoslicebyte|slicerunetostring|stringtoslicerune))"'
	if found=$(grep -E -- "$names" <<<"$block"); then
		echo "linknames: blocked hook names in $loader:" >&2
		echo "$found" >&2
		exit 1
	fi
	echo "linknames $(go env GOVERSION): no hook name in blockedLinknames ($(grep -c '^[[:space:]]*"' <<<"$block") entries)"
	;;
escape)
	# The escape comparison (see runtime-escape-compare.sh), with -m and -m=2.
	# Each run
	# builds with -a and has its own GOCACHE.
	for level in m m2; do
		GOCACHE="$cache_root/gocache-escape-$level-$tag" ORCHESTRION="${orchestrion[*]}" \
			.github/runtime-escape-compare.sh "$MODE" "$level" "$out/escape"
	done
	;;
bench)
	# The gate-off benchmark (not a gate: CI runners are
	# noisy). It compares the woven and the unwoven test binary, in turns.
	# The woven binary also links the tracer, so the difference also has a GC
	# cost that is not a hook cost. runtime-bench.sh measures the gate
	# (hook - nohook). The output is Markdown for the job summary.
	dir="$out/bench-$tag"
	mkdir -p "$dir"
	woven woven go test ${flags[@]+"${flags[@]}"} -ldflags=-checklinkname=1 \
		-c -o "$dir/woven.test" ./iast/runtime
	go test ${flags[@]+"${flags[@]}"} -c -o "$dir/plain.test" ./iast/runtime
	: >"$dir/woven.txt"
	: >"$dir/plain.txt"
	for _ in 1 2 3 4 5 6; do
		for binary in woven plain; do
			# The unwoven binary fails with DD_IAST_REQUIRE_WOVEN=1.
			env -u DD_IAST_REQUIRE_WOVEN "$dir/$binary.test" -test.run='^$' \
				-test.bench='^BenchmarkRuntimeOff$' -test.benchtime=100ms \
				-test.benchmem -test.count=1 >>"$dir/$binary.txt"
		done
	done
	echo "## Gate-off benchmark, $tag (not a gate)"
	echo
	echo "Unwoven vs woven test binary of \`./iast/runtime\`, 6 interleaved rounds."
	echo 'The woven binary also links the tracer: the difference is not only the hook cost.'
	echo
	echo '```text'
	go run golang.org/x/perf/cmd/benchstat@v0.0.0-20260929162123-406019bb8b68 \
		"plain=$dir/plain.txt" "woven=$dir/woven.txt"
	echo '```'
	;;
*)
	echo "unknown check $CHECK" >&2
	exit 2
	;;
esac
