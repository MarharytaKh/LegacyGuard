#!/usr/bin/env bash
# End-to-end demo of LegacyGuard on a throwaway copy of data/.
#   ./scripts/demo.sh             run the demo
#   ./scripts/demo.sh --valgrind  run every command under valgrind
set -u

cd "$(dirname "$0")/.."
BIN=./legacyguard
[ -x "$BIN" ] || { echo "build first: make" >&2; exit 1; }

RUN=()
if [ "${1:-}" = "--valgrind" ]; then
    RUN=(valgrind -q --leak-check=full --error-exitcode=99)
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cp -r data "$WORK/data"
rm -rf "$WORK/data/sandbox" "$WORK/data/legacyguard.log"

FAILED=0
step() {
    local expect=$1; shift
    printf '\n\033[1m$ legacyguard %s\033[0m\n' "$*"
    "${RUN[@]}" "$BIN" -d "$WORK/data" "$@"
    local rc=$?
    if [ "$rc" -ne "$expect" ]; then
        echo ">>> unexpected exit code $rc (expected $expect)" >&2
        FAILED=1
    fi
}

step 0 list
step 2 scan
step 0 patch list
step 0 patch check PATCH-0001
step 0 backport PATCH-0002
step 2 backport PATCH-0003
step 0 patch apply PATCH-0002-BP
step 1 patch apply PATCH-0002-BP
step 0 patch check PATCH-0002-BP
step 0 patch revert PATCH-0002-BP
step 2 patch apply PATCH-0003
step 0 compare 1.2.9 1.2.10
step 0 diag

printf '\n\033[1mLog (%s)\033[0m\n' "data/legacyguard.log"
grep -v DEBUG "$WORK/data/legacyguard.log" | tail -n 12

exit $FAILED
