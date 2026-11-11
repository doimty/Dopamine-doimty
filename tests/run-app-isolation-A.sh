#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
if [[ "$(uname -s)" != Darwin ]]; then
    printf '%s\n' 'Native A tests require macOS Foundation; use check-app-isolation-A.py for static checks.'
    exit 2
fi
# All binaries, includes and plist/path fixtures are confined to system tmp.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/doimty-official-A.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/containers" "$WORK/jbroot" "$WORK/include/libjailbreak"
ln -s "$ROOT/BaseBin/libroothider/src" "$WORK/include/libroothider"
ln -s "$ROOT/BaseBin/libjailbreak/src/info.h" "$WORK/include/libjailbreak/info.h"
ln -s "$ROOT/BaseBin/libjailbreak/src/doimty_isolation.h" "$WORK/include/libjailbreak/doimty_isolation.h"
CC="${CC:-$(xcrun --find clang)}"
# An explicit host sysroot keeps the macOS SDK headers visible no matter which
# clang xcrun resolves on the runner.
HOST_SDK="$(xcrun --sdk macosx --show-sdk-path)"
SAN=()
if [[ "${SANITIZE:-0}" == 1 ]]; then SAN=(-fsanitize=address,undefined -fno-omit-frame-pointer); fi
COMMON=(-std=c11 -Wall -Wextra -isysroot "$HOST_SDK" "${SAN[@]}")
"$CC" "${COMMON[@]}" -Werror "$ROOT/tests/app-isolation-spawn.c" \
    "$ROOT/BaseBin/launchdhook/src/app_isolation_spawn.c" -o "$WORK/spawn"
"$WORK/spawn"
"$CC" "${COMMON[@]}" -Werror "$ROOT/tests/app-isolation-environment.c" \
    "$ROOT/BaseBin/launchdhook/src/app_isolation_policy.c" -o "$WORK/environment"
"$WORK/environment"
"$CC" "${COMMON[@]}" -Wno-nullability-completeness -I"$WORK/include" \
    -isysroot "$HOST_SDK" "$ROOT/tests/app-isolation-settings.c" \
    "$ROOT/BaseBin/launchdhook/src/jbserver/jbsettings.c" -o "$WORK/settings"
"$WORK/settings"
"$CC" "${COMMON[@]}" -fobjc-arc -fblocks -Werror -Wno-deprecated-declarations \
    -Wno-nullability-completeness -framework Foundation -isysroot "$HOST_SDK" \
    -I"$ROOT/tests/app-isolation-integration/include" -I"$WORK/include" \
    -I"$ROOT/BaseBin/libjailbreak/src" -I"$ROOT/BaseBin/libroothider/src" \
    -I"$ROOT/BaseBin/launchdhook/src" \
    "-DAPP_PATH_PREFIX=\"$WORK/containers/\"" \
    "$ROOT/tests/app-isolation-integration.m" "$ROOT/BaseBin/libroothider/src/blacklist.m" \
    "$ROOT/BaseBin/launchdhook/src/app_isolation_policy.c" \
    "$ROOT/BaseBin/launchdhook/src/app_isolation_classify.m" \
    "$ROOT/BaseBin/launchdhook/src/app_isolation_spawn.c" -o "$WORK/integration"
"$WORK/integration" "$WORK/jbroot"
printf '%s\n' 'A native tests passed: source factory and adapter only; no device/process operations.'
