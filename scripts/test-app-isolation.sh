#!/usr/bin/env bash
# Host-only policy checks. No iOS SDK, spawn, device or jailbreak access is used.
# Run from Git Bash or a POSIX host: bash scripts/test-app-isolation.sh
# CC may be an executable name/path; macOS prefers xcrun's macOS clang.
# APP_ISOLATION_SANITIZERS=1 enables ASan+UBSan elsewhere (0 disables on macOS).
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
host_system="$(uname -s)"

if [[ "$host_system" == Darwin ]] && command -v xcrun >/dev/null 2>&1 &&
    xcrun --sdk macosx --find clang >/dev/null 2>&1; then
    compiler=(xcrun --sdk macosx clang)
else
    compiler=("${CC:-cc}")
fi
if ! command -v "${compiler[0]}" >/dev/null 2>&1; then
    printf 'C compiler unavailable: %s. Set CC to a host C compiler.\n' \
        "${compiler[0]}" >&2
    exit 1
fi

flags=(-std=c11 -Wall -Wextra -Werror -pedantic)
sanitize="${APP_ISOLATION_SANITIZERS:-auto}"
if [[ "$sanitize" != auto && "$sanitize" != 0 && "$sanitize" != 1 ]]; then
    printf 'APP_ISOLATION_SANITIZERS must be auto, 0 or 1.\n' >&2
    exit 1
fi
if [[ "$sanitize" == 1 || ( "$sanitize" == auto && "$host_system" == Darwin ) ]]; then
    flags+=(-g -fno-omit-frame-pointer -fsanitize=address,undefined)
fi

# mktemp gives concurrent workers private artifacts below the requested location.
output_parent="$repo_root/worker/tests"
mkdir -p -- "$output_parent"
output_dir="$(mktemp -d "$output_parent/app-isolation-policy.XXXXXX")"
case "$host_system" in
    MSYS*|MINGW*|CYGWIN*) executable="$output_dir/app-isolation-policy.exe" ;;
    *) executable="$output_dir/app-isolation-policy" ;;
esac

printf 'Compile policy tests using %s\n' "${compiler[*]}"
"${compiler[@]}" "${flags[@]}" \
    "$repo_root/BaseBin/launchdhook/src/app_isolation_policy.c" \
    "$repo_root/tests/app-isolation-policy.c" \
    -o "$executable"
"$executable"

printf 'Compile isolated spawn lifecycle tests\n'
"${compiler[@]}" "${flags[@]}" \
    "$repo_root/BaseBin/launchdhook/src/app_isolation_spawn.c" \
    "$repo_root/tests/app-isolation-spawn.c" -o "$output_dir/app-isolation-spawn"
"$output_dir/app-isolation-spawn"
printf 'Compile environment and patch-range tests\n'
"${compiler[@]}" "${flags[@]}" \
    "$repo_root/BaseBin/launchdhook/src/app_isolation_policy.c" \
    "$repo_root/tests/app-isolation-environment.c" -o "$output_dir/app-isolation-environment"
"$output_dir/app-isolation-environment"
if [[ "$host_system" == Darwin ]]; then
    printf 'Compile real XPC acknowledgment tests\n'
    "${compiler[@]}" "${flags[@]}" \
        "$repo_root/BaseBin/libroothider/src/app_isolation_reply.c" \
        "$repo_root/tests/app-isolation-reply.c" -o "$output_dir/app-isolation-reply"
    "$output_dir/app-isolation-reply"
fi
printf 'Host test artifacts: %s\n' "$output_dir"
