#!/usr/bin/env python3
"""Source/ABI/wiring checks only. Native execution belongs to macOS CI."""
from pathlib import Path
import ctypes
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = "9617d75f476423fdfd33477299c8a1349eb6f375"
OWN = "ac8b411"
checks = 0

def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])

def normalized(data):
    return data.decode("utf-8-sig").replace("\r\n", "\n")

def read(path):
    return normalized((ROOT / path).read_bytes())

HAVE_OWN = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", OWN + "^{commit}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def old(ref, path):
    return normalized(git("show", f"{ref}:{path}"))

def require(value, message):
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)

def function(text, name):
    match = re.search(r"^(?:void|int|bool|char\s*\*|NSString\s*\*)\s*" + re.escape(name) + r"\([^\n]*\)\n\{", text, re.M)
    require(match is not None, f"find definition {name}")
    # All protected functions' braces in comments/strings are balanced or absent.
    start = text.index("{", match.start())
    clean = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', lambda m: " " * len(m.group()), text, flags=re.S)
    depth = 0
    for i in range(start, len(clean)):
        if clean[i] == "{": depth += 1
        elif clean[i] == "}":
            depth -= 1
            if not depth: return text[match.start():i + 1]
    raise AssertionError(f"unclosed function {name}")

paths = git("ls-tree", "-r", "--name-only", BASE, "--", "BaseBin").decode().splitlines()
protected = [p for p in paths if p.startswith(("BaseBin/boomerang/", "BaseBin/jbctl/")) or
    p.startswith("BaseBin/libjailbreak/src/primitives") or
    p in ("BaseBin/launchdhook/src/main.c", "BaseBin/launchdhook/src/main.m", "BaseBin/launchdhook/src/spawn_hook.c") or "stockfix" in p]
require(bool(protected), "protected official inventory exists")
for path in protected:
    require(read(path) == old(BASE, path), f"official bytes: {path}")
roothider = read("BaseBin/launchdhook/src/roothider.m")
base_roothider = old(BASE, "BaseBin/launchdhook/src/roothider.m")
for name in ("roothide_launchd_preinit", "roothide_launchd_postinit", "roothide_launchd_trust_executable",
             "roothide_launchd___posix_spawn_posthook", "trust_tslite_app_bundle",
             "__blacklisted_posix_spawn_orig_wrapper", "roothide_launchd___posix_spawn__spinlock_fix_only"):
    require(function(roothider, name) == function(base_roothider, name), f"official function bytes: {name}")
# Early launchd self-exec / activation / jailbreakd special cases are untouched.
entry = "int roothide_launchd___posix_spawn_prehook("
end = "\t// mitigate spinlock panic for ios15(A12+) devices"
require(roothider[roothider.index(entry):roothider.index(end)] ==
        base_roothider[base_roothider.index(entry):base_roothider.index(end)], "official prehook early guards")
if HAVE_OWN:
    # Local audit: our own prior pure modules are reused byte for byte.
    for suffix in ("c", "h"):
        p = f"BaseBin/launchdhook/src/app_isolation_spawn.{suffix}"
        require(read(p) == old(OWN, p), f"only own prior pure lifecycle reused: {suffix}")
    policy = read("BaseBin/launchdhook/src/app_isolation_policy.c")
    old_policy = old(OWN, "BaseBin/launchdhook/src/app_isolation_policy.c")
    start = "static bool path_is_canonical"
    require(policy[policy.index(start):] == old_policy[old_policy.index(start):], "own environment implementation unchanged")
else:
    # Portable CI audit without the prior local commit: structural equivalence only.
    for suffix in ("c", "h"):
        p = f"BaseBin/launchdhook/src/app_isolation_spawn.{suffix}"
        body = read(p)
        require("app_isolation_spawn(" in body or "struct app_isolation_spawn_ops" in body,
                f"own lifecycle present: {suffix}")
    policy = read("BaseBin/launchdhook/src/app_isolation_policy.c")
    start = "static bool path_is_canonical"
    require(start in policy and "RHIsolationCopyEnvironment" in policy,
            "own environment filter implementation present")
for symbol in ("_configuration", "_wantsInject", "_whitelist", "_zqbb", "zqbb_", "JailFools", "DORuntimeConfiguration", "trollstore_lite_fix_enabled", "spinlock_safe_isolation_enabled"):
    for p in ("BaseBin/libroothider/src/blacklist.m", "BaseBin/libroothider/src/common.h",
              "BaseBin/launchdhook/src/roothider.m", "BaseBin/launchdhook/src/app_isolation_policy.c",
              "BaseBin/launchdhook/src/app_isolation_policy.h", "BaseBin/launchdhook/src/app_isolation_spawn.c",
              "BaseBin/launchdhook/src/app_isolation_spawn.h"):
        require(symbol not in read(p), f"no unrelated layer {symbol} in {p}")
blacklist = read("BaseBin/libroothider/src/blacklist.m")
factory = blacklist[blacklist.index("struct roothide_app_spawn_policy roothide_get_app_spawn_policy"):]
require(factory.count("doimtyCopyRootHideConfig()") == 1, "production factory single config read")
require("return blacklisted.boolValue;" in blacklist, "official boolValue retained")
for requirement in ("CFGetTypeID", "CFBooleanGetTypeID", "CFBooleanGetValue", "lstat(", "S_ISREG", "S_IXUSR", "CFBundleExecutable", "NSUUID"):
    require(requirement in blacklist, f"production qualifier: {requirement}")
require("static NSDictionary" in blacklist and "snapshot" not in blacklist.split("doimtyCopyRootHideConfig(void)", 1)[1].split("static bool", 1)[0], "no retained config snapshot")
for field in ("global_isolation_enabled", "ios15_arm64e", "global_dyld_fix", "launchd_first_load", "verified_main_executable", "isolation_opted_out"):
    require(field in policy and field in roothider, f"strict gate wired: {field}")
require("app_isolation_classify_path(path," in roothider, "production shared classifier used")
require("isolation_spawn_strict((pid_t *)blacklistedPidp" in roothider, "registered PID reaches strict spawn")
require("if(!strictIsolation && ret==0" in roothider, "strict child avoids legacy debug mutation")
info = read("BaseBin/libjailbreak/src/info.h")
require("bool markAppsAsDebugged;" in info and "bool doimtyBlacklistIsolationEnabled;" in info and "double jetsamMultiplier;" in info, "positive bool ABI layout")
require("iterator(ctx, jailbreakSettings.doimtyBlacklistIsolationEnabled);" in info, "new setting serialized")
settings = read("BaseBin/launchdhook/src/jbserver/jbsettings.c")
for symbol in ("__atomic_load_n", "__atomic_store_n", "__ATOMIC_ACQUIRE", "__ATOMIC_RELEASE", "DOIMTY_ISOLATION_SETTING_KEY", "DOIMTY_ISOLATION_SUPPORTED_KEY", "return ENOTSUP"):
    require(symbol in settings, f"backend setting: {symbol}")
class Official(ctypes.Structure):
    _fields_ = [("mark", ctypes.c_bool), ("jetsam", ctypes.c_double)]
class Isolation(ctypes.Structure):
    _fields_ = [("mark", ctypes.c_bool), ("isolation", ctypes.c_bool), ("jetsam", ctypes.c_double)]
require(ctypes.sizeof(Official) == ctypes.sizeof(Isolation) == 16 and Official.jetsam.offset == Isolation.jetsam.offset == 8 and Isolation.isolation.offset == 1, "modeled arm64/mac64 settings padding ABI")
integration = read("tests/app-isolation-integration.m")
for probe in ("roothide_get_app_spawn_policy", "method_exchangeImplementations", "atomic replacement", "helper XPC", "globaloff", "unsupported", "Choicy-only", "extension", "prewarm", "closures", "app_isolation_spawn(&ops"):
    require(probe in integration, f"native coverage probe: {probe}")
require("app_isolation_classify_path(" in integration, "tests use the production shared classifier")
require(".verified_main_executable = p." not in integration, "tests must not hand-fill eligibility")
require("app_isolation_classify_path(" in read("BaseBin/launchdhook/src/app_isolation_classify.m"),
        "shared classifier owns production wiring")
require("mktemp -d" in read("tests/run-app-isolation-A.sh") and 'trap ' in read("tests/run-app-isolation-A.sh"), "native fixture systemtmp cleanup")
print(f"app-isolation-A-static: {checks} checks passed; official protected files/functions byte-identical (Git LF normalization); prior-commit reuse audited={HAVE_OWN}; no native claim")
