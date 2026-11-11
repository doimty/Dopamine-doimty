#!/usr/bin/env python3
"""Portable source guard. No ac8 history, build, device, or REA dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

BASE = "9617d75f476423fdfd33477299c8a1349eb6f375"
REPOSITORY = "https://github.com/roothide/Dopamine-roothide"
FIXTURE = Path(__file__).resolve().parents[1] / "tests/official-baseline.json"
OWN_KEY = "doimtyBlacklistIsolationEnabled"
MUTABLE = {
    ".github/workflows/main.yml", "Application/Makefile",
    "Application/Dopamine/Jailbreak/DOJailbreaker.m",
    "Application/Dopamine/UI/Settings/DOSettingsController.m",
    "BaseBin/jailbreakd/src/main.m", "BaseBin/launchdhook/src/roothider.m",
    "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c",
    "BaseBin/launchdhook/src/jbserver/jbsettings.c",
    "BaseBin/launchdhook/src/jbserver/jbsettings.h", "BaseBin/libjailbreak/src/info.h",
    "BaseBin/libroothider/src/blacklist.m", "BaseBin/libroothider/src/common.h",
    "BaseBin/libroothider/src/dyld_patch.m", "BaseBin/libroothider/src/jailbreakd.c",
    "BaseBin/libroothider/src/jailbreakd.h", "BaseBin/systemhook/Makefile",
}
PRODUCTION_SUFFIXES = {".c", ".h", ".m", ".mm", ".cpp", ".S", ".x"}
BANNED = ("_configuration", "_wantsInject", "_whitelist", "_zqbb", "zqbb_",
          "JailFools", "DORuntimeConfiguration", "trollstore_lite_fix_enabled",
          "spinlock_safe_isolation_enabled", "txm_trust_policy", "update_target")
ROOTHIDER = "BaseBin/launchdhook/src/roothider.m"
DYLD = "BaseBin/libroothider/src/dyld_patch.m"
INFO = "BaseBin/libjailbreak/src/info.h"
DOJ = "Application/Dopamine/Jailbreak/DOJailbreaker.m"
ROOTHIDER_FUNCTIONS = (
    "roothide_launchd_preinit", "roothide_launchd_postinit",
    "roothide_launchd_trust_executable", "roothide_launchd___posix_spawn_posthook",
    "trust_tslite_app_bundle", "__blacklisted_posix_spawn_orig_wrapper",
    "roothide_launchd___posix_spawn__spinlock_fix_only",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def text(data):
    return data.decode("utf-8-sig").replace("\r\n", "\n")


def source_digest(data):
    try:
        if b"\0" not in data:
            return digest(text(data).encode("utf-8")), "git-lf-utf8"
    except UnicodeDecodeError:
        pass
    return digest(data), "bytes"


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments], timeout=60)


def clean_code(value):
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: " " * len(m.group()), value, flags=re.S)


def block(value, start):
    clean = clean_code(value)
    opening = clean.index("{", start)
    depth = 0
    for index in range(opening, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                return value[start:index + 1]
    raise ValueError("unterminated source block")


def function(value, name):
    pattern = r"^(?:static\s+)?(?:void|int|bool|char\s*\*|NSString\s*\*)\s*" + re.escape(name) + r"\([^;]*?\)\s*\{"
    matches = list(re.finditer(pattern, value, re.M))
    require(len(matches) == 1, "unique C function required: " + name)
    return block(value, matches[0].start())


def objc_methods(value):
    result = {}
    for match in re.finditer(r"^[-+]\s*\([^\n)]*\)\s*([A-Za-z_]\w*)[^;\n]*\n\{", value, re.M):
        name = match.group(1)
        result.setdefault(name, []).append(block(value, match.start()))
    return result


def read_source(root, path):
    target = root / path
    require(target.exists() and target.is_file() and not target.is_symlink(), "regular source required: " + path)
    return text(target.read_bytes())


def info_without_own(value, fixture):
    value = re.sub(r"\t\t// Own isolation V1;[^\n]*\n\t\t// Zero initialization[^\n]*\n", "", value)
    require(value.count("\t\tbool doimtyBlacklistIsolationEnabled;\n") == 1, "one own bool field")
    value = value.replace("\t\tbool doimtyBlacklistIsolationEnabled;\n", "")
    require(value.count("\titerator(ctx, jailbreakSettings.doimtyBlacklistIsolationEnabled); \\\n") == 1, "one own serialized field")
    value = value.replace("\titerator(ctx, jailbreakSettings.doimtyBlacklistIsolationEnabled); \\\n", "")
    start = value.index("// Only the own isolation field uses atomic access.")
    end = value.index("#define kconstant", start)
    region = value[start:end]
    require("__atomic_load_n" in region and "__atomic_store_n" in region and
            "__ATOMIC_ACQUIRE" in region and "__ATOMIC_RELEASE" in region,
            "own serialization must use atomic access")
    require("&gSystemInfo.jailbreakSettings.doimtyBlacklistIsolationEnabled" in region,
            "atomic access must target fixed own bool, not all generic types")
    return value[:start] + fixture["info_serialization"] + value[end:]


def generate(root, destination):
    entries = git(root, "ls-tree", "-rz", BASE).split(b"\0")
    rows = []
    for entry in entries:
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        rows.append((path.decode(), mode, kind, oid))
    files, submodules, contents = {}, {}, {}
    process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for path, mode, kind, oid in rows:
            if kind == "commit":
                submodules[path] = oid
                continue
            require(kind == "blob", "unexpected baseline object")
            process.stdin.write((oid + "\n").encode()); process.stdin.flush()
            header = process.stdout.readline().decode().split()
            require(len(header) == 3 and header[1] == "blob", "baseline blob missing")
            size = int(header[2]); require(size < 128 * 1024 * 1024, "oversized baseline blob")
            data = process.stdout.read(size)
            require(len(data) == size and process.stdout.read(1) == b"\n", "short baseline read")
            sha, normalization = source_digest(data)
            files[path] = {"sha256": sha, "raw_sha256": digest(data), "bytes": size,
                           "normalization": normalization, "git_mode": mode}
            if path in (ROOTHIDER, DYLD, INFO, DOJ, "BaseBin/systemhook/Makefile", "Application/Makefile"):
                contents[path] = text(data)
    finally:
        process.stdin.close(); process.stdout.close()
        require(process.wait(timeout=10) == 0, "git cat-file failed")
    roothider = contents[ROOTHIDER]
    entry = "int roothide_launchd___posix_spawn_prehook("
    end = "\t// mitigate spinlock panic for ios15(A12+) devices"
    info = contents[INFO]
    manifest = {
        "schema_version": 1, "baseline_commit": BASE, "baseline_repository": REPOSITORY,
        "normalization": "UTF-8 source is compared after BOM/CRLF to Git-LF normalization; binary bytes remain exact",
        "files": files, "submodules": submodules,
        "roothider_functions": {name: digest(function(roothider, name).encode()) for name in ROOTHIDER_FUNCTIONS},
        "roothider_early_sha256": digest(roothider[roothider.index(entry):roothider.index(end)].encode()),
        "dyld_legacy_sha256": digest(contents[DYLD].encode()),
        "dyld_legacy_text": contents[DYLD],
        "doj_methods": {name: [digest(body.encode()) for body in bodies]
                        for name, bodies in objc_methods(contents[DOJ]).items() if name != "runWithError"},
        "info_serialization": info[info.index("#define SYSTEM_INFO_SERIALIZE_COMPONENT"):info.index("#define kconstant")],
        "systemhook_makefile": contents["BaseBin/systemhook/Makefile"],
        "application_makefile": contents["Application/Makefile"],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("generated", len(files), "official blobs and", len(submodules), "submodule identities from", BASE)


def verify(root, variant, fixture_path=FIXTURE, source_commit=None, workflow_commit=None, require_clean=False):
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    require(fixture["schema_version"] == 1 and fixture["baseline_commit"] == BASE,
            "wrong official baseline fixture")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    require(not source_commit or source_commit == commit, "SOURCE_COMMIT does not match source checkout")
    if variant == "control":
        require(commit == BASE, "control must build fixed official commit")
    dirty = bool(git(root, "status", "--porcelain", "--untracked-files=no").strip())
    require(not require_clean or not dirty, "tracked source differs from selected checkout")
    checked = 0
    for path, expected in fixture["files"].items():
        mutable = path in MUTABLE or (path.endswith(".strings") and path.startswith("Application/"))
        if variant == "isolation" and mutable:
            continue
        target = root / path
        require(target.exists() or target.is_symlink(), "official file missing: " + path)
        data = os.readlink(target).encode() if target.is_symlink() else target.read_bytes()
        sha = source_digest(data)[0] if expected["normalization"] == "git-lf-utf8" else digest(data)
        require(sha == expected["sha256"], "official bytes changed: " + path)
        checked += 1
    for path, expected in fixture["submodules"].items():
        target = root / path
        # Uninitialized gitlinks are accepted in local source-only audits. CI checks recursive checkout.
        if (target / ".git").exists():
            require(git(target, "rev-parse", "HEAD").decode().strip() == expected, "submodule changed: " + path)
    for parent in ("BaseBin", "Application", "tests", "scripts"):
        for target in (root / parent).rglob("*"):
            if not target.is_file() or target.is_symlink() or any(part in (".git", ".theos", "build", ".build", ".include") for part in target.parts):
                continue
            relative = target.relative_to(root).as_posix()
            name = target.name.lower()
            require(not any(word in name for word in ("jailfools", "doruntimeconfiguration", "txm_trust", "update_target", "worker-ai", "tslite_fix")), "unrelated layer file: " + relative)
            if parent in ("BaseBin", "Application") and target.suffix in PRODUCTION_SUFFIXES:
                value = read_source(root, relative)
                # Official files are already byte-protected above; the token scan is
                # for files this project adds, so official symbols cannot false-positive.
                if relative not in fixture["files"]:
                    require(not any(token in value for token in BANNED), "unrelated layer symbol: " + relative)
                if variant == "control":
                    require(OWN_KEY not in value and "app_isolation_" not in name, "own feature in control source: " + relative)
    if variant == "isolation":
        roothider = read_source(root, ROOTHIDER)
        for name, expected in fixture["roothider_functions"].items():
            require(digest(function(roothider, name).encode()) == expected, "official function changed: " + name)
        entry = "int roothide_launchd___posix_spawn_prehook("
        end = "\t// mitigate spinlock panic for ios15(A12+) devices"
        require(digest(roothider[roothider.index(entry):roothider.index(end)].encode()) == fixture["roothider_early_sha256"], "official early guards changed")
        dyld = read_source(root, DYLD).split("/* OWN CHECKED REPAIR:", 1)
        require(len(dyld) == 2, "own repair suffix marker missing")
        prefix = re.sub(r"/\* This must precede libjailbreak's libbsm shim[^*]*\*/\n", "", dyld[0])
        for line in ('#include <bsm/audit.h>\n', '#include "app_isolation_mach.h"\n', '#include "app_isolation_repair.h"\n', '#include "app_isolation_ranges.h"\n', '#include <errno.h>\n'):
            require(prefix.count(line) == 1, "expected own include missing/duplicated")
            prefix = prefix.replace(line, "", 1)
        # Addition leaves one separator blank line; the official tail itself is otherwise byte-exact.
        prefix = prefix.replace("#import <Foundation/Foundation.h>\n\n\n", "#import <Foundation/Foundation.h>\n\n", 1)
        require(prefix.rstrip() == fixture["dyld_legacy_text"].rstrip(), "official dyld legacy prefix changed")
        methods = objc_methods(read_source(root, DOJ))
        for name, expected in fixture["doj_methods"].items():
            require([digest(body.encode()) for body in methods.get(name, [])] == expected, "official DOJ method changed: " + name)
        info = info_without_own(read_source(root, INFO), fixture)
        require(digest(info.encode()) == fixture["files"][INFO]["sha256"], "info.h changed beyond own bool/serde")
        makefile = read_source(root, "BaseBin/systemhook/Makefile")
        makefile = makefile.replace("LDFLAGS = -dynamiclib -lbsm", "LDFLAGS = -dynamiclib")
        makefile = makefile.replace("../libroothider/src/jailbreakd.c ../libroothider/src/app_isolation_mach.c roothider_inline.o", "../libroothider/src/jailbreakd.c roothider_inline.o")
        require(makefile == fixture["systemhook_makefile"], "systemhook Makefile changed beyond own transport link")
        application = read_source(root, "Application/Makefile")
        for line in fixture["application_makefile"].splitlines():
            if line and "CFBundleIdentifier" not in line:
                require(line in application.splitlines(), "official Application build/resource/rename line changed: " + line)
        require("com.doimty.dopamine" in application and "CFBundleVersion" in application and '"34"' in application, "own app identity/build missing")
        require(OWN_KEY in read_source(root, "BaseBin/libjailbreak/src/doimty_isolation.h"), "own setting key missing")
    result = {"schema_version": 1, "variant": variant, "SOURCE_COMMIT": commit,
              "WORKFLOW_COMMIT": workflow_commit or commit, "official_baseline_commit": BASE,
              "baseline_repository": REPOSITORY, "fixture_sha256": digest(fixture_path.read_bytes()),
              "source_tracked_dirty": dirty, "official_files_checked": checked,
              "status": "passed", "authority": "source-only; not runtime equivalence"}
    return result



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--variant", choices=("control", "isolation"), default="isolation")
    parser.add_argument("--baseline", type=Path, default=FIXTURE)
    parser.add_argument("--source-commit")
    parser.add_argument("--workflow-commit")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generate", action="store_true", help="maintainer-only: generate fixture from fixed Git object")
    args = parser.parse_args()
    try:
        if args.generate:
            generate(args.source_root.resolve(), args.baseline)
            return
        result = verify(args.source_root.resolve(), args.variant, args.baseline,
                        args.source_commit, args.workflow_commit, args.require_clean)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("FAIL official-source: " + str(error))


if __name__ == "__main__":
    main()
