#!/usr/bin/env python3
"""Check update wiring; on macOS compile and exercise the production ObjC helpers.

--static-only is useful on the Windows editing host. It never claims the native
Foundation cases ran. No phone, installation, launchd or Git mutation is used.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import plistlib
import zipfile
import warnings

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig")


def static_checks() -> None:
    target = read("BaseBin/jbctl/src/update_target.m")
    identifier = re.search(r'JBCTLDopamineBundleIdentifier\s*=\s*@"([^"]+)"', target)
    assert identifier, "missing compiled update target identifier"
    bundle_id = identifier.group(1)
    assert bundle_id == "com.doimty.dopamine", bundle_id
    makefile = read("Application/Makefile")
    packaged = re.search(r'plutil -replace CFBundleIdentifier -string "([^"]+)"', makefile)
    assert packaged and packaged.group(1) == bundle_id, "packaged ID differs from CLI update target"
    project = read("Application/Dopamine.xcodeproj/project.pbxproj")
    assert project.count("PRODUCT_BUNDLE_IDENTIFIER = " + bundle_id + ";") == 2, "Debug/Release IDs drifted"
    cli = read("BaseBin/jbctl/src/main.m")
    assert "applicationProxyForIdentifier:JBCTLDopamineBundleIdentifier" in cli
    assert "jbctl_update_bound_basebin_path(dopamineAppProxy.bundleURL.path, package)" in cli
    assert cli.index("jbctl_update_preflight_tipa") < cli.index('"install", "skip-uicache", "force"'), "TIPA must be validated before installation"
    assert "-larchive" in read("BaseBin/jbctl/Makefile")
    assert "if (!basebinPath)" in cli and "updateFile = strdup(basebinPath.fileSystemRepresentation)" in cli
    assert 'applicationProxyForIdentifier:@"cn.zqbb.dopaRH"' not in cli
    assert '$(wildcard src/*.m)' in read("BaseBin/jbctl/Makefile"), "update_target.m not compiled"
    manager = read("Application/Dopamine/UI/DOUIManager.m")
    start = manager.index("- (BOOL)environmentUpdateAvailable")
    end = manager.index("- (bool)launchedReleaseNeedsManualUpdate", start)
    update = manager[start:end]
    assert "DOEnvironmentVersionNeedsUpdate" in update
    assert "numericalVersionRepresentation" not in update and "getLaunchedReleaseTag" not in update
    assert "environment.jailbrokenVersionRootHide" in update and "environment.jailbrokenVersion" in update
    revision = read("BaseBin/_external/basebin/.version-roothide").strip()
    assert revision.isascii() and revision.isdecimal() and int(revision) == 30, "doimty revision must match official pairing (30)"
    print("PASS static update wiring: package IDs, validated archive selection, paired version comparator, revision == 30")


def generate_tipa_fixtures(directory: Path) -> None:
    """Real ZIP bytes consumed by the production libarchive parser, not metadata mocks."""
    prefix = "Payload/Doimty.app/"
    def info(identifier="com.doimty.dopamine", version="3.0.13-31"):
        return plistlib.dumps({"CFBundleIdentifier": identifier,
                              "CFBundleShortVersionString": version,
                              "CFBundleExecutable": "Dopamine"}, fmt=plistlib.FMT_BINARY)
    good = [(prefix + "Info.plist", info()), (prefix + "basebin.tar", b"test archive")]
    def emit(name, entries):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # Deliberate duplicate-member fixtures.
            with zipfile.ZipFile(directory / name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path, contents in entries:
                    archive.writestr(path, contents)
    emit("good.tipa", good)
    emit("other.tipa", [(prefix + "Info.plist", info("cn.zqbb.dopaRH")), good[1]])
    emit("old-version.tipa", [(prefix + "Info.plist", info(version="3.0.12-30")), good[1]])
    emit("missing-info.tipa", [good[1]])
    emit("missing-basebin.tipa", [good[0]])
    emit("empty-basebin.tipa", [good[0], (prefix + "basebin.tar", b"")])
    emit("duplicate-info.tipa", good + [good[0]])
    emit("duplicate-basebin.tipa", good + [(prefix + "basebin.tar", b"xxxx archive")])
    emit("two-apps.tipa", good + [("Payload/Other.app/Info.plist", info("other.app"))])
    emit("traversal.tipa", good + [("../outside", b"bad")])
    emit("parent-file.tipa", [("Payload", b"not a directory"), *good])
    emit("oversized-info.tipa", [(prefix + "Info.plist", b"x" * (1024 * 1024 + 1)), good[1]])
    emit("many-entries.tipa", good + [("extra/%05d" % i, b"") for i in range(20000)])
    link = zipfile.ZipInfo(prefix + "basebin.tar")
    link.create_system = 3
    link.external_attr = (0o120777 << 16)
    emit("symlink-basebin.tipa", [good[0], (link, b"../Other.app/basebin.tar")])


def native_checks() -> None:
    if platform.system() != "Darwin":
        raise SystemExit("Native update-contract tests require macOS; use --static-only for source checks.")
    with tempfile.TemporaryDirectory(prefix="dopamine-update-contracts-") as directory:
        work = Path(directory)
        executable = work / "update-contracts"
        fixture = work / "fixtures"
        fixture.mkdir()
        generate_tipa_fixtures(fixture)
        command = ["xcrun", "--sdk", "macosx", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                   "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-framework", "Foundation", "-I" + str(ROOT / "Application/Dopamine/Extensions"),
                   "-I" + str(ROOT / "BaseBin/jbctl/src"),
                   "-idirafter", str(ROOT / "BaseBin/_external/include"), "-larchive",
                   str(ROOT / "Application/Dopamine/Extensions/NSString+Version.m"),
                   str(ROOT / "BaseBin/jbctl/src/update_target.m"),
                   str(ROOT / "tests/update-contracts.m"), "-o", str(executable)]
        subprocess.run(command, check=True)
        environment = dict(os.environ)
        environment["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
        subprocess.run([str(executable), str(fixture)], check=True, env=environment, timeout=30)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-only", action="store_true")
    options = parser.parse_args()
    static_checks()
    if options.static_only:
        print("SKIP native Foundation execution (--static-only)")
    else:
        native_checks()


if __name__ == "__main__":
    main()
