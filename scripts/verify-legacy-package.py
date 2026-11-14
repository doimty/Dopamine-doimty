#!/usr/bin/env python3
"""Verify a package built from the legacy 3.0.12 isolation line.

This line predates the official-baseline guard, so the check is limited to the
package itself: byte identity, bundle identity, basebin markers and the shipped
binaries. It makes no claim about source equivalence with upstream.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import plistlib
import struct
import tarfile
import zipfile

REQUIRED = ("jbctl", "boomerang", "opainject", "launchdhook.dylib", "jailbreakd",
            "systemhook.dylib", "libroothider.dylib", "libjailbreak.dylib")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def slices(data):
    """Return [(arch, cpu_subtype)] for a thin or FAT Mach-O."""
    if len(data) < 8:
        raise ValueError("short Mach-O")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        count = struct.unpack_from(">I", data, 4)[0]
        stride = 32 if magic == 0xCAFEBABF else 20
        out = []
        for index in range(count):
            base = 8 + index * stride
            cpu, subtype = struct.unpack_from(">II", data, base)
            out.append((cpu, subtype & 0x00FFFFFF))
        return out
    cpu, subtype = struct.unpack_from("<II", data, 4)
    return [(cpu, subtype & 0x00FFFFFF)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", required=True, type=Path)
    parser.add_argument("--tipa", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    ipa, tipa = args.ipa.read_bytes(), args.tipa.read_bytes()
    assert ipa == tipa, "TIPA must be a byte-identical copy of the signed IPA"
    prefix = "Payload/Dopamine.app/"
    binaries = {}
    with zipfile.ZipFile(io.BytesIO(tipa)) as package:
        assert package.testzip() is None, "ZIP CRC failure"
        names = package.namelist()
        assert len(names) == len(set(names)), "duplicate ZIP entries"
        info = plistlib.loads(package.read(prefix + "Info.plist"))
        assert info["CFBundleIdentifier"] == "com.doimty.dopamine"
        assert info["CFBundleExecutable"] == "Dopamine"
        version = info["CFBundleShortVersionString"]
        executable = package.read(prefix + "Dopamine")
        assert executable[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                                  b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        tar_bytes = package.read(prefix + "basebin.tar")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        members = {member.name.lstrip("./"): member for member in archive.getmembers()}
        def read(name):
            stream = archive.extractfile(members["basebin/" + name])
            assert stream is not None
            return stream.read()
        base = read(".version").decode().strip()
        revision = read(".version-roothide").decode().strip()
        assert version == base + "-" + revision, "package version must match basebin markers"
        for name in REQUIRED:
            content = read(name)
            assert content, "empty basebin file: " + name
            arches = {arch for _cpu, arch in slices(content)}
            assert {0x0C, 0x02} <= arches or 0x02 in arches, "missing arm64e slice: " + name
            binaries[name] = {"sha256": sha(content), "bytes": len(content)}
    result = {
        "schema_version": 1,
        "line": "legacy-3.0.12-isolation",
        "commit": args.commit,
        "bundle_identifier": info["CFBundleIdentifier"],
        "app_version": version,
        "basebin_version": base,
        "roothide_revision": revision,
        "ipa_sha256": sha(ipa),
        "bytes": len(ipa),
        "main_executable_sha256": sha(executable),
        "basebin_binaries": binaries,
        "scope": "package structure and identities only; no claim of source equivalence with upstream Dopamine",
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS legacy package", version, "sha256", result["ipa_sha256"])


if __name__ == "__main__":
    main()
