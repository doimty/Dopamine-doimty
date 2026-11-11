#!/usr/bin/env python3
"""Inspect IPA/TIPA and nested basebin tar in memory; never extract or execute payloads.

Only Python's standard library is used. Mach-O facts and C-string presence are
static observations, not claims of runtime isolation, signature trust, or source equivalence.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import re
import stat
import struct
import tarfile
import unicodedata
import uuid
import zipfile

BASE = "9617d75f476423fdfd33477299c8a1349eb6f375"
KEY = b"doimtyBlacklistIsolationEnabled"
REQUIRED = ("jbctl", "boomerang", "opainject", "launchdhook.dylib", "jailbreakd",
            "systemhook.dylib", "libroothider.dylib", "libjailbreak.dylib")
MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 30000


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(path):
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(data); hasher.update(data)
    return {"bytes": size, "sha256": hasher.hexdigest()}


def canonical(name, directory=False, tar=False):
    require(isinstance(name, str) and name and "\\" not in name and "\0" not in name,
            "invalid archive path")
    require(not any(ord(char) < 32 for char in name), "control character in archive path")
    if tar:
        while name.startswith("./"):
            name = name[2:]
    if directory:
        name = name.rstrip("/")
    require(name and not name.startswith("/") and not re.match(r"^[A-Za-z]:", name), "absolute archive path")
    require(all(part not in ("", ".", "..") for part in name.split("/")), "noncanonical archive path: " + name)
    return unicodedata.normalize("NFC", name)


def version(value):
    return "%d.%d.%d" % (value >> 16, (value >> 8) & 255, value & 255)


def macho(data):
    require(len(data) >= 32, "short Mach-O")
    magic = data[:4]
    slices = []
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        endian = ">" if magic[:2] == b"\xca\xfe" else "<"
        wide = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        stride = 32 if wide else 20
        require(0 < count <= 16 and 8 + count * stride <= len(data), "invalid FAT directory")
        ranges = []
        for index in range(count):
            location = 8 + index * stride
            cpu, subtype = struct.unpack_from(endian + "II", data, location)
            if wide:
                offset, size, align, reserved = struct.unpack_from(endian + "QQII", data, location + 8)
                require(reserved == 0, "FAT64 reserved field")
            else:
                offset, size, align = struct.unpack_from(endian + "III", data, location + 8)
            require(align <= 31 and offset % (1 << align) == 0 and size >= 32 and
                    offset >= 8 + count * stride and offset + size <= len(data), "invalid FAT slice range")
            require(all(offset + size <= start or offset >= end for start, end in ranges), "overlapping FAT slices")
            ranges.append((offset, offset + size))
            slices.append((offset, size, cpu, subtype))
    else:
        slices.append((0, len(data), None, None))
    result = []
    for offset, size, declared_cpu, declared_subtype in slices:
        image = data[offset:offset + size]
        require(image[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"), "64-bit Mach-O required")
        endian = "<" if image[:4] == b"\xcf\xfa\xed\xfe" else ">"
        cpu, subtype, filetype, ncmds, commands_size, flags, reserved = struct.unpack_from(endian + "7I", image, 4)
        require(cpu == 0x0100000c, "unexpected CPU family")
        require(declared_cpu is None or (cpu == declared_cpu and subtype == declared_subtype), "FAT/thin CPU mismatch")
        arch = {0: "arm64", 2: "arm64e"}.get(subtype & 0x00ffffff)
        require(arch is not None and ncmds <= 65536 and 32 + commands_size <= len(image), "invalid Mach header")
        position = 32
        uuids, builds, loads = [], [], []
        for _ in range(ncmds):
            require(position + 8 <= 32 + commands_size, "short load command")
            command, length = struct.unpack_from(endian + "II", image, position)
            require(length >= 8 and length % 8 == 0 and position + length <= 32 + commands_size, "invalid load command length")
            if command == 0x1b:
                require(length == 24, "invalid LC_UUID")
                uuids.append(str(uuid.UUID(bytes=image[position + 8:position + 24])))
            elif command == 0x32:
                require(length >= 24, "short LC_BUILD_VERSION")
                platform, minos, sdk, ntools = struct.unpack_from(endian + "4I", image, position + 8)
                require(24 + ntools * 8 <= length, "short build tools")
                builds.append({"command": "LC_BUILD_VERSION", "platform": platform,
                               "minos": version(minos), "sdk": version(sdk),
                               "tools": [{"tool": struct.unpack_from(endian + "I", image, position + 24 + i * 8)[0],
                                          "version": version(struct.unpack_from(endian + "I", image, position + 28 + i * 8)[0])}
                                         for i in range(ntools)]})
            elif command in (0x24, 0x25, 0x2f, 0x30):
                require(length == 16, "invalid legacy version command")
                minos, sdk = struct.unpack_from(endian + "II", image, position + 8)
                builds.append({"command": "LC_VERSION_MIN", "command_id": command,
                               "minos": version(minos), "sdk": version(sdk)})
            elif command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x20, 0x80000023):
                require(length >= 24, "short dylib command")
                name_offset, timestamp, current, compatibility = struct.unpack_from(endian + "4I", image, position + 8)
                require(24 <= name_offset < length, "invalid dylib name offset")
                raw = image[position + name_offset:position + length]
                require(b"\0" in raw, "unterminated dylib name")
                loads.append({"command": command, "name": raw.split(b"\0", 1)[0].decode("utf-8"),
                              "current_version": version(current), "compatibility_version": version(compatibility)})
            position += length
        require(position == 32 + commands_size and len(uuids) <= 1 and len(builds) <= 1,
                "inconsistent Mach command inventory")
        result.append({"arch": arch, "cpu_subtype": subtype, "offset": offset, "bytes": size,
                       "sha256": sha(image), "filetype": filetype, "uuid": uuids[0] if uuids else None,
                       "build": builds[0] if builds else None, "dylibs": loads,
                       "own_setting_key_cstring_present": KEY in image})
    require(len({row["arch"] for row in result}) == len(result), "duplicate architecture slices")
    return result


def zip_inventory(archive):
    members = archive.infolist()
    require(0 < len(members) <= MAX_ENTRIES, "ZIP entry budget")
    result = {}
    total = 0
    for member in members:
        require(not member.flag_bits & 1, "encrypted ZIP entry")
        require(member.file_size <= MAX_MEMBER, "ZIP member budget")
        total += member.file_size
        require(total <= MAX_TOTAL, "ZIP total byte budget")
        name = canonical(member.filename, member.is_dir())
        require(name not in result, "duplicate normalized ZIP path: " + name)
        result[name] = member
    require(archive.testzip() is None, "ZIP CRC mismatch")
    return result


def tar_inventory(data):
    require(len(data) <= MAX_MEMBER, "basebin tar byte budget")
    result, records = {}, []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            require(len(records) < MAX_ENTRIES, "tar entry budget")
            name = canonical(member.name, member.isdir(), tar=True)
            require(name == "basebin" or name.startswith("basebin/"), "unexpected basebin root")
            require(name not in result, "duplicate normalized tar path: " + name)
            require(member.isfile() or member.isdir() or member.issym() or member.islnk(), "unsupported special tar entry")
            require(member.uid == 0 and member.gid == 0, "non-root basebin owner")
            require(0 <= member.size <= MAX_MEMBER, "tar member budget")
            total += member.size; require(total <= MAX_TOTAL, "tar total byte budget")
            row = {"path": name, "bytes": member.size, "mode": oct(member.mode),
                   "uid": member.uid, "gid": member.gid, "type": member.type.decode("ascii"),
                   "link_target": member.linkname or None}
            content = None
            if member.isfile():
                stream = archive.extractfile(member)
                require(stream is not None, "missing tar member bytes")
                content = stream.read(MAX_MEMBER + 1)
                require(len(content) == member.size, "short tar data")
                row["sha256"] = sha(content)
            result[name] = (row, content)
            records.append(row)
    require(result, "empty basebin tar")
    return result, records


def load_guard():
    script = Path(__file__).with_name("test-official-baseline.py")
    spec = importlib.util.spec_from_file_location("official_source_guard", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(ipa, tipa, source_root, variant, source_commit, workflow_commit, require_clean=False):
    identity = file_identity(ipa)
    require(identity == file_identity(tipa), "IPA and TIPA bytes differ")
    mode = "control" if variant in ("control", "official-control") else "isolation"
    label = "official-control" if mode == "control" else "doimty-isolation"
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) and re.fullmatch(r"[0-9a-f]{40}", workflow_commit), "full commit identities required")
    source = load_guard().verify(source_root.resolve(), mode, source_commit=source_commit,
                                 workflow_commit=workflow_commit, require_clean=require_clean)
    with zipfile.ZipFile(ipa) as archive:
        inventory = zip_inventory(archive)
        roots = [path[:-11] for path in inventory if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", path)]
        require(len(roots) == 1, "exactly one app Info.plist required")
        app = roots[0]
        info = plistlib.loads(archive.read(app + "/Info.plist"))
        expected_id = "com.opa334.Dopamine-roothide" if mode == "control" else "com.doimty.dopamine"
        require(info.get("CFBundleIdentifier") == expected_id, "unexpected app bundle identifier")
        base_version = (source_root / "BaseBin/_external/basebin/.version").read_text(encoding="utf-8").strip()
    revision = (source_root / "BaseBin/_external/basebin/.version-roothide").read_text(encoding="utf-8").strip()
    expected_version = base_version + "-" + revision
    require(info.get("CFBundleShortVersionString") == expected_version, "unexpected ShortVersion")
        require(mode == "control" or str(info.get("CFBundleVersion")) == revision,
                "own build version must equal the shipped revision")
        executable = info.get("CFBundleExecutable")
        require(isinstance(executable, str) and executable and "/" not in executable and "\\" not in executable and executable not in (".", ".."), "invalid main executable name")
        main_path = app + "/" + executable
        require(main_path in inventory, "main executable missing")
        main_mode = inventory[main_path].external_attr >> 16
        require(stat.S_IFMT(main_mode) in (0, stat.S_IFREG) and main_mode & 0o777 == 0o755, "main must be regular mode 755")
        require(not any(path.rsplit("/", 1)[-1].lower() == "roothidewhite.deb" for path in inventory), "roothideWhite.deb must not be bundled")
        resource_facts = {}
        for name in ("bootstrap_1800.tar.zst", "bootstrap_1900.tar.zst", "Frameworks/palera1n.framework/palera1n"):
            path = app + "/" + name
            require(path in inventory and inventory[path].file_size > 0, "required complete resource missing: " + name)
            content = archive.read(path)
            resource_facts[name] = {"bytes": len(content), "sha256": sha(content)}
            if name.endswith("/palera1n"):
                resource_facts[name]["macho"] = macho(content)
        tar_path = app + "/basebin.tar"
        require(tar_path in inventory, "basebin.tar missing")
        tar_bytes = archive.read(tar_path)
        basebin, tar_records = tar_inventory(tar_bytes)
        versions = {}
        for filename, expected in ((".version", base_version), (".version-roothide", revision)):
            key = "basebin/" + filename
            require(key in basebin and basebin[key][1] is not None, "basebin version missing")
            value = basebin[key][1].decode("ascii").strip()
            require(value == expected, "basebin version changed: " + filename)
            versions[filename] = value
        native = {}
        for name in REQUIRED:
            path = "basebin/" + name
            require(path in basebin and basebin[path][1] is not None, "required basebin file missing: " + name)
            row, content = basebin[path]
            slices = macho(content)
            require({part["arch"] for part in slices} == {"arm64", "arm64e"}, "basebin must retain both slices: " + name)
            native[path] = dict(row, macho=slices)
        if "basebin/launchd" in basebin:
            row, content = basebin["basebin/launchd"]
            native["basebin/launchd"] = dict(row, macho=macho(content) if content is not None else None)
        else:
            native["basebin/launchd"] = {"status": "absent", "required": False}
        app_native = {}
        for name in (executable, "libjailbreak.dylib", "libroothider.dylib"):
            path = app + "/" + name
            require(path in inventory, "app-root native file missing: " + name)
            content = archive.read(path)
            app_native[path] = {"bytes": len(content), "sha256": sha(content), "macho": macho(content)}
        presence = {path: any(part["own_setting_key_cstring_present"] for part in row.get("macho", []) or [])
                    for path, row in {**native, **app_native}.items() if row.get("macho")}
        if mode == "control":
            require(not any(presence.values()), "own setting key present in official control")
        else:
            # The key compiles into the launchd hook (backend settings) and the app
            # (preference plumbing); libjailbreak itself does not reference it.
            for path in ("basebin/launchdhook.dylib", app + "/" + executable):
                require(presence[path], "compiled own setting key missing: " + path)
        zip_records = [{"path": path, "bytes": member.file_size, "crc32": "%08x" % member.CRC,
                        "mode": oct(member.external_attr >> 16), "compressed_bytes": member.compress_size}
                       for path, member in inventory.items()]
    return {"schema_version": 1, "variant": label, "SOURCE_COMMIT": source_commit,
            "WORKFLOW_COMMIT": workflow_commit, "official_baseline_commit": BASE,
            "ipa": dict(identity, filename=ipa.name), "tipa": dict(identity, filename=tipa.name),
            "ipa_tipa_byte_identical": True, "bundle_info": info, "basebin_versions": versions,
            "zip_crc_validated": True, "zip_entries": zip_records,
            "basebin_tar": {"bytes": len(tar_bytes), "sha256": sha(tar_bytes), "entries": tar_records},
            "native": native, "app_root_native": app_native, "resources": resource_facts,
            "own_setting_key_cstring_presence": presence, "source_guard": source,
            "limitations": ["C-string presence plus source commitment is finite static evidence, not hook execution or runtime isolation proof",
                            "Mach-O signing/authenticity, OS behavior and dependency resolution are unverified",
                            "Archives inspected in memory; payloads were not extracted, run, patched or re-signed"]}


def self_test():
    for bad in ("../escape", "/absolute", "a//b", "a/./b", "C:/drive", "a\\b", "a/../b"):
        try:
            canonical(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted bad path " + bad)
    require(canonical("./basebin/jbctl", tar=True) == "basebin/jbctl", "tar normalization")
    image = struct.pack("<8I", 0xfeedfacf, 0x0100000c, 0, 2, 1, 24, 0, 0) + struct.pack("<II", 0x1b, 24) + bytes(range(16))
    require(macho(image)[0]["arch"] == "arm64", "thin Mach fixture")
    try:
        macho(image[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("accepted short Mach fixture")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a", b"one"); archive.writestr("a/", b"")
    with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
        try:
            zip_inventory(archive)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted duplicate normalized ZIP fixture")
    print("PASS package self-test: path rejection, tar normalization, thin Mach bounds, duplicate ZIP paths")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path)
    parser.add_argument("--tipa", type=Path)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--variant", choices=("control", "isolation", "official-control", "doimty-isolation"))
    parser.add_argument("--source-commit")
    parser.add_argument("--workflow-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(); return
        require(all((args.ipa, args.tipa, args.source_root, args.variant, args.source_commit,
                     args.workflow_commit, args.output)), "all package/source/commit/output arguments are required")
        result = verify(args.ipa, args.tipa, args.source_root, args.variant,
                        args.source_commit, args.workflow_commit, args.require_clean)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        print("PASS", result["variant"], result["ipa"]["sha256"], "manifest", args.output)
    except (ValueError, KeyError, OSError, UnicodeError, struct.error, zipfile.BadZipFile, tarfile.TarError) as error:
        raise SystemExit("FAIL package: " + str(error))


if __name__ == "__main__":
    main()
