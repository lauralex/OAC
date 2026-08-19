#!/usr/bin/env python3
"""Create a small Joliet data ISO for an OAC disposable Hyper-V guest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

import pycdlib


REQUIRED_FILES = {
    "Autounattend.xml",
    "Bootstrap.ps1",
    "Run-OACVmTests.ps1",
    "Install-OACTestDriver.ps1",
    "OAC-Protocol-Test.exe",
    "OAC-Protocol-Unit.exe",
    "OAC-Game-Manifest-Expired.bin",
    "OAC-Game-Manifest-Expired.bin.p7s",
    "OAC-Game-Manifest-Wrong-Build.bin",
    "OAC-Game-Manifest-Wrong-Build.bin.p7s",
    "OAC-Game-Manifest-Rollback.bin",
    "OAC-Game-Manifest-Rollback.bin.p7s",
    "OAC-VM-SEED.TAG",
    "package-manifest.json",
    "package/OAC.sys",
    "package/OAC.inf",
    "package/OAC.cat",
    "package/OAC-Client.exe",
    "package/OAC-Service.exe",
    "package/OAC-Launcher.exe",
    "package/OAC-Liveness-Target.exe.oac-manifest",
    "package/OAC-Liveness-Target.exe.oac-manifest.p7s",
    "certificate/OAC-Local-Test.cer",
}
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")


def iso_extension(path: Path) -> str:
    extension = path.suffix.lstrip(".").upper()
    aliases = {"JSON": "JSN"}
    return aliases.get(extension, extension[:3] or "BIN")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def validate_manifest(source: Path) -> None:
    manifest_path = source / "package-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid package manifest: {error}") from error
    if manifest.get("schema") != 1 or manifest.get("purpose") != (
        "OAC disposable-VM test package; never production"
    ):
        raise SystemExit("package manifest has an unexpected schema or purpose")
    source_commit = manifest.get("source_commit")
    if not isinstance(source_commit, str) or not SOURCE_COMMIT.fullmatch(source_commit):
        raise SystemExit("package manifest has no canonical source commit")

    expected = {
        "package": {
            "OAC.sys",
            "OAC.inf",
            "OAC.cat",
            "OAC-Client.exe",
            "OAC-Service.exe",
            "OAC-Launcher.exe",
            "OAC-Liveness-Target.exe.oac-manifest",
            "OAC-Liveness-Target.exe.oac-manifest.p7s",
        },
        "": {
            "OAC-Protocol-Test.exe",
            "OAC-Protocol-Unit.exe",
            "OAC-Game-Manifest-Expired.bin",
            "OAC-Game-Manifest-Expired.bin.p7s",
            "OAC-Game-Manifest-Wrong-Build.bin",
            "OAC-Game-Manifest-Wrong-Build.bin.p7s",
            "OAC-Game-Manifest-Rollback.bin",
            "OAC-Game-Manifest-Rollback.bin.p7s",
        },
    }
    groups = (("package", manifest.get("files")), ("", manifest.get("test_files")))
    for prefix, entries in groups:
        if not isinstance(entries, list) or not entries:
            raise SystemExit(f"package manifest has no entries for {prefix or 'test files'}")
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise SystemExit("package manifest contains a non-object file entry")
            name = entry.get("name")
            if not isinstance(name, str) or Path(name).name != name or name in seen:
                raise SystemExit(f"package manifest contains an unsafe or duplicate name: {name!r}")
            seen.add(name)
            path = source / prefix / name if prefix else source / name
            if not path.is_file():
                raise SystemExit(f"manifest-covered seed file is missing: {path}")
            if path.stat().st_size != entry.get("bytes") or sha256(path) != entry.get("sha256"):
                raise SystemExit(f"manifest mismatch for seed file: {path}")
        missing = sorted(expected[prefix] - seen)
        if missing:
            raise SystemExit(f"package manifest does not hash required files: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if not source.is_dir():
        raise SystemExit(f"seed source is not a directory: {source}")
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")
    if output.is_relative_to(source):
        raise SystemExit("the output ISO must be outside the seed source")

    entries = list(source.rglob("*"))
    links = sorted(path for path in entries if path.is_symlink())
    if links:
        raise SystemExit(f"refusing symbolic links in the seed source: {links}")
    files = sorted(path for path in entries if path.is_file())
    relative_files = {path.relative_to(source).as_posix() for path in files}
    missing = sorted(REQUIRED_FILES - relative_files)
    if missing:
        raise SystemExit(f"seed is missing required files: {missing}")
    unexpected = sorted(relative_files - REQUIRED_FILES)
    if unexpected:
        raise SystemExit(f"seed contains unexpected files: {unexpected}")
    private_keys = [path for path in files if path.suffix.lower() in {".pfx", ".p12", ".key"}]
    if private_keys:
        raise SystemExit(f"refusing to include private-key material: {private_keys}")
    validate_manifest(source)

    output.parent.mkdir(parents=True, exist_ok=True)
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, joliet=3, vol_ident="OACSEED")

    directories = sorted(
        (path for path in source.rglob("*") if path.is_dir()),
        key=lambda path: (len(path.relative_to(source).parts), path.as_posix().lower()),
    )
    iso_directories: dict[Path, str] = {source: ""}
    for index, directory in enumerate(directories, start=1):
        parent_iso = iso_directories[directory.parent]
        identifier = f"D{index:07d}"
        iso_path = f"{parent_iso}/{identifier}" if parent_iso else f"/{identifier}"
        joliet_path = "/" + PurePosixPath(directory.relative_to(source).as_posix()).as_posix()
        image.add_directory(iso_path=iso_path, joliet_path=joliet_path)
        iso_directories[directory] = iso_path

    for index, path in enumerate(files, start=1):
        parent_iso = iso_directories[path.parent]
        iso_name = f"F{index:07d}.{iso_extension(path)};1"
        iso_path = f"{parent_iso}/{iso_name}" if parent_iso else f"/{iso_name}"
        joliet_path = "/" + PurePosixPath(path.relative_to(source).as_posix()).as_posix()
        image.add_file(str(path), iso_path=iso_path, joliet_path=joliet_path)

    image.write(str(output))
    image.close()
    print(f"created={output}")
    print(f"files={len(files)}")
    print(f"bytes={output.stat().st_size}")
    print(f"sha256={sha256(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
