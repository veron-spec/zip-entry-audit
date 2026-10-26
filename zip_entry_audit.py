"""Inspect ZIP metadata for risky archive entries without extracting files."""

from __future__ import annotations

import argparse
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath


def inspect_archive(path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename
            normalized = name.replace("\\", "/")
            parts = PurePosixPath(normalized).parts
            if normalized.startswith("/") or (parts and parts[0].endswith(":")) or ".." in parts:
                findings.append({"entry": name, "issue": "unsafe-path"})

            key = normalized.rstrip("/").casefold()
            if key and key in seen:
                findings.append({"entry": name, "issue": "duplicate-path"})
            if key:
                seen.add(key)

            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append({"entry": name, "issue": "symbolic-link"})

            if entry.file_size >= 1_000_000 and entry.compress_size == 0:
                findings.append({"entry": name, "issue": "extreme-compression-ratio"})
            elif entry.file_size >= 1_000_000 and entry.file_size / entry.compress_size > 1000:
                findings.append({"entry": name, "issue": "extreme-compression-ratio"})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit ZIP entry metadata without extracting files.")
    parser.add_argument("archive", type=Path, help="ZIP archive to inspect")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args()

    try:
        findings = inspect_archive(args.archive)
    except (OSError, zipfile.BadZipFile, NotImplementedError) as exc:
        parser.error(f"cannot inspect archive: {exc}")

    if args.json:
        print(json.dumps(findings, indent=2))
    elif findings:
        for finding in findings:
            print(f"{finding['issue']}: {finding['entry']}")
    else:
        print("No risky ZIP entries found.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
