#!/usr/bin/env python3
"""Read-only secret heuristic. Reports locations/rules, NEVER matching values.

Default: tracked and non-ignored untracked files. --include-ignored additionally
checks local text files (including .env); Git internals/build caches are excluded.
Exit 0: no matches in scanned scope; 1: potential secrets; 2: incomplete/error.
This is not a credential validator or a Git-history scanner.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


RULES = {
    "provider-key": re.compile(r"\bsk-[A-Za-z0-9_-]{24,}"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "aws-access-id": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "literal-secret": re.compile(
        r'''(?ix)(?:api[_-]?key|api[_-]?token|password|client[_-]?secret|access[_-]?token)
        ["']?\s*[:=]\s*["']?([A-Za-z0-9_+/=-]{20,})'''),
}
EXCLUDED = {".git", "bin", "obj", "node_modules", ".venv", "venv", "__pycache__"}
MAX_BYTES = 16 * 1024 * 1024


def findings(content):
    return [(number, name) for number, line in enumerate(content.splitlines(), 1)
            for name, pattern in RULES.items() if pattern.search(line)]


def decode_text(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if b"\0" in data:
        return None
    # ASCII credential prefixes remain detectable in legacy-encoded text.
    return data.decode("utf-8-sig", errors="replace")


def candidates(root, include_ignored):
    def fail_walk(error):
        raise error

    if include_ignored:
        for directory, dirs, files in os.walk(root, followlinks=False,
                                               onerror=fail_walk):
            dirs[:] = sorted(name for name in dirs if name not in EXCLUDED
                             and not (Path(directory) / name).is_symlink()
                             and not os.path.isjunction(Path(directory) / name))
            for name in sorted(files):
                yield Path(directory) / name
    else:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True)
        for name in sorted(set(result.stdout.decode("utf-8", errors="strict").split("\0")) - {""}):
            yield root / name


def scan(root, include_ignored=False):
    root = root.resolve()
    checked = binary = hits = errors = 0
    try:
        for path in candidates(root, include_ignored):
            label = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                print(f"UNSCANNED {label}: symlink/outside root")
                errors += 1
                continue
            if not path.exists():  # A tracked deletion is absent from the working tree.
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    print(f"UNSCANNED {label}: exceeds 16 MiB")
                    errors += 1
                    continue
                content = decode_text(path.read_bytes())
                if content is None:
                    binary += 1
                    continue
                checked += 1
                for line, rule in findings(content):
                    print(f"POTENTIAL {label}:{line} [{rule}] (value withheld)")
                    hits += 1
            except (OSError, UnicodeError):
                print(f"UNSCANNED {label}: read/decode error")
                errors += 1
    except (OSError, UnicodeError, subprocess.SubprocessError):
        print("ERROR: file enumeration failed; no clean-scan claim")
        errors += 1
    print(f"Summary: text_files={checked}, binary_skipped={binary}, matches={hits}, errors={errors}")
    print("Scope: working tree only; no Git history, build caches, archives or database decoding.")
    return 2 if errors else 1 if hits else 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--include-ignored", action="store_true")
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error("root must be an existing project directory")
    return scan(args.root, args.include_ignored)


if __name__ == "__main__":
    sys.exit(main())
