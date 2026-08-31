"""Exact, value-silent verification using LMIST_LLM_APIKEY only.

Checks working tree (including ignored files), index objects, and every local
Git object (including unreachable history). Never passes the key as an argument.
Exit 0 requires ABSENT in all scopes; errors cannot be reported as absence.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
key = os.environ.get("LMIST_LLM_APIKEY", "")
if not key or "\n" in key or "\r" in key:
    raise SystemExit("A single nonempty LMIST_LLM_APIKEY environment value is required.")
secret = key.encode("utf-8")


def git(*args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def scan_objects(objects):
    process = subprocess.Popen(["git", "-C", str(root), "cat-file", "--batch"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    found = False
    try:
        for oid in objects:
            process.stdin.write(oid + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3:
                raise ValueError("Cannot inspect Git object")
            remaining = int(header[2])
            tail = b""
            while remaining:
                chunk = process.stdout.read(min(65536, remaining))
                if not chunk:
                    raise ValueError("Incomplete Git object")
                joined = tail + chunk
                found |= secret in joined
                tail = joined[-(len(secret) - 1):]
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise ValueError("Invalid Git framing")
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            raise ValueError("Git reader failed")
        return "FOUND" if found else "ABSENT"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


result = {}
try:
    check = subprocess.run(["rg", "--quiet", "--text", "--fixed-strings", "--hidden", "--no-ignore",
                            "-f", "-", str(root)],
                           input=secret + b"\n", capture_output=True)
    result["workingTree"] = {0: "FOUND", 1: "ABSENT"}.get(check.returncode, "ERROR")
    index = {entry.split(b"\t", 1)[0].split()[1]
             for entry in git("ls-files", "--stage", "-z").split(b"\0") if entry}
    result["index"] = scan_objects(sorted(index))
    objects = git("cat-file", "--batch-all-objects", "--batch-check=%(objectname)").splitlines()
    result["localGitHistoryAndObjects"] = scan_objects(objects)
    result["indexObjectsChecked"] = len(index)
    result["gitObjectsChecked"] = len(objects)
except (OSError, ValueError, subprocess.SubprocessError):
    result["error"] = "Verification incomplete (details withheld to avoid credential disclosure)"
print(json.dumps(result, ensure_ascii=False))
sys.exit(0 if all(result.get(scope) == "ABSENT" for scope in
                  ["workingTree", "index", "localGitHistoryAndObjects"]) else 1)
