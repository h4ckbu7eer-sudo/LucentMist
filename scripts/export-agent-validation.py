"""Export already-captured real evidence, without making any model calls.

Each --capture is LABEL=PATH. Writes raw model content, CLI transcripts, and
session/tool records after redaction; recomputes contract flags against the
actual tool definitions in each recorded request, not a guessed allowlist.
"""
import argparse
import json
from pathlib import Path
import re
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument("--capture", action="append", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()
output = Path(args.output)
output.mkdir(parents=True, exist_ok=True)


def clean(value):
    return re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED]", value)


def save(path, text):
    if path.suffix == ".txt":
        # Remove terminal padding only; raw model strings remain in JSONL.
        text = "\n".join(line.rstrip(" \t") for line in text.splitlines()).rstrip("\n") + "\n"
    path.write_text(clean(text), encoding="utf-8")


all_rows = []
summary = []
for capture in args.capture:
    label, directory = capture.split("=", 1)
    directory = Path(directory)
    records = directory / "model-responses.jsonl"
    if not records.exists():
        summary.append({"capture": label, "calls": 0, "note": "No model response captured; not counted as successful validation"})
        continue
    rows = []
    for index, line in enumerate(records.read_text(encoding="utf-8").splitlines(), 1):
        raw = json.loads(line)
        valid_json = valid_action = valid_input = False
        action = None
        tools = set()
        try:
            step = json.loads(raw["content"])
            valid_json = isinstance(step, dict)
            action = step.get("action")
            definitions = raw["requestContext"][-1]["content"].split("## 用户问题")[0]
            tools = set(re.findall(r"^- ([a-z_]+):", definitions, re.MULTILINE))
            valid_action = action == "final_answer" or action in tools
            value = step.get("action_input")
            valid_input = isinstance(value, str) if action == "final_answer" else isinstance(value, dict) or isinstance(value, str) and isinstance(json.loads(value), dict)
            valid_json = valid_json and isinstance(step.get("thought"), str)
        except (ValueError, KeyError, TypeError):
            pass
        rows.append({"capture": label, "call": index, "utc": raw["utc"], "run": raw["run"],
                     "httpStatus": raw["httpStatus"], "jsonValid": valid_json, "actionValid": valid_action,
                     "inputValid": valid_input, "action": action, "responseFormat": raw.get("responseFormat"),
                     "availableTools": sorted(tools),
                     "rawModelContent": raw["content"]})
    all_rows.extend(rows)
    passed = sum(row["httpStatus"] == 200 and row["jsonValid"] and row["actionValid"] and row["inputValid"] for row in rows)
    summary.append({"capture": label, "calls": len(rows), "contractPassed": passed, "percent": round(100 * passed / len(rows), 2)})
    for transcript in ("ip.txt", "gateway.txt", "repl.txt"):
        path = directory / transcript
        if path.exists():
            save(output / f"{label}-{transcript}", path.read_text(encoding="utf-8"))
    db_path = directory / "validation.db"
    if db_path.exists():
        with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            messages = [dict(row) for row in db.execute("SELECT session_id, role, content, tool_calls, created_at FROM agent_messages ORDER BY created_at, rowid")]
        save(output / f"{label}-sessions.jsonl", "\n".join(json.dumps(row, ensure_ascii=False) for row in messages) + "\n")
save(output / "model-responses.jsonl", "\n".join(json.dumps(row, ensure_ascii=False) for row in all_rows) + "\n")
save(output / "contract-summary.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(summary, ensure_ascii=False))
