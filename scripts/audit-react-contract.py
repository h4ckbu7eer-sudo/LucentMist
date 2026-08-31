"""Re-score exported raw replies without changing historical records or calling a model."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from react_contract import evaluate


def audit(paths):
    groups = defaultdict(lambda: {"calls": 0, "strictPassed": 0, "changedCalls": []})
    for path in sorted(paths):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if "rawModelContent" not in row or "availableTools" not in row:
                raise ValueError("Export lacks raw response or actual available tools; cannot score honestly")
            key = (path.as_posix(), row["capture"])
            group = groups[key]
            passed = row["httpStatus"] == 200 and all(evaluate(row["rawModelContent"], set(row["availableTools"]))[:3])
            recorded = row["httpStatus"] == 200 and all(row[field] for field in ("jsonValid", "actionValid", "inputValid"))
            group["calls"] += 1
            group["strictPassed"] += int(passed)
            if passed != recorded:
                group["changedCalls"].append({"call": row["call"], "recordedPass": recorded, "strictPass": passed})
    return [{"file": key[0], "capture": key[1], **group} for key, group in groups.items()]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(audit(args.records), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
