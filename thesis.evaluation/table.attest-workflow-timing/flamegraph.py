#!/usr/bin/env python3
"""
log_stats.py — Parse workflow log files and compute per-step duration statistics.

Usage: python3 log_stats.py <log_dir> [output.json]

Steps are delimited by info-level lines from "workflows/..." callers.
The final step ends at the "evident/attest" line.
Outputs JSON with p90, mean, and median for each step.
"""

import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def parse_ts(ts_str: str) -> float:
    """Parse ISO timestamp with tz offset to epoch milliseconds."""
    if "+" in ts_str[10:]:
        base, offset = ts_str.rsplit("+", 1)
        sign = 1
    elif ts_str[10:].count("-") > 0:
        base, offset = ts_str.rsplit("-", 1)
        sign = -1
    else:
        base = ts_str.rstrip("Z")
        offset = "0000"
        sign = 1

    offset = offset.replace(":", "")
    off_h, off_m = int(offset[:2]), int(offset[2:])

    if "." in base:
        dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")

    tz = timezone(timedelta(hours=sign * off_h, minutes=sign * off_m))
    dt = dt.replace(tzinfo=tz)
    return dt.timestamp() * 1000


def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (p / 100) * (len(s) - 1)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


def parse_log_file(filepath: str) -> list[dict] | None:
    """
    Parse a single log file. Return list of {name, duration_ms} for each step,
    or None if the file doesn't have the expected structure.
    """
    # Collect all boundary lines: workflow/* lines and evident/attest
    boundaries = []
    # Track the first getsnpevidencesubtasks/evidence timestamp for substep split
    evidence_substep_ts = None

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            caller = entry.get("caller", "")
            msg = entry.get("msg", "").strip()
            ts = parse_ts(entry["ts"])

            if "workflows/" in caller and entry.get("level") == "info":
                boundaries.append({"ts": ts, "msg": msg, "type": "step_start"})
            elif "evident/attest" in caller:
                boundaries.append({"ts": ts, "msg": msg, "type": "end"})

            if (
                evidence_substep_ts is None
                and "getsnpevidencesubtasks/evidence" in caller
            ):
                evidence_substep_ts = ts

    if len(boundaries) < 2:
        return None

    # Build steps: each workflow/* line starts a step, next boundary ends it
    steps = []
    for i, b in enumerate(boundaries):
        if b["type"] == "end":
            break
        if i + 1 < len(boundaries):
            step_end = boundaries[i + 1]["ts"]
            duration = step_end - b["ts"]

            if b["msg"] == "Getting evidence" and evidence_substep_ts is not None:
                steps.append(
                    {
                        "name": b["msg"],
                        "duration_ms": duration,
                        "substeps": [
                            {
                                "name": "Get Additional Artifacts",
                                "duration_ms": evidence_substep_ts - b["ts"],
                            },
                            {
                                "name": "Get Evidence",
                                "duration_ms": step_end - evidence_substep_ts,
                            },
                        ],
                    }
                )
            else:
                steps.append({"name": b["msg"], "duration_ms": duration})

    return steps if steps else None


def main():
    log_dir = sys.argv[1] if len(sys.argv) > 1 else None
    output_path = sys.argv[2] if len(sys.argv) > 2 else "step_stats.json"

    if not log_dir:
        print(f"Usage: {sys.argv[0]} <log_dir> [output.json]", file=sys.stderr)
        sys.exit(1)

    log_files = sorted(f for f in os.listdir(log_dir) if f.endswith(".log"))
    if not log_files:
        print(f"No .log files found in {log_dir}", file=sys.stderr)
        sys.exit(1)

    # Parse all runs
    all_runs = {}
    for fname in log_files:
        run_id = fname.removesuffix(".log")
        steps = parse_log_file(os.path.join(log_dir, fname))
        if steps:
            all_runs[run_id] = steps
            print(
                f"  {run_id}: {len(steps)} steps, "
                f"total {sum(s['duration_ms'] for s in steps):.0f}ms",
                file=sys.stderr,
            )
        else:
            print(
                f"  {run_id}: SKIPPED (no workflow boundaries found)", file=sys.stderr
            )

    if not all_runs:
        print("Error: no valid runs found.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{len(all_runs)} runs parsed.", file=sys.stderr)

    # Aggregate: collect durations per step name, and substep durations
    step_durations = defaultdict(list)
    substep_durations = defaultdict(lambda: defaultdict(list))
    total_durations = []

    for run_id, steps in all_runs.items():
        total_durations.append(sum(s["duration_ms"] for s in steps))
        for s in steps:
            step_durations[s["name"]].append(s["duration_ms"])
            if "substeps" in s:
                for sub in s["substeps"]:
                    substep_durations[s["name"]][sub["name"]].append(sub["duration_ms"])

    # Preserve step order from first run
    first_run = next(iter(all_runs.values()))
    ordered_names = list(dict.fromkeys(s["name"] for s in first_run))

    # Preserve substep order from first run
    substep_order = {}
    for s in first_run:
        if "substeps" in s:
            substep_order[s["name"]] = [sub["name"] for sub in s["substeps"]]

    def stats(values):
        n = len(values)
        mean = sum(values) / n
        median = percentile(values, 50)
        p90 = percentile(values, 90)
        return {
            "count": n,
            "mean_ms": round(mean),
            "median_ms": round(median),
            "p90_ms": round(p90),
            "min_ms": round(min(values)),
            "max_ms": round(max(values)),
        }

    def build_step(name):
        entry = {"name": name, **stats(step_durations[name])}
        if name in substep_durations:
            entry["substeps"] = [
                {"name": sub_name, **stats(substep_durations[name][sub_name])}
                for sub_name in substep_order.get(name, substep_durations[name].keys())
            ]
        return entry

    output = {
        "run_count": len(all_runs),
        "total": stats(total_durations),
        "steps": [build_step(name) for name in ordered_names],
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nOutput written to: {output_path}", file=sys.stderr)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
