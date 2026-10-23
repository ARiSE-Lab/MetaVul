#!/usr/bin/env python3
"""
Add stable UUIDs to dataset files for traceability.

Paired format (TitanVul/CWEval): uuid is a 2-element list per row.
Flat format (PrimeVul): uuid is a string per row.

Skips rows that already have a uuid field.

Saves to {stem}_uuid.jsonl alongside the original.

Usage:
  python data/scripts/add_uuids.py data/titanvul_cweval_optimization_val.jsonl
  python data/scripts/add_uuids.py data/primevul/test_with_vul_lines.jsonl
"""
import argparse
import json
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Add UUIDs to dataset JSONL files")
    parser.add_argument("input", type=Path, help="Path to JSONL file")
    args = parser.parse_args()

    with args.input.open("r", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    if not rows:
        print("Empty file, nothing to do.")
        return

    is_paired = "func_vulnerable" in rows[0] and "func_patched" in rows[0]
    added = 0

    for r in rows:
        if "uuid" in r:
            continue
        if is_paired:
            r["uuid"] = [str(uuid.uuid4()), str(uuid.uuid4())]
        else:
            r["uuid"] = str(uuid.uuid4())
        added += 1

    out_path = args.input.with_stem(args.input.stem + "_uuid")
    with out_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")

    fmt = "paired (2-element list)" if is_paired else "flat (string)"
    print(f"{out_path}: {len(rows)} rows, {added} UUIDs added ({fmt})")


if __name__ == "__main__":
    main()
