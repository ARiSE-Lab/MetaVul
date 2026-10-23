#!/usr/bin/env python3
"""
Convert TitanVul CSV to paired JSONL with vuln_lines annotations.

Each output row contains both the vulnerable and patched function,
plus diff-based vuln_lines (which lines in the vulnerable version
were changed by the patch).

Usage:
  python data/scripts/convert_titanvul.py \
    --input data/titanvul/TitanVul.csv \
    --output data/titanvul/titanvul_paired.jsonl

  # Limit to first N pairs:
  python data/scripts/convert_titanvul.py \
    --input data/titanvul/TitanVul.csv \
    --output data/titanvul/titanvul_paired.jsonl \
    --limit 100
"""
import argparse
import csv
import difflib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def diff_pair(vul_func: str, pat_func: str) -> Tuple[str, List[int], List[str]]:
    """Diff a vulnerable function against its patched version.

    Returns (vuln_type, vuln_lines, vuln_line_contents).
    """
    vul_lines = vul_func.split("\n")
    pat_lines = pat_func.split("\n")

    opcodes = difflib.SequenceMatcher(None, vul_lines, pat_lines).get_opcodes()

    removed_indices = []
    removed_contents = []
    added_only = True

    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        if tag in ("delete", "replace"):
            added_only = False
            for i in range(i1, i2):
                removed_indices.append(i + 1)
                removed_contents.append(vul_lines[i].rstrip())
        elif tag == "insert":
            pass

    if not removed_indices and added_only:
        insert_indices = []
        insert_contents = []
        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "insert":
                before = i1
                after = i1 + 1
                if before >= 1 and before not in insert_indices:
                    insert_indices.append(before)
                    insert_contents.append(vul_lines[before - 1].rstrip())
                if after <= len(vul_lines) and after not in insert_indices:
                    insert_indices.append(after)
                    insert_contents.append(vul_lines[after - 1].rstrip())
        return "additive_context", insert_indices, insert_contents

    return "removed", removed_indices, removed_contents


def convert(input_path: Path, output_path: Path, limit: int = 0) -> None:
    csv.field_size_limit(sys.maxsize)

    with open(input_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"Loaded {len(rows)} rows from {input_path}")

    if limit:
        rows = rows[:limit]
        print(f"Limited to {len(rows)} rows")

    skipped = 0
    results: List[Dict[str, Any]] = []

    for idx, row in enumerate(rows):
        func_before = row.get("func_before", "")
        func_after = row.get("func_after", "")

        if not func_before or not func_after:
            skipped += 1
            continue

        if func_before.strip() == func_after.strip():
            skipped += 1
            continue

        vuln_type, vuln_lines, vuln_line_contents = diff_pair(func_before, func_after)

        entry = {
            "idx": idx,
            "cve_id": row.get("cve_id", ""),
            "cwe_id": row.get("cwe_id", ""),
            "cve_description": row.get("cve_description", ""),
            "commit_link": row.get("commit_link", ""),
            "commit_message": row.get("commit_message", ""),
            "file_name": row.get("file_name", ""),
            "extension": row.get("extension", ""),
            "datetime": row.get("datetime", ""),
            "func_vulnerable": func_before,
            "func_patched": func_after,
            "vuln_type": vuln_type,
            "vuln_lines": vuln_lines,
            "vuln_line_contents": vuln_line_contents,
        }

        results.append(entry)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    vuln_types = {}
    for r in results:
        vt = r["vuln_type"]
        vuln_types[vt] = vuln_types.get(vt, 0) + 1

    ext_dist = {}
    for r in results:
        ext = r["extension"]
        ext_dist[ext] = ext_dist.get(ext, 0) + 1

    print(f"\nWrote {len(results)} pairs to {output_path}")
    print(f"Skipped: {skipped} (empty or identical functions)")
    print(f"vuln_type distribution: {vuln_types}")
    print(f"Extension distribution (top 10): {dict(sorted(ext_dist.items(), key=lambda x: -x[1])[:10])}")


def main():
    parser = argparse.ArgumentParser(description="Convert TitanVul CSV to paired JSONL with vuln_lines")
    parser.add_argument("--input", required=True, help="Path to TitanVul.csv")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--limit", type=int, default=0, help="Max rows to process (0 = all)")
    args = parser.parse_args()

    convert(Path(args.input), Path(args.output), args.limit)


if __name__ == "__main__":
    main()
