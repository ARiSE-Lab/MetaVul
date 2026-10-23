#!/usr/bin/env python3
"""
Convert a PrimeVul paired JSONL file into the _with_vul_lines format.

For each consecutive pair (vulnerable, patched), diffs the two functions
to identify which lines in the vulnerable version were changed by the patch.

Adds four fields to each sample:
  - pair_index: shared index for the pair (even numbers)
  - vuln_type: "removed" | "additive_context" | "patched"
  - vuln_lines: list of 1-indexed line numbers in the vulnerable function
  - vuln_line_contents: list of line strings at those positions

Usage:
  python data/scripts/build_vul_lines.py --input data/primevul/test.jsonl --output data/primevul/test_with_vul_lines.jsonl
"""
import argparse
import difflib
import json
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
        # Patch only added lines; the vulnerable version is missing them.
        # Mark the insertion points in the vulnerable function.
        insert_indices = []
        insert_contents = []
        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "insert":
                # Mark the line before and after the insertion point (1-indexed)
                before = i1  # 1-indexed: line before insertion
                after = i1 + 1  # 1-indexed: line after insertion
                if before >= 1 and before not in insert_indices:
                    insert_indices.append(before)
                    insert_contents.append(vul_lines[before - 1].rstrip())
                if after <= len(vul_lines) and after not in insert_indices:
                    insert_indices.append(after)
                    insert_contents.append(vul_lines[after - 1].rstrip())
        return "additive_context", insert_indices, insert_contents

    return "removed", removed_indices, removed_contents


def process_file(input_path: Path, output_path: Path) -> None:
    with open(input_path) as f:
        samples = [json.loads(line) for line in f]

    if len(samples) % 2 != 0:
        raise ValueError(f"Expected even number of samples, got {len(samples)}")

    results: List[Dict[str, Any]] = []

    for i in range(0, len(samples), 2):
        a, b = samples[i], samples[i + 1]

        if a["target"] == 1 and b["target"] == 0:
            vul, pat = a, b
        elif a["target"] == 0 and b["target"] == 1:
            vul, pat = b, a
        else:
            raise ValueError(f"Pair at index {i} has targets {a['target']}, {b['target']}")

        vuln_type, vuln_lines, vuln_line_contents = diff_pair(vul["func"], pat["func"])

        pair_index = i

        vul_out = {**vul, "pair_index": pair_index, "vuln_type": vuln_type,
                   "vuln_lines": vuln_lines, "vuln_line_contents": vuln_line_contents}
        pat_out = {**pat, "pair_index": pair_index, "vuln_type": "patched",
                   "vuln_lines": [], "vuln_line_contents": []}

        results.append(vul_out)
        results.append(pat_out)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Stats
    vuln_types = {}
    for r in results:
        vt = r["vuln_type"]
        vuln_types[vt] = vuln_types.get(vt, 0) + 1

    print(f"Wrote {len(results)} samples ({len(results) // 2} pairs) to {output_path}")
    print(f"vuln_type distribution: {vuln_types}")


def main():
    parser = argparse.ArgumentParser(description="Add vuln_lines fields to PrimeVul paired JSONL")
    parser.add_argument("--input", required=True, help="Input paired JSONL file")
    parser.add_argument("--output", required=True, help="Output JSONL file with vul_lines fields")
    args = parser.parse_args()

    process_file(Path(args.input), Path(args.output))


if __name__ == "__main__":
    main()
