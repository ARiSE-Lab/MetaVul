#!/usr/bin/env python3
"""
Convert CWEval benchmark into paired JSONL with vuln_lines annotations.

Each output row contains:
  - func_vulnerable: the unsafe implementation
  - func_patched: the safe implementation (from the task file)
  - cwe_id: extracted from the filename
  - vuln_lines / vuln_line_contents: diff-based annotation
  - language, file paths, test info

Pairs the _task file (safe) with the _unsafe file (vulnerable) for each CWE.
Languages without _unsafe files (e.g. Python) are skipped.

Usage:
  python data/scripts/convert_cweval.py \
    --input cloned_repos/CWEval/benchmark/core \
    --output data/cweval/cweval_paired.jsonl

  # Include lang/ directory tasks too:
  python data/scripts/convert_cweval.py \
    --input cloned_repos/CWEval/benchmark/core \
    --lang-dir cloned_repos/CWEval/benchmark/lang \
    --output data/cweval/cweval_paired.jsonl
"""
import argparse
import ast
import difflib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple


def diff_pair(vul_func: str, pat_func: str) -> Tuple[str, List[int], List[str]]:
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


def extract_cwe_from_test(test_path: Path) -> str:
    """Extract CWE description from test file docstring."""
    try:
        text = test_path.read_text(encoding="utf-8")
        match = re.search(r"'''(.*?)'''", text, re.DOTALL)
        if match:
            return match.group(1).strip().split("\n")[0]
    except Exception:
        pass
    return ""


def parse_cwe_id(filename: str) -> str:
    match = re.match(r"cwe_(\d+)_(\d+)", filename)
    if match:
        return f"CWE-{match.group(1)}"
    return ""


def parse_task_id(filename: str) -> str:
    match = re.match(r"(cwe_\d+_\d+)", filename)
    if match:
        return match.group(1)
    return ""


LANG_EXTENSIONS = {
    "c": [".c"],
    "cpp": [".cpp", ".cc", ".cxx"],
    "go": [".go"],
    "js": [".js"],
    "py": [".py"],
}


def extract_py_unsafe_funcs(test_path: Path) -> List[str]:
    """Extract unsafe function source code from a Python test file.

    Python CWEval tasks embed the unsafe implementation directly in the
    test file as functions with 'unsafe' in the name (excluding test_*
    functions).
    """
    source = test_path.read_text(encoding="utf-8")
    source_lines = source.split("\n")
    tree = ast.parse(source)

    funcs = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if "unsafe" not in node.name:
            continue
        if node.name.startswith("test_"):
            continue
        start = node.lineno - 1
        end = node.end_lineno
        func_source = "\n".join(source_lines[start:end])
        funcs.append(func_source)

    return funcs


def find_pairs(core_dir: Path, lang_dir: Path = None) -> List[Dict[str, Any]]:
    pairs = []
    search_dirs = [core_dir]
    if lang_dir and lang_dir.exists():
        search_dirs.append(lang_dir)

    for base_dir in search_dirs:
        for lang_path in sorted(base_dir.iterdir()):
            if not lang_path.is_dir():
                continue
            lang = lang_path.name

            task_files = {}
            unsafe_files = {}
            test_files = {}

            for f in lang_path.iterdir():
                if not f.is_file():
                    continue
                task_id = parse_task_id(f.name)
                if not task_id:
                    continue
                if "_task" in f.name:
                    task_files[task_id] = f
                elif "_unsafe" in f.name:
                    unsafe_files[task_id] = f
                elif "_test" in f.name:
                    test_files[task_id] = f

            for task_id in sorted(task_files.keys()):
                task_path = task_files[task_id]
                test_path = test_files.get(task_id)
                safe_code = task_path.read_text(encoding="utf-8")
                cwe_id = parse_cwe_id(task_id)
                cwe_desc = extract_cwe_from_test(test_path) if test_path else ""
                source = "lang" if lang_dir and base_dir == lang_dir else "core"

                if task_id in unsafe_files:
                    unsafe_path = unsafe_files[task_id]
                    unsafe_code = unsafe_path.read_text(encoding="utf-8")

                    vuln_type, vuln_lines, vuln_line_contents = diff_pair(unsafe_code, safe_code)

                    pairs.append({
                        "task_id": task_id,
                        "cwe_id": cwe_id,
                        "cwe_description": cwe_desc,
                        "language": lang,
                        "source": source,
                        "task_file": str(task_path.relative_to(task_path.parents[3])),
                        "unsafe_file": str(unsafe_path.relative_to(unsafe_path.parents[3])),
                        "func_vulnerable": unsafe_code,
                        "func_patched": safe_code,
                        "vuln_type": vuln_type,
                        "vuln_lines": vuln_lines,
                        "vuln_line_contents": vuln_line_contents,
                    })

                elif lang == "py" and test_path:
                    unsafe_funcs = extract_py_unsafe_funcs(test_path)
                    if unsafe_funcs:
                        uf = unsafe_funcs[0]
                        vuln_type, vuln_lines, vuln_line_contents = diff_pair(uf, safe_code)

                        pairs.append({
                            "task_id": task_id,
                            "cwe_id": cwe_id,
                            "cwe_description": cwe_desc,
                            "language": lang,
                            "source": source,
                            "task_file": str(task_path.relative_to(task_path.parents[3])),
                            "unsafe_file": str(test_path.relative_to(test_path.parents[3])) + " (inline unsafe)",
                            "func_vulnerable": uf,
                            "func_patched": safe_code,
                            "vuln_type": vuln_type,
                            "vuln_lines": vuln_lines,
                            "vuln_line_contents": vuln_line_contents,
                        })

    return pairs


def convert(core_dir: Path, output_path: Path, lang_dir: Path = None) -> None:
    pairs = find_pairs(core_dir, lang_dir)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for i, p in enumerate(pairs):
            p["idx"] = i
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    vuln_types = {}
    for p in pairs:
        vt = p["vuln_type"]
        vuln_types[vt] = vuln_types.get(vt, 0) + 1

    lang_dist = {}
    for p in pairs:
        lang_dist[p["language"]] = lang_dist.get(p["language"], 0) + 1

    cwe_dist = {}
    for p in pairs:
        cwe_dist[p["cwe_id"]] = cwe_dist.get(p["cwe_id"], 0) + 1

    print(f"Wrote {len(pairs)} pairs to {output_path}")
    print(f"vuln_type distribution: {vuln_types}")
    print(f"Language distribution: {lang_dist}")
    print(f"Unique CWEs: {len(cwe_dist)}")
    print(f"CWE distribution: {dict(sorted(cwe_dist.items(), key=lambda x: -x[1]))}")


def main():
    parser = argparse.ArgumentParser(description="Convert CWEval benchmark to paired JSONL with vuln_lines")
    parser.add_argument("--input", required=True, help="Path to CWEval benchmark/core directory")
    parser.add_argument("--lang-dir", default=None, help="Path to CWEval benchmark/lang directory (optional)")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    args = parser.parse_args()

    lang_dir = Path(args.lang_dir) if args.lang_dir else None
    convert(Path(args.input), Path(args.output), lang_dir)


if __name__ == "__main__":
    main()
