#!/usr/bin/env python3
"""
Split CWEval and TitanVul paired JSONL files by language.

CWEval uses the 'language' field directly.
TitanVul uses the 'extension' field, which is mapped to a canonical language.

Output structure:
  data/cweval/splits/  -> {lang}.jsonl
  data/titanvul/splits/ -> {lang}.jsonl

Usage:
  python data/scripts/split_paired_jsonl_by_language.py
"""
import json
from pathlib import Path

TITANVUL_EXT_TO_LANG = {
    "c": "c",
    "h": "c",
    "cpp": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "hpp": "cpp",
    "java": "java",
    "py": "py",
    "js": "js",
    "jsx": "js",
    "ts": "ts",
    "go": "go",
    "rb": "rb",
    "php": "php",
    "cs": "cs",
    "rs": "rs",
    "scala": "scala",
    "swift": "swift",
    "m": "objc",
    "lua": "lua",
}


def split_dataset(input_path: Path, output_dir: Path, lang_field: str, ext_map: dict = None, prefix: str = ""):
    output_dir.mkdir(parents=True, exist_ok=True)

    rows_by_lang = {}
    skipped = 0

    with open(input_path) as f:
        for line in f:
            row = json.loads(line)
            raw = row.get(lang_field, "")
            if ext_map:
                lang = ext_map.get(raw, "")
            else:
                lang = raw

            if not lang:
                skipped += 1
                continue

            rows_by_lang.setdefault(lang, []).append(row)

    for lang, rows in sorted(rows_by_lang.items()):
        out = output_dir / f"{prefix}_{lang}_split.jsonl"
        with open(out, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = {lang: len(rows) for lang, rows in sorted(rows_by_lang.items(), key=lambda x: -len(x[1]))}
    print(f"\n{input_path.name} -> {output_dir}")
    print(f"  Total written: {sum(counts.values())}  |  Skipped (no lang): {skipped}")
    for lang, n in counts.items():
        print(f"  {lang:8s}: {n}")


def main():
    base = Path("data")

    cweval_in = base / "cweval" / "cweval_paired.jsonl"
    cweval_out = base / "cweval" / "splits"

    titanvul_in = base / "titanvul" / "titanvul_paired.jsonl"
    titanvul_out = base / "titanvul" / "splits"

    if cweval_in.exists():
        split_dataset(cweval_in, cweval_out, lang_field="language", prefix="cweval_paired")
    else:
        print(f"Not found: {cweval_in}")

    if titanvul_in.exists():
        split_dataset(titanvul_in, titanvul_out, lang_field="extension", ext_map=TITANVUL_EXT_TO_LANG, prefix="titanvul_paired")
    else:
        print(f"Not found: {titanvul_in}")


if __name__ == "__main__":
    main()
