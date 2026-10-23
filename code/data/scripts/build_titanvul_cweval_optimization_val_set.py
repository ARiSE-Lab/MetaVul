#!/usr/bin/env python3
"""
Build a combined C/C++ validation set for the self-improving optimization
loop from CWEval (all pairs) and TitanVul (stratified by CWE).

Usage:
  python data/scripts/build_titanvul_cweval_optimization_val_set.py \
    --titanvul-splits data/titanvul/splits \
    --cweval-splits data/cweval/splits \
    --titanvul-n 150 \
    --output data/titanvul_cweval_optimization_val.jsonl \
    --seed 42
"""
import argparse
import json
import random
from collections import defaultdict
from pathlib import Path


LANGS = ["c", "cpp"]
UNLABELED_CWES = {"", "NVD-CWE-noinfo", "NVD-CWE-Other"}


def load_splits(splits_dir: Path) -> list[dict]:
    rows = []
    for lang in LANGS:
        for f in splits_dir.glob(f"*_{lang}_split.jsonl"):
            with open(f) as fh:
                for line in fh:
                    row = json.loads(line)
                    row["_lang"] = lang
                    rows.append(row)
    return rows


def stratified_sample(rows: list[dict], n: int, rng: random.Random) -> list[dict]:
    by_cwe = defaultdict(list)
    for r in rows:
        cwe = r.get("cwe_id", "").strip()
        by_cwe[cwe].append(r)

    labeled_groups = {k: v for k, v in by_cwe.items() if k not in UNLABELED_CWES}
    unlabeled = []
    for k in UNLABELED_CWES:
        unlabeled.extend(by_cwe.get(k, []))

    labeled_total = sum(len(v) for v in labeled_groups.values())

    unlabeled_budget = max(5, round(n * len(unlabeled) / (labeled_total + len(unlabeled))))
    labeled_budget = n - unlabeled_budget

    sampled = []
    for cwe in sorted(labeled_groups, key=lambda k: -len(labeled_groups[k])):
        group = labeled_groups[cwe]
        share = len(group) / labeled_total * labeled_budget
        count = max(1, round(share))
        count = min(count, len(group))
        sampled.extend(rng.sample(group, count))

    if len(sampled) > labeled_budget:
        rng.shuffle(sampled)
        sampled = sampled[:labeled_budget]

    if unlabeled:
        ub = min(unlabeled_budget, len(unlabeled))
        sampled.extend(rng.sample(unlabeled, ub))

    return sampled


def main():
    parser = argparse.ArgumentParser(
        description="Build combined C/C++ validation set for optimization loop"
    )
    parser.add_argument("--titanvul-splits", required=True)
    parser.add_argument("--cweval-splits", required=True)
    parser.add_argument("--titanvul-n", type=int, default=150)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    cweval_rows = load_splits(Path(args.cweval_splits))
    titanvul_rows = load_splits(Path(args.titanvul_splits))

    print(f"CWEval C/C++: {len(cweval_rows)} pairs (keeping all)")
    print(f"TitanVul C/C++: {len(titanvul_rows)} pairs (sampling {args.titanvul_n})")

    titanvul_sample = stratified_sample(titanvul_rows, args.titanvul_n, rng)

    combined = []
    for r in cweval_rows:
        r["_source"] = "cweval"
        combined.append(r)
    for r in titanvul_sample:
        r["_source"] = "titanvul"
        combined.append(r)

    rng.shuffle(combined)
    for i, r in enumerate(combined):
        r["val_idx"] = i

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for r in combined:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    source_counts = defaultdict(int)
    cwe_counts = defaultdict(int)
    lang_counts = defaultdict(int)
    for r in combined:
        source_counts[r["_source"]] += 1
        lang_counts[r["_lang"]] += 1
        cwe = r.get("cwe_id", "").strip()
        if cwe:
            cwe_counts[cwe] += 1

    print(f"\nWrote {len(combined)} pairs to {out}")
    print(f"By source: {dict(source_counts)}")
    print(f"By language: {dict(lang_counts)}")
    print(f"Unique CWEs: {len(cwe_counts)}")
    print(f"Top CWEs:")
    for cwe, cnt in sorted(cwe_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {cwe}: {cnt}")


if __name__ == "__main__":
    main()
