#!/usr/bin/env python3
"""PrimeVul held-out pairwise accuracy grouped by CVE year (contamination check).

If a model memorized fix commits during training, older CVEs (public for
longer) should be easier. This script groups the 430 scored PrimeVul pairs by
the year in their CVE ID and reports pairwise accuracy per year for every
held-out run, plus a trend test.

Scoring matches evaluation/metrics_paper.py exactly: the same run discovery
and best-copy choice, the same per-sample dedupe, the same 5 excluded pairs,
and the same pair rule (a pair counts once both predictions exist; it is
correct when the vulnerable function is flagged and the patched one is not).

Trend test: Spearman correlation between CVE year and pair correctness (0/1)
over all scored pairs of a run, with a two-sided permutation p-value (10,000
shuffles, fixed seed). Memorization predicts a negative correlation. The test
is repeated without 2022 (the largest and most recent year) to check whether
a correlation reflects a gradual age effect or only a 2022 dip.

By default only runs in this repo's results/ are read, so the check covers a
subset of the paper's runs (the Opus seed baselines are not in the repo).

Outputs (default ../results/cve_year/):
  per_year.csv   one row per run and year
  summary.csv    one row per run: pairs, accuracy, binned accuracy, rho, p
  report.md      seed harnesses, main-table selected harnesses, all-run counts

Usage (from code/):
  python evaluation/cve_year.py
  python evaluation/cve_year.py 20260716_181608 20260909_054308
  METRICS_EXTRA_ROOTS=/path/a/meta-vul-code:/path/b/meta-vul-code python evaluation/cve_year.py
"""
import argparse
import csv
import os
import random
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from metrics import load_predictions  # noqa: E402
from metrics_paper import (  # noqa: E402
    EXTRA_HELD_RUNS, HELD_EXCLUDE_PAIRS, HELD_GT, HELD_RE, REPO,
    best_copy, dedupe, discover_sessions, load_gt, roots,
)

BINS = [(2008, 2014), (2015, 2018), (2019, 2020), (2021, 2021), (2022, 2022)]

# Selected harnesses in the paper's main table (results/main_table.tex): (session, model, iter).
# Runs not present under the scanned roots are skipped in the report.
MAIN_TABLE_SELECTED = [
    ("20260716_181608", "opus-4-6", 3),
    ("20260716_181608", "opus-5", 3),
    ("20260909_054308", "thinkingmachines-Inkling-Small", 12),
    ("20260909_054308", "nvidia-NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16", 12),
    ("20260909_054308", "openai-gpt-4o", 12),
]


def pair_years(gt: List[dict]) -> Dict[int, int]:
    """Pair start row -> CVE year of the pair's vulnerable function. Two PrimeVul
    pairs join functions from different CVEs (e.g. rows 542/543: a CVE-2015-5239
    vulnerable function with a CVE-2014-7815 patched one); the vulnerable side is
    the bug the model must detect, so its CVE sets the year."""
    years = {}
    for i in range(0, len(gt), 2):
        vuln = gt[i] if gt[i].get("target") == 1 else gt[i + 1]
        m = re.match(r"CVE-(\d{4})-", str(vuln.get("cve", "")))
        if not m:
            raise ValueError(f"pair at row {i} has no CVE year: {vuln.get('cve')!r}")
        years[i] = int(m.group(1))
    return years


def pair_outcomes(pred_file: Path, exclude: frozenset) -> Dict[int, int]:
    """Pair start row -> 1 if correct, 0 if not, for pairs with both predictions.
    Same rule as metrics.pairwise_accuracy."""
    by_index = {r.get("index"): r for r in dedupe(load_predictions(pred_file))}
    out = {}
    for i in range(0, max((k for k in by_index if isinstance(k, int)), default=-1) + 1, 2):
        if i in exclude:
            continue
        a, b = by_index.get(i), by_index.get(i + 1)
        if not a or not b:
            continue
        vuln = a if a.get("label") == 1 else b if b.get("label") == 1 else None
        patch = a if a.get("label") == 0 else b if b.get("label") == 0 else None
        if not vuln or not patch:
            continue
        out[i] = int(vuln.get("vulnerable") is True and patch.get("vulnerable") is False)
    return out


def ranks(xs: List[float]) -> List[float]:
    order = sorted(range(len(xs)), key=lambda k: xs[k])
    r = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        for k in range(i, j + 1):
            r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r


def pearson(x: List[float], y: List[float]) -> float:
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    return sxy / (sxx * syy) ** 0.5 if sxx and syy else 0.0


def spearman_perm(years: List[int], hits: List[int], n_perm: int = 10_000, seed: int = 0) -> Tuple[float, float]:
    rx, ry = ranks(years), ranks(hits)
    rho = pearson(rx, ry)
    rng = random.Random(seed)
    ry_shuf = list(ry)
    extreme = 0
    for _ in range(n_perm):
        rng.shuffle(ry_shuf)
        if abs(pearson(rx, ry_shuf)) >= abs(rho) - 1e-12:
            extreme += 1
    return rho, (extreme + 1) / (n_perm + 1)


def rel_source(path: Path) -> str:
    """Predictions path without the local checkout prefix (keeps outputs anonymous)."""
    parts = path.parts
    for anchor in ("meta-vul-code", "results", "old-claude-cli-agent"):
        if anchor in parts:
            return "/".join(parts[parts.index(anchor):])
    return path.name


def pct(c: int, n: int) -> str:
    return f"{100 * c / n:.1f}" if n else "-"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sessions", nargs="*", help="Session IDs (default: every session with held-out runs)")
    ap.add_argument("--extra-root", action="append", default=[],
                    help="Another checkout's meta-vul-code dir to include (repeatable)")
    ap.add_argument("--out", default=str(REPO.parent / "results" / "cve_year"), help="Output directory")
    ap.add_argument("--min-coverage", type=float, default=95.0,
                    help="Skip runs with fewer than this percent of the 430 pairs scored")
    args = ap.parse_args()

    extra = list(args.extra_root)
    if os.environ.get("METRICS_EXTRA_ROOTS"):
        extra += [e for e in os.environ["METRICS_EXTRA_ROOTS"].split(":") if e]
    rs = roots(extra)
    gt = load_gt(HELD_GT)
    years = pair_years(gt)
    exclude = HELD_EXCLUDE_PAIRS
    n_scored = len(years) - len(exclude)

    per_year_rows, summary_rows = [], []
    summary_by_run: Dict[Tuple[str, str, int], dict] = {}
    year_counts: Dict[int, int] = {}
    for i, y in years.items():
        if i not in exclude:
            year_counts[y] = year_counts.get(y, 0) + 1

    for s in args.sessions or discover_sessions(rs):
        held: Dict[Tuple[str, int], List[Path]] = {}
        for r in rs:
            for d in r.glob(f"*-agent/outputs/held_out_primevul_{s}_iter*"):
                m = HELD_RE.match(d.name)
                if m and m.group(1) == s:
                    held.setdefault((m.group(3), int(m.group(2))), []).extend(d.glob("*/predictions.jsonl"))
        for sess, it, model, rel in EXTRA_HELD_RUNS:
            if sess == s:
                held.setdefault((model, it), []).extend(p for r in rs if (p := r / rel).exists())

        for (model, it), cands in sorted(held.items()):
            path, m = best_copy(cands, gt, exclude)
            if not path:
                continue
            outcomes = pair_outcomes(path, exclude)
            if 100 * len(outcomes) / n_scored < args.min_coverage:
                continue
            ys = [years[i] for i in sorted(outcomes)]
            hs = [outcomes[i] for i in sorted(outcomes)]
            by_year: Dict[int, List[int]] = {}
            for y, h in zip(ys, hs):
                by_year.setdefault(y, []).append(h)
            for y in sorted(by_year):
                per_year_rows.append({"session": s, "model": model, "iter": it, "year": y,
                                      "pairs": len(by_year[y]), "correct": sum(by_year[y]),
                                      "pairwise_accuracy": round(100 * sum(by_year[y]) / len(by_year[y]), 2)})
            rho, p = spearman_perm(ys, hs)
            keep = [k for k, y in enumerate(ys) if y != 2022]
            rho_x, p_x = spearman_perm([ys[k] for k in keep], [hs[k] for k in keep])
            row = {"session": s, "model": model, "iter": it, "pairs": len(hs), "correct": sum(hs),
                   "pairwise_accuracy": round(100 * sum(hs) / len(hs), 2),
                   "spearman_rho": round(rho, 4), "perm_p": round(p, 4),
                   "rho_without_2022": round(rho_x, 4), "p_without_2022": round(p_x, 4),
                   "source": rel_source(path)}
            for lo, hi in BINS:
                sel = [h for y, h in zip(ys, hs) if lo <= y <= hi]
                key = f"{lo}" if lo == hi else f"{lo}-{hi}"
                row[f"n_{key}"] = len(sel)
                row[f"acc_{key}"] = round(100 * sum(sel) / len(sel), 2) if sel else None
            summary_rows.append(row)
            summary_by_run[(s, model, it)] = {"row": row, "by_year": by_year}
            # The paper's pairwise accuracy must match metrics_paper.py.
            if abs(row["pairwise_accuracy"] - m["pairwise_accuracy"]) > 0.01:
                print(f"warning: {s} {model} iter {it}: {row['pairwise_accuracy']} vs "
                      f"metrics_paper {m['pairwise_accuracy']}", file=sys.stderr)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "per_year.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(per_year_rows[0]))
        w.writeheader()
        w.writerows(per_year_rows)
    with open(out / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary_rows[0]))
        w.writeheader()
        w.writerows(summary_rows)

    # Report: seed harnesses (iteration 0) of every model, then the main-table selected harnesses.
    all_years = sorted(year_counts)
    bin_keys = [f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in BINS]
    seeds = sorted(k for k in summary_by_run if k[2] == 0)
    selected = [k for k in MAIN_TABLE_SELECTED if k in summary_by_run]
    report_runs = [("seed", k) for k in seeds] + [(f"iter {k[2]}", k) for k in selected]

    def binned_row(label: str, key: Tuple[str, str, int]) -> str:
        r = summary_by_run[key]["row"]
        cells = [f"{r[f'acc_{k}']:.1f} ({r[f'n_{k}']})" if r[f"acc_{k}"] is not None else "-" for k in bin_keys]
        return (f"| {key[1]} | {key[0]} | {label} | " + " | ".join(cells)
                + f" | {r['pairwise_accuracy']:.1f} | {r['spearman_rho']:+.3f} | {r['perm_p']:.3f}"
                + f" | {r['rho_without_2022']:+.3f} | {r['p_without_2022']:.3f} |")

    head = ("| Model | Session | Harness | " + " | ".join(bin_keys)
            + " | All | rho | p | rho w/o 2022 | p w/o 2022 |")
    rule = "|" + "---|" * (len(bin_keys) + 8)
    rows_all = summary_rows
    lines = ["# PrimeVul pairwise accuracy by CVE year", "",
             f"{n_scored} scored pairs (5 validation-overlap pairs removed), CVE years "
             f"{all_years[0]}-{all_years[-1]}. Generated by `code/evaluation/cve_year.py` from the "
             f"{len(rows_all)} held-out runs found (runs below {args.min_coverage:.0f}% pair coverage skipped).", "",
             "## Pairs per year", "",
             "| " + " | ".join(str(y) for y in all_years) + " | Total |",
             "|" + "---|" * (len(all_years) + 1),
             "| " + " | ".join(str(year_counts[y]) for y in all_years) + f" | {sum(year_counts.values())} |", "",
             "## Binned pairwise accuracy (%, pairs in brackets)", "",
             "rho is the Spearman correlation between CVE year and pair correctness; "
             "memorization predicts rho < 0 (older CVEs easier). p is a two-sided permutation p-value.", "",
             "### Seed harnesses (iteration 0)", "", head, rule]
    lines += [binned_row("seed", k) for k in seeds]
    lines += ["", "### Selected harnesses from the main table", "", head, rule]
    lines += [binned_row(f"iter {k[2]}", k) for k in selected]
    lines += ["", "## Every year (pairwise accuracy %)", "",
              "| Model | Session | Harness | " + " | ".join(str(y) for y in all_years) + " |",
              "|" + "---|" * (len(all_years) + 3)]
    for label, key in report_runs:
        by = summary_by_run[key]["by_year"]
        lines.append(f"| {key[1]} | {key[0]} | {label} | "
                     + " | ".join(pct(sum(by.get(y, [])), len(by.get(y, []))) for y in all_years) + " |")
    seed_rows = [summary_by_run[k]["row"] for k in seeds]
    lines += ["", "## All runs", "",
              "| Runs | rho < 0 | p < 0.05 | p < 0.05 and rho < 0 | rho < 0 w/o 2022 | p < 0.05 w/o 2022 |",
              "|---|---|---|---|---|---|"]
    for name, rr in (("seed harnesses", seed_rows), ("all held-out runs", rows_all)):
        lines.append(f"| {len(rr)} {name} | {sum(r['spearman_rho'] < 0 for r in rr)} | "
                     f"{sum(r['perm_p'] < 0.05 for r in rr)} | "
                     f"{sum(r['perm_p'] < 0.05 and r['spearman_rho'] < 0 for r in rr)} | "
                     f"{sum(r['rho_without_2022'] < 0 for r in rr)} | "
                     f"{sum(r['p_without_2022'] < 0.05 for r in rr)} |")
    lines += ["", "Per-run values: `summary.csv`; per-year counts: `per_year.csv`."]
    (out / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nWrote {out}/per_year.csv, summary.csv, report.md")


if __name__ == "__main__":
    main()
