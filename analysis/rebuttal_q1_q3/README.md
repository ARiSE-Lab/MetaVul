# Q1/Q3 saved-prediction audit

Analysis for author review, not finalized rebuttal text. No inference or paper changes.
Snapshot: `094436ba3a37b84a17f06728e8e4d9769e2288db` (7 November 2026 audit).

## What the two columns mean

**Selection:** highest validation conditional Joint on the pairwise/Joint frontier;
ties go to higher validation pairwise accuracy, then earliest iteration. The final
tie-break does not affect these choices. Ratios are compared before rounding.
This is a retrospective validation-only analysis, not a preregistered rule.

**Q3 end-to-end Joint:** correctly detected vulnerable function, correct first CWE,
and at least one correct evidence line, divided by **all eligible vulnerable
functions**, including misses. The original numerator and line-matching logic are
unchanged. All PrimeVul results exclude the five overlapping pairs and use 430 pairs.

## Q1: pairwise accuracy under the fixed selection rule

All eight available main comparisons have positive point-estimate gains. This does
not imply eight statistically established improvements; GPT-OSS-120B's interval
reaches zero. The separate GPT-4o result under this rule is missing.

| Optimization → evaluation | Iteration | Seed % | Selected % | Gain, pp [paired 95% CI] | Frontier gain range, pp |
|---|---:|---:|---:|---:|---:|
| Opus 4.6 → Opus 4.6 | 2 | 10.47 | 18.84 | +8.37 [3.95, 12.79] | +7.21 to +8.37 |
| Opus 4.6 → Opus 5 | 2 | 22.56 | 32.09 | +9.53 [5.12, 13.95] | +9.53 to +14.65 |
| Inkling-Small → Inkling-Small | 6 | 8.84 | 15.58 | +6.74 [2.56, 10.93] | +6.74 to +11.86 |
| Inkling-Small → Nemotron | 6 | 12.79 | 19.07 | +6.28 [1.86, 10.70] | +2.09 to +8.37 |
| DeepSeek V4 Flash → DeepSeek V4 Flash | 1 | 13.26 | 24.88 | +11.63 [6.74, 16.51] | +6.51 to +25.81 |
| DeepSeek V4 Flash → GLM-4.7 Flash | 1 | 15.81 | 23.72 | +7.91 [2.56, 13.26] | −1.16 to +7.91 |
| GLM-5.3 → GLM-5.3 | 6 | 18.37 | 23.95 | +5.58 [1.16, 10.00] | +5.58 |
| GLM-5.3 → GPT-OSS-120B | 6 | 14.42 | 19.07 | +4.65 [0.00, 9.30] | +4.65 |

Frontier ranges describe test outcomes, not test-independent choices. Not every
frontier harness improves transfer: GLM-4.7 Flash includes a −1.16-point result.

**Missing GPT-4o results:** DeepSeek iteration 1 is needed for the selected result.
Iterations 5 and 9 are also missing from this snapshot, so a full frontier range
cannot be reported. Iterations 11 and 14 give a partial range of +4.19 to +5.35 pp.
The previously reported iteration 11 is 89/430 (20.70%); test-best iteration 12 is
100/430 (23.26%); seed is 71/430 (16.51%). Neither replaces iteration 1 under this rule.

## Q3: end-to-end Joint at those same selected checkpoints

| Optimization → evaluation | Seed % | Selected % | Change, pp [paired 95% CI] |
|---|---:|---:|---:|
| Opus 4.6 → Opus 4.6 | 12.79 | 7.67 | −5.12 [−7.67, −2.79] |
| Opus 4.6 → Opus 5 | 18.14 | 13.95 | −4.19 [−6.74, −1.86] |
| Inkling-Small → Inkling-Small | 10.93 | 7.91 | −3.02 [−6.28, 0.00] |
| Inkling-Small → Nemotron | 6.28 | 6.98 | +0.70 [−2.33, 3.72] |
| DeepSeek V4 Flash → DeepSeek V4 Flash | 13.95 | 10.00 | −3.95 [−6.51, −1.63] |
| DeepSeek V4 Flash → GLM-4.7 Flash | 13.72 | 1.40 | −12.33 [−15.58, −9.30] |
| GLM-5.3 → GLM-5.3 | 15.12 | 10.93 | −4.19 [−7.21, −1.16] |
| GLM-5.3 → GPT-OSS-120B | 3.72 | 5.12 | +1.40 [−0.70, 3.49] |

Six of eight point estimates decrease. Both positive intervals include zero.
Pairwise discrimination improves, but end-to-end detection/CWE/localization does
not consistently improve. These are different claims, not contradictory results.

### Recompute validation selection with end-to-end Joint

| Session | Conditional frontier | Selected | End-to-end frontier | Selected |
|---|---|---:|---|---:|
| Opus 4.6 | 2, 3 | 2 | 2, 3 | 2 |
| Inkling-Small | 6, 8, 12 | 6 | 0, 6, 8, 12 | 0 |
| DeepSeek V4 Flash | 1, 5, 9, 11, 14 | 1 | 0, 4, 5, 11 | 0 |
| GLM-5.3 | 6 | 6 | 6 | 6 |

Iteration 0 is seed. Reselection chooses seed for Inkling and DeepSeek; subsequent
gains relative to seed are therefore zero by construction. Seed is not removed
after observing this result. This is reselection of saved harnesses, not rerunning
optimization with a new objective. All four validation Joint ranking orders change.
Full validation and descriptive held-out rankings are in the JSON; held-out
rankings never influence selection.

## Reproduce

Requires Python 3.10+ and NumPy. From the repository root:

```sh
python3 -m unittest discover -s analysis/rebuttal_q1_q3 -p 'test_*.py'
python3 analysis/rebuttal_q1_q3/audit.py \
  --opus46-seed /path/to/opus46_seed.jsonl \
  --opus5-seed /path/to/opus5_seed.jsonl \
  --output-dir /tmp/metavul-q1-q3-audit
```

The two standalone Opus seed files referenced by `EXTRA_HELD_RUNS` in the paper
scorer were recovered from the original runs on Darkhero. They are **not included
in this PR** or the checked public results snapshot. Request these inputs from
Arnav for full reproduction. The script fails clearly if either input is missing;
it does not silently substitute another baseline. Their hashes are recorded as
`external/opus46_seed.jsonl` and `external/opus5_seed.jsonl` in
[`results/audit-results.json`](results/audit-results.json). All other paths are
repository-relative. No API key or model call is needed.

The committed JSON is the verified snapshot. Regeneration records the current
checkout commit and input/scorer hashes. No raw predictions or response text are
included in the output. Tables above are rounded from the JSON.

## Checks and limits

- 138 files: 44 validation and 94 held-out/transfer checkpoints, including the two
  Opus seeds. Every included checkpoint has full index coverage. DeepSeek iterations
  2 and 3 have no evaluated checkpoint and are not imputed.
- Strict JSON decoding; label and UUID alignment checks. The legacy Opus 4.6 seed
  lacks UUIDs, so all CVE+index IDs and labels were checked. Its Darkhero ground-truth
  file hash matches the public file. Historical model alias provenance follows the
  paper scorer, not new inference.
- Retry deduplication follows the paper scorer: latest non-null verdict, otherwise
  latest record. No retries are launched. Duplicate binary verdicts do not conflict;
  that does not certify identical evidence text. Counts and hashes are recorded.
- Independently accumulated pairwise counts and conditional Joint counts match
  the public scorer. Eight tests cover misses, parse failures, first-CWE scoring,
  localization, deduplication, missing samples, ties and paired uncertainty.
- Primary Joint eligibility is 123 validation / 430 held-out vulnerable functions.
  The inherited scorer includes five nonempty NVD placeholder CWE labels in
  validation. A numeric-CWE-only sensitivity check leaves 118; the end-to-end
  frontiers and selected iterations remain unchanged.
- 50,000 paired bootstrap resamples, seed 20261107. Pairwise resamples intact pairs;
  Joint resamples eligible vulnerable functions (one per pair). JSON also includes
  exact two-sided McNemar tests. Intervals/tests are unadjusted for multiplicity,
  do not account for project clustering, and do not estimate discovery-run or
  repeated-inference variability.
- Q2 optimizer baselines, new inference, and manuscript edits are outside this PR.
