# Data

| File | Contents |
|---|---|
| `titanvul_cweval_optimization_val_uuid.jsonl` | Validation set used for optimization: 202 pairs (404 functions), 150 from TitanVul and 52 from CWEval, C and C++ only |
| `primevul/test_with_vul_lines_uuid.jsonl` | Held-out PrimeVul paired test set: 870 functions (5 pairs overlapping the validation set are excluded at scoring, leaving 430 pairs) |

The scripts that built these files are in `scripts/`. Run every command below from `code/`.

## Raw inputs (not included)

- TitanVul CSV, saved as `data/titanvul/TitanVul.csv`
- CWEval benchmark repo, cloned to `cloned_repos/CWEval/`
- PrimeVul test set, saved as `data/primevul/test.jsonl`

## Validation set (TitanVul + CWEval)

```bash
# 1. Convert each benchmark to paired JSONL with diff-based vuln_lines
python data/scripts/convert_titanvul.py \
  --input data/titanvul/TitanVul.csv \
  --output data/titanvul/titanvul_paired.jsonl
python data/scripts/convert_cweval.py \
  --input cloned_repos/CWEval/benchmark/core \
  --lang-dir cloned_repos/CWEval/benchmark/lang \
  --output data/cweval/cweval_paired.jsonl

# 2. Split both by language (writes data/{titanvul,cweval}/splits/)
python data/scripts/split_paired_jsonl_by_language.py

# 3. Keep all C/C++ CWEval pairs and sample 150 TitanVul C/C++ pairs, stratified by CWE
python data/scripts/build_titanvul_cweval_optimization_val_set.py \
  --titanvul-splits data/titanvul/splits \
  --cweval-splits data/cweval/splits \
  --titanvul-n 150 \
  --output data/titanvul_cweval_optimization_val.jsonl \
  --seed 42

# 4. Add per-function UUIDs
python data/scripts/add_uuids.py data/titanvul_cweval_optimization_val.jsonl
```

How the TitanVul sample is drawn (step 3):
- Pool: 17,101 C/C++ TitanVul pairs.
- Strata are the raw `cwe_id` string, so a multi-CWE label such as `CWE-120,CWE-362` is its own stratum. Each stratum gets at least one pair.
- Pairs with no usable CWE (empty, `NVD-CWE-noinfo`, `NVD-CWE-Other`) get a proportional budget with a floor of 5. Since about half the pool has no CWE, 84 of the 150 sampled pairs are in this group (79 empty, 3 `NVD-CWE-Other`, 2 `NVD-CWE-noinfo`).
- PrimeVul is not filtered out, which is why 5 PrimeVul test pairs overlap the sample.

## Held-out set (PrimeVul)

```bash
python data/scripts/build_vul_lines.py \
  --input data/primevul/test.jsonl \
  --output data/primevul/test_with_vul_lines.jsonl
python data/scripts/add_uuids.py data/primevul/test_with_vul_lines.jsonl
```

## Reproducibility

Steps 1 to 3 are deterministic given the same inputs and seed. `add_uuids.py` uses random UUIDs, so rerunning it gives new IDs. The committed `_uuid.jsonl` files are the ones every run and score in `results/` refers to, so use them as they are instead of regenerating.
