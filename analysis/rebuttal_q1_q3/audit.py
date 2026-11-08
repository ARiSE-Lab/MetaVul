"""Offline Q1/Q3 audit. Never calls a model or modifies experiment artifacts."""
import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from fractions import Fraction
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO / 'code/evaluation'))
import metrics as M
import metrics_paper as P

SESSIONS = {
    '20260716_181608': 'Opus 4.6',
    '20260909_054308': 'Inkling-Small',
    '20260919_204729': 'DeepSeek V4 Flash',
    '20260922_170038': 'GLM-5.3',
}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def provenance_path(p):
    try:
        return p.resolve().relative_to(REPO.resolve()).as_posix()
    except ValueError:
        return 'external/' + p.name

def strict_load(p):
    text = p.read_text()
    dec, rows, pos = json.JSONDecoder(), [], 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos == len(text):
            break
        row, pos = dec.raw_decode(text, pos)
        assert isinstance(row, dict), p
        rows.append(row)
    return rows

def assess(path, split, gt, uuids):
    raw = strict_load(path)
    assert all(type(r.get('index')) is int for r in raw), path
    assert all(r.get('vulnerable') is None or type(r.get('vulnerable')) is bool for r in raw), path
    by = {r['index']: r for r in P.dedupe(raw)}
    included = [i for i in range(len(gt)) if split == 'validation' or i//2*2 not in P.HELD_EXCLUDE_PAIRS]
    assert all(0 <= i < len(gt) for i in by), path
    missing = sorted(set(included) - set(by))
    matched_uuid = absent_uuid = 0
    for i,r in by.items():
        assert r['label'] == gt[i]['target'], (path,i,'label mismatch')
        if r.get('uuid'):
            assert r['uuid'] == uuids[i], (path,i,'UUID mismatch')
            matched_uuid += 1
        else:
            absent_uuid += 1
            assert split == 'heldout' and r.get('id') == f"{gt[i]['cve']}_{i}", (path,i,'legacy ID mismatch')
    preds = [by[i] for i in included if i in by]
    eligible = [i for i in included if gt[i]['target']==1 and M._get_gt_cwes(gt[i]) and gt[i].get('vuln_lines')]
    flagged = [i for i in eligible if by.get(i,{}).get('vulnerable') is True]
    hits = {i:int(by.get(i,{}).get('vulnerable') is True and
                 M._get_top1_cwe(by[i]) in M._get_gt_cwes(gt[i]) and
                 bool(set(gt[i]['vuln_lines']) & M._get_pred_lines(by[i],gt[i].get('func','')))) for i in eligible}
    pairs = {}
    for i in included[::2]:
        assert gt[i]['target']==1 and gt[i+1]['target']==0
        pairs[i] = int(by.get(i,{}).get('vulnerable') is True and by.get(i+1,{}).get('vulnerable') is False)
    original = M.joint_top1_metrics(preds,gt)
    assert original['joint_top1_both'] == sum(hits.values())
    assert original['joint_top1_total'] == len(flagged)
    pair_check = M.pairwise_accuracy(preds)
    if not missing:
        assert pair_check['correct_pairs']==sum(pairs.values()) and pair_check['total_pairs']==len(pairs)
    duplicates = len(raw)-len(by)
    conflicts = sum(len({r.get('vulnerable') for r in raw if r['index']==i and r.get('vulnerable') is not None})>1 for i in by) if duplicates else 0
    out = dict(path=provenance_path(path),sha256=sha(path),split=split,raw_records=len(raw),unique_records=len(by),
               duplicate_records=duplicates,conflicting_verdict_indices=conflicts,missing_indices=missing,
               uuid_matched=matched_uuid,uuid_absent=absent_uuid,
               parse_failures=sum(r.get('vulnerable') is None for r in preds),
               correct_pairs=sum(pairs.values()),pair_denominator=len(pairs),
               joint_successes=sum(hits.values()),conditional_denominator=len(flagged),eligible_denominator=len(eligible),
               pairwise=100*sum(pairs.values())/len(pairs),
               conditional_joint=100*sum(hits.values())/len(flagged) if flagged else 0,
               unconditional_joint=100*sum(hits.values())/len(eligible) if eligible else 0,
               eligible_recall=100*len(flagged)/len(eligible) if eligible else 0,
               _pairs=pairs,_hits=hits)
    numeric_eligible = [i for i in eligible if any(re.fullmatch(r'CWE-\d+',c) for c in M._get_gt_cwes(gt[i]))]
    out['numeric_cwe_eligible'] = len(numeric_eligible)
    out['numeric_cwe_joint_successes'] = sum(hits[i] for i in numeric_eligible)
    return out

def val_fraction(r, metric):
    if metric=='pairwise': return Fraction(r['correct_pairs'],r['pair_denominator'])
    denom = r['conditional_denominator'] if metric=='conditional_joint' else r['eligible_denominator']
    return Fraction(r['joint_successes'],denom) if denom else Fraction(0)

def frontier(rows,metric):
    front=[]
    for r in sorted(rows,key=lambda r:r['iteration']):
        v=(val_fraction(r,'pairwise'),val_fraction(r,metric))
        if any(all(a>=b for a,b in zip((val_fraction(s,'pairwise'),val_fraction(s,metric)),v)) and
               (val_fraction(s,'pairwise'),val_fraction(s,metric))!=v for s in rows): continue
        if any((val_fraction(s,'pairwise'),val_fraction(s,metric))==v for s in front): continue
        front.append(r)
    return front

def selection(rows,metric):
    return max(frontier(rows,metric),key=lambda r:(val_fraction(r,metric),val_fraction(r,'pairwise'),-r['iteration']))

def uncertainty(seed,selected,key):
    a,b=seed[key],selected[key]
    assert a.keys()==b.keys()
    dif=np.array([b[i]-a[i] for i in sorted(a)],dtype=np.int8)
    counts=np.array([(dif==-1).sum(),(dif==0).sum(),(dif==1).sum()])
    # Multinomial sampling of paired differences is equivalent to resampling pairs.
    rng=np.random.default_rng(20261107)
    boot=rng.multinomial(len(dif),counts/len(dif),size=50000)
    delta=100*(boot[:,2]-boot[:,0])/len(dif)
    losses,wins=int(counts[0]),int(counts[2]); n=losses+wins
    p=min(1.,2*sum(math.comb(n,k) for k in range(min(losses,wins)+1))/2**n) if n else 1.
    return dict(delta_pp=float(100*dif.mean()),ci95_pp=np.quantile(delta,[.025,.975]).tolist(),
                seed_only=losses,selected_only=wins,exact_mcnemar_p=p,units=len(dif))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--opus46-seed', type=Path, required=True, help='Standalone legacy Opus 4.6 SCoT predictions; not included in the public results.')
    parser.add_argument('--opus5-seed', type=Path, required=True, help='Standalone Opus 5 SCoT predictions; not included in the public results.')
    parser.add_argument('--output-dir', type=Path, default=ROOT/'results')
    args = parser.parse_args()
    for p in (args.opus46_seed,args.opus5_seed):
        if not p.is_file():
            parser.error(f'Seed predictions not found: {p}')
    gt={s:P.load_gt(p) for s,p in [('validation',P.VAL_GT),('heldout',P.HELD_GT)]}
    vr=strict_load(P.VAL_GT)
    uuids={'validation':[u for r in vr for u in r['uuid']], 'heldout':[r['uuid'] for r in gt['heldout']]}
    rows=[]
    for session in SESSIONS:
        base=REPO/'results'/session
        for p in sorted((base/'meta-vul/outputs'/session).glob('iter_*/predictions.jsonl')):
            r=assess(p,'validation',gt['validation'],uuids['validation'])
            r.update(session=session,iteration=int(p.parent.name.split('_')[1]),model=SESSIONS[session]);rows.append(r)
        for p in sorted(base.glob('*-agent/outputs/held_out_primevul_*/**/predictions.jsonl')):
            folder=next(x for x in p.parts if x.startswith('held_out_primevul_'))
            m=P.HELD_RE.match(folder); assert m and m[1]==session
            r=assess(p,'heldout',gt['heldout'],uuids['heldout'])
            r.update(session=session,iteration=int(m[2]),model=m[3]);rows.append(r)
    for model,p in [('opus-4-6',args.opus46_seed),('opus-5',args.opus5_seed)]:
        if p.exists():
            r=assess(p,'heldout',gt['heldout'],uuids['heldout'])
            r.update(session='20260716_181608',iteration=0,model=model); rows.append(r)
    summaries=[];comparisons=[];rankings=[]
    for session,name in SESSIONS.items():
        val=[r for r in rows if r['session']==session and r['split']=='validation' and not r['missing_indices']]
        old,new=selection(val,'conditional_joint'),selection(val,'unconditional_joint')
        info=dict(session=session,name=name,old_frontier=[r['iteration'] for r in frontier(val,'conditional_joint')],
                  new_frontier=[r['iteration'] for r in frontier(val,'unconditional_joint')],
                  old_selected=old['iteration'],new_selected=new['iteration'],
                  old_joint_ranking=[r['iteration'] for r in sorted(val,key=lambda r:(-val_fraction(r,'conditional_joint'),-val_fraction(r,'pairwise'),r['iteration']))],
                  new_joint_ranking=[r['iteration'] for r in sorted(val,key=lambda r:(-val_fraction(r,'unconditional_joint'),-val_fraction(r,'pairwise'),r['iteration']))])
        summaries.append(info)
        restricted=[{**r,'joint_successes':r['numeric_cwe_joint_successes'],'eligible_denominator':r['numeric_cwe_eligible']} for r in val]
        info['numeric_cwe_sensitivity_selected']=selection(restricted,'unconditional_joint')['iteration']
        info['numeric_cwe_sensitivity_frontier']=[r['iteration'] for r in frontier(restricted,'unconditional_joint')]
        held=[r for r in rows if r['session']==session and r['split']=='heldout']
        for model in sorted({r['model'] for r in held}):
            group={r['iteration']:r for r in held if r['model']==model and not r['missing_indices']}
            seed=group.get(0)
            rankings.append(dict(session=session,model=model,
                conditional_ranking=[r['iteration'] for r in sorted(group.values(),key=lambda r:(-val_fraction(r,'conditional_joint'),r['iteration']))],
                unconditional_ranking=[r['iteration'] for r in sorted(group.values(),key=lambda r:(-val_fraction(r,'unconditional_joint'),r['iteration']))]))
            comp=dict(session=session,model=model,old_selected=old['iteration'],new_selected=new['iteration'],
                      available_iterations=sorted(group),missing_frontier=[i for i in info['old_frontier'] if i not in group])
            for label,it in [('fixed',old['iteration']),('reselected',new['iteration'])]:
                selected=group.get(it)
                if seed and selected:
                    comp[label]=dict(seed_pairwise=seed['pairwise'],selected_pairwise=selected['pairwise'],
                                     pairwise=uncertainty(seed,selected,'_pairs'),
                                     seed_joint=seed['unconditional_joint'],selected_joint=selected['unconditional_joint'],
                                     unconditional_joint=uncertainty(seed,selected,'_hits'))
                else: comp[label]=dict(blocked='Missing complete seed or selected checkpoint')
            if seed:
                fs=[group[i] for i in info['old_frontier'] if i in group]
                comp['frontier_pairwise_gain_range_pp']=[min(r['pairwise']-seed['pairwise'] for r in fs),max(r['pairwise']-seed['pairwise'] for r in fs)] if fs else None
                comp['range_complete']=not comp['missing_frontier']
            comparisons.append(comp)
    payload=dict(source_commit=subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
                 data_hashes={provenance_path(p):sha(p) for p in [P.VAL_GT,P.HELD_GT]},
                 scoring_hashes={provenance_path(p):sha(p) for p in [REPO/'code/evaluation/metrics.py',REPO/'code/evaluation/metrics_paper.py']},
                 excluded_pair_starts=sorted(P.HELD_EXCLUDE_PAIRS),
                 sessions=summaries,comparisons=comparisons,heldout_descriptive_rankings=rankings,
                 rows=[{k:v for k,v in r.items() if not k.startswith('_')} for r in rows])
    args.output_dir.mkdir(parents=True,exist_ok=True)
    output=args.output_dir/'audit-results.json'
    output.write_text(json.dumps(payload,indent=2)+'\n')
    print(f'Wrote {len(rows)} checkpoint audits to {output}')

if __name__=='__main__': main()
