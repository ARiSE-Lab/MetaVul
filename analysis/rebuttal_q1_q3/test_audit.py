import json
import tempfile
import unittest
from pathlib import Path
import audit as A

class AuditTests(unittest.TestCase):
    def make_row(self,i,flag,cwes=None,lines=None):
        return dict(index=i,label=1 if i%2==0 else 0,uuid=str(i),vulnerable=flag,
                    verdict_json={'verdict':{'cwe':cwes or ['CWE-79']},'evidence':[{'location':{'start_line':lines or 1,'end_line':lines or 1}}]})

    def score(self,rows):
        gt=[dict(target=1 if i%2==0 else 0,cwe=['CWE-79'],vuln_lines=[1],func='vulnerable_call();') for i in range(4)]
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'p.jsonl';p.write_text('\n'.join(json.dumps(r) for r in rows))
            return A.assess(p,'validation',gt,[str(i) for i in range(4)])

    def test_missed_case_stays_in_denominator(self):
        r=self.score([self.make_row(0,True),self.make_row(1,False),self.make_row(2,False),self.make_row(3,False)])
        self.assertEqual((r['conditional_joint'],r['unconditional_joint']),(100,50))
        self.assertEqual(r['pair_denominator'],2)

    def test_parse_failure_stays_in_denominator(self):
        r=self.score([self.make_row(0,True),self.make_row(1,False),self.make_row(2,None),self.make_row(3,False)])
        self.assertEqual((r['pairwise'],r['unconditional_joint'],r['parse_failures']),(50,50,1))

    def test_first_cwe_only(self):
        r=self.score([self.make_row(0,True,['CWE-89','CWE-79']),self.make_row(1,False),self.make_row(2,True),self.make_row(3,False)])
        self.assertEqual(r['joint_successes'],1)

    def test_location_required(self):
        r=self.score([self.make_row(0,True,lines=2),self.make_row(1,False),self.make_row(2,True),self.make_row(3,False)])
        self.assertEqual(r['joint_successes'],1)

    def test_retry_deduplication(self):
        rows=[self.make_row(0,None),self.make_row(0,True),self.make_row(0,None),self.make_row(1,False),self.make_row(2,True),self.make_row(3,False)]
        r=self.score(rows);self.assertEqual(r['pairwise'],100);self.assertEqual(r['duplicate_records'],2)

    def test_missing_not_silently_excluded(self):
        r=self.score([self.make_row(0,True),self.make_row(1,False)])
        self.assertEqual(r['missing_indices'],[2,3]);self.assertEqual(r['pairwise'],50)

    def test_selection_exact_tie(self):
        rows=[dict(iteration=i,correct_pairs=p,pair_denominator=10,joint_successes=2,conditional_denominator=4,eligible_denominator=8) for i,p in [(0,2),(1,3),(2,3)]]
        self.assertEqual(A.selection(rows,'conditional_joint')['iteration'],1)

    def test_identical_predictions_uncertainty(self):
        row={'_pairs':{0:1,2:0}}
        r=A.uncertainty(row,row,'_pairs');self.assertEqual(r['ci95_pp'],[0,0]);self.assertEqual(r['exact_mcnemar_p'],1)

if __name__=='__main__':unittest.main()
