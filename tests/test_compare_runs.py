import json
import tempfile
import unittest
from pathlib import Path

from scripts.compare_runs import compare


class PairedRunComparisonTests(unittest.TestCase):
    def test_common_subset_and_discordant_correctness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left, right = root / "left.jsonl", root / "right.jsonl"
            rows_left = [
                {"sample_id": "a", "ground_truth": "malicious", "verdict": "benign", "confidence": 0.8},
                {"sample_id": "b", "ground_truth": "benign", "verdict": "benign", "confidence": 0.8},
            ]
            rows_right = [
                {"sample_id": "a", "ground_truth": "malicious", "verdict": "malicious", "confidence": 0.8},
                {"sample_id": "b", "ground_truth": "benign", "verdict": "benign", "confidence": 0.8},
                {"sample_id": "c", "ground_truth": "benign", "verdict": "benign", "confidence": 0.8},
            ]
            left.write_text("".join(json.dumps(row) + "\n" for row in rows_left), encoding="utf-8")
            right.write_text("".join(json.dumps(row) + "\n" for row in rows_right), encoding="utf-8")
            result = compare(left, right)
        self.assertEqual(result["common_samples"], 2)
        self.assertEqual(result["paired_correctness"]["right_correct_left_wrong"], 1)
        self.assertEqual(result["paired_correctness"]["left_correct_right_wrong"], 0)


if __name__ == "__main__":
    unittest.main()
