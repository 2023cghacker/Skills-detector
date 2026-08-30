import json
import tempfile
import unittest
from pathlib import Path

from src.merge import merge_runs


class MergeTests(unittest.TestCase):
    def test_disjoint_shards_are_merged_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for index, (sample_id, label, verdict) in enumerate((
                ("safe", "benign", "benign"),
                ("bad", "malicious", "malicious"),
            )):
                shard = root / f"shard-{index}"
                shard.mkdir()
                config = {"mode": "model", "samples": 1, "shard_count": 2, "shard_index": index}
                (shard / "config.json").write_text(json.dumps(config), encoding="utf-8")
                record = {"sample_id": sample_id, "ground_truth": label, "verdict": verdict, "decision": "block" if label == "malicious" else "pass", "confidence": 0.9, "truncated": False, "usage": {}}
                (shard / "predictions.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
                inputs.append(shard)
            metrics = merge_runs(inputs, root / "merged")
            self.assertEqual(metrics["n"], 2)
            self.assertEqual(metrics["coverage"]["evaluated"], 2)

    def test_duplicate_sample_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for index in range(2):
                shard = root / f"shard-{index}"
                shard.mkdir()
                (shard / "config.json").write_text(json.dumps({"mode": "model", "samples": 1, "shard_count": 2, "shard_index": index}), encoding="utf-8")
                record = {"sample_id": "same", "ground_truth": "benign", "verdict": "benign", "decision": "pass", "confidence": 0.9, "truncated": False, "usage": {}}
                (shard / "predictions.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
                inputs.append(shard)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                merge_runs(inputs, root / "merged")


if __name__ == "__main__":
    unittest.main()
