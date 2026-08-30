import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.cli import _evaluate
from src.core import scan_blobs


class EvaluateFallbackTests(unittest.TestCase):
    def test_sample_failure_is_recorded_and_later_samples_continue(self):
        rows = [
            {"Skill_name": "owner/fails", "Ground_truth_path": "one", "Label": "malicious"},
            {"Skill_name": "owner/succeeds", "Ground_truth_path": "two", "Label": "benign"},
        ]
        result = scan_blobs({"SKILL.md": b"A harmless formatter."})
        snapshot = MagicMock()
        snapshot.package.return_value = {"SKILL.md": b"test"}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            args = argparse.Namespace(
                provider="deepseek", model="deepseek-v4-flash", mode="model",
                dataset_repo=Path(temporary), labels_csv="labels.csv",
                limit=0, per_class_limit=0, sample_id=None,
                commit="test-commit", output=output, resume=False, threshold=5,
            )
            with patch("src.cli.require_api_key"), patch("src.cli._rows", return_value=rows), patch(
                "src.cli.GitSnapshot", return_value=snapshot,
            ), patch("src.cli._predict", side_effect=[RuntimeError("synthetic failure"), (result, {})]), redirect_stdout(io.StringIO()):
                code = _evaluate(args)
            self.assertEqual(code, 0)
            predictions = [json.loads(line) for line in (output / "predictions.jsonl").read_text(encoding="utf-8").splitlines()]
            failures = [json.loads(line) for line in (output / "failures.jsonl").read_text(encoding="utf-8").splitlines()]
            metrics = json.loads((output / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual([item["sample_id"] for item in predictions], ["owner/succeeds"])
            self.assertEqual([item["sample_id"] for item in failures], ["owner/fails"])
            self.assertEqual(metrics["coverage"]["evaluated"], 1)
            self.assertEqual(metrics["coverage"]["failed"], 1)


if __name__ == "__main__":
    unittest.main()
