import gzip
import json
import tempfile
import unittest
from pathlib import Path

from src.dataset_prep import registry_skill_path, select_registry_candidates


class DatasetPreparationTests(unittest.TestCase):
    def test_registry_skill_path_accepts_files_and_directories(self):
        self.assertEqual(registry_skill_path("security/audit"), "security/audit/SKILL.md")
        self.assertEqual(registry_skill_path("skills/audit/SKILL.md"), "skills/audit/SKILL.md")
        self.assertEqual(registry_skill_path("skills/audit/skill.mdx"), "skills/audit/skill.mdx")

    def test_registry_selection_is_deterministic_and_repository_capped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            category = root / "development"
            category.mkdir()
            skills = [
                {"repo": f"owner/repo-{index // 4}", "path": f"skills/{index}/SKILL.md"}
                for index in range(40)
            ]
            with gzip.open(category / "part-000.json.gz", "wt", encoding="utf-8") as handle:
                json.dump({"skills": skills}, handle)
            first = select_registry_candidates(
                root, categories=("development",), target_per_category=5,
                overfetch_factor=2, per_repo_cap=2, seed=1337,
            )
            second = select_registry_candidates(
                root, categories=("development",), target_per_category=5,
                overfetch_factor=2, per_repo_cap=2, seed=1337,
            )
        self.assertEqual(first, second)
        counts = {}
        for row in first["development"]:
            counts[row["repo"]] = counts.get(row["repo"], 0) + 1
        self.assertLessEqual(max(counts.values()), 2)


if __name__ == "__main__":
    unittest.main()
