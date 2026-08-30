import csv
import tempfile
import unittest
import zipfile
from pathlib import Path

from src.ecosystem import select_repository_matched_rows, skill_blobs_from_zip


class EcosystemDatasetTests(unittest.TestCase):
    def test_repository_matched_sampling_is_balanced(self):
        with tempfile.TemporaryDirectory() as temporary:
            index = Path(temporary) / "index.csv"
            with index.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["source", "repo", "skill_name", "classification", "url"])
                writer.writeheader()
                for source in ("skills.rest", "skillsmp.com"):
                    for repo_index in range(3):
                        url = f"https://example.invalid/{source}/{repo_index}.zip"
                        for label in ("safe", "suspicious"):
                            for item_index in range(3):
                                writer.writerow({"source": source, "repo": str(repo_index), "skill_name": f"{label}-{item_index}", "classification": label, "url": url})
            rows = select_repository_matched_rows(index, per_label=4, rest_fraction=0.5, per_repo_cap=2)
        self.assertEqual(sum(row["classification"] == "safe" for row in rows), 4)
        self.assertEqual(sum(row["classification"] == "suspicious" for row in rows), 4)
        selected = {(row["source"], row["url"], row["classification"]) for row in rows}
        for source, url, _ in selected:
            self.assertIn((source, url, "safe"), selected)
            self.assertIn((source, url, "suspicious"), selected)

    def test_zip_reader_selects_only_named_skill_subtree(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "repo.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("repo-main/skills/alpha/SKILL.md", "---\nname: alpha\n---\n")
                handle.writestr("repo-main/skills/alpha/tool.py", "print('data only')")
                handle.writestr("repo-main/skills/beta/SKILL.md", "---\nname: beta\n---\n")
            blobs = skill_blobs_from_zip(archive, "alpha")
        self.assertEqual(set(blobs), {"SKILL.md", "tool.py"})


if __name__ == "__main__":
    unittest.main()
