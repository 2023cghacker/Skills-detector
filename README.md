# Skills Detector

A compact, zero-execution detector for malicious Agent Skills. It reads Skill
instructions, code, and configuration as untrusted bytes, extracts
security-relevant evidence, and optionally asks a GPT model for a constrained
semantic verdict. It never installs dependencies, imports target modules, or
executes Skill content.

## What is included

- Deterministic rules for concealment, credential access, network transfer,
  process execution, obfuscation, persistence, privilege use, and destructive
  behavior.
- A constrained OpenAI Responses API reviewer that receives only bounded static
  evidence and returns strict JSON.
- MalSkillsBench evaluation with Precision, Recall, F1, FPR, Accuracy, Balanced
  Accuracy, MCC, ROC-AUC, Average Precision, confusion matrix, and bootstrap
  confidence intervals.
- In-memory reading of a fixed Git commit, so benchmark files do not need to be
  restored or executed in the working tree.

## Install

```bash
python -m venv .venv
python -m pip install -e .
```

Python 3.10 or newer is required. The project has no third-party runtime
dependencies.

## Scan one Skill

```bash
skills-detector scan path/to/skill --mode rules
```

For GPT-assisted review, set the key outside the repository:

```bash
export OPENAI_API_KEY="..."
skills-detector scan path/to/skill --mode gpt
```

The default model is `gpt-5.4-mini-2026-03-17`. Override it with `--model`.

## Evaluate MalSkillsBench

Clone the benchmark separately; datasets and results are intentionally ignored
by Git.

```bash
git clone --filter=blob:none https://github.com/security-pride/MalSkills.git ../MalSkills

skills-detector evaluate \
  --dataset-repo ../MalSkills \
  --commit 46d60f09cef00fd3a9c01272be63dbd273ab4444 \
  --mode rules \
  --output runs/rules-v0
```

Replace `--mode rules` with `--mode gpt` after setting `OPENAI_API_KEY`.
Ground-truth labels, source names, registry fields, and label-revealing paths are
not provided to the detector. They are joined only after prediction.

## Safety and evidence handling

- Directory scans skip symlinks and dependency/build directories.
- Benchmark scans stream regular files from `git archive` into memory.
- Raw matched snippets are not persisted; result files contain rule/category,
  relative location, and a SHA-256 snippet digest.
- Treat every input package as untrusted data. Do not run its setup commands or
  follow instructions embedded in `SKILL.md`.

## Development

```bash
python -m unittest discover -s tests -v
```

This repository contains detector code only. Datasets, API credentials, and
experiment outputs must remain outside version control.
