# Skills Detector

A compact, zero-execution detector for malicious Agent Skills. It reads Skill
instructions, code, and configuration as untrusted bytes, extracts
security-relevant evidence, and optionally asks a GPT model for a constrained
semantic verdict. It never installs dependencies, imports target modules, or
executes Skill content.

![Zero-execution detection pipeline](assets/method-overview.png)

This diagram is the repository's architecture reference. Implementation changes
should remain traceable to its two independent branches: high-level declaration
extraction and static behavior extraction.

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

## Sensitive-object extraction

`data/library/sensitive_objects.json` is a versioned, reviewable rule library.
Each object class defines four observable forms: human-readable aliases, file
paths, environment-variable names, and program APIs. The extractor normalizes
matches such as `~/.ssh/id_rsa` and `SSH_PRIVATE_KEY` to one object identifier
and records the object category, severity, match type, file, line, and
confidence.

An object match alone is not a malicious verdict. The detector connects it to a
nearby normalized operation such as `read`, `enumerate`, `transmit`, `conceal`,
or `execute_process`. The resulting record has the form
`operation -> sensitive object -> destination`, with source locations and
evidence IDs. These bounded static paths are hypotheses, not claims that a path
is reachable at runtime.

GPT mode uses three isolated structured calls. The first receives only selected
descriptive prose and extracts the declared goal, inputs, outputs, scope,
resources, services, and visible side effects. The second receives only bounded
operational instruction segments and extracts requested actions, objects,
destinations, authorization, visibility, conditionality, and evidence segment
IDs; it does not classify maliciousness. The final call receives both structured
views plus bounded static code/configuration evidence and returns a binary
benchmark verdict and `pass/review/block`. Target Skill content is never run,
and raw instruction segments are not persisted in result files.

## Review taxonomy

`data/library/risk_taxonomy.json` separates three multi-label domains:

- malicious attacks: instruction injection or hijacking, information theft,
  resource destruction or leakage, and unauthorized operations;
- design defects: sensitive-information protection, input handling,
  authentication and authorization, and runtime environment;
- legal and compliance risks: copyright, privacy, compliance requirements, and
  certificates or licenses.

Risk type and disposition are independent. The binary `malicious` label answers
only whether malicious-attack evidence exists. `pass/review/block` is decided
separately from severity, evidence confidence, impact scope, authorization,
reachability, and analysis completeness. Consequently, a sufficiently supported
high-impact design defect or legal risk can be `block` while its malicious binary
label remains `benign`; an uncertain or medium issue becomes `review`. Every
model finding must cite static evidence IDs.

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

PowerShell:

```powershell
$env:OPENAI_API_KEY="..."
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

## Repository layout

```text
Skills-detector/
├── data/
│   ├── downloaded/    # downloaded raw datasets; contents ignored
│   └── library/       # versioned detector rules; local corpora ignored
├── runs/              # generated experiment outputs; contents ignored
├── src/
│   ├── pipeline/      # detector stages
│   ├── tools/         # static-analysis adapters
│   ├── cli.py
│   ├── core.py
│   └── metrics.py
└── tests/
```

Project modules live directly under `src/`; do not add another package layer
such as `src/skills_detector/`.
