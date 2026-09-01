# Research paper

This directory contains the anonymous manuscript for **Read Before You Run:
Zero-Execution Detection of Malicious Agent Skills**.

- [`Read-Before-You-Run.pdf`](Read-Before-You-Run.pdf) is the verified
  seven-page paper.
- `main.tex`, `sections/`, `figures/`, and `references.bib` are the complete
  LaTeX source.
- `IEEEtran.cls` is included to make the working layout reproducible. A target
  submission venue has not been selected.

Build with:

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

The paper reports the source-disjoint benchmark on the intersection of 977
successfully analyzed packages. Datasets, API credentials, and generated run
outputs are intentionally excluded from this repository; preparation and
evaluation commands are documented in the project root README.
