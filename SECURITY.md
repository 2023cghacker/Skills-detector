# Security policy

Skills Detector analyzes adversarial packages and may surface active security
issues in third-party ecosystems. Please do not place secrets, live malicious
endpoints, weaponized payloads, or unredacted private data in public issues.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/2023cghacker/Skills-detector/security/advisories/new)
for vulnerabilities in this repository, detector-bypass techniques, or
high-confidence findings that require coordinated disclosure. Include:

- the affected detector version or Git commit;
- a minimal, non-executing reproduction when safe;
- the relevant source locations and evidence hashes;
- expected and observed verdicts;
- potential impact and any known affected platform or maintainer.

## Third-party Skill findings

A scanner flag is not a confirmed malicious package. Reports derived from this
project should preserve the package version and provenance, undergo independent
review, and be disclosed to the affected maintainer or platform before public
publication. Public advisories should redact credentials and operational
infrastructure and should distinguish intentional attacks, design defects,
legal risks, and unresolved evidence.

## Research safety boundary

Do not execute a reported Skill merely to validate a static finding. The
project's default workflow is zero execution: target artifacts are inspected as
untrusted data, and uncertainty is retained for human review.
