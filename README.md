# GHSA to CSAF Advisory Converter
<!-- TODOs:
- Alternatives to REST API?
- What is the purpose of this tool or why is it necessary?
- 
-->
This repository provides tooling to transform GitHub Security Advisories (GHSA) into Common Security Advisory Framework (CSAF) 2.0 advisories.
Its primary focus is a converter that ingests GHSA JSON (from the GitHub API) and produces a valid CSAF advisory file.

---
## Motivation

This project is an exploratory, proof‑of‑concept attempt to see how far a direct GHSA → CSAF mapping can go without extensive manual curation.
It is not a complete nor authoritative converter, and the output should be treated as a starting point for experimentation, review, and potential enrichment.

Why explore this?
- To surface the practical friction points when aligning an informal ecosystem advisory format (GHSA) with a formal standard (CSAF).
- To provide a lightweight sandbox for evaluating the viability of adopting CSAF for open source package advisories.
- To document gaps and edge cases rather than to claim seamless interoperability.

What this is NOT:
- A drop‑in production adapter guaranteeing schema fullness or semantic fidelity in all cases.
- An exhaustive coverage of all CSAF fields or advanced constructs (distribution, localization, signature handling, etc.).
- A normalization engine that infers missing business/vendor context.

Expectation management & disclaimers:
- Information loss is unavoidable: many CSAF fields lack source data in GHSA and are intentionally omitted.
- Some field representations are simplified or flattened (e.g., product taxonomy) to keep the prototype maintainable.
- No guarantee that version range formatting or score sets match best‑practice CSAF authoring guidelines.
- Consumers should perform validation and apply domain-specific post‑processing before relying on the output.

Value of the prototype:
- Makes differences concrete by producing tangible CSAF documents from real GHSA examples.
- Highlights where additional metadata or tooling would be required for a robust pipeline.
- Serves as a foundation others can iterate on (fill gaps, strengthen mappings, add validation).
