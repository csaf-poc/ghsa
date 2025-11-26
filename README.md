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

### Optional Sections (Product Tree & Vulnerabilities)
Both `product_tree` and `vulnerabilities` are optional in the CSAF 2.0 specification;
a syntactically valid document can consist solely of the mandatory `document` section.
For clarity and experimentation this prototype chooses to populate them when GHSA provides enough input.

Heuristic choices applied, e.g. ecosystem becomes a top-level language/category branch.

If these assumptions do not align with a consumer’s taxonomy strategy or introduce risk of misinterpretation,
the generation of these sections can be skipped or pruned in the future—yielding a leaner CSAF advisory focused only on tracking metadata.

---
## Limitations and Differences

### CSAF Document
| Aspect                       | GHSA Source                                   | CSAF Expectation                                     | Result / Handling / Assumption                                                                                  |
|------------------------------|-----------------------------------------------|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Acknowledgments              | `credits_detailed` entries                     | `acknowledgments[]` optional                         | Mapped per entry: Names = user.login, Organization = organizations_url, URLs = html_url, Summary via credit type |
| Aggregate severity           | `severity` string                              | `aggregate_severity.text`                            | Direct mapping to `text`; `namespace` omitted                                                                   |
| Category                     | n/a                                            | `document.category` required                         | Fixed constant from config (`Security Advisory`)                                                                 |
| CSAF version                 | n/a                                            | `csaf_version` required                              | Fixed to CSAF 2.0                                                                                                |
| Distribution (TLP)           | n/a                                            | `document.distribution`                              | Set TLP to White by default                                                                                      |
| Language (`lang`)            | n/a                                            | Optional                                             | Default to `en` (GHSA does not provide language)                                                                 |
| Notes                        | `summary`, `description`                       | Optional `notes[]`                                   | Two notes created: Summary + Description                                                                         |
| Publisher: Category          | n/a                                            | Category (e.g., coordinator/discovery/other)         | Use `Discoverer`                                                                                                 |
| Publisher: Issuing Authority | n/a                                            | Issuer                                               | Use `GitHub`                                                                                                     |
| Publisher: Name              | `user.login`, `user.name`                      | Single name                                          | Use `login` because it is always set                                                                             |
| Publisher: Namespace         | `user.html_url`                                | URI/namespace                                        | Use HTMLURL as namespace                                                                                         |
| Publisher: Contact details   | `user.html_url`, optional `user.email`         | Optional contact string                              | Compose: `URL: <html_url>; email: <email>` if present                                                            |
| References                   | URLs in GHSA body                              | Optional references array                            | Not populated                                                                                                 |
| Source language              | n/a                                            | Optional                                             | Not populated                                                                                                    |
| Title                        | `summary`                                      | Required                                             | Use `summary`; nil if empty                                                                                      |
| Tracking: Aliases            | `identifiers[]`                                | Optional list                                        | Map all GHSA identifiers to aliases                                                                              |
| Tracking: ID                 | `ghsa_id`                                      | Required                                             | Use GHSA ID                                                                                                      |
| Tracking: Initial release    | `published_at`                                 | Required (ISO 8601)                                  | Use `published_at`                                                                                                |
| Tracking: Current release    | `updated_at` if > `published_at`               | Required (ISO 8601)                                  | Use `updated_at` if newer, else `published_at`                                                                    |
| Tracking: Revision history   | `published_at`, `updated_at`                   | Required                                             | Synthesized: 1 = published, 2 = updated (if newer); numbers via `strconv.Itoa`                                    |
| Tracking: Status             | n/a                                            | Required                                             | Fixed to `final`                                                                                                 |
| Tracking: Version            | n/a                                            | Required                                             | Length of revision history (as decimal string)                                                                    |
| Digital signatures           | n/a                                            | Optional signing metadata                            | Not populated                                                                                                    |

### Product Tree
| Aspect | GHSA Source | CSAF Expectation | Result / Handling / Assumption                                                                                                                                         |
|--------|-------------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Branch hierarchy | Ecosystem → package name → vulnerable range | Hierarchical branches | Implemented as `Language` → `ProductName` → `ProductVersionRange` → `Product`.                                                                                         |
| Ecosystem category | `package.ecosystem` | Category label | Mapped to `Language` category. Assumption: `Language` comprises programming language. Other categories possible, e.g. Vendor if it is `GitHub` or the `Package Owner`. |
| Product name display | `package.name` and repository path | Full product name | Derived via `getRepositoryName`: third path segment (e.g., `github.com/org/repo` → `repo`), fallback to full package name.                                             |
| Product ID | `package.name` | Stable identifier | Use full package name as `product_id`.                                                                                                                                 |
| Version range formatting | `vulnerable_version_range` | Clean canonical ranges | Whitespace normalized with operator replacement; `<` and `<=` may be substituted with Unicode lookalikes to avoid JSON HTML escaping (see `normalizeOperators`).       |
| Multi-product relationships | Multiple packages per advisory | Cross-product mapping | Each package is a separate branch; no merging across packages.                                                                                                         |
| Full product names | Consolidated list | `full_product_names[]` | Populated alongside branches for all products.                                                                                                                         |

### Vulnerabilities
| Aspect | GHSA Source | CSAF Expectation                | Result / Handling / Assumption |
|--------|-------------|---------------------------------|-------------------|
| Vulnerability count | Single advisory with multiple CWEs | One CWE per flaw                | Single CSAF Vulnerability generated; CWEs reduced to the first (primary) one to respect 1:1 CWE constraint. |
| IDs | `ghsa_id` and `cve_id` | Multiple identifiers            | `IDs[]` includes GHSA ID; `CVE` set if provided. |
| CWE mapping | `cwes[]` | One CWE per vulnerability       | Map first CWE (`id` and `name`), omit others. |
| References | Advisory URL (`html_url`) | Typed references                | One external reference pointing to GHSA HTML page with summary "Advisory HTML URL". |
| Product status | Affected packages | `known_affected`, `fixed`, etc. | All products derived from product tree marked as `KnownAffected`; no unaffected or fixed breakdown yet. |
| Scores (CVSS) | `cvss_severities`, `cvss` legacy | CVSS3 with version              | Prefer CVSS v3.1/v3.0 vectors; legacy CVSS used if v3 absent; unsupported vectors are skipped. Severity derived from base score. |
| Remediations | `patched_versions` per vulnerability | Remediation entries             | If patched versions exist, one `VendorFix` remediation with details "Upgrade to version: <versions>" and product IDs attached. |
| Discovery / release dates | Not distinct in GHSA | Optional fields                 | Omitted; document tracking covers publish/update. |
| Threats / VEX flags | Not present | Optional                        | Omitted. |
| Notes / Title | Advisory-level text | Optional per-vuln               | Omitted to avoid duplication; document notes/title already describe the advisory. |

Not performed: semantic rewriting of version operators, inference of missing ecosystem data, enrichment of vendor/product naming conventions beyond what GHSA provides.
