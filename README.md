# GHSA to CSAF Advisory Converter
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
## GHSA Source/API Decision Context
This repository includes a small analysis of which GHSA source and GitHub API are most suitable for **GHSA -> CSAF conversion**:

- [data_source_and_api_strategy.md](data_source_and_api_strategy.md)

The analysis covers:
- Repository GHSA vs Global GHSA for converter data quality and scope.
- GraphQL vs REST capabilities with live query evidence.
- A decision matrix and final recommendation for single-API implementation.

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
| Tracking: Generator          | converter metadata                              | Optional (`tracking.generator.engine`)               | Populated as engine name/version (`ghsa-to-csaf`, `0.1.0`) to satisfy CSAF schema expectations and identify producer |
| Tracking: Status             | n/a                                            | Required                                             | Fixed to `final`                                                                                                 |
| Tracking: Version            | n/a                                            | Required                                             | Length of revision history (as decimal string)                                                                    |
| Digital signatures           | n/a                                            | Optional signing metadata                            | Not populated                                                                                                    |

### Product Tree
| Aspect | GHSA Source | CSAF Expectation | Result / Handling / Assumption                                                                                                                                         |
|--------|-------------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Branch hierarchy | Ecosystem → package name → vulnerable range | Hierarchical branches | Implemented as `Language` → `ProductName` → `ProductVersion` → `Product` (range text stored in branch name).                                                          |
| Ecosystem category | `package.ecosystem` | Category label | Mapped to `Language` category. Assumption: `Language` comprises programming language. Other categories possible, e.g. Vendor if it is `GitHub` or the `Package Owner`. |
| Product name display | `package.name` and repository path | Full product name | Derived via `getRepositoryName`: for paths on flat-namespace VCS hosts (`github.com`, `bitbucket.org`) the repo segment is extracted (e.g., `github.com/org/repo/v5` → `repo`). GitLab is excluded because subgroups make the repo boundary unknowable from the path. All other names (npm, PyPI, Maven, Composer, Go vanity imports, etc.) are returned as-is. |
| Product ID | `package.name`, `vulnerable_version_range` | Stable identifier | Use `<package.name>:<normalized_version_range>` as `product_id` (operators encoded as `lte-`, `gte-`, `lt-`, `gt-`) so entries with different ranges remain unique within one document and contain no HTML-escapable characters.                                     |
| Version range formatting | `vulnerable_version_range` | Clean canonical ranges | In branch names: operators are rewritten to ASCII words (e.g. `<=` → `less or equal`) for readability (see `normalizeOperators`). In product IDs: operators are encoded as compact tokens (see `normalizeVersionRangeForID`) to avoid HTML-escaping.             |
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
| Scores (CVSS) | `cvss_severities`, `cvss` legacy | CVSS3 with version              | Source precedence: `cvss_severities.cvss_v3` first, then legacy `cvss`. If only meaningful `cvss_v4` exists, no CVSS score is emitted (to avoid lossy v4->v3 projection), a warning is logged, and a vulnerability note is added. Severity for emitted CVSS v3 remains derived from base score. |
| Remediations | `patched_versions` per vulnerability | Remediation entries             | If patched versions exist, one `VendorFix` remediation with details "Upgrade to version: <versions>" and product IDs attached. |
| Discovery / release dates | Not distinct in GHSA | Optional fields                 | Omitted; document tracking covers publish/update. |
| Threats / VEX flags | Not present | Optional                        | Omitted. |
| Notes / Title | Advisory-level text | Optional per-vuln               | Omitted to avoid duplication; document notes/title already describe the advisory. |

Not performed: semantic rewriting of version operators, inference of missing ecosystem data, enrichment of vendor/product naming conventions beyond what GHSA provides.

---
## Design and Workflow
High-level pipeline:
1. Input acquisition: GHSA advisory JSON loaded into internal model (`models/ghsa/...`).
2. Conversion orchestrator (`service/converter/`) assembles CSAF structures.
3. Product tree construction (`producttree.go`): branches categorized (language → product name → product version [range text] → product instance).
4. Vulnerability section (`vulnerabilities.go`): maps GHSA vulnerabilities, identifiers, scores, references.
5. Revision history (`document.go`): timestamps converted into sequential revision numbers (fixed from earlier control character issue by using proper integer → string conversion).
6. Tracking and metadata: populates minimal CSAF tracking fields from GHSA advisory context.
7. Serialization: CSAF advisory saved (current path uses upstream library defaults; HTML escaping of `<` may appear as `\u003c`).

Development notes:
- Project layout mirrors responsibility (converter, downloader, store, models, schemas).
- Utilities (`internal/utils/ref.go`) help with pointer/value wrapping to reduce noise when assembling CSAF structs.
- Tests exist for product tree and downloader components to validate structure and basic behaviors.
- Incremental enhancements can extend mapping coverage without breaking existing schema usage.

---
## Usage
Prerequisites: Go ≥ 1.21.

Run converter:
```bash
go run cmd/main.go <GHSA_INPUT> <OUTPUT_TARGET>
```

`<GHSA_INPUT>` can be:
- A single GHSA URL (browser or API).
- A repository URL (browser, API, or bare `OWNER/REPO`) to fetch and convert **all** published advisories for that repository.

`<OUTPUT_TARGET>` can be:
- A filename (for a single advisory).
- A directory (for batch processing repository listings). If the directory doesn't exist, it will be created. Filenames in batch mode are derived from the GHSA ID (lowercase).

Supported URL formats (both repository and global):
- Repository Listing: `https://github.com/OWNER/REPO`, `OWNER/REPO`, `https://github.com/OWNER/REPO/security/advisories`
- Repository Browser: `https://github.com/OWNER/REPO/security/advisories/GHSA-XXXX-XXXX-XXXX`
- Global Browser:     `https://github.com/advisories/GHSA-XXXX-XXXX-XXXX`
- API equivalents for all the above.

Example (single):
```bash
go run cmd/main.go https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp out.json
```

Example (batch repository):
```bash
go run cmd/main.go https://github.com/golang-jwt/jwt advisories_output/
```

Validate output against the CSAF 2.0 schema:
```bash
python3 scripts/validate.py out.json
```

---
## Advisory Types and Schemas

This tool supports both **Repository-level** and **Global** GitHub Security Advisories. From the perspective of running the program, there is no difference; the tool automatically detects the advisory type from the provided URL.

### Schema Differences
While they share core fields (like `ghsa_id`, `summary`, and `description`), the Repository and Global GHSA schemas are not identical:

- **Repository GHSA**: Contains GitHub-specific metadata related to the repository where the advisory was reported. This includes fields like `publisher`, `author`, `state`, and `credits_detailed`.
- **Global GHSA**: Focused on ecosystem-wide vulnerability data. It includes additional root-level information such as `epss` scores, `cwes`, and a `type` (e.g., `reviewed`, `malware`). It uses a different structure for `credits` and slightly different field names for affected versions (e.g., `first_patched_version` vs `patched_versions`).

Neither schema is a strict subset of the other. Repository advisories are more publication-centric on GitHub, while Global advisories are more vulnerability-centric for the wider ecosystem.

### CVSS Optionality
A significant challenge in converting GHSA to CSAF is that **CVSS data is not mandatory in GHSA**. Since CSAF documents typically rely on standardized severity scores for automated risk assessment, the absence of CVSS in the source GHSA results in a less complete CSAF document. The converter handles missing CVSS by omitting the scores section in the output, which may limit its utility in some automated pipelines.

---
## Data Mapping (GHSA → CSAF)
- GHSA advisory ID → `document.tracking.id` and vulnerability IDs list.
- CVE (if present) → `vulnerabilities[].cve`.
- Package ecosystem/name → Product tree branches.
- Severity / CVSS → `vulnerabilities[].scores[]` with score type set appropriately.
- References (URLs) → `vulnerabilities[].references[]`.
- Published / Updated timestamps → `document.tracking.revision_history[]` entries.
- Description / summary → `vulnerabilities[].notes[]` (if implemented; may be minimal).

Unsupported or partially mapped:
- Advisory aliases beyond CVE/GHSA ID (unless provided explicitly).
- Rich supplier, distributor, and release channel metadata.
- Full remediation guidance if GHSA lacks structured fix details.

---
## JSON Encoding Notes
We rely on the upstream `gocsaf.SaveAdvisory` function to serialize the CSAF advisory.
That helper internally creates its own `json.Encoder` with Go's default settings;
we cannot inject `SetEscapeHTML(false)`.
As a consequence characters `<`, `>`, and `&` are HTML‑escaped in the emitted JSON (e.g. `<` becomes `\u003c`).
For version range fields this makes strict comparisons `<` and `<=` awkward.
To keep output ASCII-only and avoid escaped sequences without changing the encoder, the converter normalizes operators into descriptive English phrases:
- `<=` → `less or equal`
- `>=` → `greater or equal`
- `<` → `less than`
- `>` → `greater than`

This sidesteps HTML escaping while preserving the intended comparison semantics in a human‑readable form. The trade‑off is that downstream tooling expecting literal operators will need to adapt.
A more robust long‑term solution would be either (a) bypassing `gocsaf.SaveAdvisory` and performing our own encoding with `enc.SetEscapeHTML(false)`, or (b) post‑processing the JSON to unescape these characters.

---
## Examples
See `examples/` directory:
- `global_GHSA/GHSA-cpj6-fhp6-mr6j.json` (global advisory input).
- `repository_GHSA/GHSA-mh63-6h87-95cp.json` (repository advisory input).
- `repository_GHSA/csaf_example_output.json` (sample converted CSAF output).

You can diff the input vs. output to observe:
- Product tree hierarchy creation.
- Revision history entries.
- Identifier and reference mappings.

---
## Troubleshooting
| Symptom | Cause | Resolution |
|---------|-------|-----------|
| Escaped `<` in version range | Default JSON encoder HTML escape | Accept as-is or post-process; custom encoder if allowed. |
| Missing product branches | Empty `vulnerabilities` list in GHSA | Validate input advisory content; ensure downloader acquired full data. |
| Lost CVSS vector | GHSA advisory lacks usable CVSS v3 (`cvss_v3` and legacy `cvss`) | CSAF omits score; if meaningful `cvss_v4` exists, converter logs a warning and adds a vulnerability note about v4-only data. |
| Unexpected whitespace in ranges | GHSA formatting quirks | Normalization collapses spaces automatically. |

Logging: converter emits structured logs (via `slog`) for save operations; enable debug verbosity if expanding.

---
## Roadmap
- [x] Support global GHSA
- [x] Support repository advisory listings (batch processing)
- [x] Systematic output handling (file vs directory)
- [ ] Check if CLI could be improved
- [ ] Check hidden GHSA (requires authentication/GITHUB_TOKEN)
- [ ] Extensive review & additional tests
- [ ] Perform validation against more edge cases

---
## License and Acknowledgments
Licensed under the terms in `LICENSE` (refer to file). Built upon:
- `github.com/gocsaf/csaf` for CSAF model structures.
- GitHub Security Advisory data as source material.

Contributions, issues, and suggestions are welcome.
