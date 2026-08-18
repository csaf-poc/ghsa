# GHSA Data Source and API Strategy Conclusion

## Why both GraphQL and REST exist on GitHub

GitHub explicitly supports **both** APIs and states that some features are available on one API but not the other.

- **GraphQL** is optimized for read efficiency and shape control: fetch exactly the fields you need, and combine nested data in one request.
- **REST** is optimized for broad feature coverage and workflow-oriented operations using resource endpoints and HTTP verbs.

GitHub's own guidance is to use the API that best fits the use case, not to assume strict parity between GraphQL and REST.

---

## Context for this project: suitability for GHSA -> CSAF conversion

The key question is: **which source/API best supplies the fields needed to produce better CSAF documents**.

### CSAF-relevant GHSA data needed by the converter

For CSAF mapping quality, the most relevant source attributes are:

- advisory identifiers (`GHSA`, `CVE`)
- summary/description
- severity + CVSS vectors/scores
- publish/update timestamps
- CWEs
- affected package ecosystem/name
- vulnerable version range + fixed version hint (`patched_versions` or `first_patched_version`)
- references
- optional enrichment (EPSS, credits)

### Suitability by source (for conversion purpose only)

| Conversion goal | Better source | Why |
|---|---:|---|
| Repository-centric CSAF generation (maintainer-issued advisories, repo workflow context) | ✅ Repository GHSA | Preserves repository advisory semantics (state/workflow context, repo-published perspective). |
| Ecosystem-scale/public-intelligence CSAF generation | ✅ Global GHSA | Better as a broad curated feed with advisory-database enrichment and aggregation across sources. |

Global GHSA is better when you want to ingest many already-public advisories across many ecosystems in one bulk feed, while repository GHSA is better when you need the repo-specific advisory context and workflow state of a single project.

### Suitability by API (for conversion purpose only)

| API | Suitable for converter as sole API | Why |
|---|---:|---|
| REST only | ✅✅ | Covers both global + repository advisory endpoints and repository-scoped retrieval/listing workflows. |
| GraphQL only | ⚠️ | Good read model for advisory content, but missing repository advisory scope/fields/operations that can matter depending on converter scope. |

This is why the recommendation stays REST-only when one API must be chosen.

---

## 1) Repository GHSA vs Global GHSA: is one superior?

Short answer: **neither is universally superior**; they serve different purposes.

### Why GitHub differentiates them

From GitHub docs:

- **Repository security advisories** are a maintainer workflow for private coordination and disclosure:
    - draft advisories
    - private collaboration
    - temporary private forks
    - publication when patch is ready
- **GitHub Advisory Database (global advisories)** is a public dataset aggregated from multiple sources (GitHub advisories, NVD, ecosystem feeds, etc.), with types like reviewed / unreviewed / malware and enrichment such as EPSS.

GitHub states that repository advisories for supported ecosystems are published into the global advisory database.

### Could we use only Global GHSA?

Yes, but if we want more information about advisory lifecycle/workflow semantics (drafts, collaborator state, private-fork coordination, explicit repo advisory state transitions), global-only is insufficient.

### Repository vs Global capability table

| Capability | Repository GHSA | Global GHSA |
|---|---:|---:|
| Publicly consumable for CSAF | ✅ | ✅ |
| Draft/unpublished advisory lifecycle | ✅ | ❌ |
| Advisory collaboration metadata (collaborators/teams, credits_detailed workflow context) | ✅ | ❌ |
| Temporary private fork workflow | ✅ | ❌ |
| Aggregated multi-source corpus | ❌ | ✅ |
| EPSS enrichment in advisory dataset | ❌ | ✅ |

Legend: ✅ supported, ❌ not supported

---

## 2) Concrete example: `GHSA-mh63-6h87-95cp`

We queried all three representations:

1. REST repository advisory endpoint
2. REST global advisory endpoint
3. GraphQL `securityAdvisory(ghsaId: "...")`

### Observed differences (same GHSA ID)

| Field / Behavior | REST Repository | REST Global | GraphQL |
|---|---:|---:|---:|
| `ghsa_id` / `ghsaId` | ✅ | ✅ | ✅ |
| CVE value available | ✅ (`cve_id`) | ✅ (`cve_id`) | ✅ (via `identifiers`, not direct `cveId`) |
| Advisory state (`published`/`draft`/...) | ✅ | ❌ | ❌ |
| Publisher metadata | ✅ | ❌ | ❌ |
| Detailed credits structure | ✅ (`credits_detailed`) | ❌ | ❌ |
| EPSS | ❌ | ✅ | ✅ |
| CVSS v3/v4 severities | ✅ | ✅ | ✅ |
| Vulnerability package/version data | ✅ | ✅ | ✅ |

Additional observation from this GHSA:

- Repository and global forms are not always byte-identical in timestamps/text and vulnerability representation details.

---

## 3) “Retrieve all GHSAs for a given repository”: Query language the better choice?
The idea: Maybe for this specific case (we want to add soon), the GraphQL shines in its ability to fetch nested data in one request.

### REST

Direct endpoint:

- `GET /repos/{owner}/{repo}/security-advisories`

Repository scope is first-class and supports filters like `state`.

### GraphQL

For security advisories:

- `securityAdvisories` has **no repository argument** (verified by live query error).
- You can approximate via `securityVulnerabilities(ecosystem, package)` and dedupe advisories, but this is package-centric, not repository-scoped, and can require multiple package variants (`.../jwt`, `.../jwt/v4`, `.../jwt/v5`).

### Conclusion for this feature

For “all advisories for repository X”, **REST is clearly superior** (native scope, simpler logic, less risk of misses).

---

## 4) GraphQL-only vs REST-only decision matrix

| Criterion | GraphQL-only | REST-only |
|---|---:|---:|
| Efficient, field-specific reads  | ✅ | ❌ |
| Repository-scoped “list all advisories” | ❌ | ✅ |
| Simpler implementation for this project’s target workflows | ❌ | ✅ |

---

## Final recommendation

For this GHSA-to-CSAF converter, REST is the better choice because it fits the project’s actual ingestion needs: repository-scoped advisory lookup and repository-specific metadata are first-class in REST, while GraphQL is mainly useful for narrow, client-shaped reads of known advisory objects but lacks, e.g., the repository-level listing pattern.