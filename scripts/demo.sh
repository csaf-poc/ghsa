#!/usr/bin/env bash
# Live walkthrough of ghsaToCSAF. Press Enter to advance; DEMO_NO_PAUSE=1 runs straight through.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d -t ghsa-demo)"
BIN="$WORK/ghsaToCSAF"
GHSA_ID="GHSA-mh63-6h87-95cp"
REPO="golang-jwt/jwt"
# Prefer the repo-local venv (has jsonschema) over the system python.
PYTHON="python3"
[[ -x "$REPO_ROOT/.venv/bin/python3" ]] && PYTHON="$REPO_ROOT/.venv/bin/python3"

bold=$'\e[1m'; cyan=$'\e[36m'; green=$'\e[32m'; dim=$'\e[2m'; reset=$'\e[0m'

step() { printf '\n%s━━ %s ━━%s\n' "$bold$cyan" "$1" "$reset"; }
say()  { printf '%s%s%s\n' "$dim" "$1" "$reset"; }
pause() { [[ -n "${DEMO_NO_PAUSE:-}" || ! -t 0 ]] || read -r -p "${dim}[enter]${reset} " _; }
run() {
  printf '%s$ %s%s\n' "$green" "$*" "$reset"
  eval "$@"
}

for tool in go jq curl; do
  command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }
done

say "Building ghsaToCSAF into $WORK ..."
(cd "$REPO_ROOT" && go build -o "$BIN" ./cmd)
cd "$WORK"
ghsaToCSAF() { "$BIN" "$@"; }

step "1. What the tool does"
say "Fetches GitHub Security Advisories (GHSA) and converts them into CSAF 2.0 documents."
run "ghsaToCSAF -h 2>&1 || true"
pause

step "2. The input: a GHSA from the GitHub Advisory Database"
say "CVE-2025-30204 in golang-jwt: three affected Go modules, CVSS 3.1, EPSS, one CWE."
run "curl -s https://api.github.com/advisories/$GHSA_ID | jq '{ghsa_id, cve_id, summary, severity, cvss: .cvss_severities.cvss_v3, epss, cwes, vulnerabilities: [.vulnerabilities[] | {package: .package.name, range: .vulnerable_version_range, patched: .first_patched_version}]}'"
pause

step "3. Convert the global advisory to CSAF"
run "ghsaToCSAF global -o global.json $GHSA_ID"
pause

say "Document section: GHSA ID becomes the tracking ID, CVE an alias, timestamps a revision history."
run "jq '.document | {category, title, aggregate_severity, publisher, tracking: .tracking | {id, aliases, status, version, revision_history}}' global.json"
pause

say "Product tree: ecosystem → package → vulnerable version range."
run "jq '.product_tree.full_product_names' global.json"
pause

say "Vulnerabilities: CVE, primary CWE, CVSS score, EPSS as a note, upgrade paths as vendor fixes."
run "jq '.vulnerabilities[0] | {cve, cwe, scores: [.scores[].cvss_v3 | {vectorString, baseScore}], notes: [.notes[]? | {title, text}], remediations: [.remediations[] | {details, product_ids}]}' global.json"
say "Note: the v3 module has no patched version, so it gets no remediation."
pause

step "4. Same advisory, but from the repository"
say "Repository GHSAs are maintainer-centric: no EPSS, and here only two affected modules."
run "ghsaToCSAF repo -o repo.json $REPO $GHSA_ID"
run "jq '{products: [.product_tree.full_product_names[].product_id], epss_note: [.vulnerabilities[0].notes[]?.title]}' repo.json"
pause

step "5. Batch: every published advisory of a repository"
run "ghsaToCSAF all -o jwt-advisories $REPO"
run "ls -1 jwt-advisories"
pause

step "6. Auto-detect: just paste a URL"
run "ghsaToCSAF -o from-url.json https://github.com/advisories/GHSA-cpj6-fhp6-mr6j"
run "jq '{title: .document.title, products: [.product_tree.full_product_names[].product_id]}' from-url.json"
pause

step "7. Validate against the CSAF 2.0 JSON schema"
if "$PYTHON" -c 'import jsonschema' 2>/dev/null; then
  run "'$PYTHON' '$REPO_ROOT/scripts/validate.py' global.json"
  run "'$PYTHON' '$REPO_ROOT/scripts/validate.py' repo.json"
else
  say "Skipped: jsonschema not installed (python3 -m venv .venv && .venv/bin/pip install jsonschema)."
fi

step "Done"
say "Generated files are in $WORK"
