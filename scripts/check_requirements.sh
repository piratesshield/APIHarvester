#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# check_requirements.sh — Verify apisecscan's runtime + optional-tool + payload
# prerequisites are in place. Read-only: never installs or downloads anything.
# Run install_requirements.sh to fix any gaps this reports.
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD_DIR="${APISECSCAN_WORDLIST_DIR:-$ROOT_DIR/payloads}"

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BOLD="\033[1m"; RESET="\033[0m"

PASS=0
WARN=0
MISS=0

pass() { echo -e "  ${GREEN}[OK]${RESET}   $1"; PASS=$((PASS+1)); }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $1"; WARN=$((WARN+1)); }
miss() { echo -e "  ${RED}[MISS]${RESET} $1"; MISS=$((MISS+1)); }
section() { echo -e "\n${BOLD}== $1 ==${RESET}"; }

version_of() {
    # Best-effort single-line version string for a binary.
    "$1" --version 2>&1 | head -n1 || "$1" -version 2>&1 | head -n1
}

check_required_bin() {
    local bin="$1" label="$2"
    if command -v "$bin" >/dev/null 2>&1; then
        pass "$label — found ($(command -v "$bin"))"
        return 0
    fi
    miss "$label — not found (REQUIRED)"
    return 1
}

check_optional_bin() {
    local bin="$1" label="$2" used_by="$3"
    if command -v "$bin" >/dev/null 2>&1; then
        pass "$label — found ($(command -v "$bin"))"
    else
        warn "$label — not installed, falls back to pure-Python ($used_by)"
    fi
}

check_file() {
    local path="$1" label="$2"
    if [ -s "$path" ]; then
        local size
        size=$(du -h "$path" 2>/dev/null | cut -f1)
        pass "$label — present ($path, $size)"
    else
        warn "$label — missing ($path)"
    fi
}

echo -e "${BOLD}apisecscan — requirement check${RESET}"
echo "Project root : $ROOT_DIR"
echo "Payload dir  : $PAYLOAD_DIR"

# ---------------------------------------------------------------------------
section "Core runtime (required)"
# ---------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    PYVER=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
    PYMAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
    PYMINOR=$(python3 -c 'import sys; print(sys.version_info[1])')
    if [ "$PYMAJOR" -ge 3 ] && [ "$PYMINOR" -ge 8 ]; then
        pass "python3 — found (v$PYVER)"
    else
        miss "python3 — found but too old (v$PYVER, need >= 3.8)"
    fi
else
    miss "python3 — not found (REQUIRED — apisecscan is stdlib-only Python)"
fi

check_required_bin curl "curl (used by install script + crt.sh/wayback lookups)"
check_required_bin git  "git (used to clone tool sources, optional installs)"

# ---------------------------------------------------------------------------
section "Recon accelerators (optional — pure-Python fallback exists for each)"
# ---------------------------------------------------------------------------
check_optional_bin subfinder  "subfinder"  "recon/subdomains.py passive enum"
check_optional_bin haktrails  "haktrails"  "recon/subdomains.py passive enum"
check_optional_bin puredns    "puredns"    "recon/subdomains.py active brute-force"
check_optional_bin massdns    "massdns"    "puredns dependency"
check_optional_bin dnsx       "dnsx"       "recon/resolver.py bulk DNS resolution"
check_optional_bin httpx      "httpx"      "recon/prober.py HTTP probing"
check_optional_bin wafw00f    "wafw00f"    "recon/waf_detector.py WAF fingerprinting"
check_optional_bin nuclei     "nuclei"     "recon/waf_detector.py tier-2 WAF templates"
check_optional_bin katana     "katana"     "recon/crawler.py JS-aware crawling"
check_optional_bin kr         "kr (kiterunner)" "recon/endpoint_discovery.py route scan"
check_optional_bin ffuf       "ffuf"       "recon/endpoint_discovery.py content discovery"
check_optional_bin arjun      "arjun"      "recon/param_discovery.py cross-validation"

# ---------------------------------------------------------------------------
section "Fuzzing / brute-force payloads"
# ---------------------------------------------------------------------------
check_file "$PAYLOAD_DIR/subdomains.txt"            "Subdomain brute-force wordlist (puredns)"
check_file "$PAYLOAD_DIR/directories.txt"            "Directory/content wordlist (ffuf)"
check_file "$PAYLOAD_DIR/params.txt"                 "Parameter name wordlist (arjun cross-check)"
check_file "$PAYLOAD_DIR/kiterunner/routes-large.kite" "Kiterunner API route wordlist"

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
TOTAL=$((PASS+WARN+MISS))
echo -e "  ${GREEN}OK: $PASS${RESET}   ${YELLOW}WARN: $WARN${RESET}   ${RED}MISS: $MISS${RESET}   (of $TOTAL checks)"

if [ "$MISS" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}Required prerequisites are missing.${RESET}"
    echo "  Run: scripts/install_requirements.sh"
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    echo -e "\n${YELLOW}All required prerequisites are in place.${RESET}"
    echo "  Optional accelerators/payloads are missing — apisecscan will still run"
    echo "  using its pure-Python fallbacks and built-in wordlists, but external"
    echo "  tools give faster/deeper results. To install them:"
    echo "    scripts/install_requirements.sh"
    exit 0
fi

echo -e "\n${GREEN}${BOLD}Everything is in place.${RESET}"
exit 0
