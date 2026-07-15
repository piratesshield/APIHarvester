#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install_requirements.sh — Install optional accelerator tools + download
# fuzzing/brute-force payloads used by apisecscan's recon phases.
#
# Nothing here is required: apisecscan (stdlib-only Python) falls back to
# pure-Python logic for every phase if a given tool/payload isn't present.
# This script just makes the scan faster/deeper by wiring up the real tools.
#
# Safe to re-run — every step skips work that's already done.
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD_DIR="${APISECSCAN_WORDLIST_DIR:-$ROOT_DIR/payloads}"
TOOLS_SRC_DIR="$ROOT_DIR/tools"     # already-cloned repos from download_tools.sh, if present

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BOLD="\033[1m"; RESET="\033[0m"

OK=0
SKIP=0
FAIL=0

ok()   { echo -e "  ${GREEN}[DONE]${RESET} $1"; OK=$((OK+1)); }
skip() { echo -e "  ${YELLOW}[SKIP]${RESET} $1"; SKIP=$((SKIP+1)); }
fail() { echo -e "  ${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }
section() { echo -e "\n${BOLD}== $1 ==${RESET}"; }

mkdir -p "$PAYLOAD_DIR" "$PAYLOAD_DIR/kiterunner"

# ---------------------------------------------------------------------------
section "Package managers"
# ---------------------------------------------------------------------------
OS="$(uname -s)"
HAVE_BREW=0; HAVE_APT=0
if command -v brew >/dev/null 2>&1; then HAVE_BREW=1; fi
if command -v apt-get >/dev/null 2>&1; then HAVE_APT=1; fi
echo "  OS: $OS   brew: $HAVE_BREW   apt: $HAVE_APT"

if ! command -v go >/dev/null 2>&1; then
    echo "  go not found — installing (needed for ProjectDiscovery/ffuf tools)..."
    if [ "$HAVE_BREW" -eq 1 ]; then
        brew install go && ok "go installed via brew" || fail "go install via brew failed"
    elif [ "$HAVE_APT" -eq 1 ]; then
        sudo apt-get update -y && sudo apt-get install -y golang-go \
            && ok "go installed via apt" || fail "go install via apt failed"
    else
        fail "no supported package manager found for go — install manually: https://go.dev/dl/"
    fi
else
    skip "go already installed ($(go version 2>/dev/null))"
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
if [ -n "$GOBIN" ]; then
    export PATH="$PATH:$GOBIN"
    case ":$PATH:" in
        *":$GOBIN:"*) : ;;
    esac
fi

go_install() {
    # go_install <binary-name> <module@version>
    local bin="$1" mod="$2"
    if command -v "$bin" >/dev/null 2>&1; then
        skip "$bin already installed"
        return 0
    fi
    if ! command -v go >/dev/null 2>&1; then
        fail "$bin — cannot install, go toolchain unavailable"
        return 1
    fi
    echo "  Installing $bin via 'go install $mod' ..."
    if go install "$mod" >/tmp/apisecscan_install_$bin.log 2>&1; then
        ok "$bin installed"
    else
        fail "$bin install failed — see /tmp/apisecscan_install_$bin.log"
    fi
}

pip_install() {
    # pip_install <binary-name> <pip-package>
    local bin="$1" pkg="$2"
    if command -v "$bin" >/dev/null 2>&1; then
        skip "$bin already installed"
        return 0
    fi
    echo "  Installing $pkg via pip3 ..."
    if pip3 install --user --quiet "$pkg" >/tmp/apisecscan_install_$bin.log 2>&1; then
        ok "$bin ($pkg) installed"
    else
        fail "$bin ($pkg) install failed — see /tmp/apisecscan_install_$bin.log"
    fi
}

download() {
    # download <url> <dest-path> <label>
    local url="$1" dest="$2" label="$3"
    if [ -s "$dest" ]; then
        skip "$label already present ($dest)"
        return 0
    fi
    echo "  Downloading $label ..."
    if curl -fsSL --retry 2 -o "$dest" "$url"; then
        ok "$label saved to $dest"
    else
        fail "$label download failed from $url"
        rm -f "$dest"
    fi
}

# ---------------------------------------------------------------------------
section "ProjectDiscovery + Go-based recon accelerators"
# ---------------------------------------------------------------------------
go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install dnsx      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install katana    "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install ffuf      "github.com/ffuf/ffuf/v2@latest"
go_install haktrails "github.com/hakluke/haktrails@latest"
go_install puredns   "github.com/d3mondev/puredns/v2@latest"

# puredns needs massdns on the system
if ! command -v massdns >/dev/null 2>&1; then
    echo "  massdns not found (required by puredns) — attempting install..."
    if [ "$HAVE_BREW" -eq 1 ]; then
        brew install massdns >/tmp/apisecscan_install_massdns.log 2>&1 \
            && ok "massdns installed via brew" \
            || fail "massdns brew install failed — build manually: https://github.com/blechschmidt/massdns"
    else
        fail "massdns — no brew found, build manually: https://github.com/blechschmidt/massdns"
    fi
else
    skip "massdns already installed"
fi

# ---------------------------------------------------------------------------
section "kiterunner (kr) — API route scanner"
# ---------------------------------------------------------------------------
if command -v kr >/dev/null 2>&1; then
    skip "kr already installed"
elif [ "$HAVE_BREW" -eq 1 ] && brew tap | grep -q assetnote 2>/dev/null; then
    brew install kiterunner >/tmp/apisecscan_install_kr.log 2>&1 \
        && ok "kr installed via brew (assetnote tap)" \
        || fail "kr brew install failed"
elif [ -d "$TOOLS_SRC_DIR/kiterunner" ]; then
    echo "  Building kr from local clone at $TOOLS_SRC_DIR/kiterunner ..."
    ( cd "$TOOLS_SRC_DIR/kiterunner" && make build ) >/tmp/apisecscan_install_kr.log 2>&1
    if [ -x "$TOOLS_SRC_DIR/kiterunner/dist/kr" ]; then
        mkdir -p "$GOBIN"
        cp "$TOOLS_SRC_DIR/kiterunner/dist/kr" "$GOBIN/kr"
        ok "kr built from source and installed to $GOBIN/kr"
    else
        fail "kr build failed — see /tmp/apisecscan_install_kr.log (endpoint_discovery.py falls back to ffuf/pure-Python)"
    fi
else
    fail "kr not available (no brew tap, no local clone) — endpoint_discovery.py falls back to ffuf/pure-Python"
fi

# ---------------------------------------------------------------------------
section "Python-based tools"
# ---------------------------------------------------------------------------
pip_install arjun   arjun
pip_install wafw00f wafw00f

# ---------------------------------------------------------------------------
section "Fuzzing / brute-force payloads (SecLists, Arjun DB, Kiterunner routes)"
# ---------------------------------------------------------------------------
SECLISTS_RAW="https://raw.githubusercontent.com/danielmiessler/SecLists/master"

download \
    "$SECLISTS_RAW/Discovery/DNS/subdomains-top1million-5000.txt" \
    "$PAYLOAD_DIR/subdomains.txt" \
    "Subdomain brute-force wordlist (SecLists top-5000)"

download \
    "$SECLISTS_RAW/Discovery/Web-Content/raft-large-directories.txt" \
    "$PAYLOAD_DIR/directories.txt" \
    "Directory/content wordlist (SecLists raft-large-directories)"

if [ -s "$TOOLS_SRC_DIR/Arjun/arjun/db/params.txt" ]; then
    cp "$TOOLS_SRC_DIR/Arjun/arjun/db/params.txt" "$PAYLOAD_DIR/params.txt"
    ok "Parameter wordlist copied from local Arjun clone"
else
    download \
        "https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/params.txt" \
        "$PAYLOAD_DIR/params.txt" \
        "Parameter name wordlist (Arjun params.txt)"
fi

KITE_TARBALL="$PAYLOAD_DIR/kiterunner/routes-large.kite.tar.gz"
if [ -s "$PAYLOAD_DIR/kiterunner/routes-large.kite" ]; then
    skip "Kiterunner routes-large.kite already present"
else
    download \
        "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz" \
        "$KITE_TARBALL" \
        "Kiterunner API route wordlist (assetnote routes-large.kite)"
    if [ -s "$KITE_TARBALL" ]; then
        tar -xzf "$KITE_TARBALL" -C "$PAYLOAD_DIR/kiterunner/" \
            && ok "Extracted routes-large.kite" \
            || fail "Failed to extract $KITE_TARBALL"
        rm -f "$KITE_TARBALL"
    fi
fi

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
echo -e "  ${GREEN}DONE: $OK${RESET}   ${YELLOW}SKIP: $SKIP${RESET}   ${RED}FAIL: $FAIL${RESET}"
echo
echo "Payload directory: $PAYLOAD_DIR"
echo "  Set APISECSCAN_WORDLIST_DIR to point apisecscan at a different location."
if [ -n "${GOBIN:-}" ]; then
    echo
    echo "Go tools installed to: $GOBIN"
    echo "  Add this to your shell profile if not already on PATH:"
    echo "    export PATH=\"\$PATH:$GOBIN\""
fi
echo
echo "Run scripts/check_requirements.sh to verify everything landed correctly."

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
