"""Scan responses for leaked secrets/credentials — API keys, tokens,
passwords, private keys. Same patterns as apisec.py."""
import re
import sys

from ..http_client import HTTPClient
from ..models import Finding, ScanContext
from ..utils.validation import looks_like_real_secret


def _log(msg):
    print(f"[*] Attack: Secrets: {msg}", file=sys.stderr)


# High-confidence secret patterns extracted from real-world finds
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Generic Secret Assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token|"
                r"client[_-]?secret|private[_-]?key|auth[_-]?token)"
                r"['\"\s:=]{1,4}[A-Za-z0-9\-_./+]{16,}")),
]


def run_secrets(ctx: ScanContext):
    """Scan all discovered endpoints' response bodies for leaked secrets."""
    endpoints = ctx.endpoints[:200]  # cap requests
    _log(f"Scanning {len(endpoints)} endpoints for secrets in responses")

    client = HTTPClient(timeout=ctx.timeout)
    headers = {}
    if ctx.auth:
        headers["Authorization"] = ctx.auth

    found = 0

    for ep in endpoints:
        # Only GET/unauthenticated endpoints are likely to leak secrets
        # (they're often unfiltered, cached, or part of public bundles)
        resp = client.request("GET", ep.url, headers=headers)
        if not resp.body or resp.status == 0:
            continue

        # Skip echoing the caller's own bearer token back as a "leak".
        own_token = (ctx.auth or "").split()[-1] if ctx.auth else None

        for pattern_name, pattern in SECRET_PATTERNS:
            match = pattern.search(resp.body)
            if match:
                secret = match.group(0)

                # VALIDATION: drop docs placeholders / low-entropy noise, and
                # never flag the caller's own auth token reflected back.
                candidate = match.group(len(match.groups())) if match.groups() \
                    else secret
                if own_token and own_token in secret:
                    continue
                if not looks_like_real_secret(candidate):
                    continue

                # Redact for display (show first 12 chars + ellipsis)
                redacted = secret[:12] + "…" if len(secret) > 12 else secret

                ctx.add_finding(Finding(
                    title=f"Secret leaked in API response: {pattern_name}",
                    severity="high",
                    category="Exposure",
                    method="GET",
                    path=ep.path,
                    host=ep.host,
                    status=resp.status,
                    evidence=f"Pattern '{pattern_name}' matched in response "
                             f"body (redacted: {redacted})",
                    remediation="Never return credentials/keys in API "
                               "responses. Rotate exposed secrets immediately "
                               "and scrub them from the codebase.",
                    attack_phase="secrets"))
                found += 1
                break  # one secret per endpoint is enough signal

    _log(f"Secrets findings: {found}")
