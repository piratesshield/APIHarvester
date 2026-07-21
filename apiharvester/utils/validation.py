"""Shared finding-validation helpers — the anti-false-positive layer.

Every module that claims a vulnerability should *validate* it here first.
The recurring real-world lesson (see REAL_WORLD_RESEARCH.md) is that scanners
drown teams in false positives. These primitives enforce the preconditions
that make a finding trustworthy:

  * is_auth_enforced()  — before claiming any auth *bypass*, prove the endpoint
    actually rejects a garbage credential. If garbage is accepted, the endpoint
    simply isn't protected (a different, and lower-confidence, finding) and a
    "forged JWT accepted" claim would be a false positive.
  * responses_equivalent() / same_object() — before claiming BOLA cross-account
    access, prove two identities received the *same* object, not merely two
    independent 200s (each user reading their own record).
  * looks_like_error_or_empty() — reject soft-error / empty bodies that would
    otherwise masquerade as "leaked data".
  * confirm_timing() — multi-sample timing so a single slow response can't fake
    a time-based SQLi/command-injection hit.
  * shannon_entropy() / is_placeholder() — separate real secrets from docs
    examples and low-entropy config noise.
"""
import difflib
import re
import secrets as _secrets
import time

from .soft404 import normalize_body

# A syntactically-valid but cryptographically-bogus JWT: correct 3-segment
# shape, decodable header/payload, garbage signature. A server that enforces
# auth MUST reject this. Used as the control for every JWT bypass test.
GARBAGE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJhcGloYXJ2ZXN0ZXItY29udHJvbCIsInJvbGUiOiJndWVzdCJ9"
    ".apiharvester_invalid_signature_control_value"
)

# Bodies that look like data but are really "nothing here" responses.
_EMPTY_ISH = re.compile(
    r'^\s*(\{\s*\}|\[\s*\]|null|""|\{\s*"data"\s*:\s*(null|\[\s*\]|\{\s*\})\s*\})\s*$',
    re.I)

_ERROR_HINT = re.compile(
    r'"(error|message|detail|code)"\s*:\s*"?[^"]*'
    r'(not.?found|forbidden|unauthor|denied|invalid|no.?access|does.?not.?exist)',
    re.I)

# Placeholder / example values that pattern-matchers wrongly flag as secrets.
_PLACEHOLDER = re.compile(
    r'(?i)(your[_-]?(api[_-]?)?key|example|sample|placeholder|xxx+|<[^>]+>|'
    r'insert[_-]?here|change[_-]?me|dummy|test[_-]?key|redacted|abcdefgh|'
    r'000000|123456|foobar|lorem)')


def garbage_auth_header(scheme="Bearer"):
    """A control Authorization header that any real auth layer must reject."""
    return f"{scheme} {GARBAGE_JWT}"


def is_auth_enforced(client, url, method="GET", extra_headers=None):
    """Return True iff the endpoint *rejects* a garbage credential.

    This is the precondition for any 'auth bypass' claim. If a garbage token
    yields a 2xx, the endpoint isn't enforcing auth at all — so a later
    'forged token accepted' result is meaningless (false positive) and callers
    should downgrade/relabel accordingly.
    """
    h = dict(extra_headers or {})
    h["Authorization"] = garbage_auth_header()
    r = client.request(method, url, headers=h)
    # Reject == not a success. 401/403 is the ideal; anything non-2xx counts as
    # "the garbage token did not get in".
    return not (200 <= r.status < 300)


def looks_like_error_or_empty(resp):
    """True if the response body is an error/empty shell rather than real data."""
    if resp is None or resp.status == 0:
        return True
    body = (resp.body or "").strip()
    if not body:
        return True
    if _EMPTY_ISH.match(body):
        return True
    # Short body that is mostly an error message.
    if len(body) < 400 and _ERROR_HINT.search(body):
        return True
    return False


def _norm(resp):
    return normalize_body(resp.body or "", resp.url)


def similarity(resp_a, resp_b):
    """0..1 structural similarity of two response bodies (volatile-normalized)."""
    a, b = _norm(resp_a), _norm(resp_b)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


def responses_equivalent(resp_a, resp_b, threshold=0.95):
    """True if two responses represent the *same* object/content.

    Used to distinguish 'both identities got their own object' (NOT a BOLA)
    from 'both identities got the identical object' (a real cross-account read).
    """
    if resp_a.status != resp_b.status:
        return False
    return similarity(resp_a, resp_b) >= threshold


def is_distinct_object(baseline, alt, min_delta=64):
    """True if `alt` looks like a genuinely different *valid* object vs baseline.

    Requires: alt is a 2xx, not an error/empty shell, and differs from the
    baseline beyond volatile-field noise. Prevents ID-fuzz hits on soft-404s
    and echoed error pages.
    """
    if not (200 <= alt.status < 300):
        return False
    if looks_like_error_or_empty(alt):
        return False
    sim = similarity(baseline, alt)
    if sim >= 0.98:
        return False  # effectively the same object (or same catch-all)
    if abs(len(_norm(alt)) - len(_norm(baseline))) < min_delta and sim >= 0.9:
        return False
    return True


def confirm_timing(client, method, slow_url, fast_url, headers,
                   floor_s, samples=3, ratio=2.5):
    """Multi-sample timing confirmation for blind time-based injection.

    Fires the payload and control `samples` times each and only confirms when
    the *median* payload time clears `floor_s` AND beats the median control
    time by `ratio`. Kills single-sample network-jitter false positives.
    """
    def median_time(url):
        ts = []
        for _ in range(samples):
            t0 = time.time()
            r = client.request(method, url, headers=headers)
            ts.append(time.time() - t0)
            if r.status == 0:
                return None
        ts.sort()
        return ts[len(ts) // 2]

    slow = median_time(slow_url)
    if slow is None or slow < floor_s:
        return False, 0.0, 0.0
    fast = median_time(fast_url)
    if fast is None or fast <= 0:
        return False, slow, 0.0
    return (slow >= fast * ratio), slow, fast


def shannon_entropy(s):
    """Bits-per-char Shannon entropy — real secrets are high-entropy."""
    if not s:
        return 0.0
    from math import log2
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def is_placeholder(value):
    """True if the matched 'secret' is really a docs placeholder/example."""
    return bool(_PLACEHOLDER.search(value or ""))


def looks_like_real_secret(value, min_entropy=3.0):
    """Heuristic: high entropy and not a known placeholder pattern."""
    if not value or is_placeholder(value):
        return False
    # Structured, always-real prefixes bypass the entropy gate.
    if re.match(r'^(AKIA|AIza|sk_live_|xox[baprs]-|gh[pousr]_|-----BEGIN)', value):
        return True
    return shannon_entropy(value) >= min_entropy


def rand_marker(prefix="ah"):
    return f"{prefix}_{_secrets.token_hex(5)}"
