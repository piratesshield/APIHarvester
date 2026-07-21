"""HTTP client — stdlib urllib, no redirects, permissive TLS."""
import itertools
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .config import UA
from .models import Response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class HTTPClient:
    # ---- Optional WAF/User-Agent bypass (opt-in; set by --waf-bypass) ----
    # Class-level so a single CLI flag flips behaviour for every client the
    # pipeline constructs, with no per-module changes. Default: OFF.
    ROTATE_UA = False        # rotate a realistic browser UA instead of bot UA
    BYPASS_ON_BLOCK = False  # on a WAF block, retry with UA/header variants
    _ua_cycle = None         # lazily-built round-robin UA iterator

    @classmethod
    def enable_waf_bypass(cls):
        """Turn on UA rotation + block-retry for all HTTPClient instances."""
        from .utils.waf_bypass import BROWSER_USER_AGENTS
        cls.ROTATE_UA = True
        cls.BYPASS_ON_BLOCK = True
        cls._ua_cycle = itertools.cycle(BROWSER_USER_AGENTS)

    @classmethod
    def _next_ua(cls):
        if cls._ua_cycle is None:
            from .utils.waf_bypass import BROWSER_USER_AGENTS
            cls._ua_cycle = itertools.cycle(BROWSER_USER_AGENTS)
        return next(cls._ua_cycle)

    def __init__(self, timeout=10, extra_headers=None, max_body=65536):
        self.timeout = timeout
        self.max_body = max_body
        self.extra = extra_headers or {}
        self.delay = float(os.environ.get("APISECSCAN_DELAY", "0.0"))
        self._bypassing = False  # reentrancy guard for the bypass retry loop
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(self, method, url, body=None, headers=None):
        if self.delay > 0:
            time.sleep(self.delay)
        # Default UA — rotate a browser UA when bypass is enabled and the caller
        # hasn't set its own User-Agent.
        default_ua = self._next_ua() if self.ROTATE_UA else UA
        h = {"User-Agent": default_ua, "Accept": "*/*"}
        h.update(self.extra)
        h.update(headers or {})
        resp = self._raw_request(method, url, body, h)

        # Optional: if the response looks WAF-blocked, retry with bypass
        # variants (once, bounded). Guard against recursion.
        if (self.BYPASS_ON_BLOCK and not self._bypassing):
            from .utils.waf_bypass import is_waf_blocked, attempt_bypass
            if is_waf_blocked(resp):
                self._bypassing = True
                try:
                    # Preserve caller-supplied headers (e.g. Authorization).
                    caller = dict(self.extra)
                    caller.update(headers or {})
                    bypassed, technique = attempt_bypass(
                        self, method, url, base_headers=caller)
                finally:
                    self._bypassing = False
                if bypassed is not None:
                    bypassed.bypassed = True
                    bypassed.bypass_technique = technique
                    return bypassed
        return resp

    def _raw_request(self, method, url, body=None, h=None):
        h = h or {"User-Agent": UA, "Accept": "*/*"}
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        t0 = time.time()

        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read(self.max_body)
                return Response(
                    url, method, r.status, len(raw),
                    r.headers.get("Content-Type", ""),
                    {k.lower(): v for k, v in r.headers.items()},
                    raw.decode("utf-8", "replace"),
                    elapsed_ms=int((time.time() - t0) * 1000))
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(self.max_body) if hasattr(e, "read") else b""
            except Exception:
                raw = b""
            return Response(
                url, method, e.code, len(raw),
                e.headers.get("Content-Type", "") if e.headers else "",
                {k.lower(): v for k, v in (e.headers or {}).items()},
                raw.decode("utf-8", "replace") if raw else "",
                elapsed_ms=int((time.time() - t0) * 1000))
        except Exception as e:
            return Response(
                url, method, 0, 0, "", {}, "",
                error=type(e).__name__ + ": " + str(e)[:120],
                elapsed_ms=int((time.time() - t0) * 1000))
