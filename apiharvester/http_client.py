"""HTTP client — stdlib urllib, no redirects, permissive TLS."""
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
    def __init__(self, timeout=10, extra_headers=None, max_body=65536):
        self.timeout = timeout
        self.max_body = max_body
        self.extra = extra_headers or {}
        self.delay = float(os.environ.get("APISECSCAN_DELAY", "0.0"))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(self, method, url, body=None, headers=None):
        if self.delay > 0:
            time.sleep(self.delay)
        h = {"User-Agent": UA, "Accept": "*/*"}
        h.update(self.extra)
        h.update(headers or {})
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
