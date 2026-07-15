"""Soft-404 / catch-all error page detection — from apisec.py."""
import difflib
import secrets
import urllib.parse

from ..config import SOFT_404_MARKERS, VOLATILE_FIELD_RE, VOLATILE_RE


def normalize_body(body, url=None):
    text = body or ""
    text = VOLATILE_FIELD_RE.sub('"F":"X"', text)
    if url:
        path = urllib.parse.urlparse(url).path or ""
        if path and path != "/":
            text = text.replace(path, "")
            for seg in path.split("/"):
                if len(seg) >= 3:
                    text = text.replace(seg, "")
    text = VOLATILE_RE.sub("N", text)
    return text[:2000]


class Soft404Detector:
    def __init__(self):
        self.baselines = []  # [(status, normalized_text, length)]

    def fingerprint(self, client, base_url):
        probes = [
            base_url + "/__apiharvester_nonexistent_%s" % secrets.token_hex(6),
            base_url + "/api/__apiharvester_nonexistent_%s" % secrets.token_hex(6),
            base_url + "/api/v1/__apiharvester_nonexistent_%s" % secrets.token_hex(6),
        ]
        for u in probes:
            r = client.request("GET", u)
            if r.status == 0:
                continue
            self.baselines.append(
                (r.status, normalize_body(r.body, u), r.length))

    def is_soft_404(self, r):
        if SOFT_404_MARKERS.search(r.body or ""):
            return True
        if not self.baselines:
            return False
        norm = normalize_body(r.body, r.url)
        for status, base_text, base_len in self.baselines:
            if status != r.status:
                continue
            if not base_text and not norm:
                return True
            if abs(len(norm) - len(base_text)) > max(64, base_len * 0.15):
                continue
            ratio = difflib.SequenceMatcher(None, norm, base_text).quick_ratio()
            if ratio >= 0.90:
                return True
        return False
