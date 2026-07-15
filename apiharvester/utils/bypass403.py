"""403 bypass engine — path mutation + header spoofing, from apisec.py."""
import urllib.parse

from ..config import (BYPASS_PATH_SUFFIXES, BYPASS_PATH_PREFIXES,
                      BYPASS_CASE_VARIANTS, BYPASS_HEADER_SETS)


def try_403_bypass(client, url, soft404_detector=None):
    """Attempt access-control-bypass techniques against a 403 URL.
    Returns (Response, technique_description) or (None, None)."""
    parsed = urllib.parse.urlparse(url)
    base_path = parsed.path or "/"
    variants = []

    for suf in BYPASS_PATH_SUFFIXES:
        variants.append(
            (base_path.rstrip("/") + suf, None, "path suffix %r" % suf))

    for pre in BYPASS_PATH_PREFIXES:
        variants.append(
            (pre + base_path.lstrip("/"), None, "path prefix %r" % pre))

    if BYPASS_CASE_VARIANTS:
        segs = base_path.rstrip("/").split("/")
        if segs and segs[-1]:
            upper = "/".join(segs[:-1] + [segs[-1].upper()])
            variants.append((upper, None, "uppercase final segment"))

    for hdrset in BYPASS_HEADER_SETS:
        filled = {k: (v if v is not None else url) for k, v in hdrset.items()}
        variants.append(
            (base_path, filled, "header %s" % list(hdrset.keys())[0]))

    for new_path, hdrs, technique in variants:
        new_url = parsed._replace(path=new_path).geturl()
        req_headers = {}
        if hdrs:
            req_headers.update(hdrs)
        resp = client.request("GET", new_url, headers=req_headers or None)
        if 200 <= resp.status < 300:
            if soft404_detector and soft404_detector.is_soft_404(resp):
                continue
            return resp, technique

    return None, None
