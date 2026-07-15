"""Phase 9: Link crawling + JS endpoint extraction."""
import json
import re
import sys
import urllib.parse

from ..config import API_PATH_RE
from ..http_client import HTTPClient
from ..models import Endpoint, ScanContext
from ..utils.tool_runner import run_tool, tool_available

LINK_RE = re.compile(
    r'''(?:href|src|action)\s*=\s*["']([^"'#]{2,200})["']''', re.I)

JS_SRC_RE = re.compile(
    r'''(?:src)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']''', re.I)

JS_ENDPOINT_RE = re.compile(
    r'''["'](/(?:api|v[1-9]|rest|graphql|auth|oauth|admin|internal)'''
    r'''[A-Za-z0-9/_\-.]*)["']''')

JS_FETCH_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete)|\.ajax)\s*\(\s*'''
    r'''["'`]([^"'`]+)["'`]''', re.I)

FORM_RE = re.compile(
    r"<form[^>]*>(.*?)</form>", re.I | re.S)
FORM_ACTION_RE = re.compile(
    r'''action\s*=\s*["']([^"']*)["']''', re.I)
FORM_METHOD_RE = re.compile(
    r'''method\s*=\s*["']([^"']*)["']''', re.I)
INPUT_RE = re.compile(
    r'''<input[^>]+name\s*=\s*["']([^"']+)["']''', re.I)

WAYBACK_API = ("https://web.archive.org/cdx/search/cdx"
               "?url=*.{domain}&output=json&fl=original&collapse=urlkey"
               "&limit=500")


def _log(msg):
    print(f"[*] Phase 9 (crawler): {msg}", file=sys.stderr)


def _normalize_url(href, base_url):
    """Resolve a relative URL against a base URL."""
    if href.startswith(("http://", "https://")):
        return href
    return urllib.parse.urljoin(base_url, href)


def _extract_links(body, base_url):
    """Extract and normalize all links from HTML."""
    urls = set()
    for match in LINK_RE.finditer(body or ""):
        href = match.group(1).strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        url = _normalize_url(href, base_url)
        urls.add(url)
    return urls


def _extract_js_urls(body, base_url):
    """Extract JavaScript file URLs from HTML."""
    urls = set()
    for match in JS_SRC_RE.finditer(body or ""):
        url = _normalize_url(match.group(1).strip(), base_url)
        urls.add(url)
    return urls


def _extract_endpoints_from_js(js_body):
    """Extract API endpoints from JavaScript source."""
    endpoints = set()
    for pattern in (JS_ENDPOINT_RE, JS_FETCH_RE):
        for match in pattern.finditer(js_body or ""):
            path = match.group(1).strip()
            if len(path) > 4 and not path.endswith((".js", ".css", ".png",
                                                     ".jpg", ".svg")):
                endpoints.add(path)
    return endpoints


def _extract_forms(body, base_url):
    """Extract form actions, methods, and input names from HTML."""
    forms = []
    for form_match in FORM_RE.finditer(body or ""):
        form_html = form_match.group(0)
        action = ""
        am = FORM_ACTION_RE.search(form_html)
        if am:
            action = _normalize_url(am.group(1), base_url)
        method = "GET"
        mm = FORM_METHOD_RE.search(form_html)
        if mm:
            method = mm.group(1).upper()
        inputs = INPUT_RE.findall(form_html)
        if action:
            forms.append({"action": action, "method": method,
                          "inputs": inputs})
    return forms


def _wayback_urls(domain):
    """Query Wayback Machine for historical URLs."""
    try:
        import urllib.request
        url = WAYBACK_API.format(domain=domain)
        req = urllib.request.Request(
            url, headers={"User-Agent": "apiharvester"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        urls = set()
        for row in data[1:]:
            if row and isinstance(row, list) and row[0]:
                urls.add(row[0])
        return urls
    except Exception:
        return set()


def _katana_crawl(url):
    """Use katana for JS-aware crawling if installed."""
    if not tool_available("katana"):
        return set()
    result = run_tool("katana",
                      ["-u", url, "-jc", "-xhr", "-d", "2",
                       "-silent", "-nc"], timeout=180)
    if result is None:
        return set()
    stdout, _, _ = result
    return set(l.strip() for l in stdout.splitlines() if l.strip())


def crawl_and_extract(ctx: ScanContext):
    """Crawl live hosts, extract links, JS endpoints, and forms."""
    live = ctx.active_hosts()
    _log(f"Crawling {len(live)} hosts")

    client = HTTPClient(timeout=ctx.timeout)
    total_new = 0
    existing_urls = {e.url for e in ctx.endpoints}

    for host in live:
        base = host.url.rstrip("/")
        host_domain = urllib.parse.urlparse(base).netloc

        katana_urls = _katana_crawl(base)
        for kurl in katana_urls:
            if kurl not in existing_urls and host_domain in kurl:
                ep = Endpoint(url=kurl, is_api=bool(API_PATH_RE.search(kurl)),
                              source="katana")
                ctx.endpoints.append(ep)
                existing_urls.add(kurl)
                total_new += 1

        resp = client.request("GET", base + "/")
        if resp.status == 0:
            continue

        links = _extract_links(resp.body, base)
        for link in links:
            if host_domain not in link:
                continue
            if link not in existing_urls:
                ep = Endpoint(url=link,
                              is_api=bool(API_PATH_RE.search(link)),
                              source="crawl")
                ctx.endpoints.append(ep)
                existing_urls.add(link)
                total_new += 1

        js_urls = _extract_js_urls(resp.body, base)
        for js_url in js_urls:
            if host_domain not in js_url:
                continue
            js_resp = client.request("GET", js_url)
            if js_resp.status != 200:
                continue
            js_paths = _extract_endpoints_from_js(js_resp.body)
            for path in js_paths:
                full_url = base + path
                if full_url not in existing_urls:
                    ep = Endpoint(url=full_url, is_api=True, source="js")
                    ctx.endpoints.append(ep)
                    existing_urls.add(full_url)
                    total_new += 1

        forms = _extract_forms(resp.body, base)
        for form in forms:
            if form["action"] not in existing_urls:
                ep = Endpoint(
                    url=form["action"],
                    methods=[form["method"]],
                    params={inp: "" for inp in form["inputs"]},
                    source="form")
                ctx.endpoints.append(ep)
                existing_urls.add(form["action"])
                total_new += 1

        wb_urls = _wayback_urls(host.domain)
        for wb_url in wb_urls:
            if wb_url not in existing_urls and API_PATH_RE.search(wb_url):
                ep = Endpoint(url=wb_url, is_api=True, source="wayback")
                ctx.endpoints.append(ep)
                existing_urls.add(wb_url)
                total_new += 1

    _log(f"New endpoints from crawling: {total_new}, "
         f"total: {len(ctx.endpoints)}")
