"""Data models shared across all modules."""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set
import hashlib
import json
import re
import urllib.parse

from .config import ID_SEGMENT_RE, API_PATH_RE, SENSITIVE_PATH_RE, AUTH_PATH_RE


@dataclass
class Response:
    url: str
    method: str
    status: int = 0
    length: int = 0
    ctype: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: str = ""
    elapsed_ms: int = 0


@dataclass
class Host:
    domain: str
    ips: List[str] = field(default_factory=list)
    is_live: bool = False
    status_code: int = 0
    server: str = ""
    content_type: str = ""
    title: str = ""
    is_api: bool = False
    is_cdn: bool = False
    waf_vendor: str = "none"
    skip_bruteforce: bool = False
    catchall: bool = False
    js_challenge: bool = False
    url: str = ""

    def __post_init__(self):
        if not self.url:
            self.url = "https://" + self.domain


@dataclass
class Endpoint:
    url: str
    host: str = ""
    path: str = ""
    methods: List[str] = field(default_factory=list)
    params: Dict[str, str] = field(default_factory=dict)
    status_code: int = 0
    content_type: str = ""
    response_length: int = 0
    is_api: bool = False
    is_sensitive: bool = False
    is_auth_endpoint: bool = False
    has_id_param: bool = False
    source: str = ""
    object_fields: List[str] = field(default_factory=list)

    def __post_init__(self):
        parsed = urllib.parse.urlparse(self.url)
        self.host = self.host or parsed.netloc
        self.path = self.path or parsed.path or "/"
        if not self.params:
            self.params = dict(urllib.parse.parse_qsl(parsed.query or ""))
        self.has_id_param = bool(ID_SEGMENT_RE.search(self.url))
        self.is_sensitive = bool(SENSITIVE_PATH_RE.search(self.path))
        self.is_auth_endpoint = bool(AUTH_PATH_RE.search(self.path))
        if not self.is_api:
            self.is_api = bool(API_PATH_RE.search(self.path))

    def base_url(self):
        parsed = urllib.parse.urlparse(self.url)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    def template_path(self):
        parts = []
        for seg in self.path.split("/"):
            if seg and re.match(
                r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$", seg
            ):
                parts.append("{id}")
            else:
                parts.append(seg)
        return "/".join(parts)


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    method: str
    path: str
    host: str
    status: int
    evidence: str
    remediation: str
    attack_phase: str = ""

    def key(self):
        return (self.category, self.method, self.path, self.host, self.title)

    def dedup_key(self):
        return hashlib.md5(
            f"{self.method}|{self.path}|{self.host}|{self.title}".encode()
        ).hexdigest()

    def to_dict(self):
        return asdict(self)

    def to_jsonl(self):
        return json.dumps(self.to_dict())


@dataclass
class ScanContext:
    """Holds all state accumulated across the pipeline."""
    target: str
    output_dir: str
    auth: str = ""
    auth2: str = ""
    threads: int = 20
    timeout: int = 10
    burst: int = 20

    hosts: List[Host] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    findings: Dict[str, Finding] = field(default_factory=dict)
    swagger_specs: Dict[str, dict] = field(default_factory=dict)
    waf_hosts: Set[str] = field(default_factory=set)
    tokens: List[str] = field(default_factory=list)

    def add_finding(self, f: Finding):
        self.findings.setdefault(f.key(), f)

    def active_hosts(self):
        return [h for h in self.hosts if h.is_live]

    def api_hosts(self):
        return [h for h in self.hosts if h.is_live and h.is_api]

    def scannable_hosts(self):
        return [h for h in self.hosts if h.is_live and not h.skip_bruteforce]

    def api_endpoints(self):
        return [e for e in self.endpoints if e.is_api]

    def endpoints_with_params(self):
        return [e for e in self.endpoints if e.params]

    def endpoints_for_host(self, domain):
        return [e for e in self.endpoints if e.host == domain]

    def sorted_findings(self):
        from .config import SEV_RANK
        return sorted(
            self.findings.values(),
            key=lambda f: (SEV_RANK.get(f.severity, 9), f.category, f.path))
