from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any

SERVICE_RE = re.compile(r"^(?P<port>\d+)\/(?P<transport>[a-z0-9]+)\s+(?P<state>\w+)\s+(?P<service>\S+)(?:\s+(?P<product>.+))?$", re.I)

@dataclass(frozen=True, slots=True)
class AssetCandidate:
    asset_type: str
    value: str
    normalized_value: str
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class ServiceCandidate:
    host: str
    transport: str
    port: int
    state: str
    service: str | None
    product: str | None
    version: str | None
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    url: str
    host: str
    method: str
    path: str
    endpoint_type: str
    auth_hint: str | None
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class TechnologyCandidate:
    host: str
    name: str
    version: str | None
    category: str | None
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

def normalize_host(value: str) -> str | None:
    raw = value.strip().lower().rstrip('.')
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    raw = raw.split('/', 1)[0]
    raw = raw.split(':', 1)[0] if raw.count(':') == 1 and raw.replace(':', '').replace('.', '').isalnum() else raw
    if raw.startswith('*.'):
        raw = raw[2:]
    if '.' not in raw and raw != 'localhost':
        return None
    labels = raw.split('.')
    if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in labels):
        return None
    return raw

def host_from_url(value: str) -> str | None:
    candidate = value.strip()
    if '://' not in candidate:
        candidate = '//' + candidate
    try:
        return normalize_host(urlparse(candidate).hostname or '')
    except ValueError:
        return None

def asset_type_for_host(host: str, target: str) -> str:
    try:
        ipaddress.ip_address(host)
        return 'ip'
    except ValueError:
        pass
    return 'domain' if host == target.lower().rstrip('.') else 'subdomain'

def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return []

def extract_observation(observation, target: str) -> tuple[list[AssetCandidate], list[ServiceCandidate], list[EndpointCandidate], list[TechnologyCandidate]]:
    kind = observation.kind
    data = dict(observation.data)
    source = observation.source
    confidence = observation.confidence
    structured = data.get('structured') if isinstance(data.get('structured'), dict) else {}
    assets: dict[tuple[str,str], AssetCandidate] = {}
    services: list[ServiceCandidate] = []
    endpoints: list[EndpointCandidate] = []
    technologies: list[TechnologyCandidate] = []

    def add_host(raw: str | None, meta: dict[str, Any] | None = None):
        host = normalize_host(raw or '')
        if not host:
            return
        atype = asset_type_for_host(host, target)
        assets[(atype, host)] = AssetCandidate(atype, host, host, source, confidence, meta or {})

    if kind == 'asset.subdomain':
        add_host(observation.subject)
    elif kind == 'web.http_probe':
        url = str(structured.get('url') or observation.subject)
        host = host_from_url(url)
        add_host(host, {'http_url': url, 'status_code': structured.get('status-code') or structured.get('status_code'), 'title': structured.get('title')})
        if host:
            parsed = urlparse(url if '://' in url else '//' + url)
            if parsed.scheme and parsed.hostname:
                endpoints.append(EndpointCandidate(url, host, 'GET', parsed.path or '/', 'web', None, source, confidence, structured))
        for tech_key in ('tech', 'technologies', 'technology'):
            for tech in _string_list(structured.get(tech_key)):
                technologies.append(TechnologyCandidate(host or '', tech, None, None, source, confidence, {}))
        for key, cat in (('webserver','web_server'), ('server','web_server'), ('framework','framework')):
            if structured.get(key) and host:
                raw_tech = str(structured[key]).strip()
                version = None
                m = re.match(r"^(?P<name>[^/\s]+?)/(?:v)?(?P<version>\d+(?:\.\d+){1,3})$", raw_tech, re.I)
                name = raw_tech
                if m:
                    name = m.group('name')
                    version = m.group('version')
                technologies.append(TechnologyCandidate(host, name, version, cat, source, confidence, {}))
    elif kind in {'endpoint', 'api_endpoint', 'openapi'}:
        url = str(structured.get('url') or observation.subject)
        host = host_from_url(url) or normalize_host(str(data.get('host') or structured.get('host') or target))
        add_host(host)
        if host:
            parsed = urlparse(url if '://' in url else '//' + url)
            path = parsed.path or (url if url.startswith('/') else '/')
            endpoints.append(EndpointCandidate(url if '://' in url else f'https://{host}{path}', str(structured.get('method') or data.get('method') or 'UNKNOWN'), path, kind.replace('_endpoint','').replace('openapi','api') or 'web', str(structured.get('auth') or data.get('auth_hint') or '') or None, source, confidence, structured or data))
    elif kind == 'service.scan_output':
        line = str(structured.get('raw') or data.get('raw') or observation.subject).strip()
        match = SERVICE_RE.match(line)
        host = normalize_host(str(structured.get('host') or data.get('host') or ''))
        if not host:
            # A raw Nmap service line has no host identity; fall back to the observation subject when it is a host.
            host = normalize_host(observation.subject)
        add_host(host)
        if match and host:
            product = (match.group('product') or '').strip() or None
            version = None
            if product:
                version_match = re.search(r"\b(?:v)?(\d+(?:\.\d+){1,3})\b", product)
                version = version_match.group(1) if version_match else None
            services.append(ServiceCandidate(host, match.group('transport').lower(), int(match.group('port')), match.group('state').lower(), match.group('service'), product, version, source, confidence, structured or data))
        elif isinstance(structured, dict) and structured.get('port') and host:
            try:
                services.append(ServiceCandidate(host, str(structured.get('transport') or 'tcp'), int(structured['port']), str(structured.get('state') or 'unknown'), str(structured.get('service') or '') or None, str(structured.get('product') or '') or None, str(structured.get('version') or '') or None, source, confidence, structured))
            except (TypeError, ValueError):
                pass
    else:
        host = host_from_url(observation.subject) or normalize_host(observation.subject)
        if host:
            add_host(host)
        if kind in {'technology', 'web.technology', 'technology.fingerprint'} and host:
            name = str(structured.get('name') or structured.get('technology') or observation.subject).strip()
            if name:
                technologies.append(TechnologyCandidate(host, name, str(structured.get('version') or '') or None, str(structured.get('category') or '') or None, source, confidence, structured))

    return list(assets.values()), services, endpoints, technologies
