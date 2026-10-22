"""WOLF FANG engine. Standard library only. A single IP per run, with no exploitation.

Public intelligence sources are contacted only with --live. TCP connections
are gated by an explicit scope file and --authorized consent.
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

VERSION = "0.1.3"
PROVIDERS = ("rdap", "ripe", "ripestatus", "internetdb", "greynoise", "ipwhois", "ipinfo", "ipapiis", "abuseipdb", "dns", "otx")
# Reliable defaults from the user-verified v0.1.1 sessions; "all" remains supported.
DEFAULT_PROVIDERS = ("rdap", "ripe", "internetdb", "ipwhois", "ipinfo", "dns", "ipapiis")
RED = '\033[91m'
CYAN = '\033[96m'
SILVER = '\033[37m'
GREEN = '\033[92m'
GOLD = '\033[93m'
DIM = '\033[2m'
RESET = '\033[0m'


def validate_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Only literal IPv4/IPv6 accepted: no URLs, hostnames or CIDR ranges."""
    try:
        return ipaddress.ip_address(raw.strip())
    except ValueError as exc:
        raise ValueError("Enter exactly one IPv4 or IPv6 address, not a hostname, URL or CIDR") from exc


def is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_global


class ProviderHTTPError(RuntimeError):
    """An HTTP failure reported by a third-party provider."""
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"HTTP {status}" + (" (rate limited)" if status == 429 else ""))


class ProviderNoRecord(RuntimeError):
    """The provider explicitly has no indexed record; not a query failure."""


def get_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 7) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise ValueError("Only HTTPS providers supported")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"GlitchByte-WolfFang/{VERSION} (+single-IP-research)", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > 2_000_000:
                raise RuntimeError("Provider response too large")
            data = resp.read(2_000_001)
            if len(data) > 2_000_000:
                raise RuntimeError("Provider response too large")
            obj = json.loads(data)
            if not isinstance(obj, dict):
                raise RuntimeError("Provider did not return a JSON object")
            return obj
    except urllib.error.HTTPError as exc:
        raise ProviderHTTPError(exc.code) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Provider unavailable: {type(exc).__name__}") from exc


def endpoint(base: str, **params: Any) -> str:
    return base + '?' + urllib.parse.urlencode(params)


def rdap(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    obj = fetch(f"https://rdap.org/ip/{ip}")
    entities = []
    for ent in obj.get("entities", []):
        if isinstance(ent, dict):
            entities.append({"handle": ent.get("handle"), "roles": ent.get("roles", [])})
    return {"name": obj.get("name"), "handle": obj.get("handle"), "type": obj.get("type"),
            "country": obj.get("country"), "startAddress": obj.get("startAddress"),
            "endAddress": obj.get("endAddress"), "ipVersion": obj.get("ipVersion"),
            "entities": entities[:20], "remarks": [x.get("description") for x in obj.get("remarks", []) if isinstance(x, dict)][:5]}


def ripe(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    network = fetch(endpoint("https://stat.ripe.net/data/network-info/data.json", resource=ip)).get("data", {})
    abuse = fetch(endpoint("https://stat.ripe.net/data/abuse-contact-finder/data.json", resource=ip)).get("data", {})
    asns = network.get("asns", [])
    out = {"prefix": network.get("prefix"), "origin_asns": asns,
           "abuse_contacts": abuse.get("abuse_contacts", []),
           "authoritative_rir": abuse.get("authoritative_rir")}
    if asns:
        try:
            overview = fetch(endpoint("https://stat.ripe.net/data/as-overview/data.json", resource=f"AS{asns[0]}")).get("data", {})
            out["asn_overview"] = {"holder": overview.get("holder"), "announced": overview.get("announced")}
        except Exception as exc:
            out["asn_overview_note"] = type(exc).__name__
    return out


def ripestatus(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    """RIPE RIS routing visibility snapshot, not a network scan."""
    obj = fetch(endpoint("https://stat.ripe.net/data/routing-status/data.json", resource=ip))
    if obj.get("status") not in (None, "ok"):
        raise RuntimeError("RIPEstat returned a non-OK response")
    data = obj.get("data") or {}
    visibility = data.get("visibility") or {}
    # Avoid excessive/deceptively precise outputs: only selected metadata.
    return {"query_time": data.get("query_time"),
            "first_seen": data.get("first_seen"), "last_seen": data.get("last_seen"),
            "visibility": visibility,
            "note": "RIPE RIS collector visibility, not direct connectivity verification"}


def internetdb(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    try:
        obj = fetch(f"https://internetdb.shodan.io/{ip}")
    except ProviderHTTPError as exc:
        if exc.status == 404:
            raise ProviderNoRecord("No InternetDB observations for this IP") from exc
        raise
    return {"ports": obj.get("ports", []), "hostnames": obj.get("hostnames", []),
            "tags": obj.get("tags", []), "cpes": obj.get("cpes", []), "reported_cves": obj.get("vulns", [])}


def greynoise(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    try:
        obj = fetch(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": os.environ.get("GREYNOISE_API_KEY", "")} if os.environ.get("GREYNOISE_API_KEY") else None)
    except ProviderHTTPError as exc:
        if exc.status == 404:
            raise ProviderNoRecord("Not observed by GreyNoise Community dataset") from exc
        raise
    return {k: obj.get(k) for k in ("noise", "riot", "classification", "name", "last_seen", "link", "message")}


def ipwhois(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    obj = fetch(f"https://ipwho.is/{ip}")
    if obj.get("success") is False:
        raise RuntimeError("Geolocation provider has no record")
    connection = obj.get("connection") or {}
    return {"country": obj.get("country"), "region": obj.get("region"),
            "city": obj.get("city"), "latitude": obj.get("latitude"), "longitude": obj.get("longitude"),
            "asn": connection.get("asn"), "org": connection.get("org"), "isp": connection.get("isp"),
            "domain": connection.get("domain"), "timezone": (obj.get("timezone") or {}).get("id")}


def ipinfo(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    token = os.environ.get("IPINFO_TOKEN")
    url = endpoint(f"https://ipinfo.io/{ip}/json", token=token) if token else f"https://ipinfo.io/{ip}/json"
    obj = fetch(url)
    if obj.get("error"):
        raise RuntimeError("IPinfo returned an error")
    return {k: obj.get(k) for k in ("hostname", "city", "region", "country", "org", "postal", "timezone", "anycast")}


def ipapiis(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    """Anonymous ipapi.is ownership/geolocation subset; no premium risk claims."""
    obj = fetch(endpoint("https://api.ipapi.is/", q=ip))
    if obj.get("error"):
        raise RuntimeError("IPapi.is returned an error")
    return {"company": obj.get("company"), "asn": obj.get("asn"),
            "country": obj.get("country"), "region": obj.get("region"),
            "city": obj.get("city"), "lat": obj.get("lat"), "lon": obj.get("lon"),
            "timezone": obj.get("timezone"), "is_bogon": obj.get("is_bogon"),
            "security_flags_available": False,
            "note": "Anonymous tier: ownership/location only; VPN/proxy/Tor/abuse flags not supplied"}


def abuseipdb(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("Skipped (set ABUSEIPDB_API_KEY to enable)")
    obj = fetch(endpoint("https://api.abuseipdb.com/api/v2/check", ipAddress=ip, maxAgeInDays=90), headers={"Key": key})
    data = obj.get("data", {})
    return {k: data.get(k) for k in ("abuseConfidenceScore", "totalReports", "lastReportedAt", "usageType", "isp", "domain", "isWhitelisted")}



def otx(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    """Basic public Open Threat Exchange summary. Community reporting is not validation."""
    kind = "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"
    token = os.environ.get("OTX_API_KEY")
    headers = {"X-OTX-API-KEY": token} if token else None
    try:
        obj = fetch(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general", headers=headers)
    except ProviderHTTPError as exc:
        if exc.status == 404:
            raise ProviderNoRecord("No OTX general indicator record") from exc
        raise
    pulse_info = obj.get("pulse_info") or {}
    count = pulse_info.get("count")
    if not isinstance(count, int) or isinstance(count, bool):
        count = None
    return {"pulse_count": count, "reputation": obj.get("reputation"),
            "asn": obj.get("asn"), "country_code": obj.get("country_code"),
            "note": "Community-submitted indicator context; not proof of active threat, ownership or abuse"}


def dns(ip: str, fetch: Callable[..., dict] = get_json) -> dict:
    del fetch
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror, socket.gaierror):
        return {"reverse_dns": None, "forward_confirmed": False, "aliases": []}
    try:
        resolved = {item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
        confirmed = ip in resolved
    except OSError:
        confirmed = False
    return {"reverse_dns": hostname, "forward_confirmed": confirmed, "aliases": aliases[:10]}


ADAPTERS = {"rdap": rdap, "ripe": ripe, "ripestatus": ripestatus, "internetdb": internetdb,
            "greynoise": greynoise, "ipwhois": ipwhois, "ipinfo": ipinfo,
            "ipapiis": ipapiis, "abuseipdb": abuseipdb, "dns": dns, "otx": otx}


def honeypot_assessment(results: dict[str, Any]) -> dict[str, Any]:
    """Passive evidence only. Not a definitive honeypot detection or evasion score."""
    raw_tags = results.get("internetdb", {}).get("tags", [])
    tags = [str(t).lower() for t in raw_tags] if isinstance(raw_tags, list) else []
    matches = [t for t in tags if any(word in t for word in ("honeypot", "honeynet", "cowrie", "dionaea", "t-pot"))]
    if matches:
        return {"verdict": "POSSIBLE HONEYPOT INDICATOR", "confidence": "low",
                "evidence": [f"InternetDB public tag: {t}" for t in matches],
                "caution": "Third-party tags may be stale, ambiguous, or wrong; no direct validation performed."}
    return {"verdict": "NO POSITIVE PUBLIC TAG", "confidence": "none",
            "evidence": [], "caution": "Absence of a tag cannot establish that the address is not a honeypot."}


def parse_ports(raw: str) -> list[int]:
    if not raw:
        return []
    ports = []
    for part in raw.split(','):
        token = part.strip()
        if not token.isdecimal() or not 1 <= int(token) <= 65535:
            raise ValueError("Ports must be comma-separated integers from 1 to 65535")
        n = int(token)
        if n not in ports:
            ports.append(n)
    if len(ports) > 16:
        raise ValueError("For safety, limit checks to 16 explicitly chosen TCP ports")
    return ports


def scope_allows(ip: str, scope_file: str | None) -> bool:
    if not scope_file:
        return False
    path = Path(scope_file).expanduser()
    if not path.is_file():
        raise ValueError("Scope file not found")
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            # Exact IP entries only; no entire subnets or wildcards.
            try:
                if str(validate_ip(line)) == ip:
                    return True
            except ValueError:
                continue
    return False


def authorized_tcp_check(ip: str, ports: list[int], timeout: float = 1.0) -> list[dict[str, Any]]:
    results = []
    for port in ports:
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                state = "open"
        except ConnectionRefusedError:
            state = "closed"
        except (TimeoutError, socket.timeout):
            state = "filtered_or_unreachable"
        except OSError:
            state = "network_error"
        results.append({"port": port, "protocol": "tcp", "state": state,
                        "milliseconds": round(1000 * (time.monotonic() - start), 1)})
        time.sleep(0.2)
    return results


def analyze(ip_raw: str, *, live: bool = False, selected: list[str] | None = None,
            delay: float = 0.7, ports: list[int] | None = None,
            authorized: bool = False, scope_file: str | None = None,
            timeout: float = 7) -> dict[str, Any]:
    ip_obj = validate_ip(ip_raw)
    ip = str(ip_obj)
    selected = selected if selected is not None else list(DEFAULT_PROVIDERS)
    if any(p not in PROVIDERS for p in selected):
        raise ValueError("Unknown provider")
    ports = ports or []
    if ports and (not authorized or not scope_allows(ip, scope_file)):
        raise ValueError("TCP checks require --authorized AND an exact IP entry in --scope-file")
    report: dict[str, Any] = {
        "tool": "WOLF FANG", "version": VERSION,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "ip": ip, "ip_version": ip_obj.version, "public_routable": is_public(ip_obj),
        "mode": "public-source lookups" if live else "offline", "providers": {}, "provider_errors": {}, "provider_status": {},
        "tcp_check": [], "notices": [
            "IP intelligence is not proof of identity, physical address, or wrongdoing.",
            "Published hostnames are not a complete list of domains on an IP.",
            "Provider CVE associations may be unverified and do not constitute an exploitation test."]}
    if live and is_public(ip_obj):
        # Applies --timeout to EVERY HTTPS adapter; 0.1.0 inadvertently used
        # the default 7s timeout regardless of CLI timeout setting.
        def fetch(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
            return get_json(url, headers=headers, timeout=timeout)

        for index, provider in enumerate(selected):
            _provider_started = time.monotonic()
            try:
                if provider == "abuseipdb" and not os.environ.get("ABUSEIPDB_API_KEY"):
                    report["provider_status"][provider] = {"state": "not_configured", "detail": "Optional key not set; run ./CONFIGURE_KEYS.sh"}
                else:
                    report["providers"][provider] = ADAPTERS[provider](ip, fetch=fetch)
                    report["provider_status"][provider] = {"state": "ok"}
            except ProviderNoRecord as exc:
                report["provider_status"][provider] = {"state": "no_record", "detail": str(exc)}
            except ProviderHTTPError as exc:
                states = {401: "authentication_error", 402: "plan_restricted", 403: "access_denied", 429: "rate_limited"}
                state = states.get(exc.status, "provider_error")
                detail = {401: "Check API key", 402: "Provider plan does not permit this request",
                          403: "Request not permitted", 429: "Rate limited; stop and retry later"}.get(exc.status, f"HTTP {exc.status}")
                report["provider_status"][provider] = {"state": state, "http_status": exc.status, "detail": detail}
                report["provider_errors"][provider] = detail
            except Exception as exc:
                # Never interpolate URLs or secrets into reports or diagnostics.
                detail = (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__)[:160]
                report["provider_status"][provider] = {"state": "unavailable", "detail": detail}
                report["provider_errors"][provider] = detail
            # Useful on slow connections: elapsed time is measured even on errors.
            report["provider_status"].setdefault(provider, {"state": "unknown"})["elapsed_ms"] = round(
                (time.monotonic() - _provider_started) * 1000, 1)
            if index < len(selected) - 1:
                time.sleep(max(0.0, delay))
    elif live:
        report["notices"].append("Non-global IP: skipped all external providers; local/private addresses stay local.")
    else:
        report["notices"].append("Offline mode: no provider requests. Pass --live to query APIs.")
    report["honeypot"] = honeypot_assessment(report["providers"])
    if ports:
        report["tcp_check"] = authorized_tcp_check(ip, ports, timeout=min(timeout, 3.0))
        report["notices"].append("Authorized direct TCP connection checks only; no authentication, exploits or payloads.")
    return report


def demo_report() -> dict[str, Any]:
    """Synthetic offline example, without any network operations."""
    return {"tool": "WOLF FANG", "version": VERSION, "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "ip": "192.0.2.10", "ip_version": 4, "public_routable": False,
            "mode": "SYNTHETIC DEMO (NOT A LIVE LOOKUP)",
            "providers": {"rdap": {"name": "DEMO-NET", "country": "EXAMPLE", "startAddress": "192.0.2.0", "endAddress": "192.0.2.255"},
                          "ripe": {"prefix": "192.0.2.0/24", "origin_asns": ["AS64500"], "abuse_contacts": ["abuse@example.invalid"]},
                          "internetdb": {"ports": [22, 443], "tags": ["honeypot-demo"], "hostnames": ["sample.example.invalid"], "reported_cves": []}},
            "provider_errors": {}, "provider_status": {}, "tcp_check": [],
            "honeypot": {"verdict": "POSSIBLE HONEYPOT INDICATOR", "confidence": "low",
                         "evidence": ["Synthetic public tag: honeypot-demo"],
                         "caution": "SYNTHETIC: no actual host identified or verified."},
            "notices": ["DEMO DATA ONLY. No live IP owner, host, or actual honeypot was tested."]}


def colorize(value: str, color: str, enabled: bool = True) -> str:
    return f"{color}{value}{RESET}" if enabled else value


def format_console(report: dict[str, Any], color: bool = True) -> str:
    header = ("╔════════════════════════════════════════════════════════════╗\n"
              "║  🐺 WOLF FANG // GLITCHBYTE PHANTOM LABS // INTEL CORE   ║\n"
              "╚════════════════════════════════════════════════════════════╝")
    lines = [colorize(header, RED, color),
             f"  {colorize('◆ TARGET', CYAN, color)}   {report['ip']}   [{report['mode']}]",
             f"  {colorize('◆ ROUTABLE', CYAN, color)} {report['public_routable']}"]
    for name, data in report.get("providers", {}).items():
        lines.append(colorize(f"\n  ◆ {name.upper()} // RECEIVED", GREEN, color))
        for key, val in data.items():
            if val is not None and val != [] and val != "":
                display = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val)
                lines.append(f"    {key:<23} {display[:350]}")
    for name, status in report.get("provider_status", {}).items():
        if status.get("state") != "ok":
            lines.append(colorize(f"  ◇ {name.upper()} // {status['state'].upper()} // {status.get('detail', '')}", GOLD, color))
    if not report.get("provider_status"):
        for name, msg in report.get("provider_errors", {}).items():
            lines.append(colorize(f"  ◇ {name.upper()} // {msg}", GOLD, color))
    hp = report.get("honeypot", {})
    lines.append(colorize(f"\n  ◆ HONEYPOT SENTINEL // {hp.get('verdict', 'UNKNOWN')}", RED, color))
    lines.append(f"    Confidence: {hp.get('confidence', 'none')} | {hp.get('caution', '')}")
    for finding in hp.get("evidence", []):
        lines.append(f"    Evidence: {finding}")
    for obj in report.get("tcp_check", []):
        lines.append(f"  ◆ TCP {obj['port']:>5}  {obj['state']}  ({obj['milliseconds']} ms)")
    for notice in report.get("notices", []):
        lines.append(colorize(f"  NOTE: {notice}", DIM, color))
    return '\n'.join(lines)


def _flatten(obj: dict, prefix: str = '') -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, value in obj.items():
        new_key = (prefix + '.' + key).strip('.')
        if isinstance(value, dict):
            rows.extend(_flatten(value, new_key))
        else:
            rows.append((new_key, json.dumps(value, ensure_ascii=False) if isinstance(value, list) else str(value)))
    return rows


def save_reports(report: dict[str, Any], dest: str) -> dict[str, str]:
    target = Path(dest).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target, 0o700)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    prefix = f"WOLF-FANG-{report['ip'].replace(':', '_')}-{timestamp}"
    json_path, csv_path, html_path = [target / (prefix + ext) for ext in ('.json', '.csv', '.html')]
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    with csv_path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['field', 'value'])
        writer.writerows(_flatten(report))
    from .vision import render_dashboard
    html_path.write_text(render_dashboard(report), encoding='utf-8')
    for path in (json_path, csv_path, html_path):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return {"json": str(json_path), "csv": str(csv_path), "html": str(html_path)}


def apply_local_feed(report: dict[str, Any], feed: str | None) -> None:
    """Join a user-owned CSV feed containing exact ip,tag,source records, offline."""
    if not feed:
        return
    path = Path(feed).expanduser()
    if not path.is_file():
        raise ValueError("Local feed CSV file not found")
    if path.stat().st_size > 1_000_000:
        raise ValueError("Local feed exceeds the 1 MB limit")
    matched: list[dict[str, str]] = []
    with path.open(newline='', encoding='utf-8') as inp:
        for row in csv.DictReader(inp):
            try:
                row_ip = str(validate_ip(row.get('ip', '')))
            except ValueError:
                continue
            if row_ip == report['ip']:
                matched.append({"tag": str(row.get('tag', ''))[:120], "source": str(row.get('source', 'local CSV'))[:120]})
            if len(matched) >= 50:
                break
    report['local_tag_feed'] = matched
    hints = [m for m in matched if any(word in m['tag'].lower() for word in ('honeypot', 'honeynet', 'deception', 'cowrie', 'dionaea', 't-pot'))]
    if hints:
        assessment = report['honeypot']
        assessment['verdict'] = 'POSSIBLE HONEYPOT INDICATOR'
        assessment['confidence'] = 'low'
        assessment['evidence'].extend(f"Local analyst feed ({m['source']}): {m['tag']}" for m in hints)
        assessment['caution'] = 'Locally supplied tags require independent validation; no direct fingerprinting performed.'
