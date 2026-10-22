"""FANG VISION: static, offline intelligence dashboard. No network or external assets.

Works with WOLF FANG v0.1.0+ JSON reports and never changes the source JSON.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import html
import ipaddress
import json
import os
from pathlib import Path
import stat
import webbrowser
from typing import Any

SOURCE_INFO = {
    'rdap': ('NETWORK REGISTRATION', 'Allocation, registration contacts and administrative remarks'),
    'ripe': ('BGP & ASN', 'RIPEstat network origin, routing prefix and abuse contacts'),
    'ripestatus': ('ROUTING VISIBILITY', 'RIPE RIS routing observation, not direct reachability'),
    'internetdb': ('INTERNETDB INDEX', 'Previously indexed ports, hostnames, candidate CPEs and tags'),
    'ipwhois': ('GEO / PROVIDER', 'Estimated location and network operator'),
    'ipinfo': ('HOST & GEO', 'Reverse hostname and approximate city or ISP'),
    'ipapiis': ('OWNERSHIP', 'Supplemental ASN, organization and approximate location'),
    'greynoise': ('INTERNET NOISE', 'Community scanning visibility; not a honeypot verdict'),
    'abuseipdb': ('ABUSE REPORTS', 'User-submitted reports, not independently verified guilt'),
    'dns': ('DNS OBSERVATION', 'Reverse DNS and forward confirmation'),
    'otx': ('OTX COMMUNITY', 'Community-submitted indicator context, not a verified threat'),
}

CSS = '''
:root{color-scheme:dark;--bg:#090c13;--panel:#141b27;--panel2:#101520;--border:#2d3c4b;--silver:#e8eef2;--muted:#a5b4c3;--cyan:#5adce5;--red:#f54b62;--green:#a0f4b2;--gold:#ffce72}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#2e111d 0%,transparent 34%),radial-gradient(ellipse at 3% 25%,#0d303a 0%,transparent 32%),var(--bg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--silver)}
.container{max-width:1190px;margin:auto;padding:38px 22px 70px}.topline{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-size:11px;letter-spacing:2px;color:var(--cyan);font-weight:750}.sig{color:var(--red)}
.hero{padding:30px 30px 34px;border:1px solid #69303b;border-radius:17px;background:linear-gradient(125deg,#24121d,#171b29 60%,#102b32);position:relative;overflow:hidden;margin:16px 0 20px}
.wolf-banner{width:100%;height:auto;display:block;max-height:360px;object-fit:cover;object-position:center;border-radius:11px;margin-bottom:18px;border:1px solid #792c3b} .hero:after{content:'//';position:absolute;right:28px;top:10px;color:#f54b6240;font-size:145px;font-weight:900;line-height:1}h1{margin:0;color:#f9f9fc;font-weight:900;letter-spacing:1px;font-size:clamp(35px,5vw,58px)}h1 b{color:var(--red)}.hero p{max-width:800px;color:#cad8e1;margin:8px 0}.target{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:clamp(17px,3vw,27px);color:var(--cyan);font-weight:750;word-break:break-word}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 0}.pill,.state{border-radius:99px;border:1px solid #395064;padding:4px 10px;font-size:11px;letter-spacing:.7px;font-weight:800;text-transform:uppercase;background:#152737;color:#b8ddea}.state.ok{border-color:#286b5b;background:#14352f;color:var(--green)}.state.issue{border-color:#775038;background:#3a291d;color:var(--gold)}.state.miss{border-color:#4a5366;background:#252832;color:#bcc5d3}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:15px 0 23px}.card{background:var(--panel);border:1px solid var(--border);padding:17px;border-radius:13px;min-width:0}.card .num{font-weight:900;color:var(--cyan);font-size:30px}.card .cap{font-size:11px;letter-spacing:1.2px;font-weight:850;color:var(--muted)}
.group{margin-top:21px}.heading{display:flex;align-items:center;gap:11px;margin:0 0 10px;font-size:18px;letter-spacing:.4px}.heading:before{content:'';height:18px;width:4px;background:var(--red);border-radius:5px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.panel{background:var(--panel);border:1px solid var(--border);padding:17px;border-radius:14px;min-width:0;overflow-wrap:anywhere}.provider-head{display:flex;align-items:center;justify-content:space-between;gap:9px;flex-wrap:wrap}.provider-name{font-weight:850;letter-spacing:.6px}.hint{color:var(--muted);font-size:12px;margin:7px 0}.kv{display:grid;grid-template-columns:minmax(90px,35%) 1fr;gap:7px;padding:7px 0;border-bottom:1px solid #26303b}.kv:last-child{border-bottom:0}.key{color:var(--cyan);font-size:12px;overflow-wrap:anywhere}.value{overflow-wrap:anywhere;font-size:13px}.value.mono{font-family:ui-monospace,Consolas,monospace}.empty{color:var(--muted);font-style:italic}
.note{padding:16px 18px;border:1px solid #63454b;background:#241923;border-radius:12px;color:#e6cbd0}.note.soft{border-color:#304c57;background:#14222b;color:#c4e3e5}.note p{margin:5px 0}.label{letter-spacing:.9px;text-transform:uppercase;font-size:11px;font-weight:900;color:var(--red)}
details{margin-top:8px;border-top:1px solid var(--border);padding-top:8px}summary{cursor:pointer;color:var(--cyan);font-weight:750;font-size:12px}small,footer{color:var(--muted)}a{color:var(--cyan)}.footer{border-top:1px solid var(--border);padding-top:18px;margin-top:28px;font-size:12px} .geo-alert{color:var(--gold)}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}}
@media(max-width:475px){.container{padding:18px 12px 40px}.hero{padding:20px}.cards{grid-template-columns:1fr 1fr}.card{padding:12px}.card .num{font-size:24px}}
@media print{body{background:white;color:black}.panel,.card,.hero,.note{background:white;color:black;border-color:#aaa}.key,.target,.provider-name{color:#005b66} .value,.hint,.cap,.hero p{color:black} .grid{grid-template-columns:1fr}}
'''


def esc(v: Any) -> str:
    if v is None: return 'Unknown'
    if isinstance(v, (list, dict)): v = json.dumps(v, ensure_ascii=False, sort_keys=True)
    return html.escape(str(v), quote=True)


def brief(v: Any, maxlen: int = 1200) -> str:
    s = esc(v)
    return (s[:maxlen] + '…') if len(s) > maxlen else s


def kv_rows(obj: dict, *, max_entries: int = 35) -> str:
    rows = []
    for key, value in list(obj.items())[:max_entries]:
        if value is None or value == '' or value == []: continue
        rows.append(f'<div class="kv"><span class="key">{esc(key)}</span><span class="value">{brief(value)}</span></div>')
    return '\n'.join(rows) if rows else '<p class="empty">No additional fields supplied</p>'


def state_tag(state: str) -> str:
    cls = 'ok' if state == 'ok' else 'miss' if state in ('no_record','not_configured','offline','skipped') else 'issue'
    return f'<span class="state {cls}" data-state="{esc(state)}">{esc(state.replace("_", " "))}</span>'


def embedded_wolf_art() -> str:
    """Embed locally packaged wolf artwork. Reports remain portable and work offline.

    This is a fixed trusted package asset, never a path or URL from report data.
    """
    art = Path(__file__).resolve().parent.parent / 'assets' / 'fang-vision-inline.webp'
    if not art.is_file():
        return ''  # Allow source-only installations to keep their CSS-only header.
    raw = art.read_bytes()
    if len(raw) > 400_000:
        return ''  # Cap inlined assets so reports stay manageable.
    return '<img class="wolf-banner" src="data:image/webp;base64,' + base64.b64encode(raw).decode('ascii') + '" alt="WOLF FANG cyber-wolf command-center cover artwork">'


def render_dashboard(report: dict[str, Any]) -> str:
    if not isinstance(report, dict) or not isinstance(report.get('ip'), str):
        raise ValueError('Report must be a JSON object with an IP string')
    ip = report['ip']
    # Prevent arbitrary HTML or fake source metadata from unsanitized imported files.
    prov = report.get('providers') if isinstance(report.get('providers'), dict) else {}
    statuses = report.get('provider_status') if isinstance(report.get('provider_status'), dict) else {}
    hp = report.get('honeypot') if isinstance(report.get('honeypot'), dict) else {}
    notices = report.get('notices') if isinstance(report.get('notices'), list) else []
    provider_names = list(dict.fromkeys([*statuses, *prov]))
    good = sum(1 for name in provider_names if isinstance(prov.get(name), dict) and (not isinstance(statuses.get(name), dict) or statuses[name].get('state')=='ok'))
    health = f'{good}/{len(provider_names)}' if provider_names else '0/0'
    ip_index = prov.get('internetdb') if isinstance(prov.get('internetdb'), dict) else {}
    ports = ip_index.get('ports') if isinstance(ip_index.get('ports'), list) else []
    hostnames = ip_index.get('hostnames') if isinstance(ip_index.get('hostnames'), list) else []
    asn = None
    ri = prov.get('ripe') if isinstance(prov.get('ripe'), dict) else {}
    asns = ri.get('origin_asns') if isinstance(ri.get('origin_asns'), list) else []
    if asns: asn = asns[0]
    if not asn:
        pi = prov.get('ipinfo') if isinstance(prov.get('ipinfo'), dict) else {}
        asn = pi.get('org') or 'Not reported'
    def card(value: Any, caption: str):
        return f'<div class="card"><div class="num">{brief(value,80)}</div><div class="cap">{esc(caption)}</div></div>'
    cards = (card(health, 'SOURCES RETURNING DATA') + card(asn, 'ASN / NETWORK') +
             card(len(ports), 'INDEXED PORTS, NOT LIVE') + card(len(hostnames), 'PUBLISHED HOSTNAMES'))
    sections=[]
    for name in provider_names:
        st = statuses.get(name)
        if not isinstance(st, dict): st={'state': 'ok' if name in prov else 'unknown'}
        state = str(st.get('state', 'unknown'))
        title, hint = SOURCE_INFO.get(name, (name.upper(), 'External data source'))
        d = prov.get(name) if isinstance(prov.get(name), dict) else {}
        meta = {k:v for k,v in st.items() if k!='state'}
        datapart = kv_rows(d) if d else '<p class="empty">No source data returned</p>'
        if meta:
            datapart += '<details><summary>Connection details</summary>' + kv_rows(meta) + '</details>'
        sections.append(f'<article class="panel"><div class="provider-head"><span class="provider-name">{esc(name.upper())} · {esc(title)}</span>{state_tag(state)}</div><p class="hint">{esc(hint)}</p>{datapart}</article>')
    if not sections: sections=['<div class="panel empty">No provider lookups were run for this report.</div>']
    hp_evidence = hp.get('evidence') if isinstance(hp.get('evidence'), list) else []
    hp_lines = ''.join('<p>• '+brief(x,450)+'</p>' for x in hp_evidence[:30])
    hp_box = f'''<div class="note"><div class="label">Honeypot Sentinel // Passive evidence only</div>
    <strong>{brief(hp.get('verdict','UNDETERMINED'),150)}</strong><p>Confidence: {brief(hp.get('confidence','none'),60)}</p>
    {hp_lines}<p>{brief(hp.get('caution','No direct honeypot fingerprinting performed'),800)}</p></div>'''
    details=[]
    if ports: details.append(f'<div class="kv"><span class="key">Historical port index</span><span class="value mono">{brief(ports)}</span></div>')
    if hostnames: details.append(f'<div class="kv"><span class="key">Indexed hostnames</span><span class="value">{brief(hostnames)}</span></div>')
    idx = ''.join(details) or '<p class="empty">No port or hostname index included in this report.</p>'
    # Allow transparent viewing of authorized checks without encouraging scanning by dashboard.
    tcp = report.get('tcp_check') if isinstance(report.get('tcp_check'), list) else []
    if tcp: idx += '<details><summary>Previously recorded authorized TCP checks</summary>' + ''.join(kv_rows(x) for x in tcp[:16] if isinstance(x, dict)) + '</details>'
    note_lines=''.join('<p>• '+brief(n,500)+'</p>' for n in notices[:18])
    sample = 'SYNTHETIC' in str(report.get('mode','')).upper()
    demo = '<span class="pill">SYNTHETIC / NO LIVE HOST</span>' if sample else ''
    warn = 'Offline local report. Imported observations may be historical or inaccurate. Location refers to IP registration or infrastructure and can be very misleading for anycast networks or VPNs.'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
    <title>WOLF FANG · FANG VISION · {esc(ip)}</title><style>{CSS}</style></head><body><main class="container">
    <div class="topline"><span>◈ GLITCHBYTE PHANTOM LABS // WOLF FANG</span><span class="sig">OFFLINE INTELLIGENCE DISPLAY</span></div>
    <header class="hero">{embedded_wolf_art()}<h1>🐺 WOLF <b>FANG</b></h1><div class="target">TARGET // {esc(ip)}</div>
    <p>FANG VISION · IP ownership, routing, indexed observations, source reliability and honeypot context.</p>
    <div class="pills"><span class="pill">{esc(report.get('mode','unknown'))}</span><span class="pill">REPORT {esc(report.get('version','?'))}</span>
    <span class="pill">{esc(report.get('timestamp_utc','time not supplied'))}</span>{demo}</div></header>
    <section class="cards" aria-label="At a glance">{cards}</section>
    <section class="group"><h2 class="heading">ANALYST CAUTIONS</h2><div class="note soft"><div class="label">Network data ≠ personal identity</div>
    <p>{esc(warn)}</p><p>InternetDB ports and hostnames are indexed observations, not a current port scan or proof that a particular person controls these domains.</p></div></section>
    <section class="group"><h2 class="heading">HONEYPOT SENTINEL</h2>{hp_box}</section>
    <section class="group"><h2 class="heading">PUBLISHED PORT & DOMAIN OBSERVATIONS</h2><div class="panel">{idx}</div></section>
    <section class="group"><h2 class="heading">PROVIDER STATUS & EVIDENCE</h2><div class="grid">{''.join(sections)}</div></section>
    <section class="group"><h2 class="heading">REPORT NOTICES</h2><div class="panel">{note_lines or '<p class="empty">No additional notices.</p>'}</div></section>
    <div class="footer">WOLF FANG / FANG VISION · Rendered entirely offline from a local JSON report · Embedded local artwork; no remote JavaScript, fonts, images, tracking, or API calls · Not a vulnerability scan.</div>
    </main></body></html>'''


def build_from_file(source: Path, out_dir: Path) -> Path:
    source = source.expanduser().resolve()
    if not source.is_file() or not source.name.endswith('.json'):
        raise ValueError('Supply a WOLF FANG JSON report file')
    if source.stat().st_size > 2_000_000:
        raise ValueError('Report exceeds 2 MB safety limit')
    report = json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(report, dict) or report.get('tool') != 'WOLF FANG':
        raise ValueError('The file is not a WOLF FANG JSON report')
    if not isinstance(report.get('ip'), str):
        raise ValueError('Missing IP in report')
    ipaddress.ip_address(report['ip'])
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = out_dir / f'FANG-VISION-{report["ip"].replace(":","_")}-{timestamp}.html'
    target.write_text(render_dashboard(report), encoding='utf-8')
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='🐺 FANG VISION // Offline dashboard from WOLF FANG JSON reports')
    parser.add_argument('--file', help='Path to a WOLF FANG JSON report; defaults to most recent JSON in ~/WolfFangReports')
    parser.add_argument('--reports', default='~/WolfFangReports', help='Input report directory for latest-file lookup')
    parser.add_argument('--out', default='~/WolfFangDashboards', help='Private destination for generated HTML dashboards')
    parser.add_argument('--open', action='store_true', help='Try opening the resulting local HTML dashboard in a browser')
    args = parser.parse_args(argv)
    try:
        if args.file:
            source = Path(args.file)
        else:
            matches = list(Path(args.reports).expanduser().glob('WOLF-FANG-*.json'))
            if not matches:
                raise ValueError('No WOLF FANG JSON reports found; first run --demo or a live lookup')
            source = max(matches, key=lambda p:p.stat().st_mtime)
        dest = build_from_file(source, Path(args.out))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print('🐺 FANG VISION // OFFLINE DASHBOARD')
    print('  ◆ SOURCE', source)
    print('  ◆ SAVED', dest)
    print('  ◆ NO PROVIDER REQUESTS // REPORTS STAY LOCAL')
    if args.open:
        try:
            if not webbrowser.open(dest.as_uri()):
                print('  ◇ Browser did not open. Use: firefox "'+str(dest)+'"')
        except Exception:
            print('  ◇ Browser did not open. Use: firefox "'+str(dest)+'"')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
