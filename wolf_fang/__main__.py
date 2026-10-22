import argparse
import os
import sys
from pathlib import Path
from .core import (DEFAULT_PROVIDERS, PROVIDERS, VERSION, analyze, apply_local_feed, demo_report,
                   format_console, parse_ports, save_reports)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="wolf-fang", description="🐺 WOLF FANG // Public-source IP intelligence and scoped defensive TCP checks")
    parser.add_argument("ip", nargs="?", help="One literal IPv4 or IPv6 address")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="Query selected public intelligence providers")
    mode.add_argument("--demo", action="store_true", help="Use synthetic offline data, no network activity")
    parser.add_argument("--providers", default="default", help="default (seven working sources), all, or comma-separated names")
    parser.add_argument("--tag-feed", help="Optional local CSV with ip,tag,source for analyst-supplied metadata")
    parser.add_argument("--tcp-ports", default="", help="Authorized checks only; explicit TCP ports, max 16")
    parser.add_argument("--authorized", action="store_true", help="Affirm authorization for exact target in scope file")
    parser.add_argument("--scope-file", help="Plain text exact IP allowlist for TCP checks")
    parser.add_argument("--timeout", type=float, default=20, help="Per-provider timeout seconds (default: 20; max: 30)")
    parser.add_argument("--delay", type=float, default=0.7, help="Seconds between provider queries (default: 0.7)")
    parser.add_argument("--out", default=os.path.expanduser('~/WolfFangReports'), help="Output directory for JSON, CSV and HTML")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--list-providers", action="store_true")
    parser.add_argument("--doctor", action="store_true", help="Offline provider/key configuration diagnosis, no network requests")
    args = parser.parse_args(argv)
    if args.doctor:
        import platform
        print("🐺 WOLF FANG // OFFLINE DOCTOR // v" + VERSION)
        print("Python:", platform.python_version(), "(3.10+ required)")
        print("API keys: presence only; no secret values are printed")
        for key in ("GREYNOISE_API_KEY", "ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "OTX_API_KEY"):
            print("  ◆", key, "CONFIGURED" if os.environ.get(key) else "NOT CONFIGURED (optional)")
        print("IPapi.is anonymous tier: ownership/location only; subject to daily limits")
        print("Default sources:", ", ".join(DEFAULT_PROVIDERS))
        print("Default network timeout: 20 seconds per HTTPS request")
        print("Reports:", str(Path(args.out).expanduser()))
        print("Offline checks complete. Provider connectivity was NOT tested.")
        return 0
    if args.list_providers:
        print('\n'.join(PROVIDERS))
        return 0
    if args.demo and args.ip:
        parser.error("--demo takes no target IP")
    if not args.demo and not args.ip:
        parser.error("Supply one IP, or choose --demo")
    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be between 0 and 30 seconds")
    if not 0 <= args.delay <= 10:
        parser.error("--delay must be between 0 and 10 seconds")
    providers = (list(PROVIDERS) if args.providers.strip().lower() == 'all' else
                 list(DEFAULT_PROVIDERS) if args.providers.strip().lower() == 'default' else
                 [x.strip().lower() for x in args.providers.split(',')])
    if not providers or any(p not in PROVIDERS for p in providers):
        parser.error('Invalid providers. Choose from: ' + ', '.join(PROVIDERS))
    try:
        ports = parse_ports(args.tcp_ports)
        if args.demo and ports:
            parser.error('--demo cannot be combined with TCP checks')
        report = demo_report() if args.demo else analyze(args.ip, live=args.live, selected=providers, delay=args.delay,
            ports=ports, authorized=args.authorized, scope_file=args.scope_file, timeout=args.timeout)
        apply_local_feed(report, args.tag_feed)
        print(format_console(report, color=(not args.no_color and sys.stdout.isatty())))
        paths = save_reports(report, args.out)
        for kind, value in paths.items():
            print(f'  ◆ SAVED {kind.upper()}  {value}')
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    sys.exit(main())
