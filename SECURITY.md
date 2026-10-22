# WOLF FANG SECURITY & OPSEC

WOLF FANG is a passive IP context tool with opt-in, exact-IP scoped defensive TCP connections. Public API lookups send the target IP to chosen providers; this is not anonymous research.

1. Never share credentials or configure API keys from another person's accounts. Use `./CONFIGURE_KEYS.sh`, which stores private keys in `~/.config/wolf-fang/keys.env` with owner-only permissions. Do not copy into the repo or paste into chat.
2. Private/non-globally-routable IPs are never passed to public provider adapters even with `--live`.
3. Active TCP checks require both `--authorized` and a scope file containing the exact target IP. No arbitrary CIDRs, payloads or authentication attempts. Seek permission before probing other networks.
4. Port indexes are historical observations, not proof of live exposure. Domain names from public indexes can be stale, shared, or unrelated to a particular operator. No IP result can reliably identify an individual or physical address.
5. OTX pulse counts, AbuseIPDB reports, GreyNoise labels and honeypot tags are uncertain third-party context. Never use them to accuse or target people.
6. Provider HTTP 401/403/429 and timeouts are recorded as statuses. The program does not evade rate limits or access restrictions.
7. FANG VISION opens local static HTML reports: all fields are HTML-escaped; no scripts or external resources are loaded. The `--open` flag calls the configured local browser only.
8. Keep `~/WolfFangReports` and `~/WolfFangDashboards` private. The program sets folder permissions to 0700 and generated files to 0600.
9. Validate ZIP checksums if downloading both ZIP and checksum files. A passing checksum only verifies consistency with the published hash; it does not independently establish authorship.
