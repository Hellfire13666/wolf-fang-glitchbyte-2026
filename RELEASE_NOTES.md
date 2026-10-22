# 🐺 WOLF FANG v0.1.3 · Visual Edition

**GlitchByte Phantom Labs · FANG VISION**

This release packages the WOLF FANG public-source IP intelligence workstation with its approved cyber-wolf artwork and an offline dashboard.

## Highlights

- New GitHub-ready wolf artwork: square emblem, command-center banner and repository cover.
- FANG VISION: self-contained HTML intelligence dashboard with embedded local WebP banner. JSON and CSV remain available.
- Seven-provider default profile: RDAP, RIPEstat, Shodan InternetDB, ipwho.is, IPinfo, DNS, IPapi.is. Public providers can change or fail, and indexed port data is **not** an active scan.
- Additional opt-in data sources: RIPEstat routing-status, AlienVault OTX, GreyNoise Community and AbuseIPDB (access limits and API keys vary).
- Optional key configuration stores secrets privately outside the repository.
- No exploitation, stealth scanning, authentication bypass or credential collection.

## Quality and verification

- **37 offline unit tests passed in the packaging environment**; the user's prior v0.1.2 dashboard successfully opened on Ubuntu.
- **v0.1.3 still requires its own local Ubuntu smoke test** before release publication.
- Runtime: Python 3.10+ on Linux, Python standard library only.

## Important limitations

- Network-owner, location, historical ports and third-party reputation labels are indicators, not proof of a person's identity, wrongdoing, or current service exposure.
- Public API queries disclose the target IP to the chosen API operators.
- GreyNoise timed out on the user's connection in previous testing; API keys are optional except where individual providers require them.

## Verify the ZIP

Download the ZIP and matching `.sha256` to the same folder, then use:

```bash
sha256sum -c WOLF-FANG-GLITCHBYTE-PHANTOM-LABS-v0.1.3.zip.sha256
```

## Run

```bash
./RUN_TESTS.sh
./OPEN_WOLF_FANG.sh --doctor
./OPEN_WOLF_FANG.sh --demo
./OPEN_FANG_VISION.sh --open
```

**Branding:** WOLF FANG // GLITCHBYTE PHANTOM LABS.
