# WOLF FANG v0.1.3 // Visual Edition

Visual integration over verified v0.1.2 source. Independent install folder; prior versions and `~/WolfFangReports` untouched.

- Three approved cyber-wolf graphics replacing the previous art set.
- Repo README hero now uses approved WOLF FANG cover.
- Dashboard HTML embeds a small trusted, local WebP banner inline for fully portable offline viewing; optional fallback if source-only installation lacks image.
- Browser CSP allows **only data URI images**, no external requests or JavaScript.
- No changes to provider implementation, authorization gate, scanning behavior or API key storage.
- Additional offline tests verify the image, HTML export, escaping, and branded files.
- FANG VISION can re-render existing v0.1.0–v0.1.2 reports without changing originals.

## New install

```bash
cd "$HOME/Downloads"
unzip -oq WOLF-FANG-GLITCHBYTE-PHANTOM-LABS-v0.1.3.zip
cd wolf-fang-v0.1.3
./RUN_TESTS.sh
./OPEN_FANG_VISION.sh --open
```

Only the current user should view saved intelligence reports. Review provider terms, rates and permitted uses.
