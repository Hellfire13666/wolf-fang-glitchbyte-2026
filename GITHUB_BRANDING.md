# 🐺 WOLF FANG // GitHub branding

This is the approved GlitchByte Phantom Labs art identity for WOLF FANG.

| Image | File | Intended use |
|---|---|---|
| Repo cover | `assets/wolf-fang-repo-cover.png` | README hero |
| Wolf emblem | `assets/wolf-fang-emblem.png` | Project icon / social card |
| Command center | `assets/wolf-fang-command-center.png` | Documentation / banner |
| Dashboard embed | `assets/fang-vision-inline.webp` | Self-contained report HTML |

The README already displays the cover. To publish, first review `SECURITY.md` and `.gitignore`. Never commit `~/WolfFangReports`, API key files, private IP inventories, analyst notes, or raw third-party lookups that contain sensitive observations.

For an **existing WOLF FANG Git repository**, manually copy this release's tracked source and assets into that repo, check the diff, then use:

```bash
git status
git diff --check
git add README.md GITHUB_BRANDING.md SECURITY.md UPGRADE_NOTES.md assets/ wolf_fang/ tests/ OPEN_WOLF_FANG.sh OPEN_FANG_VISION.sh CONFIGURE_KEYS.sh RUN_TESTS.sh
git diff --cached --stat
git commit -m "WOLF FANG v0.1.3: approved visual identity and offline dashboard banner"
git push
```

Do **not** run `git init` or push to a new remote just to install WOLF FANG. Review the staged file list before committing; don't execute these commands in unrelated repositories. Nothing is auto-published by this installer.
