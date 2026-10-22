# WOLF FANG · GitHub publication guide

This repository-ready source bundle is **not automatically published**. Your original installations and `~/WolfFangReports` stay untouched.

## Stage 1: Validate safely on Ubuntu

Extract `WOLF-FANG-GITHUB-READY-v0.1.3.zip` into `~/Downloads` and run:

```bash
cd "$HOME/Downloads"
unzip -oq WOLF-FANG-GITHUB-READY-v0.1.3.zip
cd wolf-fang-glitchbyte-2026
./RELEASE_CHECK.sh
```

The validation script checks offline tests, report/demo generation and absence of secret files in the repository tree. No network requests are made. Existing API-key files are not copied in.

## Stage 2: Review public contents

The suggested repository name is `wolf-fang-glitchbyte-2026` under your linked GitHub account `Hellfire13666`. Ensure the account shown by `gh auth status` matches your intended account. Check `SECURITY.md`, `README.md`, `.gitignore`, source, images and `RELEASE_NOTES.md` before making a public project. This package does not include an open-source license. You can choose one before publication; without a license, others do not automatically receive broad reuse permissions.

If GitHub CLI is installed and authenticated, run:

```bash
./PUBLISH_WOLF_FANG.sh --check
```

It only verifies your local preparation. To **explicitly** create a **PUBLIC** GitHub repository and push the source, run:

```bash
./PUBLISH_WOLF_FANG.sh --publish
```

The script will require you to type `PUBLISH`. It refuses to proceed if the repository already exists rather than overwriting it. It creates a **DRAFT** GitHub Release, not a published release, and attaches the original full tool ZIP and checksum from `~/Downloads` when available.

## Stage 3: Review release draft on GitHub

Open your repository's Releases page, inspect the release notes, attachments and visibility, then click **Publish release** when you are satisfied. Do not publish if the v0.1.3 Ubuntu verification failed. You may also use the GitHub website instead of the CLI.

GitHub CLI docs: https://cli.github.com/manual/gh_repo_create and https://cli.github.com/manual/gh_release_create
