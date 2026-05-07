# andork

`andork` is an OSINT recon CLI for authorized external assessments.

It has two modes:

- `metadata`: search for indexed files, download them, run `exiftool`, and generate metadata reports.
- `dork`: run curated or custom dork queries across DDG + Google (Selenium), then generate findings reports.

## Repository Scope

This repository tracks the core tool code and curated dork lists.

Not tracked:

- runtime output under `output/`
- cache/build artifacts
- generated analysis markdown (outside `README.md`)

## Requirements

- Python 3.10+
- Chrome/Chromium + matching `chromedriver` (for Google backend)
- `exiftool` (metadata mode)

## Install

### uv (recommended)

```bash
cd /path/to/andork
uv tool install --force .
```

### pipx

```bash
cd /path/to/andork
pipx install . --force
```

## Quick Usage

### Dork mode (custom file)

```bash
andork dork -d domain.com --dork-file dorks/simple_focus_40.dorks --headed --wait-for-captcha
```

### Dork mode (list only)

```bash
andork dork -d domain.com --dork-file dorks/simple_focus_40.dorks --list-dorks
```

### Metadata mode

```bash
andork metadata -d domain.com --headed --wait-for-captcha
```

## Key Output Paths

- `output/<domain>/dork/findings.json`
- `output/<domain>/dork/report.html`
- `output/<domain>/metadata/metadata.json`
- `output/<domain>/metadata/report.html`

## Notes

- `--dork-file` uses simple one-query-per-line text files.
- Supports placeholders: `{site}` and `{domain}`.
- For custom dork files, default Google pages are deeper than curated mode unless `--max-pages` is explicitly set.
