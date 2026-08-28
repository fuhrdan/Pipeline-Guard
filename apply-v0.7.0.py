#!/usr/bin/env python3
from pathlib import Path
import shutil, zipfile, sys, re

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
pack = Path(__file__).resolve().parent

required = ["app.js", "index.html", "package.json"]
missing = [x for x in required if not (root/x).exists()]
if missing:
    raise SystemExit("Run from a Pipeline-Guard checkout or pass its path. Missing: " + ", ".join(missing))

for rel in ["pipeline-integration.js", "action.yml", "scripts/ci-scan.mjs", ".github/workflows/pipeline-guard.yml"]:
    src = pack/rel
    dst = root/rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

index = (root/"index.html").read_text(encoding="utf-8")
if "pipeline-integration.js" not in index:
    index = index.replace('<script src="app.js"></script>', '<script src="app.js"></script>\n  <script src="pipeline-integration.js"></script>')
(root/"index.html").write_text(index, encoding="utf-8")

app = (root/"app.js").read_text(encoding="utf-8")
app = app.replace('const APP_VERSION = "0.6.1";', 'const APP_VERSION = "0.7.0";')
app = app.replace("enabled v0.6.1 rules", "enabled v0.7.0 rules")
app = app.replace("PipelineGuard v0.6.1 Security Preflight", "PipelineGuard v0.7.0 Security Preflight")
(root/"app.js").write_text(app, encoding="utf-8")

pkg = (root/"package.json").read_text(encoding="utf-8")
pkg = re.sub(r'"version"\s*:\s*"0\.6\.1"', '"version": "0.7.0"', pkg, count=1)
(root/"package.json").write_text(pkg, encoding="utf-8")

changelog = root/"CHANGELOG.md"
if changelog.exists():
    text = changelog.read_text(encoding="utf-8")
    entry = """# Changelog

## v0.7.0 — Pipeline Integration

- Added SARIF 2.1.0 export from the browser UI.
- Added a reusable GitHub Action that runs the same browser scanner headlessly with Playwright.
- Added GitHub Actions file/line annotations for findings.
- Added configurable severity gates: none, critical, high, medium, low, or info.
- Added SARIF upload to GitHub code scanning via `github/codeql-action/upload-sarif@v4`.
- CI scans a `git archive` ZIP of the checked-out repository so browser and CI detection behavior stay aligned.

"""
    if "## v0.7.0 — Pipeline Integration" not in text:
        if text.startswith("# Changelog"):
            text = entry + text[len("# Changelog"):].lstrip()
        else:
            text = entry + text
        changelog.write_text(text, encoding="utf-8")

readme = root/"README.md"
if readme.exists():
    text = readme.read_text(encoding="utf-8")
    text = text.replace("version-v0.6.1", "version-v0.7.0")
    text = text.replace("### v0.6.1 — Current", """### v0.7.0 — Current

Pipeline Integration release.

Added:

- SARIF 2.1.0 export
- reusable GitHub Action
- pull-request file/line annotations
- configurable severity gates
- GitHub code-scanning SARIF upload

Example:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6
  - uses: fuhrdan/Pipeline-Guard@v0.7.0
    with:
      fail-on: high
```

### v0.6.1""")
    readme.write_text(text, encoding="utf-8")

print(f"Applied Pipeline Guard v0.7.0 upgrade to {root}")
print("Next: npm ci && npx playwright install chromium && npm test")
