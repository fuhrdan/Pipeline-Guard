# Pipeline Guard v0.7.0 — Upgrade Pack

This pack implements the requested **Pipeline Integration** release on top of the current v0.6.1 repository.

## Included

- Browser **Export SARIF** button producing SARIF 2.1.0.
- Reusable `action.yml` GitHub Action.
- Headless Playwright CI runner using Pipeline Guard's existing browser scanner.
- GitHub Actions file/line annotations.
- Configurable severity gate (`none`, `critical`, `high`, `medium`, `low`, `info`).
- SARIF upload through `github/codeql-action/upload-sarif@v4`.
- Example `.github/workflows/pipeline-guard.yml`.
- Version/changelog/README patching.

## Apply it

From this unpacked upgrade directory:

```bash
python apply-v0.7.0.py /path/to/Pipeline-Guard
```

On Windows PowerShell, for example:

```powershell
python .\apply-v0.7.0.py C:\Projects\Pipeline-Guard
cd C:\Projects\Pipeline-Guard
npm ci
npx playwright install chromium
npm test
```

## How the gate behaves

`fail-on: high` blocks **Critical + High** findings.
`fail-on: medium` blocks **Critical + High + Medium** findings.
`fail-on: critical` blocks only Critical.
`fail-on: none` reports but never blocks.

## GitHub requirement

The calling workflow needs:

```yaml
permissions:
  contents: read
  security-events: write
```

for SARIF upload to GitHub code scanning.
