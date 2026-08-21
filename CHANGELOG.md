# Changelog

All notable changes to Pipeline Guard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic-style version numbering.

## [Unreleased]

### Planned

- Automated browser smoke testing with Playwright
- GitHub Actions CI
- Expanded rule fixtures and regression coverage
- SARIF export
- Additional package-ecosystem coverage
- Richer CI integration and rule metadata

## [0.6.1] - 2026-08-18

### Added

- System Status diagnostics for frontend/runtime capability checks
- Relay reachability testing
- OSV upstream-health reporting
- Frontend/relay version-mismatch visibility
- Relay latency visibility
- PHP cURL availability reporting
- Browser capability checks for ZIP/Deflate, localStorage, clipboard, HTML report download, `fetch`, and `AbortController`

### Changed

- Clarified the product trust model with **Local-first · live intelligence optional** positioning
- Improved deployment troubleshooting for itch.io + PHP relay deployments
- Kept repository/source analysis local while making optional OSV behavior more explicit
- Preserved the v0.6.0 scanner rule set without introducing rule churn in the polish release

### Security / Reliability

- Relay health checks send no repository or package content
- Optional advisory lookup continues to send only exact package coordinates
- Improved visibility when frontend and relay deployments are on different versions
- Hardened the advisory lookup failure path so unavailable live intelligence does not masquerade as a clean result

## [0.6.0] - 2026-08-18

### Added

- Whole-repository ZIP auditing in the browser
- Auditable false-positive suppression workflow
- Required justification for suppressions
- Expiration dates for suppressions
- Stable finding fingerprints
- Built-in **First 60 Seconds** demo repository
- GitHub Actions / CI workflow security checks
- Dockerfile security checks
- Kubernetes manifest security checks
- Terraform / Infrastructure-as-Code checks
- Software supply-chain checks across multiple package ecosystems
- Cross-file correlation
- Deterministic repository security scoring
- Optional OSV live vulnerability intelligence
- Standalone HTML report export

### Changed

- Promoted false-positive management from a convenience feature to a first-class review workflow
- Improved first-run usability so the product can be evaluated without preparing a repository
- Expanded repository-level reasoning beyond isolated single-file findings

### Security / Reliability

- Hardened advisory retry/cache/failure behavior
- Preserved local repository analysis when live advisory services are unavailable
- Added explicit separation between local static findings and optional external vulnerability intelligence

## [0.5.0] - 2026-08-18

### Added

- Whole-repository ZIP ingestion
- Repository inventory and supported-file classification
- Multi-file security review
- Repository-level findings and scoring
- Generated/vendor directory skipping
- Browser-side archive processing limits

### Changed

- Expanded Pipeline Guard from selected-file scanning into whole-repository preflight auditing

## [0.4.0] - 2026-08-18

### Changed

- Continued scanner expansion and repository-review workflow refinement
- Improved presentation and usability of security findings

## [0.3.0] - 2026-08-18

### Changed

- Expanded the early DevSecOps preflight feature set
- Refined finding output and review workflow

## [0.2.0] - 2026-08-18

### Changed

- Expanded the initial Pipeline Guard prototype with additional scanning and usability improvements

---

[Unreleased]: https://github.com/fuhrdan/Pipeline-Guard/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/fuhrdan/Pipeline-Guard/releases/tag/v0.6.1
[0.6.0]: https://github.com/fuhrdan/Pipeline-Guard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/fuhrdan/Pipeline-Guard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/fuhrdan/Pipeline-Guard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/fuhrdan/Pipeline-Guard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/fuhrdan/Pipeline-Guard/releases/tag/v0.2.0
