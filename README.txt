# PipelineGuard v0.6.1

PipelineGuard v0.6.1 is a polish and deployment-diagnostics release. Scanner rules are intentionally unchanged from v0.6.0.

## What changed

### Local-first wording
The top trust badge now reads **Local-first · live intelligence optional**. Repository/source analysis remains local; only exact package coordinates are sent when a user explicitly runs the optional advisory lookup.

### System Status
A new **System status** dialog reports:
- frontend version
- repository ZIP/Deflate browser capability
- persistent localStorage availability
- clipboard support
- HTML report download support
- fetch/AbortController support
- relay version/reachability
- OSV reachability from the relay

### Test Relay
Relay configuration now includes **Test relay**. The health request sends no repository/package content. It reports frontend/relay version alignment, relay latency, PHP cURL availability, and OSV network reachability.

### Relay health endpoint
The v0.6.1 PHP relay supports:

```json
{"action":"health","frontendVersion":"0.6.1"}
```

The response includes service/version/runtime and upstream reachability information. Advisory lookup behavior from v0.6.0 is retained.

### Version mismatch visibility
The UI explicitly reports when the frontend and relay are on different releases, making itch.io/HawkHost deployment mismatches much easier to diagnose.

## Deployment

1. Upload `PipelineGuard-v0.6.1.zip` to itch.io as the browser-playable build.
2. Replace `/public_html/relay/pipelineguard.php` with the `pipelineguard.php` from `PipelineGuard-v0.6.1-Relay.zip`.
3. Open **System status** and click **Test relay + OSV**.
4. A healthy deployment should show frontend **0.6.1**, relay **0.6.1**, and OSV reachable.

The cover image remains version-neutral and is intentionally outside the itch.io ZIP.

## Existing v0.6 features retained

- whole-repository ZIP auditing
- false-positive suppressions with required reason and expiration
- First 60 Seconds demo
- hardened live advisory retry/cache/failure path
- GitHub Actions, Docker, Kubernetes, Terraform and supply-chain scanners
- cross-file correlation
- optional OSV live intelligence
- exportable HTML reports
