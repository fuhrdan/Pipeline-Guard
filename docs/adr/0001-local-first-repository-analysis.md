# ADR-0001: Keep Repository Security Analysis Local to the Browser

* **Status:** Accepted
* **Date:** 2026-09-15
* **Decision owners:** Pipeline Guard
* **Scope:** Repository ingestion, static analysis, privacy, and trust boundaries

## Context

Pipeline Guard analyzes source repositories for security issues including:

* credential and secret patterns;
* GitHub Actions and CI/CD configuration;
* Dockerfiles;
* Kubernetes manifests;
* Terraform and other infrastructure-as-code;
* dependency and supply-chain metadata;
* cross-file security relationships.

Repository security scanning frequently involves highly sensitive material.

Even when a repository contains no intentional secrets, its source can expose:

* proprietary application logic;
* infrastructure topology;
* internal hostnames;
* cloud-account structure;
* deployment configuration;
* dependency choices;
* authentication flows;
* security controls;
* accidentally committed credentials.

Uploading an entire repository to a remote analysis service therefore creates an additional security and privacy boundary.

Pipeline Guard is also intended to be useful as a fast pre-deployment check rather than requiring a separately provisioned analysis backend.

## Decision

Pipeline Guard performs normal repository analysis **locally inside the user's browser**.

Repository ZIP extraction, file inventory, static rule evaluation, scoring, cross-file correlation, suppression handling, and report generation remain in the browser execution environment.

The normal analysis path does not require repository source files to be uploaded to a Pipeline Guard backend.

Conceptually:

```text id="pg-local-first"
Repository ZIP / Files
        ↓
User Browser
        ↓
ZIP extraction
        ↓
Repository inventory
        ↓
Static security analysis
        ↓
Cross-file correlation
        ↓
Scoring / suppressions
        ↓
Standalone report
```

## Trust Boundary

The browser is the primary repository-analysis boundary.

Pipeline Guard may use external services for explicitly optional capabilities, such as vulnerability intelligence, but those capabilities must not require transmitting repository source code.

Where external advisory lookup is enabled, only the minimum information needed for that lookup should cross the browser boundary.

For package vulnerability lookup, that means data such as:

```text id="pg-package-coordinate"
ecosystem
package name
exact version
```

rather than source files, configuration files, or detected secrets.

## Rationale

The local-first design provides several benefits.

### Reduce source-code exposure

Repository content stays within the user's browser during normal scanning.

Pipeline Guard therefore does not need to become a trusted custodian of arbitrary source repositories simply to provide static preflight analysis.

### Reduce backend attack surface

A centralized repository-upload service would require controls for:

* upload authentication;
* temporary storage;
* deletion guarantees;
* tenant isolation;
* malware handling;
* source-code confidentiality;
* encryption at rest;
* access logging;
* retention policy;
* breach response.

Keeping repository processing local avoids introducing that server-side data-handling surface for the core scanner.

### Fast pre-deployment workflow

A browser-based scanner can be opened and used immediately without provisioning an analysis server.

This supports the project's goal of making security review lightweight enough to perform before deployment.

### Failure isolation

The core scanner remains useful even if optional external vulnerability intelligence is unavailable.

External advisory failure should degrade enrichment, not disable local repository inspection.

## Consequences

### Positive

* Repository source is not uploaded during normal analysis.
* Pipeline Guard has a smaller server-side trust boundary.
* Users can inspect repositories without creating an additional source-code copy on a scanning service.
* Core scanning can work without the optional advisory relay.
* Static hosting is sufficient for the main application.
* The architecture is easy to deploy on itch.io, Apache, nginx, or another static host.

### Tradeoffs

* Browser memory and CPU constrain repository size.
* Large archives require explicit processing limits.
* Browser APIs vary by platform and version.
* Some forms of analysis are more difficult without a native or server-side execution environment.
* Pipeline Guard cannot rely on heavyweight backend tooling for every ecosystem.

These constraints are accepted because the project prioritizes fast, privacy-conscious preflight analysis over unlimited repository size or full enterprise SAST functionality.

## Safety Limits

Local-first processing does not mean unbounded processing.

Pipeline Guard applies explicit limits to repository inputs so an unreasonable ZIP or file cannot consume unlimited browser resources.

Limits should cover areas such as:

* total archive size;
* ZIP entry count;
* individual file size;
* total selected text;
* path traversal;
* binary/generated content.

The browser trust boundary must still defend itself against hostile or malformed inputs.

## Alternatives Considered

### Upload repositories to a centralized scanner

Rejected for the core workflow because it creates an unnecessary source-code custody and isolation problem.

### Require a locally installed native agent

Rejected for the primary product because installation friction conflicts with the goal of a fast browser preflight.

A native or CI-oriented companion could be added later without replacing the browser architecture.

### Send complete files to the vulnerability relay

Rejected because package advisory lookup does not require repository source.

## Operational Invariant

> **Core Pipeline Guard repository analysis must not require repository source code to leave the browser.**

Optional external intelligence may enrich findings, but it must remain outside the core source-analysis trust boundary.
