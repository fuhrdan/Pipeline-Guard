# ADR-0002: Keep Vulnerability Intelligence Behind an Optional Minimum-Data Relay

* **Status:** Accepted
* **Date:** 2026-09-15
* **Decision owners:** Pipeline Guard
* **Scope:** External vulnerability intelligence, privacy boundary, and failure handling

## Context

Pipeline Guard performs core repository analysis locally in the browser.

Some security findings can be enriched with live package vulnerability information from external advisory sources such as OSV.

Direct browser access to third-party advisory APIs creates several concerns:

* browser CORS restrictions;
* external-service availability;
* client-side timeout handling;
* inconsistent upstream behavior;
* exposure of unnecessary repository information if requests are not tightly bounded;
* difficulty distinguishing scanner failure from advisory-provider failure.

The scanner therefore needs a controlled way to obtain live vulnerability intelligence without turning the relay into a source-code analysis backend.

## Decision

Pipeline Guard uses an **optional advisory relay** for live package vulnerability lookups.

The relay receives only the minimum package coordinates required for the advisory query.

For example:

```text
ecosystem
package name
exact version
```

The relay must not require:

* repository ZIPs;
* source files;
* detected secrets;
* Dockerfiles;
* Kubernetes manifests;
* Terraform configuration;
* unrelated dependency metadata.

Conceptually:

```text
Repository
   ↓
Browser scanner
   ↓
Local findings
   ↓
Exact package coordinates
   ↓
Optional relay
   ↓
External advisory provider
   ↓
Advisory results
   ↓
Browser scanner
```

The relay is an enrichment boundary, not the primary analysis engine.

## Rationale

### Minimize transmitted data

Package advisory lookup generally requires package identity and version, not repository source.

Sending only the required coordinates preserves the local-first trust model.

### Isolate upstream failures

The relay provides one controlled integration point for:

* timeouts;
* retry policy;
* upstream error handling;
* health checks;
* response normalization;
* future provider changes.

Pipeline Guard can therefore distinguish between:

* local scanner functionality; and
* optional advisory availability.

### Preserve core scanner availability

If the relay or advisory provider is unavailable, Pipeline Guard should still perform local repository analysis.

Live vulnerability intelligence is useful enrichment, but it is not required for the scanner to function.

### Avoid hidden trust expansion

A relay that accepts entire repositories would effectively become a remote scanning backend.

Keeping the request contract narrow prevents that architectural drift.

## Failure Model

Relay failure must degrade gracefully.

Possible failures include:

* relay unreachable;
* DNS or TLS failure;
* request timeout;
* PHP/cURL unavailable;
* malformed upstream response;
* advisory provider unavailable;
* rate limiting;
* transient server error.

These failures should be reported as advisory-intelligence failures rather than being converted into repository security findings.

The scanner must not imply that a package is safe merely because advisory lookup failed.

## Retry Behavior

Retries should be bounded.

Pipeline Guard must avoid:

* infinite retry loops;
* aggressive request storms;
* blocking the entire repository scan while an external provider is unavailable.

Where retry or cache behavior exists, it should remain explicit and failure-aware.

## Health and Diagnostics

The relay may expose health information so operators can distinguish deployment problems from scanner problems.

Useful diagnostics include:

* relay reachability;
* relay version;
* required runtime capabilities;
* upstream advisory reachability;
* frontend/relay version mismatch.

Health requests must not require repository or package content.

## Consequences

### Positive

* Repository source remains local.
* External vulnerability intelligence can still be integrated.
* CORS and provider-specific behavior are isolated behind one interface.
* Advisory failures do not disable the core scanner.
* The relay can evolve independently from static frontend deployment.
* The trust boundary remains narrow and explainable.

### Tradeoffs

* An additional service must be deployed for live intelligence.
* Relay availability becomes a dependency for advisory enrichment.
* The relay still requires secure deployment and maintenance.
* Package coordinates reveal some dependency information to the advisory path.

These tradeoffs are accepted because the relay provides useful live intelligence while preserving the browser-first security model.

## Alternatives Considered

### Query external advisory services directly from the browser

Rejected as the primary design because provider CORS behavior and failure semantics are outside Pipeline Guard's control.

### Send the entire repository to the relay

Rejected because advisory lookup does not require repository source and would unnecessarily expand the trust boundary.

### Make advisory intelligence mandatory

Rejected because local repository analysis should remain useful during external-service failure.

### Cache all repository dependency data server-side

Rejected for the current design because persistent server-side dependency inventories create additional privacy, retention, and isolation responsibilities.

## Operational Invariant

> **Failure of the advisory relay must never prevent Pipeline Guard from completing its local repository analysis.**

External intelligence may enrich a result, but it must not become a hidden dependency of the core scanner.
