# ADR-0003: Require Justification and Expiration for Finding Suppressions

* **Status:** Accepted
* **Date:** 2026-09-15
* **Decision owners:** Pipeline Guard
* **Scope:** Finding lifecycle, false-positive handling, security governance, and reporting

## Context

Static security analysis inevitably produces findings that are technically correct but not actionable in a particular repository.

Examples include:

* test credentials intentionally used in fixtures;
* deliberately vulnerable demonstration code;
* configuration accepted because of compensating controls;
* generated files that cannot be modified directly;
* risks accepted temporarily while remediation is scheduled;
* patterns that trigger a rule but are known not to represent a real secret or exploitable condition.

A scanner that provides no suppression mechanism creates alert fatigue.

However, a scanner that allows findings to be silently dismissed creates a different problem: security risk can disappear from view without any explanation, owner, or review point.

A suppression is therefore a security decision, not simply a UI preference.

## Decision

Pipeline Guard allows findings to be suppressed only through an explicit suppression record.

Each suppression must include:

* the finding or rule being suppressed;
* a human-readable justification;
* an expiration date;
* sufficient identity information to determine whether the suppression still applies.

Conceptually:

```text
Finding
   ↓
Operator review
   ↓
Suppression requested
   ↓
Justification required
   ↓
Expiration required
   ↓
Finding marked suppressed
   ↓
Suppression remains visible in reporting
   ↓
Expiration reached
   ↓
Finding becomes actionable again
```

Suppression does not delete the finding.

The scanner retains enough information to distinguish:

```text
active finding
suppressed finding
expired suppression
```

## Rationale

### Avoid silent risk removal

A dismissed finding without context becomes indistinguishable from a finding that never existed.

Requiring a justification preserves the reason the risk was accepted.

### Make temporary acceptance actually temporary

Security exceptions frequently begin as short-term decisions and become permanent through neglect.

An expiration date forces the exception back into review.

### Preserve reporting integrity

Suppressed findings remain part of the repository's security history.

Reports should be able to explain:

* what was detected;
* what was suppressed;
* why it was suppressed;
* whether the suppression remains valid.

### Reduce false-positive fatigue without weakening controls

Developers need a practical way to handle known false positives.

Governed suppressions allow the scanner to remain useful without training users to ignore recurring warnings.

## Suppression Matching

A suppression should be scoped narrowly enough that it does not unintentionally hide unrelated future findings.

Where practical, matching should consider attributes such as:

* rule identifier;
* file path;
* finding fingerprint;
* relevant line or evidence;
* finding type.

A broad suppression such as:

```text
ignore all secret findings
```

should not be treated as equivalent to:

```text
ignore this known test credential in tests/fixtures/demo.json
```

The smallest practical scope should be preferred.

## Expiration

Suppressions require expiration.

When a suppression expires:

* the underlying finding is re-evaluated;
* if the condition still exists, the finding becomes active again;
* the previous justification remains useful historical context.

Expiration prevents exception records from silently becoming permanent policy.

## Repository Changes

Suppressions must not blindly follow findings after repository structure or evidence changes.

If the evidence no longer matches the suppression identity, Pipeline Guard should treat the result as a new or changed finding rather than assume the previous decision still applies.

This prevents a legitimate suppression from masking newly introduced risk that only superficially resembles the original issue.

## Reporting

Reports should distinguish clearly between:

```text
Active findings
Suppressed findings
Expired suppressions
```

A suppressed finding should not be presented as remediated.

The correct interpretation is:

> The scanner detected this condition, and a documented decision currently permits it.

This distinction is important for both engineering review and auditability.

## Consequences

### Positive

* False positives can be managed without deleting evidence.
* Risk acceptance has an explicit rationale.
* Temporary exceptions automatically return for review.
* Reports remain transparent about suppressed conditions.
* Repository changes are less likely to inherit inappropriate suppressions.
* Security posture is easier to explain during review.

### Tradeoffs

* Suppression requires more effort than a simple ignore button.
* Expired exceptions may reappear and require renewed review.
* Suppression identity and matching logic must remain stable enough to avoid unnecessary churn.
* Teams must distinguish genuine false positives from accepted real risk.

These tradeoffs are intentional because suppressing security findings should require more thought than dismissing ordinary application notifications.

## Alternatives Considered

### Allow one-click permanent ignore

Rejected because it removes findings without preserving the security decision behind the dismissal.

### Allow justification but no expiration

Rejected because temporary exceptions frequently become permanent through neglect.

### Delete suppressed findings

Rejected because suppression represents accepted or contextualized risk, not remediation.

### Suppress entire rule categories globally

Not selected as the default because broad suppression can hide unrelated future findings.

Global rule configuration may be appropriate in future policy features, but it should remain distinct from an individual finding suppression.

## Operational Invariant

> **A suppression changes the handling of a finding; it does not erase the fact that the finding was detected.**

Every suppression should remain explainable, scoped, and time-bounded.
