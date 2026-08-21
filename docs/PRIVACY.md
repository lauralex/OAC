# Privacy and data handling

OAC is designed around data minimization: collect the evidence needed for a defined security
decision, keep raw sensitive values out of ordinary reports, retain records for a bounded period,
and make enforcement reviewable. The repository includes a deployable single-node reference
backend, but it does not operate a hosted OAC service. This document defines the minimum policy a
production operator must adopt; it is not a statement that a live data service already exists.

> [!NOTE]
> Production deployment needs jurisdiction-specific legal review, user notice, age and regional
> controls, controller/processor agreements, and verified deletion workflows. This engineering
> policy is not legal advice.

## Data classes

| Data class | Purpose | Repository handling | Reference maximum retention |
|---|---|---|---|
| Release and policy identity | Prove which code and rules made a decision | Versions, hashes, signer identity, and compatibility fields | Life of the release plus 12 months |
| Backend/session identifiers | Correlate a bounded admission lease and prevent replay | Random or pseudonymous identifiers; no password or reusable server secret in the client | 30 days after session expiry |
| Game and replay events | Server-authoritative behavior checks and reproducibility | Game/build/match/replay scope, pseudonymous player identity, sequence, tick, and bounded observations | Unflagged: 7 days; decision evidence: 30 days |
| Endpoint findings | Explain policy and containment decisions | Typed rule, severity, confidence, provenance, module/process metadata, and bounded coverage metrics | Unflagged: 7 days; decision evidence: 30 days |
| Hardware correlation | Detect large identity discontinuities without exporting raw serials | Raw component values stay in the scanner process; reports contain only the versioned composite and typed consistency/coverage findings | Derived token: 30 days after last use; raw values: never persisted |
| Operational audit | Investigate release, key, access, and service incidents | Actor, action, release, result, and time; never store private keys or bearer credentials | 90 days |
| Appeal record | Reproduce and review a disputed action | Minimum decision evidence, reviewer actions, and outcome | Until resolution plus 30 days; no more than 180 days absent a documented legal hold |

These are maximum reference periods, not automatic collection instructions. Operators should use a
shorter period whenever the security purpose can be met. Aggregated statistics must be stripped of
identifiers before longer retention.

## Collection rules

- Collect only fields defined by a typed schema and tied to a documented rule or operational need.
- Do not transmit raw SMBIOS, storage, network, display, battery, HID, Bluetooth, or other hardware
  serials. The lab scanner keeps raw values in process memory only, best-effort clears them, and
  writes only privacy-preserving composite and consistency results.
- Do not use removable peripherals as core identity anchors.
- Treat file paths, command lines, process names, module names, user names, and dumps as potentially
  personal or confidential. Prefer hashes, basenames, categories, and bounded excerpts.
- Do not collect unrelated files, messages, browser data, keystrokes, screenshots, or microphone or
  camera data.
- Do not turn an unavailable optional signal into evidence of wrongdoing. Record coverage and
  uncertainty separately from findings.
- Keep display text out of policy decisions. Store stable rule IDs, typed fields, source sequence,
  and the policy/release identity needed to reproduce the result.

## Access and security

Access is role-based and least-privileged:

| Role | Permitted access |
|---|---|
| Release engineer | Release manifests, SBOMs, signing records, and deployment health; no player evidence by default |
| Security analyst | Pseudonymous decision evidence for assigned investigations |
| Appeal reviewer | Evidence necessary for the appealed decision, separated from the original adjudicator where practical |
| Privacy administrator | Access/deletion requests and retention enforcement; no signing authority |
| Incident responder | Time-bounded exceptional access approved and audited under the incident runbook |

Encrypt data in transit and at rest, separate production and test stores, rotate service
credentials, log every privileged read/export/delete, and alert on bulk access. Private symbols,
dumps, signing records, and evidence exports belong in separate restricted stores. Test data must
not be copied into production. The included reference backend relies on operating-system access
control and an exclusive single-writer store; a production deployment must add managed encryption,
backup, retention, deletion, audit, and replica controls before accepting real player evidence.

## Access, deletion, and appeal

A production operator must publish a contact path and a process that can:

1. authenticate the requester without collecting unnecessary new identity data;
2. locate records through the operator's account-to-pseudonym mapping, not by weakening the event
   schema with raw account identifiers;
3. provide an intelligible summary of the decision, relevant rule IDs, evidence categories,
   policy/release identity, and review outcome where disclosure is lawful and safe;
4. delete or de-identify eligible data across primary, replica, export, and queued systems within a
   published service level;
5. record any legal or security exception with scope, authority, and expiry; and
6. let a human reviewer overturn or reduce an automated action and propagate that result to the
   enforcement system.

Deletion must not silently reset security high-water or emergency-revocation state that protects
the platform as a whole. Those records should be minimized, separated from player evidence, and
retained only as long as the documented integrity purpose requires.

## Incident handling

Suspected data exposure stops nonessential exports and follows the
[incident-response runbook](OPERATIONS.md#security-and-privacy-incidents). Preserve only the
forensic records needed to determine scope, rotate affected credentials, document access, notify
the responsible privacy/security owners, and apply the shortest lawful retention to the incident
copy.

The hardware-identity design and exact source behavior are described in
[`hwid-review.md`](hwid-review.md). Unsupported guarantees remain listed in the
[security model](SECURITY_MODEL.md).
