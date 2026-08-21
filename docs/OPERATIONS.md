# Operations and incident runbooks

These runbooks define the minimum control flow for a future OAC deployment. They are intentionally
short and decision-oriented. The repository supplies a bounded single-node admission backend, but
not its certificate infrastructure, managed database, updater, monitoring stack, backup service, or
on-call organization.

## Release promotion

**Entry condition:** reviewed source tag, clean hosted checks, exact unsigned candidate, private
symbols archived, SBOM valid, and platform acceptance complete.

1. Record the release owner, source tag/commit, workflow run, candidate hashes, support scope, and
   rollback release.
2. Complete Microsoft driver submission/certification and verify the returned catalog against the
   exact submitted INF and SYS.
3. Sign and timestamp the service and launcher with the protected production identity.
4. Recreate and validate final signed manifests, SBOM, and checksums; run malware scanning and
   signature-chain verification.
5. Install the exact signed package in the supported matrix and rerun launch, session, backend,
   evidence, containment, upgrade, rollback, removal, and reboot-recovery acceptance.
6. Obtain release, security, privacy, and support approvals. No one person should both control the
   signing key and approve publication.
7. Deploy to the internal ring, then small canary cohorts. Advance only while crash, launch,
   latency, false-positive, update, rollback, and support indicators remain within the recorded
   thresholds.
8. Preserve the release record and announce only the support scope that actually passed.

**Abort condition:** any identity mismatch, unexplained binary change, signature or timestamp
failure, support regression, unexpected data collection, nonzero relevant crash rate, or inability
to restore the rollback package.

## Backend deployment

1. Build the framework-dependent .NET 8 backend and game-adapter package from the exact reviewed
   source commit. Preserve their hashes with the endpoint release record.
2. Provision distinct endpoint-controller and game-server client-authentication identities. Put
   private keys in the platform secret/key store; configure only SHA-256 certificate pins in OAC.
3. Install the HTTPS server identity through the managed Kestrel configuration provider. Configure
   the endpoint's normal TLS trust and exact server pin independently.
4. Place the signed policy, detached signature, movement rules, and backend data directory on
   non-reparse, access-controlled storage. The policy and rules must name the same game and build.
5. Run `dotnet OAC.Backend.dll validate`, verify a protected backup and restore, then start one
   backend writer. Do not place two processes on the same data directory.
6. Prove role separation: endpoint credentials may fetch policy/open/renew/upload but not submit
   game events; game-server credentials may submit game events but not use endpoint routes.
7. Admit traffic only after replay, restart, revocation, partial-write, and ambiguous-response tests
   pass in the deployment environment. Monitor session, retired-receipt, game-state, and log bounds;
   capacity exhaustion is an admission failure, not an invitation to delete live state.

The included storage engine is intentionally single-node. A managed replacement may shard or
replicate it only if durable append precedes acknowledgement, request/session correlation stays
exact, replay state survives restart, and one credential/scope cannot open competing live sessions.

## Backend credential rotation and revocation

1. Add one reviewed rotation pin while retaining the active pin. Endpoint configuration lists the
   preferred usable client identity first; the backend accepts at most two identities for each role.
2. Deploy the new certificate and private key through the platform credential store. Verify its
   validity, client-authentication usage, key strength, private-key access, and exact pin.
3. Put the new endpoint identity first when both certificates are valid and immediate cutover is
   intended. Restart the affected component and prove mutual TLS and role separation with it.
4. Move all callers, then remove the old pin and key.
5. For an admitted endpoint that must be stopped immediately, run
   `dotnet OAC.Backend.dll revoke SESSION_ID_HEX` against the same protected data directory. Confirm
   the next renewal is terminal and the endpoint contains its target tree.

A client-certificate pin change is deployment configuration; it does not authorize a new signed
policy. Policy publication still requires the offline policy signer and the existing replay,
rollback, and emergency-revocation rules.

## Rollback

1. Stop promotion and new admissions for the affected release.
2. Identify the smallest affected cohort and preserve bounded evidence before changing state.
3. Revoke active sessions and contain target trees; do not replace driver or service files while
   they are active.
4. Authenticate and install the retained previous release through the same signed update path.
5. Verify package signatures, service/driver states, backend lease, policy and manifest
   compatibility, launch, evidence flow, and containment.
6. Confirm that rollback did not bypass policy high-water or emergency-revocation state.
7. Record the reason, cohorts, versions, hashes, results, and follow-up owner. Reopen promotion only
   after the root cause and a new acceptance plan are reviewed.

If schema or state restoration is not proven, disable admission and preserve containment rather
than improvising a downgrade.

## Backend outage or lease failure

1. Confirm whether the fault is transport, authentication, replay state, lease expiry, evidence
   acknowledgement, or remote service availability.
2. Keep health/status IPC responsive and stop accepting new launches once the bounded lease is no
   longer valid.
3. Apply the configured containment result to active targets; do not extend a lease from local wall
   clock or cached success.
4. Retain bounded high-priority evidence locally, track overflow/loss explicitly, and never discard
   an unacknowledged record as if delivered.
5. Recover with a fresh authenticated backend and driver session. Do not reuse a failed nonce,
   generation, acknowledgement cursor, or expired lease.
6. Reconcile delivery and document any evidence gap before restoring normal admission.

## Suspected signing-key compromise

1. Freeze signing and distribution immediately; protect audit logs and HSM/service records.
2. Identify the trust purpose, affected key/certificate, first suspected use, releases, channels,
   and downstream pins. Do not rotate unrelated keys reflexively.
3. Revoke or disable the identity at the available distribution and validation boundaries.
4. Block affected releases and, where safe, move clients to a previously approved package. A
   manifest or policy pin change remains a reviewed software update until signed rotation metadata
   is implemented.
5. Generate replacement keys in the approved non-exportable store with independent authorization.
6. Re-sign only artifacts rebuilt and reviewed from trusted source. Never bless an existing binary
   merely because its old signature is suspect.
7. Complete incident, user-impact, notification, and postmortem requirements before resuming normal
   promotion.

## False-positive or enforcement incident

1. Stop or narrow the affected rule through an authenticated, signed policy change. Use Observe
   mode when evidence is uncertain; do not patch display text or client state to suppress it.
2. Preserve the exact release, policy, manifest, rule ID, typed evidence, provenance, coverage, and
   decision. Separate current-target evidence from stale or dropped records.
3. Reproduce against the same build and representative workload, then test the smallest policy or
   implementation correction with hostile and regression cases.
4. Identify affected decisions and provide human review. Reverse enforcement where evidence no
   longer meets the approved policy.
5. Publish a bounded explanation and prevention action without disclosing attacker-useful private
   telemetry or another user's data.

## Driver or service crash

1. Verify target-tree containment and stop new launches before collecting diagnostics.
2. Record release and package hashes, Windows build/security configuration, service/driver state,
   Verifier state, event records, and dump identity. Do not place dumps in a public issue.
3. Analyze only with the exact private symbols identified by `symbols-manifest.json`.
4. Distinguish product failure from test-harness, platform, or third-party-driver failure. Never
   disable a security invariant merely to make the crash disappear.
5. Roll back or disable admission if containment, repeatability, or impact cannot be established.
6. Fix, run the complete affected validation matrix, and publish through the normal release path.

## Security and privacy incidents

1. Contain access without destroying evidence: disable compromised credentials, exports, and
   affected service paths.
2. Establish data classes, subjects/cohorts, systems, time window, accessors, and whether signing or
   backend trust was also affected.
3. Preserve a minimal, access-controlled forensic copy and audit every use. Continue normal
   retention/deletion for unrelated data.
4. Rotate affected secrets and verify replicas, queues, backups, exports, and logs.
5. Notify the responsible security, privacy, legal, support, and product owners under the applicable
   requirements; provide users an accurate scope and remediation path when required.
6. Remove temporary access, expire incident holds, verify deletion, and document control changes.

## Post-incident record

Every incident record should include timeline, detection source, affected identities and releases,
technical root cause, containment, evidence integrity, user/data impact, decisions, recovery tests,
owners, and due dates. Keep the public summary factual and separate from private exploit details,
credentials, dumps, raw hardware identifiers, or player evidence.

Release construction and signing are specified in [release engineering](RELEASE.md), compatibility
in [support scope](SUPPORT.md), and data handling in [privacy](PRIVACY.md).
