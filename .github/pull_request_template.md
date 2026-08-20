## Summary

Describe the defect, threat, or maintenance need and the resulting behavior.

## Security and compatibility

- Threat or invariant affected:
- Windows builds/configurations affected:
- False-positive, performance, privacy, or signing impact:
- Protocol, INF, lifecycle, release-profile, artifact-boundary, or generated-policy changes:

## Validation

List the exact commands and VM configurations used. Separate local checks from CI and historical
evidence.

## Checklist

- [ ] The change is defensive and does not add a mapper, bypass, exploit loader, hiding, or anti-forensics.
- [ ] The driver remains demand-start (`StartType=3`).
- [ ] Protocol changes update both sides, tests, versioning, size assertions, and documentation.
- [ ] Release-profile or packaging changes preserve exact public/lab allowlists and private-symbol separation.
- [ ] Debug and Release builds and all change-specific checks pass.
- [ ] Kernel runtime testing was confined to a disposable VM.
- [ ] No secrets, raw HWIDs, binaries, reports, dumps, VM images, or other generated artifacts are included.
- [ ] Documentation distinguishes implemented, tested, planned, and unsupported behavior.
