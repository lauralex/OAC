# Security policy

## Supported code

Security fixes target the current `main` branch. Earlier releases and commits receive best-effort
support; first confirm that the issue still reproduces on `main`. OAC is a defensive research
foundation, not a certified commercial anti-cheat or a universal Windows security boundary.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting form under the repository's **Security** tab. Do not
open a public issue for an exploitable driver, authorization bypass, memory-safety defect, signing
or update weakness, or a technique that materially evades the protection boundary.

Include, when relevant:

- the affected commit and component;
- Windows edition, build, architecture, and security configuration;
- a minimal reproduction and expected versus observed behavior;
- crash parameters and a sanitized stack trace; and
- the security impact and any known preconditions.

Do not upload private signing material, raw hardware identifiers, complete scan reports, memory
dumps, or production game/user data. Offer sensitive evidence through the private report and agree
on a safe transfer method first.

The maintainers will acknowledge the report, reproduce it when possible, coordinate a fix, and
credit the reporter if requested. Timing depends on severity, reproducibility, Windows servicing,
and signing or compatibility requirements, so this project does not promise a fixed disclosure SLA.

## Scope boundaries

OAC intentionally does not patch Code Integrity or PatchGuard, ship a vulnerable-driver loader,
hide kernel state, or promise reliable observation beneath a hostile kernel, DMA device, or
hypervisor. Reports that require adding those mechanisms are outside the supported design.
