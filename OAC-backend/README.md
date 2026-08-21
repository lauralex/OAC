# OAC backend

`OAC.Backend` is the authenticated admission service for the endpoint controller and authoritative
game servers. It is a separate .NET 8 application; the Windows service contains only the client
transport and local enforcement logic.

The backend exposes five fixed binary operations over HTTPS:

| Route | Client role | Purpose |
|---|---|---|
| `/policy` | endpoint controller | Retrieve the current detached-CMS-signed policy |
| `/session` | endpoint controller | Open a policy-bound lease and backend binding |
| `/renew` | endpoint controller | Renew or revoke the current lease |
| `/evidence` | endpoint controller | Durably append and acknowledge correlated evidence |
| `/game` | authoritative game server | Submit a canonical movement event and receive a durable decision |

Every connection requires a current client-authentication certificate. Endpoint and game-server
roles use disjoint SHA-256 certificate allowlists, with one optional rotation identity per role.
The normal TLS chain and host-name checks remain mandatory on clients; certificate pins are an
additional identity boundary.

## Configure

Copy [`appsettings.example.json`](appsettings.example.json) to `appsettings.json` beside the
application, or provide the same settings through environment variables or a managed configuration
provider. All storage, policy, signature, and movement-rule paths must be absolute. Provide the
HTTPS server certificate through normal Kestrel configuration or a managed secret provider; do not
put a certificate password or private key in this repository. The policy and movement rules must have
the same game/build scope. The policy is a fixed OAC signed-policy record with a detached CMS
signature from the configured offline policy signer.

Validate configuration and all durable state without listening on a socket:

```powershell
dotnet OAC.Backend.dll validate
```

Run the service:

```powershell
dotnet OAC.Backend.dll
```

Revoke an admitted endpoint session by its 16-byte hexadecimal identifier:

```powershell
dotnet OAC.Backend.dll revoke SESSION_ID_HEX
```

The data directory is single-writer and bounded. State snapshots and append-only records are
checksummed with SHA-256, flushed before acknowledgement, validated on restart, and kept behind an
exclusive process lock. Deploy it on protected storage with host-level backup and access control;
the checksums detect corruption but do not replace that access-control boundary.
When a session retires, the reference store replaces its detailed logs with durable byte-count and
SHA-256 receipts, then removes the live log files. Export records to the operator's retention system
before retirement when longer evidence retention is required.
This reference deployment is intentionally single-node; operators that need horizontal scale
should preserve the same transaction, replay, and acknowledgement invariants in their managed
database.

## Build and test

```powershell
dotnet restore .\tests\OAC.Backend.Tests.csproj --locked-mode
dotnet build .\tests\OAC.Backend.Tests.csproj -c Release --no-restore
dotnet run --project .\tests\OAC.Backend.Tests.csproj -c Release `
  --no-build --no-restore
```

The tests exercise restart recovery, request replay, lease expiry, revocation, partial evidence
batches, role separation, certificate rotation, real loopback mutual TLS, and the game adapter.
The managed cryptography dependency is version-locked and listed in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
