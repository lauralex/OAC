# OAC game adapter

`OAC.GameAdapter` is the typed .NET client used by an authoritative game server to submit canonical
movement records to `OAC.Backend`.

Create one `GameAdmissionSession` for an admitted endpoint, match, player pseudonym, and replay.
The adapter serializes that session's requests, creates fresh nonces, enforces exact response
correlation, and advances the event sequence only after the backend returns a durable decision.
If a response is lost or malformed, the session is marked for fresh admission instead of retrying
an ambiguous transaction.

The production constructor requires:

- an HTTPS origin with no path, user information, query, or fragment;
- a current strong client-authentication certificate with its private key;
- one active server-certificate SHA-256 pin and, optionally, one rotation pin; and
- a network timeout of no more than 30 seconds.

The adapter is intentionally small. Authentication, matchmaking, replay storage, and distribution
of the backend session identifier remain responsibilities of the integrating game platform.
