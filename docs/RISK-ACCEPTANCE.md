# Risk Acceptance Register

**Reviewed:** 2026-11-25
**Owner:** Security + Engineering

Waivers here expire on the stated date; an expired waiver fails the release gate.
Each waiver must name a compensating control.

| id | control waived | rationale | compensating control | owner | expires | status |
|---|---|---|---|---|---|---|
| RISK-0001 | Feed upstream integrity fully verified at ingest | Upstream vendors occasionally publish malformed records; full verification would block ingestion | Records normalized + CPE-validated before correlation; operator review queue; dead-letter budget | Engineering | 2027-05-25 | active |
| RISK-0002 | /api/events and /api/session were role-agnostic reads | Any authenticated role pages its own session / the event log | Explicit `requireRole(ADMIN, OPERATOR, VIEWER)` added (no behavior change); all roles authenticated | Security | 2027-05-25 | active |

No other waivers are active. New waivers require a pull request and security sign-off.
