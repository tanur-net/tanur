# Tanur field telemetry — privacy and data flow

This document answers a security reviewer's question precisely: **what data leaves
a user's device, what exists at each hop, who can read it, and how long it lives.**
It replaces any hand-wave of "fully anonymous" with the concrete flow. The design
rule behind all of it: *operator, result, time — yes; a person — never.*

This describes the engine and collector in this repository. It is grounded in the
code (`brain/telemetry.go`, `brain/stats.go`, and the engine's report path); where
behaviour is enforced in code, the symbol is named so it can be checked.

## What a report contains — and what it deliberately does not

A single report (`brain.Report`) carries only:

| Field | Meaning | Privacy note |
|---|---|---|
| `reporter` | a random token, for de-duplicating distinct reporters in a window | **Not** derived from user/device/IP; rotates on a fixed epoch (see below) |
| `endpoint` | which endpoint the report is about | an infrastructure id, not a user attribute |
| `ok` / `control` | did this endpoint work / was the line up at all | outcome only |
| `stage` | *where* it failed (tcp/tls/door/inner) | research signal, not a per-user fact |
| `reason` | *why* it failed, from a fixed vocabulary | a closed code set, never raw error text (which could carry a destination) |
| `network` | operator key | **not trusted from the client** — overridden server-side (below); on iOS the client cannot even read it |

It contains **no** user id, **no** account, **no** IP address, **no** destination
or domain, and **no** client timestamp. The absence of a client clock is both a
privacy choice and an anti-fingerprint one.

## The flow, hop by hop

### 1. On the device (the engine)

- Reports are **buffered and flushed as a jittered batch**, never sent per-dial.
  There is no phone-home beacon whose timing is itself a signature.
- The `reporter` token is random and **rotates every `reporterEpoch` (30 minutes)**.
  This is long enough that it never inflates the collector's distinct-reporter
  count, yet short enough that a long-running engine does not tag every report over
  hours or days with one linkable token. Reports are linkable only *within* an
  epoch, never across the whole life of the engine.
- The batch is posted to `reportURL`, which is the **same fronted TLS host as the
  tunnel** (`https://<cover-host>/r`). To any on-path observer it is an ordinary
  request to the cover site, not traffic to a separate analytics endpoint.

### 2. In transit

TLS to the real cover host, carried the same way the tunnel is. A prober or a
browser that GETs the report path sees only the cover site.

### 3. At the collector

- The collector reads the operator from the **connection source IP** (via
  `Collector.NetworkFromIP`), uses it *only* for that lookup, and **discards the IP
  — it is never logged or stored.** The client never sends the IP; the server never
  keeps it. This is the one place an IP is touched, and it is touched in memory and
  dropped.
- Arrival time is stamped **server-side**, so no precise client clock is on the wire.
- What the collector keeps is deliberately small:
  - a **transient per-(operator,endpoint) window** of recent observations
    (`seen`), holding only `{reporter, ok, control, arrival-time}`, used to decide
    whether *enough distinct reporters* say an endpoint is dead (burn voting). Old
    observations age out of the window.
  - a **per-operator aggregate of counts** (`brain.Stats`): ok / fail / control, a
    breakdown of failures by stage, and by reason. **Counts only — no report log.**
- There is no raw-report log, no user table, and nothing that joins a report to an
  identity, because none of the inputs carry one.

### 4. On the dashboard

`/stats` (JSON) and `/dash` (a self-contained view) are **token-gated** and expose
only the per-operator aggregate counts above. They cannot show a user because the
pipeline never had one.

## Separation and linkage — the questions a reviewer should ask

- **Can timestamps link reports to a connection?** The client sends no timestamp;
  the server stamps arrival coarsely for windowing. There is no per-connection time
  on the wire.
- **Are auth logs and telemetry joined?** They are different systems. Authentication
  happens at the host app's backend (which fronts the request); the anonymous report
  carries nothing that keys into it — no user, no account, no IP retained.
- **Can reports be linked across time?** Only within one 30-minute reporter epoch,
  by the random `reporter` token, and only to each other — never to a person.
- **Where exactly is the IP dropped?** At ingest, immediately after the operator
  lookup, in `Collector.NetworkFromIP`'s caller; it is not written to any store or
  log. (CLAUDE.md rule 6 is the standing constraint this enforces.)
- **Is it optional and disclosed?** Telemetry is part of the **opt-in** Tanur mode;
  a user who does not enable Tanur sends nothing. The user-facing disclosure of what
  is collected is maintained in the host apps' own privacy text.

## Residual considerations (honest limits)

- The operator key is a coarse bucket (e.g. MCI vs Irancell). That is the intended
  granularity; it is not fine enough to single out a person, which is the point.
- A global passive adversary who can see both a user's connection to the cover host
  *and* the collector could in principle correlate timing of the batch. Keeping the
  report on the **same** fronted host as the tunnel, batched and jittered, is what
  reduces this; it is a mitigation, not a proof of unlinkability, and we state it as
  such.
- The protections above are properties of *this* engine and collector. A different
  deployment that added logging, a separate beacon host, or a client-sent timestamp
  would weaken them — which is exactly why those choices are made in code here and
  documented, not left to operational discretion.
