# How Tanur differs from existing anti-censorship technology

This document answers the single most important question a technical funder asks:
**given what already exists, what is genuinely new here, and why is it worth
building?** It is written to be read alongside the public engine code; it claims
nothing the code and the measurement pipeline cannot back up, and it is explicit
about what is still unproven.

## The one-line claim

Tanur is **not another transport, and not a runtime for shipping transports.** It
is a **measurement-driven control plane plus a specific structure-first transport**
designed for the concrete reality of Iran's DPI — where blocking is per-operator,
fragmentation is now itself blocked, and a non-browser TLS fingerprint is dropped.
Its novelty is the *closed loop* between what is observed inside the country and
what each client is told to do next, not the number of protocols it can emit.

## The landscape, and where Tanur sits in it

Censorship-circumvention tools cluster into three layers. Tanur is deliberately
at the layer the others leave thin.

### 1. Transport cores (Xray / V2Ray, sing-box, Hysteria, Shadowsocks, …)

These are general-purpose proxy/VPN cores. They are excellent and widely used, but
from a censor's point of view they share two weaknesses in Iran specifically:

- **Fingerprintable handshakes.** A generic core's TLS ClientHello, or its custom
  framing, is a stable signature. Field intel shows Irancell drops the distinctive
  non-browser ("unsafe") TLS fingerprint outright.
- **Trick-of-the-month evasion.** Much of the real-world resilience comes from
  add-on tricks — TLS record fragmentation, padding games — and those tricks are
  exactly what the censor adapts to. Fragmentation is now blocked on MCI.

Tanur does **not** embed any of these cores (an explicit project rule). It speaks
a real TLS 1.3 session to a real cover domain, with a **real browser fingerprint
via uTLS**, and shapes **flow structure** (multi-stream, asymmetry, periodic
chunks, a small opening window) rather than per-packet size — because the field
evidence says per-packet randomization is ineffective and pure randomness is
itself a signal.

### 2. Transport *runtimes* — most relevantly, WATER

WATER (WebAssembly Transport Executable Runtime) lets an app load and swap a
transport as a signed WebAssembly module, so changing transport behaviour does not
require shipping a new app build. This is valuable and overlaps with **one** Tanur
goal (remote, app-release-free change of connection behaviour).

But WATER and Tanur are at **different layers and are complementary, not
competing**:

| | WATER | Tanur |
|---|---|---|
| What it is | A *runtime* that executes a transport module | A *transport* **and** a *control plane* |
| Supplies the transport? | No — transport-agnostic; you bring the module | Yes — the TLS-skin + door + Noise + shaper transport |
| Decides *which* transport/params a given user gets, *when*? | No | Yes — per-operator, from field measurement |
| Learns from inside the censored network? | No | Yes — anonymous telemetry drives selection & burn |

A fair way to put it to a reviewer: **Tanur's transport could itself be delivered
as a WATER module.** They are not substitutes. What Tanur adds on top of "swap the
transport remotely" is *deciding what to swap to, per operator, from real data* —
which WATER, by design, does not do.

### 3. Aggregators (e.g. Patt / PattNG and similar)

Some popular tools are **aggregators**: they bundle and chain existing cores (Warp/
WireGuard, MASQUE, Psiphon, Tor, v2ray configs, Cloudflare-Workers tunnels) plus
evasion tricks, and let the user or some heuristic pick among them. This is a
pragmatic, useful approach and it reaches users today.

Tanur differs in intent: rather than *selecting among off-the-shelf engines*, it is
a *purpose-built engine whose selection is driven by measurement it collects
itself*. Notably, the public field reports from such tools (per-operator behaviour
differences, fragmentation being blocked) **independently corroborate Tanur's
design thesis** — which is a point in Tanur's favour, not against it.

## The four things that are actually new

1. **A measurement→decision closed loop.** Anonymous, per-operator field telemetry
   (operator, outcome, where it failed, why) feeds a server-side pool that burns
   dead endpoints *per operator* and reshapes the signed recipe — without an app
   release. The novelty is the loop, not any one part.

2. **Per-operator as a first-class dimension.** Iran's filtering genuinely differs
   between MCI and Irancell (different allowed fingerprints, different fragmentation
   behaviour). Tanur treats the operator as a key for endpoint burn and (next)
   recipe selection, instead of shipping one global config.

3. **Structure-first shaping with a real protocol skin.** The first bytes are a
   genuine browser TLS handshake to a real site that really serves a page; the
   tunnel rides behind a quiet HMAC "door" and a Noise channel; the observable
   *shape* (streams, bursts, opening window, bounded session lifetime) is derived
   from a signed recipe. This targets what DPI actually keys on now, and avoids the
   tricks that are already being blocked.

4. **Signed, verifiable, app-release-free control, with the trust anchor in the
   client.** Recipes and per-user assignments are Ed25519-signed and verified
   against a pinned brain key; the client now also checks assignment *freshness*,
   *user-match* and *endpoint well-formedness* (a signature proves provenance, not
   suitability). Secrets (the door, signing keys) never ride in the public endpoint
   list.

## What is NOT claimed (honesty for the reviewer)

- **Browser fingerprint ≠ total indistinguishability.** A real Chrome ClientHello
  defeats *fingerprint*-based blocking, not every possible traffic-analysis signal.
  Post-handshake behaviour is what the shaper addresses, and that is an ongoing,
  measured effort — not a solved problem.
- **The *necessity* of uTLS on Irancell is not yet demonstrated by us.** Our one
  in-country test line did not block the plain-Go fingerprint, so we proved uTLS
  *works and is harmless*, not that it is *required* on every operator. Confirming
  that needs an Irancell test line, which is in progress.
- **Per-operator selection must earn its keep with data.** The architecture
  supports per-operator burn today; that it yields higher success / faster recovery
  than a simpler global strategy is a hypothesis the beta's telemetry is designed to
  test, not an established result.
- **The operational control plane is intentionally not open-source.** The public
  repo is the engine and reference client; the recipe factory, the live pool and the
  signing keys are withheld by design. Independence of the *engine* is real; the
  *service* is not meant to be reproduced by a censor.

## Why this is worth funding rather than extending an existing tool

The gap Tanur fills is not "one more protocol." It is the **operations layer**:
a disciplined, privacy-preserving way to *know* what the censor is doing to real
users, per operator, in near-real-time, and to *act* on it with signed,
app-release-free changes — on top of a transport built for today's DPI rather than
last year's. Existing cores and runtimes are complementary inputs to that loop, not
replacements for it.
