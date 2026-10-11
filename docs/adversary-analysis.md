# Adversary analysis, layer by layer

OTF's review asks the question directly: **how could the censor defeat this?** This
document answers it per layer — the attacker's move, our response, and the honest
**residual risk** (what we are NOT claiming to have beaten, and how we would learn
if it broke). It is the attacker-framed companion to `threat-model.md` (which
enumerates the 12 detection classes and the design requirements they drive).

The guiding discipline: no layer is claimed "unbeatable." Each has a residual risk,
and the measurement loop (`telemetry-privacy.md`) is how we detect when a residual
risk becomes a live block — per operator, from inside the country.

Adversary model: a nation-scale, in-path DPI with active probing and the ability to
drop packets silently, throttle, reset, and block by IP/ASN — specifically Iran's
operators (MCI, Irancell, …), which behave **differently from each other**. (Full
capabilities and the China/Russia comparison are in `threat-model.md` §1.)

---

## Layer 1 — The TLS skin (outer handshake + cover site)

**What the censor can try**
- Fingerprint the TLS ClientHello (JA3/JA4) and drop anything that is not a real
  browser. (Measured: Irancell drops the distinctive non-browser fingerprint.)
- Read the SNI and block or watch our cover domain.
- **Actively probe** the endpoint: connect like a browser, send junk, replay a
  captured handshake — and see whether it behaves like a real web server or like a
  tunnel.
- Block the hosting IP/ASN, or the domain, once identified.

**Our response**
- The ClientHello is a **real browser fingerprint via uTLS** (Chrome by default,
  selectable), not Go's `crypto/tls` default — so JA3/JA4 matches a mainstream
  browser. ECH is supported when a recipe provides it, hiding the SNI.
- The cover host **serves a real site**: a prober, a browser, or a wrong/absent
  "door" gets the ordinary cover page, byte-for-byte like a reference web server —
  not a tunnel signature (threat-model R11).
- IP/domain blocking is answered at Layer 5 (the fleet + rotation), not here.

**Residual risk (honest)**
- A real browser fingerprint defeats *fingerprint* blocking, not every signal; the
  handshake must also track browser versions over time (uTLS "_Auto" presets help,
  but this is maintenance, not a one-time win).
- We have proven uTLS *works and is harmless* in-country; we have **not** yet proven
  it is *necessary* on Irancell (our one test line did not block the Go fingerprint).
  An Irancell A/B is pending. The telemetry's `stage=tls` + reason will show if a TLS
  reset starts happening per operator.
- Active-probe resistance (R11/R12/R13) is specified and partly implemented; the
  door-replay window (R12) is still an open requirement (tracked in §4.8).

## Layer 2 — The door (telling a Tanur client from a browser)

**What the censor can try**
- Capture a client's first request and **replay** it to confirm the endpoint is a
  tunnel.
- Brute-force or guess the door to elicit tunnel behaviour.
- Use the *absence* of normal browser follow-up requests as a tell.

**Our response**
- The door is an **HMAC over a client nonce** carried in ordinary-looking HTTP
  headers; a wrong or absent door yields only the cover site. The door is **not the
  tunnel credential** — the real authentication is the inner Noise handshake — so
  learning or replaying the door alone gets an attacker nothing usable.
- The door secret rides only in the **signed recipe**, never in the public endpoint
  list, and rotates per deployment.

**Residual risk (honest)**
- Replaying a captured door could, within a window, still elicit the *upgrade*
  behaviour (then fail at Noise). A time-boxed nonce with server-side seen-nonce
  tracking (R12, ≤60s) is specified but **not yet implemented** — this is the most
  concrete open hardening item at this layer, and we state it as open.

## Layer 3 — The inner channel (Noise)

**What the censor can try**
- Treat it as "fully encrypted / high-entropy" traffic and block by that heuristic
  (detection class 2).
- Attack the cryptography.

**Our response**
- Crypto is **standard only** (flynn/noise, x/crypto) — no home-made primitives, so
  there is no novel crypto to break; this is a deliberate project rule.
- The inner channel never appears on the wire as raw high-entropy bytes: it is
  **inside** the real TLS session (or the HTTP carrier), so what the censor sees is
  TLS to a real site, not a "fully encrypted" flow.

**Residual risk (honest)**
- Security rests on the standard primitives being correctly composed; we rely on
  audited libraries and keep the composition small and reviewable, but an
  independent crypto review is future work we would welcome a grant to fund.

## Layer 4 — The shaper (traffic shape over time)

**What the censor can try**
- Traffic analysis: flow symmetry, burst sizes, session duration, bytes-per-IP, and
  **timing of keepalives** — the signals that survive encryption.
- The **initial-upload-window** limit some operators apply (≈6 packets on certain
  Cloudflare paths) to trip tunnels that burst immediately.
- Note that **fragmentation** tricks are now themselves blocked (MCI) — so a design
  leaning on them fails.

**Our response**
- Shape is driven by a **signed recipe**, not fixed constants: burst/gap/pause
  distributions, an **opening window** that keeps the first frames small (answering
  the initial-upload limit), bounded session lifetime (now real wall-clock), and
  multi-stream/asymmetry. We target **structure**, not per-packet randomization
  (which field intel says is ineffective, and pure randomness is itself a signal).
- Keepalives ride **inside** the tunnel and are **jittered per session** (~20–40s),
  so there is no fixed-period beat.
- We do **not** rely on fragmentation.

**Residual risk (honest)**
- Traffic analysis is an arms race; our claim is "we target the signals the field
  evidence says matter today," not "we are unobservable." No two recipes may share a
  wire constant that came from Tanur (R28) — enforced by a pcap-diff test — but a
  novel statistical attack is always possible, which is exactly why we measure.

## Layer 5 — The fleet & control plane (what gets blocked, and recovery)

**What the censor can try**
- Block the data IPs/ASNs (the thing that *actually* gets blocked — volume and IP
  reputation, not usually the protocol).
- **Enumerate** endpoints by harvesting many users' configs, then block the whole
  set at once.
- Inject a malicious config to a client (via a hostile CDN or MITM).
- Starve the system by forcing constant rotation.

**Our response**
- **Many small, reputable, rotating IPs**, not one big node — because 100% of traffic
  on one IP is a certain block. Burn is **per operator** (an IP dead on Irancell can
  stay live on MCI).
- **Anti-enumeration:** each user receives a **different, stable, per-user subset**
  (hash-based), so a single compromised/blocked user reveals only their few
  endpoints, not the fleet; and "which endpoints burned together" can fingerprint
  the leaking user (R23).
- Configs are **Ed25519-signed and verified against a pinned brain key**; the client
  additionally checks freshness, user-match and endpoint well-formedness, so a
  hostile CDN cannot inject or replay a config.
- **Measurement-driven rotation:** the collector burns an endpoint only when enough
  *distinct* reporters on an operator agree, with a per-operator floor so it never
  starves an operator's usable pool.

**Residual risk (honest)**
- This is the **operational heart** and the hardest, ongoing cost: sourcing fresh,
  clean IPs faster than they burn. The grant is largely to fund exactly this loop.
- The live pool, the recipe factory and the signing keys are **intentionally not
  open-source** — publishing them would hand the censor the rotation logic and the
  keys. The open engine can be audited; the service is deliberately not reproducible.
- Multi-anchor signing-key rotation and a recipe expiry/version field are specified
  but not yet implemented (§4.8) — real items, honestly open.

## Layer 6 — Telemetry (could the measurement itself be attacked or deanonymize users?)

**What the censor can try**
- Use the reports as a side channel to identify or correlate users.
- Block or poison the reporting endpoint to blind us.
- Use report timing as a beacon signature.

**Our response**
- Reports carry **no user identity, no IP, no timestamp** (operator is derived
  server-side from the connection and the IP discarded); batched and **jittered**,
  on the **same fronted host** as the tunnel — not a separate beacon. The reporter
  token rotates per epoch (see `telemetry-privacy.md`).
- Poisoning: burn needs **distinct** reporters crossing a threshold, with a floor
  guard, so a handful of malicious reports cannot force a burn.

**Residual risk (honest)**
- A global passive adversary correlating the batch with the tunnel is a mitigation
  target, not a solved problem (stated in `telemetry-privacy.md`).
- Sybil-style poisoning at scale (many fake "distinct" reporters) is bounded by the
  thresholds and floor, but is an area to keep hardening as the pipeline grows.

---

## How we learn when a residual risk goes live

Every residual risk above maps to a telemetry signal: per-operator success rate, the
**stage** a failure hit (tcp/tls/door/inner), and the **reason** (reset/timeout/…).
A new block shows up as a per-operator shift in those numbers — which is the whole
point of building the measurement loop before, not after, the claims.
