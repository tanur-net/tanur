# Security Policy

Tanur is used by people who may be at real risk if it fails. We take reports
seriously and practice coordinated disclosure.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: open the **Security** tab of this
repository and click **"Report a vulnerability"**. This opens a private advisory
visible only to the maintainers, so you can share details safely without
disclosing them publicly.

Please include: the affected version/commit, a description, reproduction steps or
a proof of concept, and the impact you foresee. Please give us a reasonable time
to respond before any public disclosure.

## Scope

In scope: the engine and reference client in this repository — the Noise inner
channel, the TLS skin, the recipe format and its verification, the shaper, the
carrier/tunnel, the client-side selection, and the reference binaries.

Out of scope (and intentionally not in this repository): the operational control
plane — the server-side brain/tactics, the recipe factory and signing keys, the
fleet automation, and the sentinel network. Reports about those cannot be
reproduced from this repository; contact the maintainers privately.

## What we care about most

- Anything that lets a network observer reliably **distinguish or fingerprint**
  Tanur traffic from the cover protocol.
- Any weakness in the handshake, framing, or multiplexing that breaks
  confidentiality, integrity, or forward secrecy.
- Any way a malicious endpoint list or recipe (e.g. a bad signature accepted, or
  a downgrade) could be forced on a client.
- Memory-safety or denial-of-service issues reachable from the network.

Thank you for helping keep users safe.
