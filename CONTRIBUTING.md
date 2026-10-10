# Contributing to Tanur

Thanks for your interest. Tanur protects people under censorship, so we hold a
few lines firmly.

## Ground rules

1. **Do not invent cryptography.** The handshake and primitives use only
   standard, reviewed libraries: `golang.org/x/crypto`, `flynn/noise`,
   `crypto/tls`, and uTLS. Patches that add a novel cryptographic scheme at this
   layer will be declined. Innovation belongs in **framing, shaping, selection,
   and operations** — not in new crypto.
2. **Target structure, not single-packet randomness.** The shaper should shape
   *structure* (multiplexing, asymmetry, periodic chunks) and the first bytes
   must be a real, allowed protocol (a genuine TLS skin), never noise. See
   [`docs/dpi-and-shaper-requirements.md`](docs/dpi-and-shaper-requirements.md).
3. **No fixed on-wire constants without a documented reason.** Lengths, order,
   and pauses derive from the recipe and the session nonce.
4. **Scope.** This repository is the engine and reference client. The operational
   control plane (brain/tactics, recipe factory and signing keys, fleet
   automation, sentinel network) is intentionally not here and is not accepted
   here.

## Development

Requires Go 1.27+.

```bash
go build ./...
go test ./...
go vet ./...
gofmt -l .      # must print nothing
```

Please add tests for behavior changes. Keep the public API small and documented;
every exported symbol has a doc comment.

## Submitting changes

- Open an issue first for anything non-trivial, so we can agree on the approach.
- Keep commits focused; write clear messages.
- **Sign off** your commits (Developer Certificate of Origin):
  `git commit -s`. By signing off you assert the DCO (https://developercertificate.org/).
- By contributing, you agree your contribution is licensed under the project's
  license ([MPL-2.0](LICENSE)).

## Security

Never file a public issue for a vulnerability. Follow
[`SECURITY.md`](SECURITY.md).
