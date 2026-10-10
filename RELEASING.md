# Releasing Tanur (reproducible, signed)

Official Tanur releases are **reproducible** (anyone can rebuild the exact same
binaries from a tag) and **signed** (so a user can tell an official build from a
trojaned fork). This document is the procedure. No private key is ever stored in
this repository.

## 1. Pin the toolchain

Reproducibility requires a fixed Go version. Releases are built with the Go
version named in `go.mod` (currently **go 1.27.0**). Record the exact toolchain:

```bash
go version   # must match the release's pinned version
```

## 2. Reproducible build

Build every published binary with a stripped, trim-pathed, VCS-free, CGO-free
configuration so the output depends only on the source and the toolchain:

```bash
make release VERSION=vX.Y.Z
```

which runs, for each target OS/ARCH:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false \
  -ldflags "-s -w -buildid=" \
  -o dist/bin/tanur-cli_${GOOS}_${GOARCH} ./cmd/tanur-cli
```

- `-trimpath` removes local filesystem paths.
- `-buildvcs=false` and `-buildid=` strip VCS stamps and the build id, which
  otherwise vary between machines.
- `CGO_ENABLED=0` gives a static, host-independent build.
- `SOURCE_DATE_EPOCH` is respected by the archive step for stable timestamps.

Two independent builders should produce byte-identical binaries. Diff them before
signing.

## 3. Checksums

```bash
make checksums VERSION=vX.Y.Z
# -> dist/SHA256SUMS
```

`SHA256SUMS` lists the SHA-256 of every published artifact. Users verify with:

```bash
sha256sum -c SHA256SUMS
```

## 4. Sign

Sign the `SHA256SUMS` file (one signature covers everything it lists). We use
**minisign** (small, modern); GPG is an accepted alternative.

```bash
# one-time: generate the release key OFFLINE, keep the secret key off this repo
minisign -G -p tanur-release.pub -s ~/.tanur/tanur-release.key

# per release:
minisign -S -s ~/.tanur/tanur-release.key -m dist/SHA256SUMS
# -> dist/SHA256SUMS.minisig
```

Publish the **public** key (`tanur-release.pub`) in the release notes and in this
file below. Never commit the secret key.

### Release signing public key

```
RELEASE_SIGNING_PUBLIC_KEY_PLACEHOLDER
(paste the minisign public key here once generated; this is PUBLIC and safe)
```

## 5. Publish

Upload, through the official channel only (see `NOTICE`):

- the binaries,
- `SHA256SUMS`,
- `SHA256SUMS.minisig`,
- release notes listing the tag, the Go version, and the signing key.

## How a user verifies

```bash
# 1. check the signature on the checksum file
minisign -Vm SHA256SUMS -P <release public key>
# 2. check the binaries against the checksums
sha256sum -c SHA256SUMS
```

If either step fails, the build is not an official Tanur release. Do not run it.

## Manual decisions before the first release

- Replace `SECURITY_CONTACT_PLACEHOLDER` in `SECURITY.md`.
- Replace `OFFICIAL_RELEASE_CHANNEL_PLACEHOLDER` in `NOTICE`.
- Generate the release key and paste its public half above.
- Confirm the license (MPL-2.0) and the module path / repository host.
