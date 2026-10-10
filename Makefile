# Tanur (public tree) — build, test, and reproducible release.
# Reproducible build flags are documented in RELEASING.md.

VERSION ?= dev
GOFLAGS := -mod=readonly
LDFLAGS := -s -w -buildid=
BUILDFLAGS := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

# Reference client published as a signed binary. Add more targets here if the
# release should ship additional reference binaries.
CMDS := tanur-cli
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64

.PHONY: build test vet fmt release checksums clean

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

# Reproducible, cross-compiled release binaries into dist/bin/.
release:
	@mkdir -p dist/bin
	@for c in $(CMDS); do \
	  for p in $(PLATFORMS); do \
	    os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
	    out="dist/bin/$${c}_$(VERSION)_$${os}_$${arch}$${ext}"; \
	    echo "building $$out"; \
	    CGO_ENABLED=0 GOFLAGS=$(GOFLAGS) GOOS=$$os GOARCH=$$arch \
	      go build $(BUILDFLAGS) -o "$$out" ./cmd/$$c || exit 1; \
	  done; \
	done

# SHA256SUMS over everything in dist/bin/ (run after `release`).
checksums:
	@cd dist/bin && (sha256sum * 2>/dev/null || shasum -a 256 *) > ../SHA256SUMS
	@echo "wrote dist/SHA256SUMS"

clean:
	rm -rf dist
