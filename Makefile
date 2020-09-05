export GOFLAGS = -mod=vendor
export GO111MODULE = on
export GOPROXY = direct
export GOSUMDB = off

gosrc := $(shell find cmd internal -name "*.go")

gobin := $(strip $(shell go env GOBIN))
ifeq ($(gobin),)
gobin := $(shell go env GOPATH)/bin
endif

# Yes, the quotes are part of ldflags value.
ldflags := "-s -w"

appver := $(strip $(shell git describe --abbrev=0 --tags 2>/dev/null || echo "0.0.0"))
ifeq ($(appver),0.0.0)
$(warning failed to find app version, using default)
endif

natstk: $(gosrc) vendor
	go build github.com/variadico/natstk/cmd/natstk

natstk.linuxrelease: $(gosrc) vendor
	GOOS=linux CGO_ENABLED=0 go build -o $@ -v -ldflags=$(ldflags) github.com/variadico/natstk/cmd/natstk

vendor: go.mod go.sum
	go mod vendor

release/natstk$(appver).linux-amd64.tar.gz: natstk.linuxrelease
	mkdir --parents release
	tar czf $@ --transform 's/$</natstk/g' $<

.PHONY: release
release: release/natstk$(appver).linux-amd64.tar.gz

.PHONY: build
build: natstk

.PHONY: install
install: natstk
	mv natstk $(gobin)

.PHONY: clean
clean:
	rm -rf natstk natstk.linuxrelease release
