MODULE         = github.com/venafi/sigstore-kms-venafi
PLUGIN       = sigstore-kms-venafi
GIT_TAG        = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
BUILD_METADATA =
ifeq ($(GIT_TAG),) # unreleased build
    GIT_COMMIT     = $(shell git rev-parse HEAD)
    GIT_STATUS     = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "unreleased")
	BUILD_METADATA = $(GIT_COMMIT).$(GIT_STATUS)
endif
LDFLAGS=-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
        -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
        -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
        -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

GO_BUILD_FLAGS = --ldflags="$(LDFLAGS)"

PLATFORMS=darwin linux windows
ARCHITECTURES=amd64

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: build

.PHONY: FORCE
FORCE:

sigstore-kms-venafi:
	go build $(GO_BUILD_FLAGS) -o $@ ./$<

.PHONY: cross
cross:
	$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	env CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(PLUGIN)-$(GOOS)-$(GOARCH) ))) \
	env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(PLUGIN)-darwin-arm64
	env GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(PLUGIN)-linux-arm64

.PHONY: download
download: ## download dependencies via go mod
	go mod download

.PHONY: build
build: $(PLUGIN) ## builds binaries

.PHONY: clean
clean:
	git status --short | grep '^!! ' | sed 's/!! //' | xargs rm -rf

.PHONY: install
install: 
	sudo cp sigstore-kms-venafi /usr/local/bin
