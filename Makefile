GO ?= go
NPM ?= npm

.PHONY: all build vet test web-build copy-web clean

all: build

web-build:
	cd web && $(NPM) install && $(NPM) run build

copy-web:
	./scripts/copy-web

build: copy-web
	$(GO) build ./adapter/... ./control/... ./nodeagent/... ./launcher/...

vet:
	$(GO) vet ./adapter/... ./control/... ./nodeagent/... ./launcher/...

test:
	$(GO) test ./adapter/... ./control/... ./nodeagent/... ./launcher/...

clean:
	rm -rf web/dist control/web/dist
	mkdir -p control/web/dist && touch control/web/dist/.gitkeep
