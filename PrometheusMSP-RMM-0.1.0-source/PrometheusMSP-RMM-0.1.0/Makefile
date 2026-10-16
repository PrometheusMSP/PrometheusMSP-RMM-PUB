.PHONY: fmt test vet build compose-up compose-down pki seed-dev package

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

test:
	go test ./...

vet:
	go vet ./...

build:
	./scripts/build.sh

pki:
	./scripts/generate-dev-pki.sh

compose-up:
	docker compose -f deploy/docker-compose.yml up --build -d

compose-down:
	docker compose -f deploy/docker-compose.yml down

seed-dev:
	./scripts/bootstrap-tenant.sh 00000000-0000-0000-0000-000000000001 "Local Development"

package:
	./scripts/package.sh
