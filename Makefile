SHELL := /bin/bash
GO_IMAGE ?= golang:1.25-bookworm
GO_RUN = docker run --rm -v "$(CURDIR)":/src -w /src \
	-e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
	-u "$(shell id -u):$(shell id -g)" $(GO_IMAGE)

.DEFAULT_GOAL := help

help: ## Liste les cibles disponibles
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Amorce la PKI et démarre la TSA (idempotent)
	./scripts/bootstrap.sh

demo: ## Horodate un fichier et vérifie le jeton avec openssl ts
	./scripts/demo.sh

test: ## Exécute les tests unitaires (dans un conteneur Go)
	$(GO_RUN) go test ./...

lint: ## Vérifie le formatage et lance go vet
	$(GO_RUN) sh -c 'test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }'
	$(GO_RUN) go vet ./...

audit: ## Vérifie la chaîne de hachage du journal d'audit
	docker compose exec tsa tsa-server verify-audit

helm-lint: ## Vérifie le chart Helm (lint + rendu complet)
	helm lint deploy/helm/open-eidas
	helm template open-eidas deploy/helm/open-eidas > /dev/null

logs: ## Suit les journaux de la TSA
	docker compose logs -f tsa

down: ## Arrête la pile en conservant les volumes
	docker compose down

purge: ## Arrête la pile et supprime les volumes (PKI et token HSM inclus)
	docker compose down -v
	rm -f deploy/openxpki/.sampleconfig-done

.PHONY: help up demo test lint audit helm-lint logs down purge
