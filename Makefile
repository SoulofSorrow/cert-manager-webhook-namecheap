IMAGE ?= ghcr.io/yourusername/cert-manager-webhook-namecheap
TAG   ?= latest

.PHONY: build test docker-build docker-push deploy undeploy

build:
	go build -o bin/webhook ./cmd/webhook

test:
	go test -v ./...

docker-build:
	docker build -t $(IMAGE):$(TAG) .

docker-push:
	docker push $(IMAGE):$(TAG)

docker-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--provenance=false \
		--sbom=false \
		-t $(IMAGE):$(TAG) \
		--push \
		.

deploy:
	kubectl apply -f deploy/rbac/rbac.yaml
	kubectl apply -f deploy/apiservice.yaml
	kubectl apply -f deploy/deployment.yaml

undeploy:
	kubectl delete -f deploy/deployment.yaml --ignore-not-found
	kubectl delete -f deploy/apiservice.yaml --ignore-not-found
	kubectl delete -f deploy/rbac/rbac.yaml --ignore-not-found

secret:
	@echo "Apply deploy/secret.yaml after filling in your credentials"
	@echo "kubectl apply -f deploy/secret.yaml"

lint:
	golangci-lint run ./...
