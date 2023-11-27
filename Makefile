.PHONY: test docker push

IMAGE            ?= hjacobs/kube-janitor
VERSION          ?= $(shell git describe --tags --always --dirty)
TAG              ?= $(VERSION)

default: docker

.PHONY: install
install:
	poetry install

.PHONY: lint
lint:
	poetry run pre-commit run --all-files

test: install lint
	poetry run coverage run --source=kube_janitor -m pytest -v
	poetry run coverage report

version:
	sed -i "s/version: v.*/version: v$(VERSION)/" deploy/*.yaml
	sed -i "s/kube-janitor:.*/kube-janitor:$(VERSION)/" deploy/*.yaml
	sed -i "s/appVersion:.*/appVersion: $(VERSION)/" unsupported/helm/Chart.yaml

docker:
	docker buildx create --use
	docker buildx build --rm --build-arg "VERSION=$(VERSION)" -t "$(IMAGE):$(TAG)" -t "$(IMAGE):latest" --platform linux/amd64,linux/arm64 .
	@echo 'Docker image $(IMAGE):$(TAG) multi-arch was build (cannot be used).'

push:
	docker buildx create --use
	docker buildx build --rm --build-arg "VERSION=$(VERSION)" -t "$(IMAGE):$(TAG)" -t "$(IMAGE):latest" --platform linux/amd64,linux/arm64 --push .
	@echo 'Docker image $(IMAGE):$(TAG) multi-arch can now be used.'

.PHONY: helm-docs
helm-docs:
	@helm-docs -o Values.md
