.DEFAULT_GOAL := help

GOARCH = amd64
GOOS ?= linux
BINARY = pod-relabel
VERSION ?= $(shell git show -s --format=%cd-%h --date=format:'%Y-%m-%d-%H-%M')
VERSION_CHART ?= $(shell git show -s --format=%cd --date=format:'%Y-%m-%d-%H-%M')
GOLINT_EXEC = golangci-lint
AWS_ACCOUNT_ID := 932213950603
AWS_REGION := us-east-1
AWS_ECR := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ENVIRONMENT := dev

BINARY_NAME_FULL_NAME = $(BINARY)_$(GOOS)_$(GOARCH)
BUILD_FLAGS = GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOFLAGS=-mod=vendor
GO_BUILD = $(BUILD_FLAGS) go build $(GO_LD_FLAGS) -o $(BINARY_NAME_FULL_NAME) $(VERBOSE_FLAG) $(GOTARGET)

help: ## Show help message
	@grep -E '(^[a-zA-Z_-]+:.*?##.*$$)|(^##)' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}{printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}' | sed -e 's/\[32m##/[33m/'

##Dev:
all: lint build ## Run linter and build

lint: ## Run linters
	@echo Running linters...
	$(BUILD_FLAGS) $(GOLINT_EXEC) run

build: ## build binary
	@echo Building version: $(VERSION)
	rm -rf $(BINARY_NAME_FULL_NAME)
	$(GO_BUILD)

vendor-update: ## Update vendor dependencies
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

##Docker:
login: ## AWS ECR and helm login
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
	aws ecr get-login-password --region $(AWS_REGION) | helm registry login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com

list-images: login ## List docker images in ECR
	@echo docker images:
	aws ecr describe-images --repository-name $(BINARY) --region $(AWS_REGION) | jq '[.imageDetails[]? | select(.artifactMediaType == "application/vnd.docker.container.image.v1+json" or .artifactMediaType == null) | .imageTags[]?] | sort_by(.)[]'

docker-build: build ## Build docker image locally
	@echo building docker image: $(VERSION)
	docker rmi -f anodot/$(BINARY):$(VERSION) || true
	docker build -t anodot/$(BINARY):$(VERSION) .

docker-push: login docker-build ## Push docker image to ECR
	@echo pushing image to ECR: $(VERSION)
	docker tag anodot/$(BINARY):$(VERSION) $(AWS_ECR)/$(BINARY):$(VERSION)
	docker push $(AWS_ECR)/$(BINARY):$(VERSION)

##Helm:
list-charts: login ## List available helm chart versions in ECR
	@echo helm chart versions:
	aws ecr describe-images --repository-name $(BINARY) --region $(AWS_REGION) | jq '[.imageDetails[]? | select(.artifactMediaType == "application/vnd.cncf.helm.config.v1+json") | .imageTags[]?] | sort_by(.)[]'

chart-build: ## Package helm chart
	@echo Packaging Helm chart version: $(VERSION_CHART)
	@echo "Packaging and pushing Helm chart..."
	yq -i '.base-chart.image.tag = "$(VERSION)"' ./helm/values.yaml
	helm dep build ./helm
	helm package --dependency-update --version $(VERSION_CHART) ./helm
	@echo Helm chart packaged as $(BINARY)-$(VERSION_CHART).tgz

chart-push: login chart-build ## Push helm chart to ECR
	@echo Pushing Helm chart to ECR: $(VERSION_CHART)
	helm push $(BINARY)-$(VERSION_CHART).tgz oci://$(AWS_ECR)/
	@echo Helm chart pushed to oci://$(AWS_ECR)/$(BINARY):$(VERSION_CHART)

##Combined build binary & image, package chart and push:
package: build login docker-build docker-push chart-build chart-push ## Build and push both docker image and chart

##Deployment:
diff: login ## Show diff between local and deployed chart, for prod: make diff ENVIRONMENT=prod
ifndef VERSION_CHART
	$(error "VERSION_CHART is not set, example: make diff VERSION_CHART=2023-12-26-17-42")
endif
	@echo "Comparing version $(VERSION_CHART) with current deployment..."
	rm -rf $(BINARY)
	# Pull chart version
	helm pull oci://$(AWS_ECR)/$(BINARY) --version=$(VERSION_CHART) --untar || true
	# Show diff
	helm diff upgrade $(BINARY) ./$(BINARY) --allow-unreleased --values=./$(BINARY)/values-$(ENVIRONMENT).yaml --set base-chart.image.tag=$(VERSION) -n $(ENVIRONMENT)

deploy: login ## Deploy specific version to k8s, for prod: make deploy ENVIRONMENT=prod
ifndef VERSION_CHART
	$(error "VERSION_CHART is not set, example: make deploy VERSION_CHART=2023-12-26-17-42")
endif
	@echo "Deploying version $(VERSION_CHART) to environment: $(ENVIRONMENT)"
	rm -rf $(BINARY)
	# Pull specified chart version
	helm pull oci://$(AWS_ECR)/$(BINARY) --version=$(VERSION_CHART) --untar || true
	# Deploy
	helm upgrade $(BINARY) ./$(BINARY) --install --values=./$(BINARY)/values-$(ENVIRONMENT).yaml --set base-chart.image.tag=$(VERSION) -n $(ENVIRONMENT) --debug
