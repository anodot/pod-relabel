GOARCH = amd64
GOOS ?= linux
BINARY = pod-relabel
# VERSION= 0.0.5
VERSION ?= $(shell git show -s --format=%cd-%h --date=format:'%Y-%m-%d-%H-%M')
GOLINT_EXEC = golangci-lint
AWS_ACCOUNT_ID := 932213950603
AWS_REGION := us-east-1
AWS_ECR := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ENVIRONMENT := dev

BINARY_NAME_FULL_NAME = $(BINARY)_$(GOOS)_$(GOARCH)
BUILD_FLAGS = GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOFLAGS=-mod=vendor
GO_BUILD = $(BUILD_FLAGS) go build $(GO_LD_FLAGS) -o $(BINARY_NAME_FULL_NAME) $(VERBOSE_FLAG) $(GOTARGET)

all: lint build
redeploy: build docker deploy

login: ## aws ecr helm login
	aws ecr get-login-password --region $(AWS_REGION) | docker login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
	aws ecr get-login-password --region $(AWS_REGION) | helm registry login --username AWS --password-stdin $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
	
lint:
	@echo Running linters...
	$(BUILD_FLAGS) $(GOLINT_EXEC) run

build:
	rm -rf $(BINARY_NAME_FULL_NAME)
	$(GO_BUILD)

docker: login build
	docker rmi -f anodot/$(BINARY):$(VERSION)
	docker build -t anodot/$(BINARY):$(VERSION) .
	docker tag anodot/$(BINARY):$(VERSION) $(AWS_ECR)/$(BINARY):$(VERSION)
	docker push $(AWS_ECR)/$(BINARY):$(VERSION)

deploy: login
	helm upgrade pod-relabel ./helm --install --values=helm/values-$(ENVIRONMENT).yaml --set base-chart.image.tag=$(VERSION) -n $(ENVIRONMENT) --debug


vendor-update:
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

clean:
	kubectl delete all -l "app=pod-relabel-app"
