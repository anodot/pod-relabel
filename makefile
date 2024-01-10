GOARCH = amd64
GOOS ?= linux
BINARY = pod-relabel
VERSION= 0.0.3
GOLINT_EXEC = golangci-lint
AWS_ACCOUNT_ID := 932213950603
AWS_REGION := us-east-1
AWS_ECR := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com
ENVIRONMENT := dev

BINARY_NAME_FULL_NAME = $(BINARY)_$(GOOS)_$(GOARCH)
BUILD_FLAGS = GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) GOFLAGS=-mod=vendor
GO_BUILD = $(BUILD_FLAGS) go build $(GO_LD_FLAGS) -o $(BINARY_NAME_FULL_NAME) $(VERBOSE_FLAG) $(GOTARGET)

all: lint build
redeploy: build docker k8s-deploy

lint:
	@echo Running linters...
	$(BUILD_FLAGS) $(GOLINT_EXEC) run

build:
	rm -rf $(BINARY_NAME_FULL_NAME)
	$(GO_BUILD)

docker: build
	docker rmi -f anodot/$(BINARY):$(VERSION)
	docker build -t anodot/$(BINARY):$(VERSION) .
	docker tag anodot/$(BINARY):$(VERSION) $(AWS_ECR)/$(BINARY):$(VERSION)
	docker push $(AWS_ECR)/$(BINARY):$(VERSION)

deploy:
	helm upgrade pod-relabel ./helm --install --values=helm/values-$(ENVIRONMENT).yaml --set base-chart.image.tag=$(VERSION) -n pod-relabel --debug


vendor-update:
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

clean:
	kubectl delete all -l "app=pod-relabel-app"
