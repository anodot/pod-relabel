GOARCH = amd64
GOOS ?= linux
BINARY = pod-relabel-app
VERSION= 0.0.2


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
	docker push anodot/$(BINARY):$(VERSION)

k8s-deploy:
	 kubectl delete -f ./dep.yaml || echo "NOT found"
	 kubectl apply -f ./dep.yaml

vendor-update:
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

clean:
	kubectl delete all -l "app=pod-relabel-app"
