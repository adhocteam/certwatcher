APPNAME=certwatcher

.PHONY: build local test lambda clean

build:
	go get && GOOS=linux go build -o $(APPNAME)

local: clean build test
	go run main.go -f cfg_example.json

test: clean build
	terraform fmt -recursive -write=true terraform
	go test
	@echo " -- Tests Complete -- "

lambda: clean build
	GOOS=linux go build -o main
	zip terraform/example/certwatcher-lambda.zip main

clean:
	rm -f main
