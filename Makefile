APPNAME=certwatcher

.PHONY: build local test lambda clean

build: 
	go get && GOOS=linux go build -o $(APPNAME)

local: clean build test
	go run main.go -l

test: clean build
	go test
	echo " -- Tests Complete -- "

lambda: clean build
	GOOS=linux go build -o main
	zip terraform/modules/iam-certwatcher/bin/iam-certwatcher-lambda.zip main

clean:
	rm -f main
