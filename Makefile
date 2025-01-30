APPNAME=certwatcher

.PHONY: build local lambda clean

build: 
	go get && GOOS=linux go build -o $(APPNAME)

local: clean build
	go run main.go -l

lambda: clean build
	GOOS=linux go build -o main
	zip terraform/modules/iam-certwatcher/bin/iam-certwatcher-lambda.zip main

clean:
	rm -f main
