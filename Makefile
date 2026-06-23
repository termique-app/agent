build-amd64:
	GOOS=linux GOARCH=amd64 go build -o dist/termique-agent-linux-amd64 .

build-arm64:
	GOOS=linux GOARCH=arm64 go build -o dist/termique-agent-linux-arm64 .

build: build-amd64 build-arm64
