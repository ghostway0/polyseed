tools:
	go build cmd/ps-client.go
	go build cmd/ps-server.go

all: tools
