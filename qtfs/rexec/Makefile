all: rexec rexec_server

rexec : client.go common.go fd.go
	go build -o rexec client.go common.go fd.go

rexec_server : server.go common.go
	go build -o rexec_server server.go common.go
test:
	go test -v ./common_test.go ./common.go
clean:
	rm -rf rexec rexec_server
