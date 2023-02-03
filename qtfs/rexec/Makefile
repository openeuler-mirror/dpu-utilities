all: rexec rexec_server rexec_shim

rexec : client.go common.go fd.go
	go build -o rexec client.go common.go fd.go

rexec_server : server.go common.go fd.go
	go build -o rexec_server server.go common.go fd.go
test:
	go test -v ./common_test.go ./common.go

rexec_shim:
	$(MAKE) -C ./rshim

install:
	cp -f rexec /usr/bin/
	cp -f rexec /usr/bin/
	$(MAKE) install -C ./rshim

clean:
	rm -rf rexec rexec_server
	$(MAKE) clean -C ./rshim

