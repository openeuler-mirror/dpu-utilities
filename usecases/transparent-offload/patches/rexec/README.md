## Introduction

Rexec is a simple tool to perform remote executing user specified binary on server side.
This tools-set includes client binary named rexec and a server binary, rexec_server.

## How to compile

This is based on an example usage of docker/libchan. Download original source code from `https://github.com/docker/libchan`, and apply patch file "0001-update-rexec-to-work-properly.patch" through:
```
git am 0001-update-rexec-to-work-properly.patch
```

compile rexec in proper directory:
```
cd ./examples/rexec
make
```

Note that you are supposed to have golang compiling environment and related vendor on you machine.

## How to use

* on the server side
```
CMD_NET_ADDR=tcp://0.0.0.0:7777 ./rexec_server
```

* on the client side
```
CMD_NET_ADDR=tcp//$SERVER_IP:7777 ./rexec ls
```

Environment `CMD_NET_ADDR` is used to specify destination in `ip:port` format. Executing environment will be sent to server during rexec.
