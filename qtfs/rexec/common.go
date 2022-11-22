package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/docker/libchan"
)

// RemoteCommand is the run parameters to be executed remotely
type RemoteCommand struct {
	Cmd        string
	Args       []string
	Env        []string
	Stdin      io.Reader
	Stdout     io.WriteCloser
	Stderr     io.WriteCloser
	StatusChan libchan.Sender
	Cgroups    map[string]string
}

// CommandResponse is the returned response object from the remote execution
type CommandResponse struct {
	Pid	   int
	Status int
}

// NetAddr is struct to describe net proto and addr
type NetAddr struct {
	Proto string
	Addr  string
}

func parseTCPAddr(inAddr string) (NetAddr, error) {
	if inAddr == "" {
		return NetAddr{}, fmt.Errorf("empty TCP addr")
	}

	addr := strings.TrimPrefix(inAddr, "tcp://")
	addr = strings.TrimSpace(addr)
	if strings.Contains(addr, "://") || addr == "" {
		return NetAddr{}, fmt.Errorf("invalid proto, expected tcp: %s", inAddr)
	}

	u, err := url.Parse("tcp://" + addr)
	if err != nil {
		return NetAddr{}, err
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return NetAddr{}, fmt.Errorf("invalid bind address format: %s", inAddr)
	}

	if host == "" || port == "" {
		return NetAddr{}, fmt.Errorf("invalid bind address format: %s", inAddr)
	}
	p, err := strconv.Atoi(port)
	if err != nil && p == 0 {
		return NetAddr{}, fmt.Errorf("invalid bind address format: %s", inAddr)
	}

	return NetAddr{
		Proto: "tcp",
		Addr:  host + ":" + port,
	}, nil
}

func parseUnixAddr(inAddr string) (NetAddr, error) {
	addr := strings.TrimPrefix(inAddr, "unix://")
	if strings.Contains(addr, "://") || addr == "" {
		return NetAddr{}, fmt.Errorf("invalid proto, expected unix: %s", addr)
	}

	return NetAddr {
		Proto: "unix",
		Addr:  addr,
	}, nil
}

func parseNetAddr() (NetAddr, error) {
	cna := os.Getenv("CMD_NET_ADDR")

	// default netAddr: tcp://127.0.0.1:9323
	if strings.TrimSpace(cna) == "" {
		return NetAddr{}, fmt.Errorf("need CMD_NET_ADDR")
	}

	parts := strings.SplitN(cna, "://", 2)
	if len(parts) == 1 && parts[0] != "" {
		parts = []string{"tcp", parts[0]}
	}

	switch parts[0] {
	case "tcp":
		return parseTCPAddr(parts[1])
	case "unix":
		return parseUnixAddr(parts[1])
	default:
		return NetAddr{}, fmt.Errorf("invalid bind address format: %s", cna)
	}

	return NetAddr{}, fmt.Errorf("invalid bind address format: %s", cna)
}
