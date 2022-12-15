package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"io/ioutil"
	"encoding/json"

	"github.com/docker/libchan"
)

const (
	configDir = "/etc/rexec"
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

func CheckRight(fileName string) error {
	var uid int
	var gid int
	var mode int
	var stat syscall.Stat_t
	if err := syscall.Stat(fileName, &stat); err != nil {
		return fmt.Errorf("Can't get status of %s: %s\n", fileName, err)
	}
	uid = int(stat.Uid)
	gid = int(stat.Gid)
	mode = int(stat.Mode)

	if (uid != 0 || gid != 0) {
		return fmt.Errorf("Owner of %s must be root\n", fileName)
	}

	if (mode & 0777 != 0400) {
		return fmt.Errorf("Mode of %s must be 0400\n", fileName)
	}

	return nil
}

// CommandResponse is the returned response object from the remote execution
type CommandResponse struct {
	Pid	   int
	Status int
	WhiteList int
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

func readAddrFromFile(role string) (string) {
	fileName := fmt.Sprintf("%s/%s.json", configDir, role)
	if err := CheckRight(fileName); err != nil {
		fmt.Printf("Check right of %s failed: %s", fileName, err)
		return ""
	}
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Printf("read %s failed: %s", fileName, err)
		return ""
	}
	var netAddr struct {
		Protocol string `json:"Protocol"`
		Ipaddr string	`json:"Ipaddr"`
		Port string		`json:"Port"`
	}
	err = json.Unmarshal([]byte(file), &netAddr)
	if err != nil {
		fmt.Printf("can not unmarshal %s:%s", fileName, err)
		return ""
	}
	return fmt.Sprintf("%s://%s:%s", netAddr.Protocol, netAddr.Ipaddr, netAddr.Port)
}

func parseNetAddr(role string) (NetAddr, error) {
	cna := os.Getenv("CMD_NET_ADDR")

	// default netAddr: tcp://127.0.0.1:9323
	if strings.TrimSpace(cna) == "" {
		cna = readAddrFromFile(role)
		if cna == "" {
			return NetAddr{}, fmt.Errorf("please set enviroment variable CMD_NET_ADDR or set Config file %s/%s.json", configDir, role)
		}
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
