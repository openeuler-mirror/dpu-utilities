package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"
)

func sigHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGPIPE)

	for {
		select {
		case s := <-c:
			log.Printf("rexec get signal: %v\n", s)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: <command> [<arg> ]")
	}

	var client net.Conn
	var err error

	go sigHandler()
	na , err := parseNetAddr()
	if err != nil {
		log.Fatal(err)
	}

	if os.Getenv("USE_TLS") != "" {
		client, err = tls.Dial("tcp", na.Addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		client, err = net.Dial(na.Proto, na.Addr)
	}
	if err != nil {
		log.Fatal(err)
	}

	p, err := spdy.NewSpdyStreamProvider(client, false)
	if err != nil {
		log.Fatal(err)
	}
	transport := spdy.NewTransport(p)
	sender, err := transport.NewSendChannel()
	if err != nil {
		log.Fatal(err)
	}

	receiver, remoteSender := libchan.Pipe()

	command := &RemoteCommand{
		Cmd:        os.Args[1],
		Args:       os.Args[2:],
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Env:		append([]string{}, os.Environ()...),
		StatusChan: remoteSender,
	}

	err = sender.Send(command)
	if err != nil {
		log.Fatal(err)
	}

	retryCnt := 3
	// 1. get pid from response
	time.Sleep(5*time.Millisecond)
	response := &CommandResponse{}
retry:
	err = receiver.Receive(response)
	if err != nil {
		if retryCnt >= 0 {
			time.Sleep(5 * time.Millisecond)
			retryCnt--
			goto retry
		}
		log.Fatal(err)
	}
	retryCnt = 3
	// 2. get return status from response
retry2:
	err = receiver.Receive(response)
	if err != nil {
		if retryCnt >= 0 {
			time.Sleep(5 * time.Millisecond)
			retryCnt--
			goto retry2
		}
		log.Fatal(err)
	}

	os.Exit(response.Status)
}
