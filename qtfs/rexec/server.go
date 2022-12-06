package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/docker/libchan/spdy"
)

const (
	role = "server"
)

func getHost(addr string) string {
	return strings.Split(addr, ":")[0]
}

func main() {
	cert := os.Getenv("TLS_CERT")
	key := os.Getenv("TLS_KEY")

	var listener net.Listener
	na, err := parseNetAddr(role)
	if err != nil {
		log.Fatal(err)
	}
	if cert != "" && key != "" {
		tlsCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{tlsCert},
		}

		listener, err = tls.Listen("tcp", na.Addr, tlsConfig)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		listener, err = net.Listen(na.Proto, na.Addr)
		if err != nil {
			log.Fatal(err)
		}
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			log.Print(err)
			break
		}
		p, err := spdy.NewSpdyStreamProvider(c, true)
		if err != nil {
			log.Print(err)
			break
		}
		t := spdy.NewTransport(p)

		go func() {
			switch t.(type) {
			case *spdy.Transport:
				ts, ok := t.(*spdy.Transport)
				if ok {
					defer ts.Close()
				}
			default:
				log.Print("Error occurred during transport type assertion")
			}

			receiver, err := t.WaitReceiveChannel()
			if err != nil {
				log.Print(err)
				return
			}

			command := &RemoteCommand{}
			err = receiver.Receive(command)
			if err != nil {
				log.Print(err)
				return
			}
			log.Printf("cmd(%s), args(%v)\n", command.Cmd, command.Args)

			cmd := exec.Command(command.Cmd, command.Args...)
			cmd.Stdout = command.Stdout
			cmd.Stderr = command.Stderr
			cmd.Env = append([]string{}, command.Env...)

			stdin, err := cmd.StdinPipe()
			if err != nil {
				log.Print(err)
				return
			}
			go func() {
				io.Copy(stdin, command.Stdin)
				stdin.Close()
			}()

			defer command.Stdout.Close()
			defer command.Stderr.Close()

			returnResult := &CommandResponse{}
			err = cmd.Start()
			if err != nil {
				// send return status back
				log.Printf("cmd start failed with err:%s, cmdline:%s %v\n", err.Error(), command.Cmd, command.Args)
				returnResult.Status = 10
				err = command.StatusChan.Send(returnResult)
				if err != nil {
					log.Print(err)
				}
				return
			}

			// send pid back to client here
			returnResult.Pid = cmd.Process.Pid
			returnResult.Status = 0
			err = command.StatusChan.Send(returnResult)
			if err != nil {
				log.Print(err)
				if err = cmd.Process.Kill(); err != nil {
					fmt.Println("Error when kill process")
				}
				return
			}
			log.Printf("create process with pid:%d\n", cmd.Process.Pid)

			rch := make(chan error)
			cch := make(chan error)

			go func(c chan error) {
				// check if other end is alive
				tmpCommand := &RemoteCommand{}
				c <- receiver.Receive(tmpCommand)
				// double check
				time.Sleep(1 * time.Millisecond)
				c <- receiver.Receive(tmpCommand)
			}(rch)

			go func(c chan error) {
				// check if command exit
				c <- cmd.Wait()
			}(cch)

			var res error
			select {
			case <-rch:
				log.Printf("stream closed, kill process:%d\n", cmd.Process.Pid)
				if err = cmd.Process.Kill(); err != nil {
					fmt.Println("Error when kill process: %d\n", cmd.Process.Pid)
				}
				return
			case res = <-cch:
				log.Printf("Command exit normmally:%d\n", cmd.Process.Pid)
			}
			if res != nil {
				if exiterr, ok := res.(*exec.ExitError); ok {
					returnResult.Status = exiterr.Sys().(syscall.WaitStatus).ExitStatus()
				} else {
					log.Print(res)
					returnResult.Status = 10
				}
			}

			err = command.StatusChan.Send(returnResult)
			if err != nil {
				log.Print(err)
			}
		}()
	}
}
