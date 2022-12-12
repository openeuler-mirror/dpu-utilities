package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"
	"golang.org/x/sys/unix"
)

const (
	rexecPidDir = "/var/run/rexec/pids"
	role = "client"
)

var pidPath string
var pidFile *os.File

func newPidFile(pid int, lpid int) error {
	err := os.MkdirAll(rexecPidDir, 0700)
	if err != nil {
		return err
	}
	pidPath = filepath.Join(rexecPidDir, strconv.Itoa(lpid))

	pidFile = nil
	// create pid file and write remote pid into it
	pidFile, err = os.OpenFile(pidPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("failed to open %s with %s", pidPath, err)
		return err
	}
	_, err = pidFile.WriteString(strconv.Itoa(pid))
	if err != nil {
		os.RemoveAll(pidPath)
		return err
	}
	log.Printf("new pid file(%d), with pid(%d)\n", lpid, pid)
	// Flock it to mark it inuse
	syscall.Flock(int(pidFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)

	return nil
}

func removePidFile() {
	if pidFile != nil {
		syscall.Flock(int(pidFile.Fd()), syscall.LOCK_UN)
		pidFile.Close()
	}

	os.RemoveAll(pidPath)
}

func cleanRedundantPidFile() {
	filepath.Walk(rexecPidDir, func(path string, info os.FileInfo, err error) error {
		f, err := os.Open(path)
		if err != nil {
			// open failed, just skip
			return err
		}
		// Flock it to check if it's locked
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			// file locked, just skip
			return nil
		}
		// file unlocked, it's redundant, just remove it
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		os.RemoveAll(path)

		return nil
	})
}

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

func SetParentDeathSignal(sig uintptr) error {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, sig, 0, 0, 0); err != nil {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: <command> [<arg> ]")
	}

	var client net.Conn
	var err error

	go sigHandler()

	if err := SetParentDeathSignal(uintptr(syscall.SIGHUP)); err != nil {
		log.Printf("Failed to set Parent Death Signal:%s", err.Error())
	}
	na, err := parseNetAddr(role)
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
	cleanRedundantPidFile()

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
		Env:        append([]string{}, os.Environ()...),
		StatusChan: remoteSender,
	}

	err = sender.Send(command)
	if err != nil {
		log.Fatal(err)
	}

	retryCnt := 3
	// 1. get pid from response
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
	if (response.WhiteList == 0) {
		log.Fatalf("%s command in White List of rexec server\n", command.Cmd)
	}
	pid := response.Pid
	lpid := os.Getpid()
	log.Printf("create pidFile for %d:%d\n", pid, lpid)
	if err := newPidFile(pid, lpid); err != nil {
		log.Fatal("failed to create pidFile for %d:%d - %s\n", pid, lpid, err)
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
		log.Print(err)
	}

	removePidFile()
	os.Exit(response.Status)
}
