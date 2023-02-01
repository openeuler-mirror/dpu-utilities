package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const FdPath = "/var/run/rexec/fds/"

type FileInfo struct {
	Fd     int
	Path   string
	Perm   int
	Offset int
}

type Files struct {
	Files []FileInfo
}

var defaultLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randString(n int) string {
	b := make([]rune, n)
	letterLen := len(defaultLetters)

	for i := range b {
		b[i] = defaultLetters[rand.Intn(letterLen)]
	}

	return string(b)
}

func getPosAndFlags(path string) (int, int, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("failed to read file(%s):%s", path, err.Error())
		return 0, 0, err
	}
	var pos, flags int
	fmt.Sscanf(string(content), "pos:%d\nflags:%o", &pos, &flags)
	return pos, flags, nil
}

func checkpointFileInfo(fdMaps map[int]FileInfo) {
	procPath := "/proc/self"
	fdPath := procPath + "/fd/"
	fdinfoPath := procPath + "/fdinfo/"

	filepath.Walk(fdPath, func(path string, fi os.FileInfo, err error) error {
		if fi == nil || err != nil {
			log.Printf("path %s failed with %s\n", path, err.Error())
			return nil
		}
		fdstr := strings.TrimPrefix(path, fdPath)
		if fdstr == "" {
			return nil
		}
		fd, err := strconv.Atoi(fdstr)
		if err != nil {
			log.Printf("convert fd string(%s) to int failed: %s\n", fdstr, err.Error())
			return nil
		}

		linkPath, err := os.Readlink(path)
		if err != nil {
			log.Printf("readlink (%s) failed with: %s\n", path, err.Error())
			return nil
		}
		// skip stdin/stdout/stderr or non-regular files
		if fd < 3 || !strings.HasPrefix(linkPath, "/") {
			return nil
		}

		pos, flags, err := getPosAndFlags(fdinfoPath + fdstr)
		if err != nil {
			return nil
		}
		fdMaps[fd] = FileInfo{
			Fd:     fd,
			Path:   linkPath,
			Perm:   flags,
			Offset: pos,
		}
		return nil
	})
}

func restoreFileInfo(cmd string, fdMaps map[int]FileInfo) string {
	var fds []int
	var fs Files

	for fd := range fdMaps {
		fds = append(fds, fd)
	}

	sort.Ints(fds)
	fs.Files = []FileInfo{}
	for _, fd := range fds {
		fs.Files = append(fs.Files, fdMaps[fd])
	}
	js, err := json.Marshal(fs)
	if err != nil {
		return ""
	}
	os.MkdirAll(FdPath, os.ModePerm)
	_, cmdName := filepath.Split(cmd)
	fName := FdPath + cmdName + "-" + randString(20) + ".json"
	if err := ioutil.WriteFile(fName, js, 0640); err != nil {
		log.Printf("write %s faild with error: %s\n", fName, err.Error())
		return ""
	}
	return fName
}
