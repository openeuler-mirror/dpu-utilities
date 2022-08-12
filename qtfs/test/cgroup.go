package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
	"strconv"
)

func do_watch(dir, prefix string) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Printf("read cgroup dir(%s) failed: %s\n", dir, err.Error())
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			entryPath := path.Join(dir, entry.Name())
			prefix = prefix + "   "
			do_watch(entryPath, prefix)
		} else {
			filePath := path.Join(dir, entry.Name())
			file, err := os.Open(filePath)
			if err == nil {
				file.Close()
			}
		}
	}
}

func watch(dir, prefix string, wg *sync.WaitGroup) {
	do_watch(dir, prefix)
	wg.Done()
}

func main() {
	var wg sync.WaitGroup
	begin := time.Now()
	threads, _ := strconv.Atoi(os.Args[2])
	fmt.Printf("watch %s\n", os.Args[1])
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go watch(os.Args[1], "", &wg)
		fmt.Printf("Thread run %d\n", i)
	}
	wg.Wait()
	dlt := time.Since(begin)
	fmt.Printf("All thread over, %d threads cost time:%v\n", threads, dlt)
}
