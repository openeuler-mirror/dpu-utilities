package main
import(
	"os"
	"testing"
)

func TestParseNetAddrTcp(t *testing.T) {
	var na NetAddr
	var err error

	os.Setenv("CMD_NET_ADDR", "tcp://127.0.0.1:1234")
	na, err = parseNetAddr()
	if err != nil {
		t.Fatalf("parseNetAddr tcp://127.0.0.1:1234 failed with error: %s\n", err)
	}
	
	if na.Proto != "tcp" {
		t.Fatalf("parseNetAddr tcp://127.0.0.1:1234 failed: expect proto to be tcp, get :%s\n", na.Proto) 
	}

	if na.Addr != "127.0.0.1:1234" {
		t.Fatalf("parseNetAddr tcp://127.0.0.1:1234 failed: get addr %s\n", na.Addr)
	}
}

func TestParseNetAddrUdp(t *testing.T) {
	var err error
	os.Setenv("CMD_NET_ADDR", "udp://127.0.0.1:1234")
	_, err = parseNetAddr()
	if err == nil {
		t.Fatalf("parseNetAddr udp://127.0.0.1:1234 should fail\n")
	}
}

func TestParseNetAddrUnix(t *testing.T) {
	var na NetAddr
	var err error

	os.Setenv("CMD_NET_ADDR", "unix:///tmp/test.sock")
	na, err = parseNetAddr()
	if err != nil {
		t.Fatalf("parseNetAddr unix:///tmp/test.sock failed with error: %s\n", err)
	}
	
	if na.Proto != "unix" {
		t.Fatalf("parseNetAddr unix:///tmp/test.sock failed: expect proto to be unix, get :%s\n", na.Proto) 
	}

	if na.Addr != "/tmp/test.sock" {
		t.Fatalf("parseNetAddr unix:///tmp/test.sock failed: get addr %s\n", na.Addr)
	}
}