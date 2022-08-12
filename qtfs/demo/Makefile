CFLAGS=-g -O2

all: cfifo_r cfifo_w

cfifo_r: cfifo_r.c
	gcc $(CFLAGS) -o $@ $^

cfifo_w: cfifo_w.c
	gcc $(CFLAGS) -o $@ $^

clean:
	@rm -f *.o cfifo_r cfifo_w
