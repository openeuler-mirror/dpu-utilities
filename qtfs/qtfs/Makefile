ccflags-y += -I$(src)/../ -I$(src)/../utils/ -I$(src) -DQTFS_CLIENT
KBUILD=/lib/modules/$(shell uname -r)/build/

obj-m:=qtfs.o
qtfs-objs:=qtfs-mod.o sb.o syscall.o ../conn.o xattr.o proc.o ../misc.o miss.o ../symbol_wrapper.o ../utils/utils.o

all: qtfs

qtfs:
	make -C $(KBUILD) M=$(PWD) modules

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf ../*.o ../.*.o.cmd
