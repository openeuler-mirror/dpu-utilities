ccflags-y += -I$(src)/../ -I$(src) -DQTFS_CLIENT
KBUILD=/lib/modules/5.10*/build/

obj-m:=qtfs.o
qtfs-objs:=qtfs-mod.o sb.o syscall.o ../conn.o xattr.o proc.o ../misc.o miss.o

all: qtfs

qtfs:
	make -C $(KBUILD) M=$(PWD) modules

clean:
	make -C $(KBUILD) M=$(PWD) clean
	rm -rf ../*.o
