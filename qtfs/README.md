# qtfs

## 介绍

qtfs是一个共享文件系统项目，可部署在host-dpu的硬件架构上，也可以部署在2台服务器之间。以客户端服务器的模式工作，使客户端能通过qtfs访问服务端的指定文件系统，就像访问本地文件系统一样。

qtfs的特性：
+ 支持挂载点传播；
+ 支持proc、sys、cgroup等特殊文件系统的共享；
+ 客户端对qtfs目录下文件的操作都被转移到服务端，文件读写可共享；
+ 支持在客户端对服务端的文件系统进行远程挂载；
+ 可以定制化处理特殊文件；
+ 支持远端fifo、unix-socket等，并且支持epoll，使客户端和服务端像本地通信一样使用这些文件；
+ 基于host-dpu架构时，底层通信方式可以支持PCIe，性能大大优于网络；
+ 内核模块形式开发，无需对内核进行侵入式修改。

## 软件架构

软件大体框架图：

![输入图片说明](doc/%20Overall_architecture_diagram.png)


## 安装教程

目录说明：
+ **ipc**: 跨主机unix domain socket协同组件，在该目录下编译udsproxyd二进制和libudsproxy.so库。
+ **qtfs**: 客户端内核模块相关代码，直接在该目录下编译客户端ko。
+ **qtfs_server**: 服务端内核模块相关代码，直接在该目录下编译服务端ko和相关程序。
+ **qtinfo**: 诊断工具，支持查询文件系统的工作状态以及修改log级别等。
+ **demo**、**test**、**doc**: 测试程序、演示程序以及项目资料等。
+ 根目录: 是客户端与服务端都能用到的公共模块代码。

首先找两台服务器（或虚拟机）配置内核编译环境：

    1. 要求内核版本在5.10或更高版本。
    2. 安装内核开发包：yum install kernel-devel。
	3. 假设host服务器ip为192.168.10.10，dpu为192.168.10.11

服务端安装：
    
    1. cd qtfs_server
    2. make clean && make -j
    3. insmod qtfs_server.ko qtfs_server_ip=x.x.x.x qtfs_server_port=12345 qtfs_log_level=WARN
    4. 配置白名单，将qtfs/config/qtfs/whitelist文件拷贝至/etc/qtfs/下，请手动配置需要的白名单选项，至少需要配置一个Mount白名单才能启动后续服务。
    5. nohup ./engine 16 1 192.168.10.10 12121 192.168.10.11 12121 2>&1 &
    Tips: 默认的qtfs连接使用vsock方式，如果需要在两台虚拟机或服务器之间使用网络测试本项目，请在第二步make命令后加上调试选项，即make -j QTFS_TEST_MODE=1。该模式暴露网络端口，有可能造成安全隐患，请谨慎使用。

客户端安装：
    
    1. cd qtfs
    2. make clean && make -j
    3. insmod qtfs.ko qtfs_server_ip=x.x.x.x qtfs_server_port=12345 qtfs_log_level=WARN
	4. cd ../ipc/
	5. make clean && make && make install
	6. nohup udsproxyd 1 192.168.10.11 12121 192.168.10.10 12121 2>&1 &
	Tips: 默认的qtfs连接使用vsock方式，如果需要在两台虚拟机或服务器之间使用网络测试本项目，请在第二步make命令后加上调试选项，即make -j QTFS_TEST_MODE=1。该模式暴露网络端口，有可能造成安全隐患，请谨慎使用。

## 使用说明

安装完成后，客户端通过挂载把服务端的文件系统让客户端可见，例如：
    
    mount -t qtfs / /root/mnt/

客户端进入"/root/mnt"后便可查看到server端的所有文件，以及对其进行相关操作。

## 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request
