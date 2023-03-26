# 编译：
```bash
make clean
make
```

# 测试步骤：
1. 在server上运行
```bash
cd /home
tar xzvf scmright_test.tar.gz
cd scmright_test
make clean;make
LD_LIBRARY_PATH=. ./server scm.sock
```

2. 在client上运行
```bash
cd /home
tar xzvf scmright_test.tar.gz
cd scmright_test
make clean;make
LD_PRELOAD=/usr/lib64/libudsproxy.so LD_LIBRARY_PATH=. ./client scm.sock test.log
or
LD_PRELOAD=/usr/lib64/libudsproxy.so LD_LIBRARY_PATH=. ./client scm.sock
```

3. 往client端发送消息进行测试
```bash
Input message to send:1234
Input message to send:abcd
Input message to send:quit
input quit will exit client and server
```

4. 确认server是否接收到消息或确认test.log是否写入
```bash
cat test.log | grep 1234
```