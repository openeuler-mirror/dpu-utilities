#!/bin/bash

# 检查参数
if [ $# -ne 2 ]; then
    echo "Usage: $0 <thread_count> <path>"
    echo "      thread_count: how many test thread to create."
    echo "      path: qtfs path, script will create fifo in this path and test."
    exit 1
fi

# 保存参数
thread_count=$1
path=$2

# 创建fifo文件
for i in $(seq 1 $thread_count); do
    mkfifo "$path/test_fifo_block_$i"
done

# 启动线程
for i in $(seq 1 $thread_count); do
    (
        # 读取fifo文件
        read line < "$path/test_fifo_block_$i"
        echo "Thread $i read fifo: $line"
        # 删除fifo文件
        rm "$path/test_fifo_block_$i"
    ) &
done

# 等待所有线程结束
wait