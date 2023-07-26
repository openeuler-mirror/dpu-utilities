/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * qtfs licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Liqiang
 * Create: 2023-07-26
 * Description: 
 *******************************************************************************/

use std::env;
use std::net::TcpListener;
use tokio::net::TcpListener as AsyncTcpListener;
use tokio::runtime::Builder;

mod cofifo;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        let bin: String = args[0].trim().parse().expect("Binary name error");
        println!("Usage example:");
        println!("  {} 192.168.1.10:12310 10", bin);
        return;
    }
    let addr: String = args[1].trim().parse().expect("Input address: '192.168.1.10:12310'");
    let max_block_threads: usize = args[2].trim().parse().expect("Input max blocking threads number in arg 2: like '10'");
    let listener = TcpListener::bind(addr.clone()).unwrap();
    let async_listener = AsyncTcpListener::from_std(listener).unwrap();
    let runtime = Builder::new_multi_thread()
                            .max_blocking_threads(max_block_threads)
                            .enable_all()
                            .build()
                            .unwrap();
    
    println!("Ready to listen addr:{}, max blocking threads:{}", addr, max_block_threads);

    let mut coroutine_idx: usize = 1;
    loop {
        let (s, _) = async_listener.accept().await.unwrap();
        let cur_idx = coroutine_idx.clone();
        coroutine_idx += 1;
        match Some(s) {
            Some(stream) => {
                // 收到一个新的fifo连接请求，拉起新的协程处理函数
                runtime.spawn(cofifo::qtfs_fifo_server(stream, cur_idx));
            }
            _ => {
                eprintln!("Accept error!");
            }
        }
    }
}