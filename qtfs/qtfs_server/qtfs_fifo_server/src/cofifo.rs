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

use tokio::net::TcpStream;
use std::net::TcpStream as StdTcpStream;
use std::mem;
use tokio::fs::File;
use tokio::fs;
use std::os::unix::fs::FileTypeExt;
use tokio::fs::OpenOptions;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
#[repr(C, packed)]
struct Qtreq {
    // magic: [u8; 4], //magic: 0x5aa55aa5
    msgtype: u32,
    error: u32,
    len: usize,
}

async fn qtfs_req_head(mut stream: TcpStream, _idx: usize) -> Qtreq {
    const HEADSIZE: usize = mem::size_of::<Qtreq>();
    
    let mut msghead = [0; HEADSIZE];
    let _ = stream.read_exact(&mut msghead).await;
    let head = Qtreq {
        msgtype: u32::from_le_bytes(msghead[0..4].try_into().unwrap()),
        error: u32::from_le_bytes(msghead[4..8].try_into().unwrap()),
        len: usize::from_le_bytes(msghead[8..8+mem::size_of::<usize>()].try_into().unwrap()),
    };
    println!("Recv new head:{:?}", head);
    head
}

pub async fn qtfs_fifo_server(stream: TcpStream, idx: usize) {
    const QTFS_REQ_OPEN: u32 = 2;
    const QTFS_REQ_CLOSE: u32 = 3;
    const QTFS_REQ_READ: u32 = 5;
    const QTFS_REQ_WRITE: u32 = 6;

    let stdstream: StdTcpStream = stream.into_std().unwrap();
    let s1 = stdstream.try_clone().unwrap();
    let s2 = stdstream.try_clone().unwrap();
    let s3 = stdstream.try_clone().unwrap();

    let s1 = TcpStream::from_std(s1).unwrap();
    let s2 = TcpStream::from_std(s2).unwrap();
    let s3 = TcpStream::from_std(s3).unwrap();

    //stdstream is still alive

    let mut conn = Conn {stream: s1};
    conn.package_sync().await;

    let head: Qtreq = qtfs_req_head(s2, idx.clone()).await;
    if head.msgtype != QTFS_REQ_OPEN {
        println!("first msg type is invalid");
        return;
    }
    let file = match qtfs_fifo_open(s3, head).await {
        Ok(f) => {
            conn.open_ack(0).await;
            f
        }
        Err(e) => {
            println!("Open fifo error:{}", e);
            conn.open_ack(1).await;
            return;
        }
    };

    'main: loop {
        conn.package_sync().await;
        let s1 = stdstream.try_clone().unwrap();
        let s2 = stdstream.try_clone().unwrap();
        let s1 = TcpStream::from_std(s1).unwrap();
        let s2 = TcpStream::from_std(s2).unwrap();

        let head: Qtreq = qtfs_req_head(s1, idx.clone()).await;
        match head.msgtype {
            QTFS_REQ_OPEN => {
                println!("Fifo is opened and recv open request again!");
                conn.open_ack(1).await;
            }
            QTFS_REQ_CLOSE => {
                println!("Close req idx:{}", idx.clone());
                conn.close_ack().await;
                break 'main;
            }
            QTFS_REQ_READ => {
                println!("Read req idx:{}", idx.clone());
                qtfs_fifo_read(s2, file.try_clone().await.unwrap()).await;
            }
            QTFS_REQ_WRITE => {
                println!("Write req idx:{}", idx.clone());
                qtfs_fifo_write(s2, file.try_clone().await.unwrap()).await;
            }
            _ => {
                println!("Recv invalid msg type");
            }
        }
    }
}

#[repr(C, packed)]
struct Qtrspopen {
    ret: i32,
}
async fn qtfs_fifo_open(mut stream: TcpStream, head: Qtreq) -> Result<File, i32> {
    if head.len >= 4096 {
        println!("qtfs fifo len invalid");
        return Err(1);
    }

    let mut path = Vec::with_capacity(head.len);
    path.resize(head.len, 0);
    stream.read_exact(&mut path).await.unwrap();

    let getstr = String::from_utf8(path).unwrap();
    let pathstr = getstr.trim_end_matches('\0').trim();
    match fs::metadata(pathstr.clone()).await {
        Ok(meta) => {
            if meta.file_type().is_fifo() == false {
                println!("Requst path:{} not fifo!", pathstr);
                return Err(1);
            }
        }
        Err(_) => {
            println!("path:{} check failed.", pathstr);
            return Err(1);
        }
    };
    println!("Recv open path:{}", pathstr);
    let file = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(pathstr).await.unwrap();
    
    Ok(file)
}

#[repr(C, packed)]
struct Qtreqread {
    len: u64,
}

#[repr(C, packed)]
struct Qtrspread {
    ret: i32,
    errno: i32,
    len: u64,
}


async fn qtfs_fifo_read(mut stream: TcpStream, mut file: File) {
    let mut head = [0; mem::size_of::<Qtreqread>()];
    stream.read_exact(&mut head).await.unwrap();
    let req = Qtreqread {
        len: u64::from_le_bytes(head[0..8].try_into().unwrap()),
    };
    let len = std::cmp::min(req.len, 4096);

    let mut rsp = Qtrspread {
        ret: 0,
        errno: 0,
        len: 0,
    };

    let mut buf = Vec::with_capacity(len.try_into().unwrap());
    buf.resize(len.try_into().unwrap(), 0);
    
    match file.read(&mut buf).await {
        Ok(n) => {
            rsp.len = n as u64;
            let send = unsafe {
                let ptr = &rsp as *const Qtrspread as *const u8;
                std::slice::from_raw_parts(ptr, mem::size_of::<Qtrspread>())
            };
            stream.write_all(&send[..mem::size_of::<Qtrspread>()]).await.unwrap();
            let _ = stream.write_all(&buf[..n]).await.unwrap();
        }
        Err(e) => {
            rsp.errno = -1;
            rsp.ret = 1;
            rsp.len = 0;
            let send = unsafe {
                let ptr = &rsp as *const Qtrspread as *const u8;
                std::slice::from_raw_parts(ptr, mem::size_of::<Qtrspread>())
            };
            stream.write_all(&send[..mem::size_of::<Qtrspread>()]).await.unwrap();
            println!("Read from fifo error:{}", e);
        }
    }
}

#[repr(C, packed)]
struct Qtreqwrite {
    len: u64,
}
#[repr(C, packed)]
struct Qtrspwrite {
    ret: i32,
    errno: i32,
    len: u64,
}
async fn qtfs_fifo_write(mut stream: TcpStream, mut file: File) {
    let mut whead = [0; mem::size_of::<Qtreqwrite>()];
    stream.read_exact(&mut whead).await.unwrap();
    let len = u64::from_le_bytes(whead[0..8].try_into().unwrap());

    // 最大接收一次性写入4k
    let len = std::cmp::min(len, 4096);

    let mut rsp = Qtrspwrite {
        ret: 0,
        errno: 0,
        len: 0,
    };
    println!("Qtfs fifo write len:{}", len);
    let stdstream: StdTcpStream = stream.into_std().unwrap();
    let s = stdstream.try_clone().unwrap();
    let mut stream = TcpStream::from_std(stdstream).unwrap();
    let s = TcpStream::from_std(s).unwrap();
    let mut conn = Conn {stream: s};

    let mut buf = Vec::with_capacity(len.try_into().unwrap());
    buf.resize(len.try_into().unwrap(), 0);
    stream.read_exact(&mut buf).await.unwrap();

    match file.write_all(&mut buf[..len as usize]).await {
        Ok(_) => {
            rsp.len = len as u64;
            conn.write_ack(rsp).await;
        }
        Err(e) => {
            rsp.len = 0;
            conn.write_ack(rsp).await;
            println!("Write failed {}.", e);
        }
    }
}

#[repr(C, packed)]
struct Qtrspclose {
    ret: i32,
}

struct Conn {
    stream: TcpStream,
}

impl Conn {
    // sync head magic bytes sequence: 0x5a 0xa5 0x5a 0xa5
    // 逐字节读取magic，连续匹配的四个字节即视为同步包头
    async fn package_sync(&mut self) {
        let mut byte: [u8; 1] = [0; 1];
        loop {
            self.stream.read_exact(&mut byte).await.unwrap();
            if byte[0] != 0x5a {continue;}
            self.stream.read_exact(&mut byte).await.unwrap();
            if byte[0] != 0xa5 {continue;}
            self.stream.read_exact(&mut byte).await.unwrap();
            if byte[0] != 0x5a {continue;}
            self.stream.read_exact(&mut byte).await.unwrap();
            if byte[0] != 0xa5 {continue;}
            break;
        }
    }

    async fn open_ack(&mut self, retcode: i32) {
        let rsp = Qtrspopen {ret: retcode,};
        let send = unsafe {
            let ptr = &rsp as *const Qtrspopen as *const u8;
            std::slice::from_raw_parts(ptr, mem::size_of::<Qtrspopen>())
        };
        self.stream.write_all(&send[..mem::size_of::<Qtrspopen>()]).await.expect("Response open failed");
    }

    async fn close_ack(&mut self) {
        let rsp = Qtrspclose {ret: 0};
        let send = unsafe {
            let ptr = &rsp as *const Qtrspclose as *const u8;
            std::slice::from_raw_parts(ptr, mem::size_of::<Qtrspclose>())
        };
        self.stream.write_all(&send[..mem::size_of::<Qtrspclose>()]).await.expect("Response close failed");
    }

    async fn write_ack(&mut self, rsp: Qtrspwrite) {
        let send = unsafe {
            let ptr = &rsp as *const Qtrspwrite as *const u8;
            std::slice::from_raw_parts(ptr, mem::size_of::<Qtrspwrite>())
        };
        self.stream.write_all(&send[..mem::size_of::<Qtrspwrite>()]).await.expect("Response write failed");
    }
}