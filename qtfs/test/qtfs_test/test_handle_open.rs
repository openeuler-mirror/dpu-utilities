use std::io::{Write, Read};
use std::net::TcpStream;
use std::mem;
use std::env;

#[repr(C, packed)]
struct Qtreqopen {
	_type: u32,
	err: u32,
	seq_num: u64,
	len: usize,
	flags: u64,
	mode: u32,
	path: [u8; 4096],
}

fn main() -> std::io::Result<()> {
	let argv: Vec<String> = env::args().collect();
	let addr: String = argv[1].parse().expect("please input addr(ip:port)");
	let mut stream = TcpStream::connect(addr).unwrap();
	let mut req = Qtreqopen {
		_type: 2,
		err: 0,
		seq_num: 0,
		len: 0,
		flags: 0,
		mode: 0,
		path: [0; 4096],
	};
	if argv.len() == 3 {
		let s: String = argv[2].parse().expect("Please input path to open by arg 2");
		req.path[..s.len()].copy_from_slice(s.as_bytes());
		req.len = s.len() + 12;
	} else {
		// send an err packet
		req.path = [1; 4096];
		req.len = 4108;
	}
	let bytes = unsafe {
		let ptr = &req as *const Qtreqopen as *const u8;
		std::slice::from_raw_parts(ptr, mem::size_of::<Qtreqopen>())
	};
	stream.write_all(&bytes[..24+req.len]).expect("failed to write to socket stream");
	// recv rsp
	let mut datain: [u8; 32] = [0; 32];
	stream.read(&mut datain).unwrap();
	if datain[28] == 1 || datain[4] == 1 {
		println!("Open failed!");
	} else {
		println!("Open successed.");
	}
	Ok(())
}