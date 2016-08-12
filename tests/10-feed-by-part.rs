extern crate protocol_ftp_client;
extern crate bytebuffer;

use protocol_ftp_client::*;
use bytebuffer::ByteBuffer;
use std::str;
use std::net::Ipv4Addr;

#[test]
fn simple_advance() {
  let mut output = ByteBuffer::new();
  let mut ftp_reciver = FtpReceiver::new();
  ftp_reciver.feed("220-Hi\r\n".as_bytes());
  ftp_reciver = ftp_reciver.try_advance().err().unwrap();
  ftp_reciver.feed("220 Sample banner comes\r\n".as_bytes());
  ftp_reciver.try_advance().ok().unwrap();
}

#[test]
fn cycled_advance() {
  let mut output = ByteBuffer::new();
  let lines = vec![
    "220-Hi\r\n",
    "220-Second banner line\r\n",
    "220-3rd banner line\r\n",
    "220 The last banner line\r\n",
  ];

  let mut recv_opt = Some(FtpReceiver::new());
  let mut trans_opt = None;
  let mut idx = 0;


  while recv_opt.is_some() {
    let line = lines[idx];
    idx = idx + 1;
    let mut ftp_reciver = recv_opt.take().unwrap();
    ftp_reciver.feed(line.as_bytes());
    match ftp_reciver.try_advance() {
      Err(ftp_reciver) => { recv_opt = Some(ftp_reciver); },
      Ok(ftp_transiver) => { trans_opt = Some(ftp_transiver); },
    }
  }

  assert_eq!(trans_opt.is_some(), true);
}
