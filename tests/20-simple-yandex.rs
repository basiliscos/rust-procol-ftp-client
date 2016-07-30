extern crate protocol_ftp_client;
extern crate bytebuffer;

use protocol_ftp_client::*;
use bytebuffer::ByteBuffer;
use std::str;

#[test]
fn session_sample() {
  let mut output = ByteBuffer::new();
  let mut ftp = Ftp::new();
  ftp.feed("220 This is ftp0.ydx.freebsd.org - hosted at Yandex.\n".as_bytes());
  assert_eq!(ftp.advance().is_none(), true);

  ftp.send_login(&mut output, "anonymous");
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "USER anonymous\n");

  output.clear();
  ftp.feed("331 Please specify the password.\n".as_bytes());
  assert_eq!(ftp.advance().is_none(), true);
  ftp.send_password(&mut output, "anonymous@nowhere.com");
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "PASS anonymous@nowhere.com\n");


  output.clear();
  ftp.feed("230-\n".as_bytes());
  ftp.feed("230-This is ftp0.ydx.FreeBSD.org, graciously hosted by Yandex.\n".as_bytes());
  ftp.feed("230-\n".as_bytes());
  ftp.feed("230-FreeBSD files can be found in the /pub/FreeBSD directory.".as_bytes());
  ftp.feed("230-\n".as_bytes());
  ftp.feed("230 Login successful.\n".as_bytes());
  assert_eq!(ftp.advance().is_none(), true);
}
