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

  output.clear();
  ftp.send_pwd_req(&mut output);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "PWD\n");
  ftp.feed("257 \"/\" is the current directory\n".as_bytes());
  assert_eq!(ftp.advance().is_none(), true);
  assert_eq!(ftp.get_wd(), "/");

  output.clear();
  ftp.send_type_req(&mut output, &DataMode::Binary);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "TYPE I\n");
  ftp.feed("200 Switching to Binary mode.\n".as_bytes());
/*
  check that data transpher mode is binary
*/

}
