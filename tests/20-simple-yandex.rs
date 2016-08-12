extern crate protocol_ftp_client;
extern crate bytebuffer;

use protocol_ftp_client::*;
use bytebuffer::ByteBuffer;
use std::str;
use std::net::Ipv4Addr;

// 0d0a

#[test]
fn session_sample() {
  let mut output = ByteBuffer::new();
  let mut ftp_reciver = FtpReceiver::new();
  ftp_reciver.feed("220 This is ftp0.ydx.freebsd.org - hosted at Yandex.\r\n".as_bytes());

  ftp_reciver = ftp_reciver.try_advance().ok().unwrap().send_login(&mut output, "anonymous");
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "USER anonymous\r\n");

  output.clear();
  ftp_reciver.feed("331 Please specify the password.\r\n".as_bytes());
  ftp_reciver = ftp_reciver.try_advance().ok().unwrap().send_password(&mut output, "anonymous@nowhere.com");
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "PASS anonymous@nowhere.com\r\n");

  output.clear();
  ftp_reciver.feed("230-\r\n".as_bytes());
  ftp_reciver.feed("230-This is ftp0.ydx.FreeBSD.org, graciously hosted by Yandex.\r\n".as_bytes());
  ftp_reciver.feed("230-\r\n".as_bytes());
  ftp_reciver.feed("230-FreeBSD files can be found in the /pub/FreeBSD directory.\r\n".as_bytes());
  ftp_reciver.feed("230-\r\n".as_bytes());
  ftp_reciver.feed("230 Login successful.\r\n".as_bytes());
  let mut ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();

  output.clear();
  ftp_reciver = ftp_transmitter.send_pwd_req(&mut output);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "PWD\r\n");
  ftp_reciver.feed("257 \"/\" is the current directory\r\n".as_bytes());
  ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();
  assert_eq!(ftp_transmitter.get_wd(), "/");

  output.clear();
  ftp_reciver = ftp_transmitter.send_type_req(&mut output, DataMode::Binary);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "TYPE I\r\n");
  ftp_reciver.feed("200 Switching to Binary mode.\r\n".as_bytes());
  ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();
  assert_eq!(ftp_transmitter.get_type(), &DataMode::Binary);

  output.clear();
  ftp_reciver = ftp_transmitter.send_system_req(&mut output);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "SYST\r\n");
  ftp_reciver.feed("215 UNIX Type: L8\r\n".as_bytes());
  ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();
  assert_eq!(ftp_transmitter.get_system(), (&"UNIX".to_string(), &"L8".to_string()));

  output.clear();
  ftp_reciver = ftp_transmitter.send_pasv_req(&mut output);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "PASV\r\n");
  ftp_reciver.feed("227 Entering Passive Mode (77,88,40,106,195,70).\r\n".as_bytes());
  ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();

  assert_eq!(ftp_transmitter.take_endpoint(), (Ipv4Addr::new(77, 88, 40, 106), 49990));

  output.clear();
  ftp_reciver = ftp_transmitter.send_list_req(&mut output);
  assert_eq!(str::from_utf8(output.to_bytes().as_slice()).unwrap(), "LIST -l\r\n");

  let listing = "-rw-r--r--    1 ftp      ftp          5430 Jul 19  2014 favicon.ico\r
-rw-r--r--    1 ftp      ftp           660 Nov 02  2015 index.html\r
drwxr-xr-x    3 ftp      ftp             3 Jul 19  2014 pub\r\n";

  ftp_reciver.feed("150 Here comes the directory listing.\r\n".as_bytes());
  ftp_reciver.feed_data(listing.as_bytes());
  ftp_reciver.feed("226 Directory send OK.\r\n".as_bytes());

  ftp_transmitter = ftp_reciver.try_advance().ok().unwrap();
  let list = ftp_transmitter.take_list().unwrap();
  assert_eq!(list.len(), 3);
  assert_eq!(list[0], RemoteFile { kind: RemoteFileKind::File, size: 5430,  name: "favicon.ico".to_string() } );
  assert_eq!(list[1], RemoteFile { kind: RemoteFileKind::File, size: 660,  name: "index.html".to_string() } );
  assert_eq!(list[2], RemoteFile { kind: RemoteFileKind::Directory, size: 3,  name: "pub".to_string() } );

}
