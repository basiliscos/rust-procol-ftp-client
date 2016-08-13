extern crate protocol_ftp_client;

use std::io::prelude::*;
use std::net::TcpStream;

use protocol_ftp_client::*;

fn get_reply(stream:&mut TcpStream, rx_buff: &mut [u8], receiver: FtpReceiver) -> FtpTransmitter {
  let mut opt_transmitter = None;
  let mut opt_receiver = Some(receiver);
  let mut total_size = 0;
  while opt_receiver.is_some() {
    let sz = stream.read(rx_buff).unwrap();
    total_size = total_size + sz;
    let ftp_receiver = opt_receiver.take().unwrap();
    match ftp_receiver.try_advance(&rx_buff[0 .. total_size]) {
      Ok(transmitter) => { opt_transmitter = Some(transmitter) }
      Err(receiver)   => { opt_receiver = Some(receiver) }
    }
  }
  opt_transmitter.unwrap()
}

fn main() {
  println!("starting...");

  let mut tx_buff:[u8; 1024] = [0; 1024];
  let mut tx_count = 0;
  let mut rx_buff:[u8; 1024] = [0; 1024];

  let mut stream = TcpStream::connect("ftp0.ydx.freebsd.org:21").unwrap();
  let mut ftp_receiver = FtpReceiver::new();

  let mut transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  println!("connected...");

  ftp_receiver = transmitter.send_login(&mut tx_buff, &mut tx_count, "anonymous");
  let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();
  println!("login sent...");

  transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  println!("expecting password...");

  ftp_receiver = transmitter.send_password(&mut tx_buff, &mut tx_count, "anonymous@nowhere.com");
  let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();
  println!("password sent...");

  transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  println!("logged in...");

  ftp_receiver = transmitter.send_system_req(&mut tx_buff, &mut tx_count);
  let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();
  transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  {
    let (system, subtype) = transmitter.get_system().clone();
    println!("remote system {} / {}", system, subtype);
  }

  ftp_receiver = transmitter.send_pwd_req(&mut tx_buff, &mut tx_count);
  let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();
  transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  println!("remote directory is {}", transmitter.get_wd());

  let mut data_stream = {
    ftp_receiver = transmitter.send_pasv_req(&mut tx_buff, &mut tx_count);
    let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();
    transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
    let (addr, port) = transmitter.take_endpoint().clone();
    println!("confirmed passive connection on {}:{}", addr, port);
    TcpStream::connect((addr, port)).unwrap()
  };
  println!("passive connection opened");

  ftp_receiver = transmitter.send_list_req(&mut tx_buff, &mut tx_count);
  let _ = stream.write_all(&tx_buff[0 .. tx_count]).unwrap();

  let mut data_in = Vec::with_capacity(1024 * 10);
  let _ = data_stream.read_to_end(&mut data_in);
  transmitter = get_reply(&mut stream, &mut rx_buff, ftp_receiver);
  println!("got remote list");
  for remote_file in transmitter.parse_list(data_in.as_slice()).unwrap() {
    println!("file: {}  / {}", remote_file.name, remote_file.size);
  }
}
