extern crate protocol_ftp_client;
extern crate bytebuffer;

use std::io::prelude::*;
use std::net::TcpStream;

use protocol_ftp_client::*;
use bytebuffer::ByteBuffer;

fn get_reply(stream:&mut TcpStream, input_buff: &mut [u8], receiver: FtpReceiver) -> FtpTransmitter {
  let mut opt_transmitter = None;
  let mut opt_receiver = Some(receiver);
  while opt_receiver.is_some() {
    let sz = stream.read(input_buff).unwrap();
    let mut ftp_receiver = opt_receiver.take().unwrap();
    ftp_receiver.feed(&input_buff[0 .. sz]);
    match ftp_receiver.try_advance() {
      Ok(transmitter) => { opt_transmitter = Some(transmitter) }
      Err(receiver)   => { opt_receiver = Some(receiver) }
    }
  }
  opt_transmitter.unwrap()
}

/*
fn send_req(stream:&mut TcpStream, output: &mut ByteBuffer, mut opt_transmitter: Option<FtpTransmitter>) -> Option<FtpReceiver> {
  write_all
}
*/

fn main() {
  println!("starting...");

  let mut output = ByteBuffer::new();
  let mut input_buff:[u8; 1024] = [0; 1024];

  let mut stream = TcpStream::connect("ftp0.ydx.freebsd.org:21").unwrap();
  let mut ftp_receiver = FtpReceiver::new();

  let mut transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  println!("connected...");

  output.clear();
  ftp_receiver = transmitter.send_login(&mut output, "anonymous");
  let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();
  println!("login sent...");

  transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  println!("expecting password...");

  output.clear();
  ftp_receiver = transmitter.send_password(&mut output, "anonymous@nowhere.com");
  let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();
  println!("password sent...");

  transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  println!("logged in...");

  output.clear();
  ftp_receiver = transmitter.send_system_req(&mut output);
  let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();
  transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  {
    let (system, subtype) = transmitter.get_system().clone();
    println!("remote system {} / {}", system, subtype);
  }

  output.clear();
  ftp_receiver = transmitter.send_pwd_req(&mut output);
  let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();
  transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  println!("remote directory is {}", transmitter.get_wd());

  output.clear();
  let mut data_stream = {
    ftp_receiver = transmitter.send_pasv_req(&mut output);
    let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();
    transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
    let (addr, port) = transmitter.take_endpoint().clone();
    println!("confirmed passive connection on {}:{}", addr, port);
    TcpStream::connect((addr, port)).unwrap()
  };
  println!("passive connection opened");

  output.clear();
  ftp_receiver = transmitter.send_list_req(&mut output);
  let _ = stream.write_all(output.to_bytes().as_slice()).unwrap();

  let mut data_in = Vec::with_capacity(1024 * 10);
  let _ = data_stream.read_to_end(&mut data_in);
  transmitter = get_reply(&mut stream, &mut input_buff, ftp_receiver);
  println!("got remote list");
  for remote_file in transmitter.parse_list(data_in.as_slice()).unwrap() {
    println!("file: {}  / {}", remote_file.name, remote_file.size);
  }

}
