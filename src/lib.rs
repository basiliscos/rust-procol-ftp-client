#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate bytebuffer;

use bytebuffer::ByteBuffer;
use regex::Regex;
use std::str;
use std::fmt;

pub const LOGGED_EXPECTED:u32   = 220;
pub const LOGGED_IN:u32         = 230;
pub const PASSWORD_EXPECTED:u32 = 331;

pub enum DataMode {
  Binary,
  Text
}

pub enum ConnectionMode {
  Active,
  Passive,
}


struct Context {
  dataMode: Option<DataMode>,
  connectionMode: Option<ConnectionMode>,
  working_dir: Option<String>,
}

pub enum Ftp {
  StateUndefined { buffer: ByteBuffer },
  StateLoginReady,
  StateLoggedIn { buffer: ByteBuffer },
  StatePasswordReady,
  Error,
}

pub enum FtpError {
  NotEnoughData(Ftp),
  ProtocolError(String),
}

impl fmt::Debug for FtpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ref NotEnoughData => write!(f, "no enough data"),
            // ref ProtocolError =>  unimplemented!(),
            //_ => unimplemented!(),
            //&FtpError::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}


impl Ftp {
  pub fn new() -> Self {
    Ftp::StateUndefined { buffer: ByteBuffer::new() }
  }

  pub fn feed(&mut self, data: &[u8]) {
    match self {
      &mut Ftp::StateUndefined { buffer: ref mut buffer } => buffer.write_bytes(data),
      _ => unimplemented!(),
    }
  }

  pub fn advance(mut self) -> Result<Ftp, FtpError> {
    match self {
      Ftp::StateUndefined { buffer: buffer } => {

        lazy_static! {
          static ref RE_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3}) .+$)").unwrap();
          static ref RE_PARTRIAL_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3})-.+$)").unwrap();
        }

        str::from_utf8(buffer.to_bytes().as_slice())
          .map_err(|err| FtpError::ProtocolError("gargabe".to_string()))
          .and_then(|response|
            RE_RESPONCE_CODE.captures(&response)
              .ok_or_else(||{
                if RE_PARTRIAL_RESPONCE_CODE.is_match(response) {
                  FtpError::NotEnoughData(Ftp::StateUndefined { buffer: buffer})
                } else {
                  FtpError::ProtocolError("garbage".to_string())
                }
              })
              .and_then(|captures| {
                let code_str = captures.at(1).unwrap();
                let code:u32 = code_str.parse().unwrap();
                match code {
                  LOGGED_EXPECTED   => Ok(Ftp::StateLoginReady),
                  PASSWORD_EXPECTED => Ok(Ftp::StatePasswordReady),
                  LOGGED_IN         => Ok(Ftp::StateLoggedIn { buffer: ByteBuffer::new() }),
                  _ => unimplemented!(),
                }
              })
          )
      }
      _ => unimplemented!(),
    }
  }

  pub fn send_login(self, buffer: &mut ByteBuffer, login: &str)
    -> Result<Ftp, FtpError> {
    match self {
      Ftp::StateLoginReady => {
        buffer.write_bytes("USER ".as_bytes());
        buffer.write_bytes(login.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        Ok(Ftp::StateUndefined { buffer: ByteBuffer::new() })
      },
      _ => unimplemented!(),
    }
  }

  pub fn send_password(self, buffer: &mut ByteBuffer, pass: &str)
    -> Result<Ftp, FtpError> {
    match self {
      Ftp::StatePasswordReady => {
        buffer.write_bytes("PASS ".as_bytes());
        buffer.write_bytes(pass.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        Ok(Ftp::StateUndefined { buffer: ByteBuffer::new() })
      },
      _ => unimplemented!(),
    }
  }

}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
