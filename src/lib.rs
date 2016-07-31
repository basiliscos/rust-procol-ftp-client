#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate bytebuffer;

use bytebuffer::ByteBuffer;
use regex::Regex;
use std::str;
use std::fmt;

pub const LOGGED_EXPECTED:u32    = 220;
pub const LOGGED_IN:u32          = 230;
pub const PATHNAME_AVAILABLE:u32 = 257;
pub const PASSWORD_EXPECTED:u32  = 331;

pub enum DataMode {
  Binary,
  Text
}

pub enum ConnectionMode {
  Active,
  Passive,
}

pub enum State {
  NonAuthorized,
  LoginReady,
  LoginSent,
  PasswordReady,
  PasswordSent,
  Authorized,

  PwdSent,
  PathReceived(String),
  DataTypeSent,
}

impl fmt::Display for State {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      &State::PathReceived(ref value) => {
        write!(f, "[state: path-received({})]", value)
      }
      _ => {
        let state = match self {
          &State::NonAuthorized => "non-authorized",
          &State::LoginReady    => "login-ready",
          &State::LoginSent     => "login-sent",
          &State::PasswordReady => "password-ready",
          &State::PasswordSent  => "password-sent",
          &State::Authorized    => "authorized",
          &State::PwdSent       => "pwd-sent",
          _ => unreachable!(),
        };
        write!(f, "[state: {}]", state)
      }
    }
  }
}


pub enum FtpError {
  NotEnoughData,
  ProtocolError(String),
  GargageData,
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

pub struct Ftp {
  dataMode: Option<DataMode>,
  connectionMode: Option<ConnectionMode>,
  working_dir: Option<String>,
  buffer: ByteBuffer,
  state: State,
}




impl Ftp {
  pub fn new() -> Self {
    Ftp {
      dataMode : None,
      connectionMode: None,
      working_dir: None,
      buffer: ByteBuffer::new(),
      state: State::NonAuthorized,
    }
  }

  pub fn feed(&mut self, data: &[u8]) {
    self.buffer.write_bytes(data);
  }

  fn advance_state(prev_state: &State, bytes: &[u8]) -> Result<State, FtpError> {

    lazy_static! {
      static ref RE_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3}) (.+)$)").unwrap();
      static ref RE_PATHNAME: Regex = Regex::new("\"(.+)\"").unwrap();
      static ref RE_PARTRIAL_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3})-.+$)").unwrap();
    }

    str::from_utf8(bytes)
      .map_err(|err| FtpError::GargageData)
      .and_then(|response|
        RE_RESPONCE_CODE.captures(&response)
          .ok_or_else(||{
            if RE_PARTRIAL_RESPONCE_CODE.is_match(response) {
              FtpError::NotEnoughData
            } else {
              FtpError::GargageData
            }
          })
          .and_then(|captures| {
            let code_str = captures.at(1).unwrap();
            let code:u32 = code_str.parse().unwrap();
            match code {
              LOGGED_EXPECTED    => Ok(State::LoginReady),
              PASSWORD_EXPECTED  => Ok(State::PasswordReady),
              LOGGED_IN          => Ok(State::Authorized),
              PATHNAME_AVAILABLE => {
                let pathname_str = captures.at(2).unwrap();
                RE_PATHNAME.captures(pathname_str)
                  .ok_or(FtpError::GargageData)
                  .and_then(|path_capture|{
                    let path = path_capture.at(1).unwrap();
                    Ok(State::PathReceived(path.to_string()))
                  })
              },
              _ => unimplemented!(),
            }
          })
      )
      .and_then(|new_state|{
        let allowed:bool = match (prev_state, &new_state) {
          (&State::NonAuthorized, &State::LoginReady)   => true,
          (&State::LoginSent, &State::PasswordReady)    => true,
          (&State::PasswordReady, &State::PasswordSent) => true,
          (&State::PasswordSent, &State::Authorized)    => true,
          (&State::PwdSent, &State::PathReceived(_))    => true,
          _ => false,
        };
        if allowed {
          Ok(new_state)
        } else {
          println!("transition {} => {} is not allowed", prev_state, new_state);
          Err(FtpError::ProtocolError("transition not allowed".to_string()))
        }
      })
  }

  pub fn advance(&mut self) -> Option<FtpError> {

    lazy_static! {
      static ref RE_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3}) .+$)").unwrap();
      static ref RE_PARTRIAL_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3})-.+$)").unwrap();
    }

    let transition_result = Ftp::advance_state(&self.state, self.buffer.to_bytes().as_slice());

    match transition_result {
      Err(e)        => Some(e),
      Ok(new_state) => {
        self.buffer.clear();

        let final_state = match new_state {
          State::PathReceived(path) => {
            self.working_dir = Some(path);
            State::Authorized
          }
          _ => new_state,
        };

        self.state = final_state;
        None
      }
    }
  }

  pub fn send_login(&mut self, buffer: &mut ByteBuffer, login: &str) {
    match &self.state {
      &State::LoginReady => {
        buffer.write_bytes("USER ".as_bytes());
        buffer.write_bytes(login.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = State::LoginSent
      },
      _ => panic!("send_login is not allowed from the current state"),
    }
  }

  pub fn send_password(&mut self, buffer: &mut ByteBuffer, pass: &str) {
    match &self.state {
      &State::PasswordReady => {
        buffer.write_bytes("PASS ".as_bytes());
        buffer.write_bytes(pass.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = State::PasswordSent;
      },
      _ => panic!("send_password is not allowed from the current state"),
    }
  }

  pub fn send_pwd_req(&mut self, buffer: &mut ByteBuffer) {
    match &self.state {
      &State::Authorized => {
        buffer.write_bytes("PWD\n".as_bytes());
        self.state = State::PwdSent;
      },
      _ => panic!("send_pwd_req is not allowed from the current state"),
    }
  }

  pub fn get_wd(&self) -> &str {
    match &self.working_dir {
      &Some(ref path) => &path,
      &None           => panic!("get_wd is not available (did you called send_pwd_req?)"),
    }
  }

  pub fn send_type_req(&mut self, buffer: &mut ByteBuffer, data_type: &DataMode) {
    match &self.state {
      &State::Authorized => {
        buffer.write_bytes("TYPE ".as_bytes());
        let type_string = match data_type {
          &DataMode::Binary => "I",
          &DataMode::Text => "T",
        };
        buffer.write_bytes(type_string.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = State::DataTypeSent;
      },
      _ => panic!("send_type_req is not allowed from the {}", self.state),
    }
  }



}
