#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate bytebuffer;

use bytebuffer::ByteBuffer;
use regex::Regex;
use std::str;
use std::fmt;
use std::rc::Rc;

pub const OPERATION_SUCCESS:u32  = 200;
pub const LOGGED_EXPECTED:u32    = 220;
pub const LOGGED_IN:u32          = 230;
pub const PATHNAME_AVAILABLE:u32 = 257;
pub const PASSWORD_EXPECTED:u32  = 331;

#[derive(Clone)]
pub enum DataMode {
  Binary,
  Text
}

impl fmt::Display for DataMode {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      &DataMode::Binary => write!(f, "data-mode:binary"),
      &DataMode::Text   => write!(f, "data-mode:text"),
    }
  }
}

pub enum ConnectionMode {
  Active,
  Passive,
}

pub enum State {
  NonAuthorized,
  Authorized,
  LoginReady,
  LoginReqSent,
  PasswordExpected,
  PasswordReqSent,

  PwdReqSent,
  PathReceived(String),
  DataTypeReqSent(DataMode),
  DataTypeConfirmed(DataMode),
}

impl fmt::Display for State {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      &State::PathReceived(ref value)      => write!(f, "[state: path-received({})]", value),
      &State::DataTypeReqSent(ref value)   => write!(f, "[state: data-type-req-sent({})]", value),
      &State::DataTypeConfirmed(ref value) => write!(f, "[state: data-type-confirmed({})]", value),
      _ => {
        let state = match self {
          &State::NonAuthorized    => "non-authorized",
          &State::Authorized       => "authorized",
          &State::LoginReady       => "login-ready",
          &State::LoginReqSent     => "login-req-sent",
          &State::PasswordExpected => "password-expected",
          &State::PasswordReqSent  => "password-req-sent",
          &State::PwdReqSent       => "pwd-req-sent",
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
  GarbageData,
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
  data_mode: Option<DataMode>,
  connectionMode: Option<ConnectionMode>,
  working_dir: Option<String>,
  sent_request: Option<Rc<State>>,
  buffer: ByteBuffer,
  state: Rc<State>,
}




impl Ftp {
  pub fn new() -> Self {
    Ftp {
      data_mode: None,
      connectionMode: None,
      working_dir: None,
      sent_request: None,
      buffer: ByteBuffer::new(),
      state: Rc::new(State::NonAuthorized),
    }
  }

  pub fn feed(&mut self, data: &[u8]) {
    self.buffer.write_bytes(data);
  }

  fn advance_state(prev_state: &State, prev_req: &Option<Rc<State>>, bytes: &[u8]) -> Result<State, FtpError> {

    lazy_static! {
      static ref RE_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3}) (.+)$)").unwrap();
      static ref RE_PATHNAME: Regex = Regex::new("\"(.+)\"").unwrap();
      static ref RE_PARTRIAL_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3})-.+$)").unwrap();
    }

    str::from_utf8(bytes)
      .map_err(|err| FtpError::GarbageData)
      .and_then(|response|
        RE_RESPONCE_CODE.captures(&response)
          .ok_or_else(||{
            if RE_PARTRIAL_RESPONCE_CODE.is_match(response) {
              FtpError::NotEnoughData
            } else {
              FtpError::GarbageData
            }
          })
          .and_then(|captures| {
            let code_str = captures.at(1).unwrap();
            let code:u32 = code_str.parse().unwrap();
            match code {
              LOGGED_EXPECTED    => Ok(State::LoginReady),
              PASSWORD_EXPECTED  => Ok(State::PasswordExpected),
              LOGGED_IN          => Ok(State::Authorized),
              OPERATION_SUCCESS  => {
                match &*prev_req {
                  &Some(ref prev_sent_req) => {
                    match &**prev_sent_req {
                      &State::DataTypeReqSent(ref value) => Ok(State::DataTypeConfirmed(value.clone())),
                      _ => Err(FtpError::GarbageData),
                    }
                  },
                  _ => Err(FtpError::GarbageData),
                }
              },
              PATHNAME_AVAILABLE => {
                let pathname_str = captures.at(2).unwrap();
                RE_PATHNAME.captures(pathname_str)
                  .ok_or(FtpError::GarbageData)
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
          (&State::NonAuthorized, &State::LoginReady)                => true,
          (&State::LoginReqSent, &State::PasswordExpected)           => true,
          (&State::PasswordExpected, &State::PasswordReqSent)        => true,
          (&State::PasswordReqSent, &State::Authorized)              => true,
          (&State::PwdReqSent, &State::PathReceived(_))              => true,
          (&State::DataTypeReqSent(_), &State::DataTypeConfirmed(_)) => true,
          _ => false,
        };
        if allowed {
          Ok(new_state)
        } else {
          println!("transition {} => {} is not allowed", prev_state, new_state);
          Err(FtpError::ProtocolError(format!("{} => {} is not allowed", prev_state, new_state)))
        }
      })
  }

  pub fn advance(&mut self) -> Option<FtpError> {

    lazy_static! {
      static ref RE_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3}) .+$)").unwrap();
      static ref RE_PARTRIAL_RESPONCE_CODE: Regex = Regex::new("(?m:^(\\d{3})-.+$)").unwrap();
    }

    let transition_result = Ftp::advance_state(&self.state, &self.sent_request, self.buffer.to_bytes().as_slice());

    match transition_result {
      Err(e)        => Some(e),
      Ok(new_state) => {
        self.buffer.clear();

        let final_state = match new_state {
          State::PathReceived(path) => {
            self.working_dir = Some(path);
            State::Authorized
          },
          State::DataTypeConfirmed(data_type) => {
            self.data_mode = Some(data_type);
            State::Authorized
          }
          _ => new_state,
        };

        self.state = Rc::new(final_state);
        self.sent_request = None;
        None
      }
    }
  }

  pub fn send_login(&mut self, buffer: &mut ByteBuffer, login: &str) {
    match &*self.state {
      &State::LoginReady => {
        buffer.write_bytes("USER ".as_bytes());
        buffer.write_bytes(login.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = Rc::new(State::LoginReqSent);
        self.sent_request = Some(self.state.clone());
      },
      _ => panic!("send_login is not allowed from the current state"),
    }
  }

  pub fn send_password(&mut self, buffer: &mut ByteBuffer, pass: &str) {
    match &*self.state {
      &State::PasswordExpected => {
        buffer.write_bytes("PASS ".as_bytes());
        buffer.write_bytes(pass.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = Rc::new(State::PasswordReqSent);
        self.sent_request = Some(self.state.clone());
      },
      _ => panic!("send_password is not allowed from the current state"),
    }
  }

  pub fn send_pwd_req(&mut self, buffer: &mut ByteBuffer) {
    match &*self.state {
      &State::Authorized => {
        buffer.write_bytes("PWD\n".as_bytes());
        self.state = Rc::new(State::PwdReqSent);
        self.sent_request = Some(self.state.clone());
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

  pub fn send_type_req(&mut self, buffer: &mut ByteBuffer, data_type: DataMode) {
    match &*self.state {
      &State::Authorized => {
        buffer.write_bytes("TYPE ".as_bytes());
        let type_string = match &data_type {
          &DataMode::Binary => "I",
          &DataMode::Text => "T",
        };
        buffer.write_bytes(type_string.as_bytes());
        buffer.write_bytes("\n".as_bytes());
        self.state = Rc::new(State::DataTypeReqSent(data_type));
        self.sent_request = Some(self.state.clone());
      },
      _ => panic!("send_type_req is not allowed from the {}", self.state),
    }
  }



}
