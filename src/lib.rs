#![allow(unused)]

pub mod config;
mod error;

pub use crate::error::Error;
use std::collections::HashMap;

static PERMIT: &'static [u8; 6] = b"permit";

/// Action to perform based on a rule
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Action {
    Permit = 1,
    Deny = 2,
}

impl From<&str> for Action {
    fn from(s: &str) -> Self {
        if s.as_bytes() == PERMIT.as_ref() {
            Self::Permit
        } else {
            Self::Deny
        }
    }
}

impl From<&[u8]> for Action {
    fn from(s: &[u8]) -> Self {
        if s == PERMIT.as_ref() {
            Self::Permit
        } else {
            Self::Deny
        }
    }
}

/// Options for performing a command
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Options {
    /// No password required for the specified rule
    NoPass = 0x1,
    /// Keep the environment of the specified user
    KeepEnv = 0x2,
    /// Persist the user session without requiring reauthentication
    Persist = 0x4,
    /// Keep no logs
    NoLog = 0x8,
    /// Set environment variables
    SetEnv = 0x10,
    /// No options
    Empty = 0x0,
}

/// Rule for permitting a user to perform a command as a target user
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub action: Action,
    pub options: Vec<Options>,
    pub ident: Vec<u8>,
    pub target: Option<Vec<u8>>,
    pub cmd: Option<Vec<u8>>,
    pub cmd_args: Option<Vec<Vec<u8>>>,
    pub envlist: HashMap<Vec<u8>, Vec<u8>>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            action: Action::Deny,
            options: vec![],
            ident: Vec::new(),
            target: None,
            cmd: None,
            cmd_args: None,
            envlist: HashMap::new(),
        }
    }
}

impl Rule {
    /// The action for the Rule: Permit | Deny
    pub fn action(&self) -> Action {
        self.action
    }

    /// The options for the Rule
    pub fn options(&self) -> &[Options] {
        &self.options
    }

    /// The ident for the Rule, the user or group permitted to perform the command
    pub fn ident(&self) -> &[u8] {
        &self.ident
    }

    /// The ident for the Rule, the user or group permitted to perform the command
    pub fn ident_str(&self) -> Result<String, Error> {
        Ok(std::str::from_utf8(&self.ident)?.to_string())
    }

    /// The target for the Rule, perform the command as this user
    pub fn target(&self) -> Option<&[u8]> {
        match self.target.as_ref() {
            Some(t) => Some(t.as_ref()),
            None => None,
        }
    }

    /// The command for the Rule
    pub fn cmd(&self) -> Option<&[u8]> {
        match self.cmd.as_ref() {
            Some(c) => Some(c.as_slice()),
            None => None,
        }
    }

    /// The command arguments for the Rule
    pub fn cmd_args(&self) -> Option<&[Vec<u8>]> {
        match self.cmd_args.as_ref() {
            Some(a) => Some(a.as_slice()),
            None => None,
        }
    }

    /// List of environment variables for the Rule
    pub fn envlist(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        &self.envlist
    }
}
