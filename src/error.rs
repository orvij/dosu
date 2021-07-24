/// Error type for the crate
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Error from the nix library
    BsdAuth(bsd_auth::Error),
    Io(String),
    Nix(nix::Error),
    Nom(String),
    Nul(std::ffi::NulError),
    ReadPassphrase(readpassphrase::Error),
    Utf8(std::str::Utf8Error),
    AuthUser,
    MaxConfigLen(u64),
    NullPtr,
    Pledge(i32),
    SetEnv(i32),
    Unveil(i32),
    Var(std::env::VarError),
    UnmatchedUser,
    UnmatchedGroup,
    UnmatchedCommand,
    UnmatchedCommandArgs,
    UnmatchedRule,
    UnmatchedTarget,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = match self {
            Self::BsdAuth(e) => format!("bsd_auth: {:?}", e),
            Self::Io(e) => format!("std::io: {:?}", e),
            Self::Nix(e) => format!("nix: {:?}", e),
            Self::Nom(e) => format!("nom: {:?}", e),
            Self::Nul(e) => "Nul ffi C string pointer".to_string(),
            Self::ReadPassphrase(e) => format!("readpassphrase: {:?}", e),
            Self::Utf8(e) => format!("UTF8: {}", e),
            Self::AuthUser => "AuthUser".to_string(),
            Self::NullPtr => "Null pointer".to_string(),
            Self::Pledge(e) => format!("pledge failed, errno: {}", e),
            Self::SetEnv(e) => format!("setenv failed, errno: {}", e),
            Self::Unveil(e) => format!("unveil failed, errno: {}", e),
            Self::MaxConfigLen(len) => format!("Exceeded max config len: {}", len),
            Self::Var(e) => format!("std::env::var failed: {:?}", e),
            Self::NullPtr => "Null pointer".to_string(),
            Self::UnmatchedUser => "Unmatched user".to_string(),
            Self::UnmatchedGroup => "Unmatched group".to_string(),
            Self::UnmatchedCommand => "Unmatched command".to_string(),
            Self::UnmatchedCommandArgs => "Unmatched command arguments".to_string(),
            Self::UnmatchedRule => "Unmatched rule".to_string(),
            Self::UnmatchedTarget => "Unmatched target user".to_string(),
        };
        write!(f, "{}", e)
    }
}

impl From<bsd_auth::Error> for Error {
    fn from(e: bsd_auth::Error) -> Self {
        Self::BsdAuth(e)
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        Self::Nix(e)
    }
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        match e {
            nom::Err::Error(e) | nom::Err::Failure(e) => Self::Nom(format!(
                "error: {}, at: {:?}",
                e.code.description(),
                e.input
            )),
            nom::Err::Incomplete(_) => Self::Nom("incomplete data".into()),
        }
    }
}

impl From<std::env::VarError> for Error {
    fn from(e: std::env::VarError) -> Self {
        Self::Var(e)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Nul(e)
    }
}

impl From<readpassphrase::Error> for Error {
    fn from(e: readpassphrase::Error) -> Self {
        Self::ReadPassphrase(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(format!("{}", e))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::Utf8(e)
    }
}
