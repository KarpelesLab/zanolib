//! Crate-wide error type.

use std::fmt;

/// The result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while parsing, scanning or signing.
#[derive(Debug)]
pub enum Error {
    /// A protocol/format violation, with a human-readable description.
    Msg(String),
    /// The input ended before a complete value could be read.
    UnexpectedEof,
    /// Bytes that should encode a curve point do not.
    InvalidPoint,
    /// Bytes that should encode a canonical scalar do not.
    InvalidScalar,
    /// An underlying I/O failure.
    Io(std::io::Error),
    /// Malformed JSON.
    Json(serde_json::Error),
    /// Malformed hex.
    Hex(hex::FromHexError),
}

impl Error {
    /// Builds an [`Error::Msg`] from anything displayable.
    pub fn msg(m: impl Into<String>) -> Error {
        Error::Msg(m.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Msg(m) => f.write_str(m),
            Error::UnexpectedEof => f.write_str("unexpected end of input"),
            Error::InvalidPoint => f.write_str("invalid ed25519 point encoding"),
            Error::InvalidScalar => f.write_str("invalid ed25519 scalar encoding"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Json(e) => write!(f, "json: {e}"),
            Error::Hex(e) => write!(f, "hex: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Hex(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Error::UnexpectedEof;
        }
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Error {
        Error::Hex(e)
    }
}

/// Builds an [`Error::Msg`] with `format!` syntax.
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => { $crate::Error::Msg(format!($($arg)*)) };
}
