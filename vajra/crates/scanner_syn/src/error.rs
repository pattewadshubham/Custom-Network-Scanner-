use thiserror::Error;

#[derive(Error, Debug)]
pub enum SynError {
    #[error("raw sockets not permitted (need root/CAP_NET_RAW)")]
    NotPermitted,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout")]
    Timeout,

    #[error("capture error: {0}")]
    Capture(String),

    #[error("not implemented")]
    NotImplemented,

    #[error("invalid target: {0}")]
    InvalidTarget(String),
}