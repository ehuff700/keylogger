pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    WindowsError(u32),
    KeyLoggerInitialized,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::WindowsError(code) => write!(f, "windows error: {}", code),
            Error::KeyLoggerInitialized => write!(f, "keylogger is already initialized"),
        }
    }
}

impl core::error::Error for Error {}
