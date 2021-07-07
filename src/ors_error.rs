use std::fmt;

#[derive(Debug)]
pub enum OrsError {
    Io(std::io::Error),
    Pkcs11(pkcs11::errors::Error),
    Anyhow(anyhow::Error),
    SerdeYaml(serde_yaml::Error),
    SerdeJson(serde_json::Error),
    InvalidUri(http::uri::InvalidUri),
    TODOGeneral,
}

impl From<std::io::Error> for OrsError {
    fn from(err: std::io::Error) -> OrsError {
        OrsError::Io(err)
    }
}

impl From<pkcs11::errors::Error> for OrsError {
    fn from(err: pkcs11::errors::Error) -> OrsError {
        OrsError::Pkcs11(err)
    }
}

impl From<anyhow::Error> for OrsError {
    fn from(err: anyhow::Error) -> OrsError {
        OrsError::Anyhow(err)
    }
}

impl From<serde_yaml::Error> for OrsError {
    fn from(err: serde_yaml::Error) -> OrsError {
        OrsError::SerdeYaml(err)
    }
}

impl From<serde_json::Error> for OrsError {
    fn from(err: serde_json::Error) -> OrsError {
        OrsError::SerdeJson(err)
    }
}

impl From<http::uri::InvalidUri> for OrsError {
    fn from(err: http::uri::InvalidUri) -> OrsError {
        OrsError::InvalidUri(err)
    }
}

impl fmt::Display for OrsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OrsError::Io(ref err) => err.fmt(f),
            OrsError::Pkcs11(ref err) => err.fmt(f),
            OrsError::Anyhow(ref err) => err.fmt(f),
            OrsError::SerdeYaml(ref err) => err.fmt(f),
            OrsError::SerdeJson(ref err) => err.fmt(f),
            OrsError::InvalidUri(ref err) => err.fmt(f),
            OrsError::TODOGeneral => write!(f, "TODO General error"),
        }
    }
}

impl std::error::Error for OrsError {
    fn description(&self) -> &str {
        match *self {
            OrsError::Io(ref err) => err.description(),
            OrsError::Pkcs11(ref err) => err.description(),
            OrsError::Anyhow(ref err) => err.description(),
            OrsError::SerdeYaml(ref err) => err.description(),
            OrsError::SerdeJson(ref err) => err.description(),
            OrsError::InvalidUri(ref err) => err.description(),
            OrsError::TODOGeneral => "TODO general error",
        }
    }
}
