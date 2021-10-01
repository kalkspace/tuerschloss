use anyhow::anyhow;
use crc16::CCITT_FALSE;
use std::convert::{TryFrom, TryInto};

#[derive(Debug, thiserror::Error)]
pub enum ErrorCode {
    #[error("CRC of received command is invalid")]
    BadCRC,
    #[error("Length of retrieved command payload does not match expected length")]
    BadLength,
    #[error("Used if no other error code matches")]
    Unknown,

    #[error("public key is being requested via request data command, but the Smart Lock is not in pairing mode")]
    NotPairing,
    #[error("the received authenticator does not match the own calculated authenticator")]
    BadAuthenticator,
    #[error("a provided parameter is outside of its valid range")]
    BadParameter,
    #[error("the maximum number of users has been reached")]
    MaxUser,
}

#[derive(Debug, thiserror::Error)]
#[error("Read unknown error code")]
pub struct UnknownErrorCode;

impl TryFrom<u8> for ErrorCode {
    type Error = UnknownErrorCode;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        let e = match code {
            0xFD => Self::BadCRC,
            0xFE => Self::BadLength,
            0xFF => Self::Unknown,
            0x10 => Self::NotPairing,
            0x11 => Self::BadAuthenticator,
            0x12 => Self::BadParameter,
            0x13 => Self::MaxUser,
            _ => return Err(UnknownErrorCode),
        };
        Ok(e)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Command {
    RequestData { data: Vec<u8> },
    PublicKey { key: Vec<u8> },
    // missing some
    ErrorReport { code: ErrorCode, command_ident: u16 },
    // missing more
}

impl Command {
    pub fn parse(pl: impl AsRef<[u8]>) -> Result<Self, anyhow::Error> {
        let bytes = pl.as_ref();

        let (bytes, crc) = bytes.split_at(bytes.len() - 2);
        let received_crc = u16::from_le_bytes(crc.try_into()?);
        let expected_crc = Self::crc(bytes);
        if expected_crc != received_crc {
            return Err(anyhow!(
                "CRC mismatch, expected {:02X?}, got {:02X?}",
                expected_crc,
                received_crc
            ));
        }

        let (id, bytes) = bytes.split_at(2);
        let id: [u8; 2] = id.try_into()?;
        let id = u16::from_le_bytes(id);

        let cmd = match id {
            0x0001 => Self::RequestData { data: bytes.into() },
            0x0003 => Self::PublicKey { key: bytes.into() },
            0x0012 => {
                let (code, command_ident) = bytes.split_at(1);
                let code = code
                    .get(0)
                    .copied()
                    .ok_or_else(|| anyhow!("Missing error code"))?
                    .try_into()?;
                let command_ident = u16::from_le_bytes(command_ident.try_into()?);
                Self::ErrorReport {
                    code,
                    command_ident,
                }
            }
            _ => return Err(anyhow!("unknown command code")),
        };

        Ok(cmd)
    }

    pub fn into_bytes(self) -> Box<[u8]> {
        let mut out: Vec<u8> = Default::default();
        out.extend(self.id().to_le_bytes());

        match self {
            Command::RequestData { data } => {
                out.extend(data);
            }
            Command::PublicKey { key } => out.extend(key),
            Command::ErrorReport { .. } => unimplemented!(),
        }

        let crc = Self::crc(&out);
        out.extend(crc.to_le_bytes());

        out.into_boxed_slice()
    }

    fn id(&self) -> u16 {
        match self {
            Command::RequestData { .. } => 0x1,
            Command::PublicKey { .. } => 0x3,
            Command::ErrorReport { .. } => 0x12,
        }
    }

    fn crc(bytes: impl AsRef<[u8]>) -> u16 {
        crc16::State::<CCITT_FALSE>::calculate(bytes.as_ref())
    }
}

#[cfg(test)]
mod test {
    use crate::command::Command;

    #[test]
    fn parse() {
        let bytes = vec![0x01, 0x00, 0x03, 0x00, 0x27, 0xA7];
        let cmd = Command::parse(&bytes).unwrap();
        assert!(matches!(cmd, Command::RequestData { .. }));
    }

    #[test]
    fn serialize() {
        let cmd = Command::RequestData {
            data: vec![0x03, 0x00],
        };
        let bytes = cmd.into_bytes();
        assert_eq!(&[0x01, 0x00, 0x03, 0x00, 0x27, 0xA7], bytes.as_ref());
    }
}
