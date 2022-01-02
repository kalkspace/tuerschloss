use anyhow::anyhow;
use crc16::CCITT_FALSE;
use std::{
    convert::{TryFrom, TryInto},
    io::Write,
};

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

#[derive(Debug, Clone, Copy)]
pub enum IdType {
    App,
    Bridge,
    Fob,
    KeyPad,
}

impl From<IdType> for u8 {
    fn from(id_t: IdType) -> Self {
        match id_t {
            IdType::App => 0,
            IdType::Bridge => 1,
            IdType::Fob => 2,
            IdType::KeyPad => 3,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StatusCode {
    Complete,
    Accepted,
}

#[derive(Debug)]
pub enum LockAction {
    Unlock,
    Lock,
    Unlatch,
    LockNGo,
    LockNGoWithUnlatch,
    FullLock,
    FobAction1,
    FobAction2,
    FobAction3,
}

impl From<LockAction> for u8 {
    fn from(lock_action: LockAction) -> Self {
        match lock_action {
            LockAction::Unlock => 1,
            LockAction::Lock => 2,
            LockAction::Unlatch => 3,
            LockAction::LockNGo => 4,
            LockAction::LockNGoWithUnlatch => 5,
            LockAction::FullLock => 6,
            LockAction::FobAction1 => 0x81,
            LockAction::FobAction2 => 0x82,
            LockAction::FobAction3 => 0x83,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Command {
    RequestData(u16),
    PublicKey(Vec<u8>),
    Challenge(Vec<u8>),
    AuthorizationAuthenticator([u8; 32]),
    AuthorizationData {
        authenticator: [u8; 32],
        id_type: IdType,
        app_id: u32,
        name: [u8; 32],
        nonce: [u8; 32],
    },
    AuthorizationId {
        authenticator: [u8; 32],
        authorization_id: u32,
        uuid: [u8; 16],
        nonce: [u8; 32],
    },
    LockAction {
        action: LockAction,
        app_id: u32,
        flags: u8,
        name_suffix: String,
        nonce: [u8; 32],
    },
    Status(StatusCode),
    // missing some
    ErrorReport {
        code: ErrorCode,
        command_ident: u16,
    },
    AuthorizationIdConfirmation {
        authenticator: [u8; 32],
        authorization_id: u32,
    },
    // missing more
}

impl Command {
    pub fn parse(pl: impl AsRef<[u8]>) -> Result<Self, anyhow::Error> {
        let (cmd, _) = Self::parse_impl(pl, false)?;
        Ok(cmd)
    }

    pub fn parse_with_auth(pl: impl AsRef<[u8]>) -> Result<(Self, u32), anyhow::Error> {
        let (cmd, auth_id) = Self::parse_impl(pl, true)?;
        Ok((cmd, auth_id.unwrap()))
    }

    fn parse_impl(
        pl: impl AsRef<[u8]>,
        with_auth_id: bool,
    ) -> Result<(Self, Option<u32>), anyhow::Error> {
        let bytes = pl.as_ref();

        let (mut bytes, crc) = bytes.split_at(bytes.len() - 2);
        let received_crc = u16::from_le_bytes(crc.try_into()?);
        let expected_crc = Self::crc(bytes);
        if expected_crc != received_crc {
            return Err(anyhow!(
                "CRC mismatch, expected {:02X?}, got {:02X?}",
                expected_crc,
                received_crc
            ));
        }

        let auth_id = if with_auth_id {
            let (auth_id, rest) = bytes.split_at(4);
            bytes = rest;
            Some(u32::from_le_bytes(auth_id.try_into().unwrap()))
        } else {
            None
        };

        let (id, bytes) = bytes.split_at(2);
        let id: [u8; 2] = id.try_into()?;
        let id = u16::from_le_bytes(id);

        let cmd = match id {
            0x0001 => {
                let cmd_id: [u8; 2] = bytes
                    .try_into()
                    .map_err(|_| anyhow!("Invalid length for command id"))?;
                Self::RequestData(u16::from_le_bytes(cmd_id))
            }
            0x0003 => Self::PublicKey(bytes.into()),
            0x0004 => Self::Challenge(bytes.into()),
            0x0005 => todo!(),
            0x0006 => todo!(),
            0x0007 => {
                let (authenticator, bytes) = bytes.split_at(32);
                let authenticator = authenticator
                    .try_into()
                    .map_err(|_| anyhow!("Not enough bytes to read authenticator."))?;
                let (authorization_id, bytes) = bytes.split_at(4);
                let authorization_id = u32::from_le_bytes(
                    authorization_id
                        .try_into()
                        .map_err(|_| anyhow!("Not enough bytes to read authorization id."))?,
                );
                let (uuid, bytes) = bytes.split_at(16);
                let uuid = uuid
                    .try_into()
                    .map_err(|_| anyhow!("Not enough bytes to read uuid"))?;
                let (nonce, _bytes) = bytes.split_at(32);
                let nonce = nonce
                    .try_into()
                    .map_err(|_| anyhow!("Not enough bytes to read nonce."))?;
                Self::AuthorizationId {
                    authenticator,
                    authorization_id,
                    uuid,
                    nonce,
                }
            }
            0x000e => {
                let code = bytes
                    .first()
                    .ok_or_else(|| anyhow!("Missing status code..."))?;

                let status_code = match code {
                    0 => StatusCode::Complete,
                    1 => StatusCode::Accepted,
                    _ => return Err(anyhow!("Invalid status code...")),
                };

                Self::Status(status_code)
            }
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
            0x001e => todo!(),
            _ => return Err(anyhow!("unknown command code")),
        };

        Ok((cmd, auth_id))
    }

    pub fn into_bytes(self) -> Box<[u8]> {
        self.into_bytes_impl(None)
    }

    fn into_bytes_impl(self, auth_id: Option<u32>) -> Box<[u8]> {
        let mut out: Vec<u8> = Default::default();
        if let Some(id) = auth_id {
            out.extend(id.to_le_bytes());
        }
        out.extend(self.id().to_le_bytes());

        match self {
            Command::RequestData(id) => {
                out.extend(id.to_le_bytes());
            }
            Command::PublicKey(key) => out.extend(key),
            Command::Challenge(challenge) => out.extend(challenge),
            Command::AuthorizationAuthenticator(authenticator) => out.extend(authenticator),
            Command::AuthorizationData {
                authenticator,
                id_type,
                app_id,
                name,
                nonce,
            } => {
                out.extend(authenticator);
                out.push(id_type.into());
                out.extend(app_id.to_le_bytes());
                out.extend(name);
                out.extend(nonce);
            }
            Command::AuthorizationId { .. } => unimplemented!(),
            Command::LockAction {
                action,
                app_id,
                flags,
                name_suffix,
                nonce,
            } => {
                out.push(action.into());
                out.extend(app_id.to_le_bytes());
                out.push(flags);

                let mut name = [0; 20];
                let mut name_ref: &mut [u8] = &mut name;
                name_ref.write_all(name_suffix.as_bytes()).unwrap();
                out.extend(name);

                out.extend(nonce);
            }
            Command::Status(_) => todo!(),
            Command::ErrorReport { .. } => unimplemented!(),
            Command::AuthorizationIdConfirmation {
                authenticator,
                authorization_id,
            } => {
                out.extend(authenticator);
                out.extend(authorization_id.to_le_bytes());
            }
        }

        let crc = Self::crc(&out);
        out.extend(crc.to_le_bytes());

        out.into_boxed_slice()
    }

    pub fn into_bytes_with_auth(self, auth_id: u32) -> Box<[u8]> {
        self.into_bytes_impl(Some(auth_id))
    }

    pub fn id(&self) -> u16 {
        match self {
            Command::RequestData(_) => 0x1,
            Command::PublicKey(_) => 0x3,
            Command::Challenge(_) => 0x4,
            Command::AuthorizationAuthenticator(_) => 0x5,
            Command::AuthorizationData { .. } => 0x6,
            Command::AuthorizationId { .. } => 0x7,
            Command::LockAction { .. } => 0xd,
            Command::Status(_) => 0xe,
            Command::ErrorReport { .. } => 0x12,
            Command::AuthorizationIdConfirmation { .. } => 0x1e,
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
        let cmd = Command::RequestData(3);
        let bytes = cmd.into_bytes();
        assert_eq!(&[0x01, 0x00, 0x03, 0x00, 0x27, 0xA7], bytes.as_ref());
    }
}
