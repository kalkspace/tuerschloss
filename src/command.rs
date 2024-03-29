use anyhow::anyhow;
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
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
    #[error("the maximum number of users has been reached")]
    MaxUser,

    #[error("Returned if the provided authorization id is invalid or the payload could not be decrypted using the shared key for this authorization id")]
    NotAuthorized,
    #[error("Returned if the provided pin does not match the stored one.")]
    BadPin,
    #[error("Returned if the provided nonce does not match the last stored one of this authorization id or has already been used before.")]
    BadNonce,
    #[error("Returned if a provided parameter is outside of its valid range.")]
    BadParameter,
    #[error(
        "Returned if the desired authorization id could not be deleted because it does not exist."
    )]
    InvalidAuthId,
    #[error("Returned if the provided authorization id is currently disabled.")]
    Disabled,
    #[error("Returned if the request has been forwarded by the Nuki Bridge and the provided authorization id has not been granted remote access.")]
    RemoteNotAllowed,
    #[error("Returned if the provided authorization id has not been granted access at the current time.")]
    TimeNotAllowed,
    #[error("Returned if an invalid pin has been provided too often")]
    TooManyPinAttempts,
    #[error("Returned if no more entries can be stored")]
    TooManyEntries,
    #[error("Returned if a Keypad Code should be added but the given code already exists.")]
    CodeAlreadyExists,
    #[error("Returned if a Keypad Code that has been entered is invalid.")]
    CodeInvalid,
    #[error("Returned if an invalid pin has been provided multiple times.")]
    CodeInvalidTimeout1,
    #[error("Returned if an invalid pin has been provided multiple times.")]
    CodeInvalidTimeout2,
    #[error("Returned if an invalid pin has been provided multiple times.")]
    CodeInvalidTimeout3,
    #[error("Returned on an incoming auto unlock request and if a lock action has already been executed within short time.")]
    AutoUnlockTooRecent,
    #[error("Returned on an incoming unlock request if the request has been forwarded by the Nuki Bridge and the Smart Lock is unsure about its actual lock position.")]
    PositionUnknown,
    #[error("Returned if the motor blocks.")]
    MotorBlocked,
    #[error("Returned if there is a problem with the clutch during motor movement.")]
    ClutchFailure,
    #[error("Returned if the motor moves for a given period of time but did not block.")]
    MotorTimeout,
    #[error(
        "Returned on any lock action via bluetooth if there is already a lock action processing."
    )]
    Busy,
    #[error("Returned on any lock action or during calibration if the user canceled the motor movement by pressing the button")]
    Canceled,
    #[error("Returned on any lock action if the Smart Lock has not yet been calibrated")]
    NotCalibrated,
    #[error("Returned during calibration if the internal position database is not able to store any more values")]
    MotorPositionLimit,
    #[error("Returned if the motor blocks because of low voltage.")]
    MotorLowVoltage,
    #[error("Returned if the power drain during motor movement is zero")]
    MotorPowerFailure,
    #[error("Returned if the power drain during clutch movement is zero")]
    ClutchPowerFailure,
    #[error("Returned on a calibration request if the battery voltage is too low and a calibration will therefore not be started")]
    VoltageTooLow,
    #[error("Returned during any motor action if a firmware update is mandatory")]
    FirmwareUpdateNeeded,
}

#[derive(Debug, thiserror::Error)]
#[error("Read unknown error code: {0}")]
pub struct UnknownErrorCode(u8);

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

            0x20 => Self::NotAuthorized,
            0x21 => Self::BadPin,
            0x22 => Self::BadNonce,
            0x23 => Self::BadParameter,
            0x24 => Self::InvalidAuthId,
            0x25 => Self::Disabled,
            0x26 => Self::RemoteNotAllowed,
            0x27 => Self::TimeNotAllowed,
            0x28 => Self::TooManyPinAttempts,
            0x29 => Self::TooManyEntries,
            0x2A => Self::CodeAlreadyExists,
            0x2B => Self::CodeInvalid,
            0x2C => Self::CodeInvalidTimeout1,
            0x2D => Self::CodeInvalidTimeout2,
            0x2E => Self::CodeInvalidTimeout3,
            0x40 => Self::AutoUnlockTooRecent,
            0x41 => Self::PositionUnknown,
            0x42 => Self::MotorBlocked,
            0x43 => Self::ClutchFailure,
            0x44 => Self::MotorTimeout,
            0x45 => Self::Busy,
            0x46 => Self::Canceled,
            0x47 => Self::NotCalibrated,
            0x48 => Self::MotorPositionLimit,
            0x49 => Self::MotorLowVoltage,
            0x4A => Self::MotorPowerFailure,
            0x4B => Self::ClutchPowerFailure,
            0x4C => Self::VoltageTooLow,
            0x4D => Self::FirmwareUpdateNeeded,

            code => return Err(UnknownErrorCode(code)),
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
    Unknown(u8),
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
            LockAction::Unknown(id) => id,
        }
    }
}

impl TryFrom<u8> for LockAction {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let action = match value {
            1 => LockAction::Unlock,
            2 => LockAction::Lock,
            3 => LockAction::Unlatch,
            4 => LockAction::LockNGo,
            5 => LockAction::LockNGoWithUnlatch,
            6 => LockAction::FullLock,
            0x81 => LockAction::FobAction1,
            0x82 => LockAction::FobAction2,
            0x83 => LockAction::FobAction3,
            id => LockAction::Unknown(id),
        };
        Ok(action)
    }
}

#[derive(Debug)]
pub enum NukiState {
    Uninitialized,
    PairingMode,
    DoorMode,
    MaintenanceMode,
}

impl TryFrom<u8> for NukiState {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let state = match value {
            0 => NukiState::Uninitialized,
            1 => NukiState::PairingMode,
            2 => NukiState::DoorMode,
            4 => NukiState::MaintenanceMode,
            _ => return Err(anyhow!("Unexpected state value")),
        };
        Ok(state)
    }
}

#[derive(Debug)]
pub enum LockState {
    Uncalibrated,
    Locked,
    Unlocking,
    Unlocked,
    Locking,
    Unlatched,
    UnlockedLockNGo,
    Unlatching,
    Calibration,
    BootRun,
    MotorBlocked,
    Undefined,
}

impl TryFrom<u8> for LockState {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let state = match value {
            0x00 => LockState::Uncalibrated,
            0x01 => LockState::Locked,
            0x02 => LockState::Unlocking,
            0x03 => LockState::Unlocked,
            0x04 => LockState::Locking,
            0x05 => LockState::Unlatched,
            0x06 => LockState::UnlockedLockNGo,
            0x07 => LockState::Unlatching,
            0xFC => LockState::Calibration,
            0xFD => LockState::BootRun,
            0xFE => LockState::MotorBlocked,
            0xFF => LockState::Undefined,
            _ => return Err(anyhow!("Unexpected state value")),
        };
        Ok(state)
    }
}

#[derive(Debug)]
pub enum Trigger {
    System,
    Manual,
    Button,
    Automatic,
    AutoLock,
}

impl TryFrom<u8> for Trigger {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let trigger = match value {
            0x00 => Trigger::System,
            0x01 => Trigger::Manual,
            0x02 => Trigger::Button,
            0x03 => Trigger::Automatic,
            0x06 => Trigger::AutoLock,
            _ => return Err(anyhow!("Unexpeceted trigger value")),
        };
        Ok(trigger)
    }
}

#[derive(Debug)]
pub struct BatteryState(u8);

impl From<u8> for BatteryState {
    fn from(state: u8) -> Self {
        BatteryState(state)
    }
}

#[derive(Debug)]
pub enum CompletionStatus {
    Success,
    MotorBlocked,
    Canceled,
    TooRecent,
    Busy,
    LowMotorVoltage,
    ClutchFailure,
    MotorPowerFailure,
    IncompleteFailure,
    OtherError,
    Unknown,
}

impl TryFrom<u8> for CompletionStatus {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let status = match value {
            0x00 => CompletionStatus::Success,
            0x01 => CompletionStatus::MotorBlocked,
            0x02 => CompletionStatus::Canceled,
            0x03 => CompletionStatus::TooRecent,
            0x04 => CompletionStatus::Busy,
            0x05 => CompletionStatus::LowMotorVoltage,
            0x06 => CompletionStatus::ClutchFailure,
            0x07 => CompletionStatus::MotorPowerFailure,
            0x08 => CompletionStatus::IncompleteFailure,
            0xFE => CompletionStatus::OtherError,
            0xFF => CompletionStatus::Unknown,
            _ => return Err(anyhow!("Unexpected completion status")),
        };
        Ok(status)
    }
}

#[derive(Debug)]
pub enum DoorSensorState {
    Unavailable,
    Deactivated,
    DoorClosed,
    DoorOpened,
    DoorStateUnknown,
    Calibrating,
}

impl TryFrom<u8> for DoorSensorState {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let state = match value {
            0x00 => DoorSensorState::Unavailable,
            0x01 => DoorSensorState::Deactivated,
            0x02 => DoorSensorState::DoorClosed,
            0x03 => DoorSensorState::DoorOpened,
            0x04 => DoorSensorState::DoorStateUnknown,
            0x05 => DoorSensorState::Calibrating,
            _ => return Err(anyhow!("Unexpected door sensor state")),
        };
        Ok(state)
    }
}

#[derive(Debug)]
pub struct KeyturnerState {
    pub nuki_state: NukiState,
    pub lock_state: LockState,
    pub trigger: Trigger,
    pub current_time: DateTime<FixedOffset>,
    pub battery_state: BatteryState,
    pub config_update_count: u8,
    pub lock_n_go_timer: u8,
    pub last_lock_action: LockAction,
    pub last_lock_action_trigger: Trigger,
    pub last_completion_status: CompletionStatus,
    pub door_sensors_state: DoorSensorState,
    pub nightmode_active: bool,
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
    KeyturnerStates(Option<KeyturnerState>),
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
            0x000c => {
                let mut iter = bytes.iter();
                let nuki_state = read_u8(&mut iter)?;
                let lock_state = read_u8(&mut iter)?;
                let trigger = read_u8(&mut iter)?;
                let current_time = read_timestamp(&mut iter)?;
                let battery_state = read_u8(&mut iter)?;
                let config_update_count = read_u8(&mut iter)?;
                let lock_n_go_timer = read_u8(&mut iter)?;
                let last_lock_action = read_u8(&mut iter)?;
                let last_lock_action_trigger = read_u8(&mut iter)?;
                let last_completion_status = read_u8(&mut iter)?;
                let door_sensors_state = read_u8(&mut iter)?;
                let nightmode_active = u16::from_le_bytes(
                    iter.take(2)
                        .cloned()
                        .collect::<Vec<u8>>()
                        .try_into()
                        .map_err(|_| anyhow!("Not enough bytes"))?,
                );
                Self::KeyturnerStates(Some(KeyturnerState {
                    nuki_state,
                    lock_state,
                    trigger,
                    current_time,
                    battery_state,
                    config_update_count,
                    lock_n_go_timer,
                    last_lock_action,
                    last_lock_action_trigger,
                    last_completion_status,
                    door_sensors_state,
                    nightmode_active: nightmode_active > 0,
                }))
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
                    .first()
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
            Command::KeyturnerStates { .. } => unimplemented!(),
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
            Command::KeyturnerStates { .. } => 0xc,
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

fn read_u8<'a, T, I>(iter: &mut I) -> Result<T, anyhow::Error>
where
    T: TryFrom<u8>,
    T::Error: Into<anyhow::Error>,
    I: Iterator<Item = &'a u8>,
{
    let value = (*iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?)
        .try_into()
        .map_err(Into::into)?;

    Ok(value)
}

fn read_timestamp<'a, I>(iter: &mut I) -> Result<DateTime<FixedOffset>, anyhow::Error>
where
    I: Iterator<Item = &'a u8>,
{
    let year = u16::from_le_bytes(
        iter.take(2)
            .cloned()
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| anyhow!("Not enough bytes"))?,
    );
    let month = *iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?;
    let day = *iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?;
    let hour = *iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?;
    let minute = *iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?;
    let second = *iter.next().ok_or_else(|| anyhow!("Not enough bytes"))?;
    let timezone_offset = i16::from_le_bytes(
        iter.take(2)
            .cloned()
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|_| anyhow!("Not enough bytes"))?,
    );

    let local_time = NaiveDate::from_ymd(year.into(), month.into(), day.into()).and_hms(
        hour.into(),
        minute.into(),
        second.into(),
    );
    let timezone = FixedOffset::east_opt((timezone_offset * 60).into())
        .ok_or_else(|| anyhow!("Invalid timezone offset"))?;
    timezone
        .from_local_datetime(&local_time)
        .earliest()
        .ok_or_else(|| anyhow!("Invalid DateTime"))
}

#[cfg(test)]
mod test {
    use crate::command::Command;

    #[test]
    fn parse() {
        let bytes = vec![0x01, 0x00, 0x03, 0x00, 0x27, 0xA7];
        let cmd = Command::parse(bytes).unwrap();
        assert!(matches!(cmd, Command::RequestData { .. }));
    }

    #[test]
    fn serialize() {
        let cmd = Command::RequestData(3);
        let bytes = cmd.into_bytes();
        assert_eq!(&[0x01, 0x00, 0x03, 0x00, 0x27, 0xA7], bytes.as_ref());
    }
}
