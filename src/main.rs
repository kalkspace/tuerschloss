use std::convert::TryInto;

use anyhow::anyhow;
use client::Client;
use command::{Command, LockAction};
use encrypted::AuthenticatedClient;
use pairing::{AuthInfo, PairingClient};

use crate::client::UnconnectedClient;

mod client;
mod command;
mod encrypted;
mod pairing;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";
const KEY_TURNER_SERVICE: &str = "a92ee200-5501-11e4-916c-0800200c9a66";
const KEY_TURNER_USDIO: &str = "a92ee202-5501-11e4-916c-0800200c9a66";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let connected_client = UnconnectedClient::new(LOCK_ADDRESS.into())
        .connect()
        .await?;

    let auth_info = AuthInfo::read_from_file("auth-info.json").await?;
    let characteristic = connected_client
        .with_characteristic(KEY_TURNER_SERVICE, KEY_TURNER_USDIO)
        .await?;
    let mut authenticated_client = AuthenticatedClient::new(auth_info, characteristic);

    authenticated_client
        .write(Command::RequestData(Command::Challenge(Vec::new()).id()))
        .await?;

    let received_challenge = authenticated_client.receive().await?;
    let challenge = match received_challenge {
        Command::Challenge(c) => c,
        Command::ErrorReport { code, .. } => return Err(code.into()),
        _ => return Err(anyhow!("Unexpected response")),
    };

    let lock_action_command = Command::LockAction {
        action: LockAction::Unlock,
        app_id: APP_ID,
        flags: 0,
        name_suffix: "".to_string(),
        nonce: challenge
            .try_into()
            .map_err(|_| anyhow!("Invalid challenge length"))?,
    };

    authenticated_client.write(lock_action_command).await?;

    let received_status = authenticated_client.receive().await?;
    match received_status {
        Command::Status(command::StatusCode::Accepted) => {}
        Command::ErrorReport { code, .. } => return Err(code.into()),
        _ => return Err(anyhow!("Unexpected status")),
    };

    Ok(())
}

async fn pairing(connected_client: Client) -> Result<(), anyhow::Error> {
    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;

    Ok(())
}
