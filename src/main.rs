use std::convert::TryInto;

use anyhow::anyhow;
use client::Client;
use command::{Command, LockAction};
use encrypted::AuthenticatedClient;
use keyturner::Keyturner;
use pairing::{AuthInfo, PairingClient};

use crate::client::UnconnectedClient;

mod client;
mod command;
mod encrypted;
mod keyturner;
mod pairing;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let connected_client = UnconnectedClient::new(LOCK_ADDRESS.into())
        .connect()
        .await?;

    let auth_info = AuthInfo::read_from_file("auth-info.json").await?;

    let mut keyturner = Keyturner::new(auth_info, connected_client).await?;
    keyturner.run_action(LockAction::Unlock).await?;
    keyturner.run_action(LockAction::Lock).await?;

    //pairing(connected_client).await?;

    Ok(())
}

pub async fn pairing(connected_client: Client) -> Result<(), anyhow::Error> {
    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;

    Ok(())
}
