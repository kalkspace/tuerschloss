use anyhow::anyhow;
use pairing::{AuthInfo, PairingClient};

use crate::client::UnconnectedClient;

mod client;
mod command;
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

    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;

    Ok(())
}
