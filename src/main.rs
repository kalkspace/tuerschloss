use anyhow::anyhow;
use pairing::PairingClient;

use crate::client::UnconnectedClient;

mod client;
mod command;
mod pairing;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const PAIRING_SERVICE: &str = "a92ee100-5501-11e4-916c-0800200c9a66";
const PAIRING_SERVICE_GDIO: &str = "a92ee101-5501-11e4-916c-0800200c9a66";
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let connected_client = UnconnectedClient::new(LOCK_ADDRESS.into())
        .connect()
        .await?
        .with_characteristic(PAIRING_SERVICE, PAIRING_SERVICE_GDIO)
        .await?;

    PairingClient::from(connected_client).pair().await?;

    Ok(())
}
