use std::convert::TryInto;

use anyhow::anyhow;
use client::Client;
use command::LockAction;
use futures_util::StreamExt;
use keyturner::Keyturner;
use pairing::{AuthInfo, PairingClient};
use serde::Deserialize;
use tokio::fs::read_to_string;
use tracing::info;

use crate::client::UnconnectedClient;

mod client;
mod command;
mod encrypted;
mod keyturner;
mod pairing;

const LOCK_NAME: &str = "Nuki_26AC8DC5";
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";

#[derive(Deserialize, Debug)]
struct Config {
    phone_ids: Vec<String>,
    card_ids: Vec<[u8; 4]>,
}

// only log error cases, if you're going to ignore the error otherwise
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    info!("test log zum testen");
    let config = read_to_string("config.json").await?;
    let config: Config = serde_json::from_str(&config)?;

    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let stream = nfc_stream::run().unwrap();
    tokio::pin!(stream);

    let mut connected_client = UnconnectedClient::new(LOCK_NAME.into()).connect().await?;

    let auth_info = AuthInfo::read_from_file("auth-info.json").await?;

    let mut keyturner = Keyturner::new(auth_info.clone(), &connected_client).await?;

    loop {
        let item = stream.next().await;

        if !connected_client.is_connected().await {
            info!("Reconnecting client");
            connected_client = UnconnectedClient::with_id(connected_client.device_id())
                .connect()
                .await?;
            keyturner = Keyturner::new(auth_info.clone(), &connected_client).await?;
        }

        info!("{:?}", item);

        let Some(item) = item else {
            // We expect the item to always be Some because the Stream is never closed
            unreachable!()
        };

        let Some(item) = item else {
            // If this is None there was an NFC event but we could not read an ID
            continue;
        };

        let allowed = match item {
            nfc_stream::CardDetail::MeteUuid(uuid) => config.phone_ids.contains(&uuid),
            nfc_stream::CardDetail::Plain(uuid) => config.card_ids.contains((&*uuid).try_into()?),
        };

        if allowed {
            let lock_state = keyturner.request_state().await?.lock_state;

            let action = match &lock_state {
                command::LockState::Locked => LockAction::Unlock,
                command::LockState::Unlocked => LockAction::Lock,
                state => {
                    info!("Unable to perform action. Invalid state: {:?}", state);
                    continue;
                }
            };

            keyturner.run_action(action).await?;

            // We drain the stream to prevent accidental duplicate actions
            while futures_util::poll!(stream.next()).is_ready() {}
        } else {
            info!("Unknown ID");
        }
    }
}

pub async fn pairing(connected_client: Client) -> Result<(), anyhow::Error> {
    info!("pairing");
    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    info!("writing auth info");
    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;
    info!("done");

    Ok(())
}
