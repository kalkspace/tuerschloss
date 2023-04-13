use std::{convert::TryInto, fs, net::Ipv4Addr, path::Path, sync::Arc};

use anyhow::anyhow;
use axum::{
    extract::Extension,
    routing::{get, post},
    AddExtensionLayer, Router,
};
use client::Client;
use command::{Command, LockAction};
use encrypted::AuthenticatedClient;
use futures_util::StreamExt;
use getraenkekassengeraete::nfcservice;
use hyperlocal::UnixServerExt;
use keyturner::Keyturner;
use pairing::{AuthInfo, PairingClient};
use serde::Deserialize;
use tokio::{fs::read_to_string, sync::Mutex};

use crate::client::UnconnectedClient;

mod client;
mod command;
mod encrypted;
mod keyturner;
mod pairing;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";

#[derive(Deserialize, Debug)]
struct Config {
    phone_ids: Vec<String>,
    card_ids: Vec<[u8; 4]>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = read_to_string("config.json").await?;
    let config: Config = serde_json::from_str(&config)?;

    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let stream = nfcservice::run().unwrap();
    tokio::pin!(stream);

    let connected_client = UnconnectedClient::new(LOCK_ADDRESS.into())
        .connect()
        .await?;

    let auth_info = AuthInfo::read_from_file("auth-info.json").await?;

    let mut keyturner = Keyturner::new(auth_info, connected_client).await?;

    loop {
        let item = stream.next().await;

        println!("{:?}", item);

        let Some(item) = item else {
            // We expect the item to always be Some because the Stream is never closed
            unreachable!()
        };

        let Some(item) = item else {
            // If this is None there was an NFC event but we could not read an ID
            continue;
        };

        let allowed = match item {
            nfcservice::CardDetail::MeteUuid(uuid) => config.phone_ids.contains(&uuid),
            nfcservice::CardDetail::Plain(uuid) => {
                let uuid_slice: &[u8] = &*uuid;
                config.card_ids.contains(uuid_slice.try_into()?)
            }
        };

        if allowed {
            let lock_state = keyturner.request_state().await?.lock_state;

            let action = match &lock_state {
                command::LockState::Locked => LockAction::Unlock,
                command::LockState::Unlocked => LockAction::Lock,
                state => {
                    println!("Unable to perform action. Invalid state: {:?}", state);
                    continue;
                }
            };

            keyturner.run_action(action).await?.lock_state;
        } else {
            println!("Unknown ID");
        }
    }
}

pub async fn pairing(connected_client: Client) -> Result<(), anyhow::Error> {
    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;

    Ok(())
}
