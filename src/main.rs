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
use tokio::sync::Mutex;

use crate::client::UnconnectedClient;

mod client;
mod command;
mod encrypted;
mod keyturner;
mod pairing;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";
const ALLOWED_CARD_IDS: &[&str] = &["01856030-2324-47e3-ac1e-d3cb0ddabbef"];

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
            unreachable!()
        };

        let Some(item) = item else {
            continue;
        };

        match item {
            nfcservice::CardDetail::MeteUuid(uuid) => {
                if ALLOWED_CARD_IDS.contains(&&*uuid) {
                    keyturner.run_action(LockAction::Unlock).await?;
                }
            }
            nfcservice::CardDetail::Plain(_) => continue,
        }
    }

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
