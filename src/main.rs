use std::{convert::TryInto, fs, path::Path, sync::Arc};

use anyhow::anyhow;
use axum::{
    extract::Extension,
    routing::{get, post},
    AddExtensionLayer, Router,
};
use client::Client;
use command::{Command, LockAction};
use encrypted::AuthenticatedClient;
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

    let connected_client = UnconnectedClient::new(LOCK_ADDRESS.into())
        .connect()
        .await?;

    let auth_info = AuthInfo::read_from_file("auth-info.json").await?;

    let keyturner = Keyturner::new(auth_info, connected_client).await?;
    let shared_state = Arc::new(Mutex::new(keyturner));

    // build our application with a single route
    let app = Router::new()
        .route("/lock", post(lock))
        .route("/unlock", post(unlock))
        .layer(AddExtensionLayer::new(shared_state));

    let path = Path::new("/tmp/lock");
    if path.exists() {
        fs::remove_file(path)?;
    }
    // run it with hyper on localhost:3000
    axum::Server::bind_unix(path)?
        .serve(app.into_make_service())
        .await?;

    //pairing(connected_client).await?;

    Ok(())
}

async fn lock(Extension(keyturner): Extension<Arc<Mutex<Keyturner>>>) -> &'static str {
    let mut keyturner = keyturner.lock().await;
    keyturner.run_action(LockAction::Lock).await.unwrap();
    "Locked"
}

async fn unlock(Extension(keyturner): Extension<Arc<Mutex<Keyturner>>>) -> &'static str {
    let mut keyturner = keyturner.lock().await;
    keyturner.run_action(LockAction::Unlock).await.unwrap();
    "Unlocked"
}

pub async fn pairing(connected_client: Client) -> Result<(), anyhow::Error> {
    let auth_info = PairingClient::from_client(connected_client)
        .await?
        .pair()
        .await?;

    AuthInfo::write_to_file(&auth_info, "auth-info.json").await?;

    Ok(())
}
