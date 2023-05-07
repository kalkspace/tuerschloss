use std::convert::TryInto;

use anyhow::anyhow;
use tracing::info;

use crate::{
    client::Client,
    command::{self, Command, KeyturnerState, LockAction},
    encrypted::AuthenticatedClient,
    pairing::AuthInfo,
    APP_ID,
};

const KEY_TURNER_SERVICE: &str = "a92ee200-5501-11e4-916c-0800200c9a66";
const KEY_TURNER_USDIO: &str = "a92ee202-5501-11e4-916c-0800200c9a66";

pub struct Keyturner {
    authenticated_client: AuthenticatedClient,
}

impl Keyturner {
    pub async fn new(auth_info: AuthInfo, client: Client) -> Result<Self, anyhow::Error> {
        let characteristic = client
            .with_characteristic(KEY_TURNER_SERVICE, KEY_TURNER_USDIO)
            .await?;

        let authenticated_client = AuthenticatedClient::new(auth_info, characteristic);

        Ok(Keyturner {
            authenticated_client,
        })
    }

    pub async fn run_action(
        &mut self,
        action: LockAction,
    ) -> Result<KeyturnerState, anyhow::Error> {
        self.authenticated_client
            .write(Command::RequestData(Command::Challenge(Vec::new()).id()))
            .await?;

        let received_challenge = self.authenticated_client.receive().await?;
        let challenge = match received_challenge {
            Command::Challenge(c) => c,
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unexpected response")),
        };

        let lock_action_command = Command::LockAction {
            action,
            app_id: APP_ID,
            flags: 0,
            name_suffix: "".to_string(),
            nonce: challenge
                .try_into()
                .map_err(|_| anyhow!("Invalid challenge length"))?,
        };
        self.authenticated_client.write(lock_action_command).await?;

        let received_status = self.authenticated_client.receive().await?;
        match received_status {
            Command::Status(command::StatusCode::Accepted) => {}
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unexpected status")),
        };

        let mut last_state = None;

        loop {
            let received_command = self.authenticated_client.receive().await?;
            match received_command {
                Command::Status(command::StatusCode::Complete) => break,
                Command::ErrorReport { code, .. } => return Err(code.into()),
                Command::KeyturnerStates(state) => {
                    info!("KeyturnerState: {:?}", state);
                    last_state = state;
                }
                _ => return Err(anyhow!("Unexpected command")),
            }
        }

        last_state.ok_or(anyhow!("Missing state from lock"))
    }

    pub async fn request_state(&mut self) -> Result<KeyturnerState, anyhow::Error> {
        self.authenticated_client
            .write(Command::RequestData(Command::KeyturnerStates(None).id()))
            .await?;
        let state = match self.authenticated_client.receive().await? {
            Command::KeyturnerStates(Some(state)) => state,
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unexpected response")),
        };
        Ok(state)
    }
}
