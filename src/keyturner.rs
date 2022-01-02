use std::convert::TryInto;

use anyhow::anyhow;

use crate::{
    client::Client,
    command::{self, Command, LockAction},
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

    pub async fn run_action(self: &mut Self, action: LockAction) -> Result<(), anyhow::Error> {
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

        loop {
            let received_command = self.authenticated_client.receive().await?;
            match received_command {
                Command::Status(command::StatusCode::Complete) => break,
                Command::ErrorReport { code, .. } => return Err(code.into()),
                s @ Command::KeyturnerStates { .. } => {
                    println!("KeyturnerState: {:?}", s);
                }
                _ => return Err(anyhow!("Unexpected command")),
            }
        }

        Ok(())
    }
}
