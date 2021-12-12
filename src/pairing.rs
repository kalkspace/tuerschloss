use std::{convert::TryInto, io::Write};

use anyhow::anyhow;
use rand::Rng;
use sodiumoxide::crypto::{
    auth::hmacsha256,
    box_::{gen_keypair, precompute, PrecomputedKey, PublicKey},
};

use crate::{
    client::CharacteristicClient,
    command::{self, Command},
    APP_ID, APP_NAME,
};

pub struct PairingClient {
    client: CharacteristicClient,
}

impl PairingClient {
    pub async fn pair(&mut self) -> Result<(), anyhow::Error> {
        // 5. CL generates own keypair
        let (pub_key, secret_key) = gen_keypair();

        // 3. CL writes Request Data command with Public Key command identifier to GDIO
        let pub_key_request = Command::RequestData(vec![0x03, 0x00]);

        self.client.write(pub_key_request).await?;
        println!("value written");

        // 4. SL sends its public key via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        let lock_pub_key = match cmd {
            Command::PublicKey(key) => {
                PublicKey::from_slice(&key).ok_or_else(|| anyhow!("Invalid key..."))?
            }
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unknow command...")),
        };

        // 7. Both sides calculate DH Key k using function dh1
        // 8. Both sides derive a long term shared secret key s from k using function kdf1
        let shared_key = precompute(&lock_pub_key, &secret_key);

        // 6. CL writes Public Key command to GDIO
        let send_pub_key = Command::PublicKey(pub_key.as_ref().into());
        self.client.write(send_pub_key).await?;

        // 9. SL sends Challenge command via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        println!("Got response: {:?}", cmd);

        let challenge = match cmd {
            Command::Challenge(challenge) => challenge.try_into().map_err(|c: Vec<u8>| {
                anyhow!("Expected challenge to be 32 bytes, got {} bytes", c.len())
            })?,
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unknown response...")),
        };

        let authenticator = Self::calculate_authenticator(
            &shared_key,
            pub_key.as_ref().iter().chain(lock_pub_key.as_ref()),
            &challenge,
        );

        // 13. CL writes Authorization Authenticator command with authenticator a to GDIO
        let auth_authenticator = Command::AuthorizationAuthenticator(authenticator);
        self.client.write(auth_authenticator).await?;
        println!("13 done");

        // 15. SL sends Challenge command via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        println!("Got response: {:?}", cmd);
        println!("15 done");

        // 16. CL writes Authorization Data command to GDIO
        let challenge = match cmd {
            Command::Challenge(challenge) => challenge.try_into().map_err(|c: Vec<u8>| {
                anyhow!("Expected challenge to be 32 bytes, got {} bytes", c.len())
            })?,
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unknown response...")),
        };

        // serialize name
        let mut name = [0; 32];
        let mut name_ref: &mut [u8] = &mut name;
        name_ref.write(APP_NAME.as_bytes()).unwrap();

        // compute nonce
        let mut nonce = [0; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut nonce);

        // serialize id_type
        let id_type = command::IdType::App;
        let id_type_num = id_type.into();

        // serialize app_id
        let app_id_bytes = APP_ID.to_be_bytes();

        // concatenate authenticator parameter
        let payload = Some(&id_type_num)
            .into_iter()
            .chain(app_id_bytes.iter())
            .chain(name.iter())
            .chain(&nonce);

        // calculate authenticator from partial payload and nonce
        let authenticator = Self::calculate_authenticator(&shared_key, payload, &challenge);
        let auth_data = Command::AuthorizationData {
            authenticator,
            id_type,
            app_id: APP_ID,
            name,
            nonce,
        };

        self.client.write(auth_data).await?;

        // 19. SL sends Authorization-ID command via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        println!("Got response: {:?}", cmd);

        // 20. CL verifies the received authenticator
        let (lock_nonce, authorization_id) = match cmd {
            Command::AuthorizationId {
                authenticator,
                authorization_id,
                uuid,
                nonce: lock_nonce,
            } => {
                let authorization_id_bytes = authorization_id.to_be_bytes();
                let payload = authorization_id_bytes
                    .iter()
                    .chain(uuid.iter())
                    .chain(&lock_nonce);
                let expected_authenticator =
                    Self::calculate_authenticator(&shared_key, payload, &nonce);
                if authenticator != expected_authenticator {
                    return Err(anyhow!("authenticator verification failed..."));
                }
                (lock_nonce, authorization_id)
            }
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unexpected command...")),
        };

        // 21. CL writes Authorization-ID Confirmation command to GDIO
        let authenticator = Self::calculate_authenticator(
            &shared_key,
            &authorization_id.to_be_bytes(),
            &lock_nonce,
        );
        let auth_id_confirm = Command::AuthorizationIdConfirmation {
            authenticator,
            authorization_id,
        };
        self.client.write(auth_id_confirm).await?;

        // 22. SL sends Status COMPLETE via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        println!("Got response: {:?}", cmd);

        match cmd {
            Command::Status(code) => match code {
                command::StatusCode::Complete => (),
                command::StatusCode::Accepted => {
                    return Err(anyhow!("Expect status to be complete..."))
                }
            },
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unexpected response...")),
        }

        Ok(())
    }

    fn calculate_authenticator<'a>(
        shared_key: &PrecomputedKey,
        payload: impl IntoIterator<Item = &'a u8>,
        challenge: &[u8; 32],
    ) -> [u8; 32] {
        // 10. CL concatenates its own public key with SL’s public key and the challenge to value r
        let mut r = Vec::new();
        r.extend(payload.into_iter());
        r.extend_from_slice(challenge);
        println!("10 done");

        // 11. CL calculates the authenticator a of r using function h1
        let auth_key = hmacsha256::Key::from_slice(shared_key.as_ref()).unwrap();
        let authenticator = hmacsha256::authenticate(&r, &auth_key);
        println!("11 done");

        authenticator.0
    }
}

impl From<CharacteristicClient> for PairingClient {
    fn from(characteristic_client: CharacteristicClient) -> Self {
        PairingClient {
            client: characteristic_client,
        }
    }
}
