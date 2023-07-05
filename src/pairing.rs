use std::{convert::TryInto, io::Write};

use anyhow::anyhow;
use base64::STANDARD;
use base64_serde::base64_serde_type;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sodiumoxide::crypto::{
    auth::hmacsha256,
    box_::{gen_keypair, precompute, PrecomputedKey, PublicKey},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use tracing::info;

use crate::{
    client::{CharacteristicClient, Client},
    command::{self, Command},
    APP_ID, APP_NAME,
};

const PAIRING_SERVICE: &str = "a92ee100-5501-11e4-916c-0800200c9a66";
const PAIRING_SERVICE_GDIO: &str = "a92ee101-5501-11e4-916c-0800200c9a66";

pub struct PairingClient {
    client: CharacteristicClient,
}

base64_serde_type!(Base64Serde, STANDARD);

#[derive(Serialize, Deserialize)]
pub struct AuthInfo {
    pub authorization_id: u32,
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    pub shared_key: PrecomputedKey,
}

impl PairingClient {
    pub async fn from_client(client: Client) -> Result<Self, anyhow::Error> {
        let pairing_client = client
            .with_characteristic(PAIRING_SERVICE, PAIRING_SERVICE_GDIO)
            .await?
            .into();

        Ok(pairing_client)
    }

    pub async fn pair(&mut self) -> Result<AuthInfo, anyhow::Error> {
        // 5. CL generates own keypair
        let (pub_key, secret_key) = gen_keypair();

        // 3. CL writes Request Data command with Public Key command identifier to GDIO
        let pub_key_request = Command::RequestData(Command::PublicKey(Vec::new()).id());

        self.client.write(pub_key_request).await?;
        info!("value written");

        // 4. SL sends its public key via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        let lock_pub_key = match cmd {
            Command::PublicKey(key) => {
                PublicKey::from_slice(&key).ok_or_else(|| anyhow!("Invalid key..."))?
            }
            Command::ErrorReport { code, .. } => return Err(code.into()),
            _ => return Err(anyhow!("Unknown command...")),
        };

        // 7. Both sides calculate DH Key k using function dh1
        // 8. Both sides derive a long term shared secret key s from k using function kdf1
        let shared_key = precompute(&lock_pub_key, &secret_key);

        // 6. CL writes Public Key command to GDIO
        let send_pub_key = Command::PublicKey(pub_key.as_ref().into());
        self.client.write(send_pub_key).await?;

        // 9. SL sends Challenge command via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        info!("Got response: {:?}", cmd);

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
        info!("13 done");

        // 15. SL sends Challenge command via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        info!("Got response: {:?}", cmd);
        info!("15 done");

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
        name_ref.write_all(APP_NAME.as_bytes()).unwrap();

        // compute nonce
        let mut nonce = [0; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut nonce);

        // serialize id_type
        let id_type = command::IdType::App;
        let id_type_num = id_type.into();

        // serialize app_id
        let app_id_bytes = APP_ID.to_le_bytes();

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
        info!("Got response: {:?}", cmd);

        // 20. CL verifies the received authenticator
        let (lock_nonce, authorization_id) = match cmd {
            Command::AuthorizationId {
                authenticator,
                authorization_id,
                uuid,
                nonce: lock_nonce,
            } => {
                let authorization_id_bytes = authorization_id.to_le_bytes();
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
            &authorization_id.to_le_bytes(),
            &lock_nonce,
        );
        let auth_id_confirm = Command::AuthorizationIdConfirmation {
            authenticator,
            authorization_id,
        };
        self.client.write(auth_id_confirm).await?;

        // 22. SL sends Status COMPLETE via multiple indications on GDIO
        let cmd = self.client.receive().await?;
        info!("Got response: {:?}", cmd);

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

        Ok(AuthInfo {
            authorization_id,
            shared_key,
        })
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
        info!("10 done");

        // 11. CL calculates the authenticator a of r using function h1
        let auth_key = hmacsha256::Key::from_slice(shared_key.as_ref()).unwrap();
        let authenticator = hmacsha256::authenticate(&r, &auth_key);
        info!("11 done");

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

impl AuthInfo {
    pub async fn write_to_file(&self, file_name: &str) -> Result<(), anyhow::Error> {
        let mut file = File::create(file_name).await?;
        let encoded_info = serde_json::to_string_pretty(self)?;
        file.write_all(encoded_info.as_ref()).await?;
        Ok(())
    }

    pub async fn read_from_file(file_name: &str) -> Result<AuthInfo, anyhow::Error> {
        let file = fs::read_to_string(file_name).await?;
        let decoded_info = serde_json::from_str(&file)?;
        Ok(decoded_info)
    }
}

fn serialize_key<S>(key: &PrecomputedKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(key))
}

fn deserialize_key<'de, D>(deserializer: D) -> Result<PrecomputedKey, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let secret_key_bytes = base64::decode(encoded).map_err(serde::de::Error::custom)?;
    let secret_key = PrecomputedKey::from_slice(&secret_key_bytes)
        .ok_or_else(|| serde::de::Error::custom("Invalid secret key"))?;

    Ok(secret_key)
}
