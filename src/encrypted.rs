use anyhow::anyhow;
use bluez_async::BluetoothError;
use sodiumoxide::crypto::box_::{gen_nonce, open_precomputed, seal_precomputed, Nonce};

use crate::{client::CharacteristicClient, command::Command, pairing::AuthInfo};

pub struct AuthenticatedClient {
    auth_info: AuthInfo,
    client: CharacteristicClient,
}

impl AuthenticatedClient {
    pub fn new(auth_info: AuthInfo, client: CharacteristicClient) -> Self {
        Self { auth_info, client }
    }

    pub async fn write(&self, command: Command) -> Result<(), BluetoothError> {
        let payload = command.into_bytes_with_auth(self.auth_info.authorization_id);
        println!("sending plaintext: {:02X?}", payload);

        let nonce = gen_nonce();
        let ciphertext = seal_precomputed(&payload, &nonce, &self.auth_info.shared_key);

        let mut message = Vec::new();
        message.extend_from_slice(nonce.as_ref());
        message.extend_from_slice(&self.auth_info.authorization_id.to_le_bytes());
        let ciphertext_len = (ciphertext.len() as u16).to_le_bytes();
        message.extend_from_slice(&ciphertext_len);
        message.extend_from_slice(&ciphertext);
        println!("sending full message: {:02X?}", message);

        self.client.write_raw(message).await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Command, anyhow::Error> {
        let encrypted_bytes = self.client.receive_raw().await?;
        if encrypted_bytes.len() < 30 {
            return Err(anyhow!("Invalid length"));
        }
        let (nonce, encrypted_bytes) = encrypted_bytes.split_at(24);
        let (_, encrypted_bytes) = encrypted_bytes.split_at(6);
        let nonce = Nonce::from_slice(nonce).ok_or_else(|| anyhow!("Invalid nonce"))?;

        let decrypted_bytes = open_precomputed(encrypted_bytes, &nonce, &self.auth_info.shared_key)
            .map_err(|_| anyhow!("Failed to decrypt message"))?;

        println!("received plaintext: {:02X?}", decrypted_bytes);

        let (cmd, _auth_id) = Command::parse_with_auth(&decrypted_bytes)?;

        Ok(cmd)
    }
}
