use std::io::Write;
use std::{any, convert::TryInto};

use anyhow::anyhow;
use bluez_async::{
    BluetoothEvent, BluetoothSession, CharacteristicEvent, DeviceEvent, DeviceInfo, MacAddress,
};
use futures_util::{Future, StreamExt};
use rand::Rng;
use sodiumoxide::crypto::{
    auth::{self, hmacsha256},
    box_::{gen_keypair, precompute, PrecomputedKey, PublicKey, SecretKey},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::command::Command;

mod command;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const PAIRING_SERVICE: &str = "a92ee100-5501-11e4-916c-0800200c9a66";
const PAIRING_SERVICE_GDIO: &str = "a92ee101-5501-11e4-916c-0800200c9a66";
const APP_ID: u32 = 0x4d9edba9;
const APP_NAME: &str = "KalkSpace";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;
    let mut rng = rand::thread_rng();

    // 5. CL generates own keypair
    let (pub_key, secret_key) = get_keypair().await?;

    let (_, sess) = BluetoothSession::new().await?;

    println!("looking for device");
    let device = discover_device(&sess).await?;
    println!("found my device: {:?}", device);

    let mut events = sess.event_stream().await?;
    let (gdio_tx, mut gdio_rx) = mpsc::channel(100);
    let watcher = tokio::spawn(async move {
        while let Some(event) = events.next().await {
            println!("Got event: {:?}", event);
            if let BluetoothEvent::Characteristic {
                event: CharacteristicEvent::Value { value },
                id: _,
            } = event
            {
                println!("Value: {:02X?}", value);
                if gdio_tx.send(value).await.is_err() {
                    eprintln!("failed to send into channel!");
                }
            }
        }
    });

    retry(5, || sess.connect(&device.id)).await?;
    println!("connected!");

    // look up characteristic
    let svc = sess
        .get_services(&device.id)
        .await?
        .into_iter()
        .find(|s| s.uuid.to_string() == PAIRING_SERVICE)
        .ok_or_else(|| anyhow!("Pairing service not found"))?;
    let characteristic = sess
        .get_characteristics(&svc.id)
        .await?
        .into_iter()
        .find(|c| c.uuid.to_string() == PAIRING_SERVICE_GDIO)
        .ok_or_else(|| anyhow!("characteristic not found"))?;
    println!("characteristic found: {:?}", characteristic);

    // 2. CL registers itself for indications on GDIO
    sess.start_notify(&characteristic.id).await?;

    // 3. CL writes Request Data command with Public Key command identifier to GDIO
    let pub_key_request = Command::RequestData(vec![0x03, 0x00]);
    sess.write_characteristic_value(&characteristic.id, pub_key_request.into_bytes())
        .await?;
    println!("value written");

    // 4. SL sends its public key via multiple indications on GDIO
    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    let cmd = Command::parse(&resp)?;
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
    sess.write_characteristic_value(&characteristic.id, send_pub_key.into_bytes())
        .await?;

    // 9. SL sends Challenge command via multiple indications on GDIO
    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    let cmd = Command::parse(&resp)?;
    println!("Got response: {:?}", cmd);

    let challenge = match cmd {
        Command::Challenge(challenge) => challenge.try_into().map_err(|c: Vec<u8>| {
            anyhow!("Expected challenge to be 32 bytes, got {} bytes", c.len())
        })?,
        Command::ErrorReport { code, .. } => return Err(code.into()),
        _ => return Err(anyhow!("Unknown response...")),
    };

    let authenticator = calculate_authenticator(
        &shared_key,
        pub_key.as_ref().iter().chain(lock_pub_key.as_ref()),
        &challenge,
    );

    // 13. CL writes Authorization Authenticator command with authenticator a to GDIO
    let auth_authenticator = Command::AuthorizationAuthenticator(authenticator);
    sess.write_characteristic_value(&characteristic.id, auth_authenticator.into_bytes())
        .await?;
    println!("13 done");

    // 15. SL sends Challenge command via multiple indications on GDIO
    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    let cmd = Command::parse(&resp)?;
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
    let authenticator = calculate_authenticator(&shared_key, payload, &challenge);
    let auth_data = Command::AuthorizationData {
        authenticator,
        id_type,
        app_id: APP_ID,
        name,
        nonce,
    };

    let auth_data_bytes = auth_data.into_bytes();
    sess.write_characteristic_value(&characteristic.id, auth_data_bytes)
        .await?;

    // 19. SL sends Authorization-ID command via multiple indications on GDIO
    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    println!("Value: {:?}", resp);
    let cmd = Command::parse(&resp)?;
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
            let expected_authenticator = calculate_authenticator(&shared_key, payload, &nonce);
            if authenticator != expected_authenticator {
                return Err(anyhow!("authenticator verification failed..."));
            }
            (lock_nonce, authorization_id)
        }
        Command::ErrorReport { code, .. } => return Err(code.into()),
        _ => return Err(anyhow!("Unexpected command...")),
    };

    // 21. CL writes Authorization-ID Confirmation command to GDIO
    let authenticator =
        calculate_authenticator(&shared_key, &authorization_id.to_be_bytes(), &lock_nonce);
    let auth_id_confirm = Command::AuthorizationIdConfirmation {
        authenticator,
        authorization_id,
    };
    sess.write_characteristic_value(&characteristic.id, auth_id_confirm.into_bytes())
        .await?;

    // 22. SL sends Status COMPLETE via multiple indications on GDIO
    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    println!("Value: {:?}", resp);
    let cmd = Command::parse(&resp)?;
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

    sess.stop_notify(&characteristic.id).await?;
    Ok(())
}

async fn discover_device(sess: &BluetoothSession) -> Result<DeviceInfo, anyhow::Error> {
    let lock_mac: MacAddress = LOCK_ADDRESS.into();

    let device = sess
        .get_devices()
        .await?
        .into_iter()
        .find(|d| d.mac_address == lock_mac);

    let device = match device {
        Some(dev) => dev,
        None => {
            println!("starting to scan...");
            sess.start_discovery().await?;

            let events = sess.event_stream().await?;
            let info = events
                .filter_map(|ev| {
                    println!("got event: {:?}", ev);
                    Box::pin(async {
                        if let BluetoothEvent::Device {
                            event: DeviceEvent::Discovered,
                            id,
                        } = ev
                        {
                            println!("Discovered {}", id);
                            let info = sess.get_device_info(&id).await.unwrap();
                            if info.mac_address == lock_mac {
                                return Some(info);
                            }
                        }
                        None
                    })
                })
                .next()
                .await
                .ok_or_else(|| anyhow!("Device not found!"))?;

            sess.stop_discovery().await?;

            info
        }
    };
    Ok(device)
}

async fn retry<F, Fut, O, E>(limit: usize, mut f: F) -> Result<O, anyhow::Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<O, E>>,
    E: std::error::Error,
{
    for _ in 0..limit {
        match f().await {
            Ok(r) => return Ok(r),
            Err(e) => eprintln!("Retrying after error: {:?}", e),
        }
    }
    Err(anyhow!("Retry limit reached"))
}

const PUB_KEY_FILE: &str = "pub-key";
const SECRET_KEY_FILE: &str = "secret-key";

async fn get_keypair() -> Result<(PublicKey, SecretKey), anyhow::Error> {
    // checken, ob schon ein Keypair existiert und, wenn ja das Keypair direkt zurückgeben
    let pub_key_file = fs::File::open(PUB_KEY_FILE).await;
    let secret_key_file = fs::File::open(SECRET_KEY_FILE).await;
    if let (Ok(mut pub_key_file), Ok(mut secret_key_file)) = (pub_key_file, secret_key_file) {
        let mut pub_key_buffer = Vec::new();
        let mut secret_key_buffer = Vec::new();

        pub_key_file.read_to_end(&mut pub_key_buffer).await?;
        secret_key_file.read_to_end(&mut secret_key_buffer).await?;

        let pub_key = PublicKey::from_slice(&pub_key_buffer)
            .ok_or_else(|| anyhow!("File did not contain public key"))?;
        let secret_key = SecretKey::from_slice(&secret_key_buffer)
            .ok_or_else(|| anyhow!("File did not contain secret key"))?;

        return Ok((pub_key, secret_key));
    }

    // Keypair generieren
    println!("Did not found keypair. Generating new keypair...");
    let (pub_key, secret_key) = gen_keypair();

    // Keypair speichern
    let mut pub_key_file = fs::File::create(PUB_KEY_FILE).await?;
    pub_key_file.write_all(pub_key.as_ref()).await?;

    let mut secret_key_file = fs::File::create(SECRET_KEY_FILE).await?;
    secret_key_file.write_all(secret_key.as_ref()).await?;

    Ok((pub_key, secret_key))
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
