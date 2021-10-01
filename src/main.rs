use anyhow::anyhow;
use bluez_async::{
    BluetoothEvent, BluetoothSession, CharacteristicEvent, DeviceEvent, DeviceInfo, MacAddress,
};
use futures_util::{Future, StreamExt};
use sodiumoxide::crypto::box_::{gen_keypair, precompute, PublicKey, SecretKey};
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide..."))?;

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

    sess.start_notify(&characteristic.id).await?;

    let pub_key_request = Command::RequestData {
        data: vec![0x03, 0x00],
    };
    sess.write_characteristic_value(&characteristic.id, pub_key_request.into_bytes())
        .await?;
    println!("value written");

    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    let cmd = Command::parse(&resp)?;
    let lock_pub_key = match cmd {
        Command::PublicKey { key } => {
            PublicKey::from_slice(&key).ok_or_else(|| anyhow!("Invalid key..."))?
        }
        Command::ErrorReport {
            code,
            command_ident,
        } => return Err(code.into()),
        _ => return Err(anyhow!("Unknow command...")),
    };

    // compute shared key via diffie-hellman
    let shared_key = precompute(&lock_pub_key, &secret_key);

    let send_pub_key = Command::PublicKey {
        key: pub_key.as_ref().into(),
    };
    sess.write_characteristic_value(&characteristic.id, send_pub_key.into_bytes())
        .await?;

    let resp = gdio_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("GDIO channel closed"))?;
    let cmd = Command::parse(&resp)?;
    println!("Got response: {:?}", cmd);

    watcher.await?;
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
