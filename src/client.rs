use anyhow::anyhow;
use bluez_async::{
    BluetoothError, BluetoothEvent, BluetoothSession, CharacteristicEvent, CharacteristicInfo,
    DeviceEvent, DeviceInfo, MacAddress,
};
use futures_util::StreamExt;
use std::future::Future;
use tokio::sync::mpsc;

use crate::command::Command;

const PAIRING_SERVICE: &str = "a92ee100-5501-11e4-916c-0800200c9a66";
const PAIRING_SERVICE_GDIO: &str = "a92ee101-5501-11e4-916c-0800200c9a66";

pub struct Client {
    session: Option<BluetoothSession>,
    abort_signal: Box<dyn Future<Output = ()>>,
    responses: mpsc::Receiver<Vec<u8>>,
    characteristic: CharacteristicInfo,
}

pub struct UnconnectedClient {
    mac_addr: MacAddress,
}

impl UnconnectedClient {
    pub fn new(mac_addr: MacAddress) -> Self {
        Self { mac_addr }
    }

    pub async fn connect(self) -> Result<Client, anyhow::Error> {
        let (abort_signal, sess) = BluetoothSession::new().await?;

        println!("looking for device");
        let device = self.discover_device(&sess).await?;
        println!("found my device: {:?}", device);

        let mut events = sess.event_stream().await?;
        let (gdio_tx, gdio_rx) = mpsc::channel(100);
        tokio::spawn(async move {
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

        Self::retry(5, || sess.connect(&device.id)).await?;
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

        Ok(Client {
            session: Some(sess),
            abort_signal: Box::new(async {
                abort_signal.await.ok();
            }),
            responses: gdio_rx,
            characteristic,
        })
    }

    async fn discover_device(&self, sess: &BluetoothSession) -> Result<DeviceInfo, anyhow::Error> {
        let device = sess
            .get_devices()
            .await?
            .into_iter()
            .find(|d| d.mac_address == self.mac_addr);

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
                                if info.mac_address == self.mac_addr {
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
}

impl Client {
    pub async fn write(&self, command: Command) -> Result<(), BluetoothError> {
        self.session
            .as_ref()
            .unwrap()
            .write_characteristic_value(&self.characteristic.id, command.into_bytes())
            .await
    }

    pub async fn receive(&mut self) -> Result<Command, anyhow::Error> {
        let resp = self
            .responses
            .recv()
            .await
            .ok_or_else(|| anyhow!("GDIO channel closed"))?;
        let cmd = Command::parse(&resp)?;
        Ok(cmd)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let session = self.session.take().unwrap();
        let characteristic_id = self.characteristic.id.clone();
        tokio::spawn(async move {
            session.stop_notify(&characteristic_id).await.ok();
        });
    }
}
