use anyhow::anyhow;
use bluez_async::{
    BluetoothEvent, BluetoothSession, CharacteristicEvent, CharacteristicInfo, DeviceEvent,
    DeviceInfo, MacAddress,
};
use futures_util::StreamExt;
use std::{future::Future, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::command::Command;

#[derive(Debug)]
pub struct Client {
    session: Arc<BluetoothSession>,
    device: DeviceInfo,
}

pub struct UnconnectedClient {
    mac_addr: MacAddress,
}

pub struct CharacteristicClient {
    session: Arc<BluetoothSession>,
    responses: mpsc::Receiver<Vec<u8>>,
    characteristic: CharacteristicInfo,
    device: DeviceInfo,
}

impl UnconnectedClient {
    pub fn new(mac_addr: MacAddress) -> Self {
        Self { mac_addr }
    }

    pub async fn connect(self) -> Result<Client, anyhow::Error> {
        let (_, sess) = BluetoothSession::new().await?;

        info!("looking for device");
        let device = self.discover_device(&sess).await?;
        info!("found my device: {:?}", device);

        retry(5, || sess.connect(&device.id)).await?;
        info!("connected!");

        Ok(Client {
            session: Arc::new(sess),
            device,
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
                info!("starting to scan...");
                sess.start_discovery().await?;

                let events = sess.event_stream().await?;
                let info = events
                    .filter_map(|ev| {
                        info!("got even: {:?}", ev);
                        Box::pin(async {
                            if let BluetoothEvent::Device {
                                event: DeviceEvent::Discovered,
                                id,
                            } = ev
                            {
                                info!("Discovered {}", id);
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

impl Client {
    pub async fn with_characteristic(
        &self,
        service_id: &str,
        characteristic_id: &str,
    ) -> Result<CharacteristicClient, anyhow::Error> {
        // look up characteristic
        let svc = self
            .session
            .get_services(&self.device.id)
            .await?
            .into_iter()
            .find(|s| s.uuid.to_string() == service_id)
            .ok_or_else(|| anyhow!("Pairing service not found"))?;
        let characteristic = self
            .session
            .get_characteristics(&svc.id)
            .await?
            .into_iter()
            .find(|c| c.uuid.to_string() == characteristic_id)
            .ok_or_else(|| anyhow!("characteristic not found"))?;

        debug!("characteristic found: {:?}", characteristic);

        let mut events = self.session.event_stream().await?;
        let (gdio_tx, gdio_rx) = mpsc::channel(100);
        let bg_characteristic_id = characteristic.id.clone();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                debug!("Got event: {:?}", event);
                if let BluetoothEvent::Characteristic {
                    event: CharacteristicEvent::Value { value },
                    id,
                } = event
                {
                    if id == bg_characteristic_id {
                        debug!("Value: {:02X?}", value);
                        if gdio_tx.send(value).await.is_err() {
                            eprintln!("failed to send into channel!");
                        }
                    }
                }
            }
        });

        // 2. CL registers itself for indications on GDIO
        self.session.start_notify(&characteristic.id).await?;

        Ok(CharacteristicClient {
            session: Arc::clone(&self.session),
            responses: gdio_rx,
            characteristic,
            device: self.device.clone(),
        })
    }
}

impl CharacteristicClient {
    pub async fn write(&self, command: Command) -> Result<(), anyhow::Error> {
        self.write_raw(command.into_bytes()).await
    }

    pub async fn write_raw(&self, bytes: impl Into<Vec<u8>>) -> Result<(), anyhow::Error> {
        retry(5, || self.session.connect(&self.device.id)).await?;
        self.session
            .write_characteristic_value(&self.characteristic.id, bytes)
            .await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Command, anyhow::Error> {
        let resp = self.receive_raw().await?;
        let cmd = Command::parse(resp)?;
        Ok(cmd)
    }

    pub async fn receive_raw(&mut self) -> Result<Vec<u8>, anyhow::Error> {
        self.responses
            .recv()
            .await
            .ok_or_else(|| anyhow!("GDIO channel closed"))
    }
}

impl Drop for CharacteristicClient {
    fn drop(&mut self) {
        let session = Arc::clone(&self.session);
        let characteristic_id = self.characteristic.id.clone();
        tokio::spawn(async move {
            session.stop_notify(&characteristic_id).await.ok();
        });
    }
}
