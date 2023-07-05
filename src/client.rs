use anyhow::anyhow;

use bluest::{Adapter, Characteristic, Device};
use futures_util::StreamExt;
use std::{future::Future, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::command::Command;

#[derive(Debug)]
pub struct Client {
    adapter: Arc<Adapter>,
    device: Device,
}

pub struct UnconnectedClient {
    name: String,
}

pub struct CharacteristicClient {
    adapter: Arc<Adapter>,
    responses: mpsc::Receiver<Vec<u8>>,
    characteristic: Arc<Characteristic>,
    device: Device,
}

impl UnconnectedClient {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub async fn connect(self) -> Result<Client, anyhow::Error> {
        let adapter = Adapter::default()
            .await
            .ok_or_else(|| anyhow!("Bluetooth adapter not found"))?;
        adapter.wait_available().await?;

        info!("looking for device");
        let device = self.discover_device(&adapter).await?;
        info!("found my device: {:?}", device);

        adapter.connect_device(&device).await?;
        info!("connected!");

        device.pair().await?;
        info!("paired!");

        Ok(Client {
            adapter: Arc::new(adapter),
            device,
        })
    }

    async fn discover_device(&self, adapter: &Adapter) -> Result<Device, anyhow::Error> {
        info!("starting scan");
        let mut scan = adapter.scan(&[]).await?;
        info!("scan started");

        while let Some(discovered_device) = scan.next().await {
            debug!(
                "{} - {}: {:?}",
                discovered_device
                    .device
                    .name()
                    .as_deref()
                    .unwrap_or("(unknown)"),
                discovered_device.device.id(),
                discovered_device.adv_data.services
            );
            if discovered_device
                .device
                .name()
                .as_deref()
                .map(|name| name == self.name)
                .unwrap_or(false)
            {
                return Ok(discovered_device.device);
            }
        }

        unreachable!();
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
        let service = self
            .device
            .discover_services()
            .await?
            .into_iter()
            .find(|service| service.uuid().to_string() == service_id)
            .ok_or_else(|| anyhow!("Service not found"))?;

        let characteristic = service
            .discover_characteristics()
            .await?
            .into_iter()
            .find(|characteristic| characteristic.uuid().to_string() == characteristic_id)
            .ok_or_else(|| anyhow!("Characteristic not found"))?;

        debug!(
            "characteristic found: {:?} {:?}",
            characteristic,
            characteristic.properties().await?
        );

        let (tx, rx) = mpsc::channel(10);

        let characteristic = Arc::new(characteristic);

        let notify_characteristic = Arc::clone(&characteristic);
        tokio::spawn(async move {
            // 2. CL registers itself for indications on GDIO
            let mut responses = notify_characteristic.notify().await.unwrap();
            while let Some(bytes) = responses.next().await {
                match bytes {
                    Ok(bytes) => tx.send(bytes).await.unwrap(),
                    Err(e) => warn!(error = ?e, "Error receiving notification"),
                }
            }
            info!("Notification stream ended");
        });

        Ok(CharacteristicClient {
            adapter: Arc::clone(&self.adapter),
            characteristic,
            device: self.device.clone(),
            responses: rx,
        })
    }
}

impl CharacteristicClient {
    pub async fn write(&self, command: Command) -> Result<(), anyhow::Error> {
        self.write_raw(command.into_bytes()).await
    }

    pub async fn write_raw(&self, bytes: impl AsRef<[u8]>) -> Result<(), anyhow::Error> {
        if !self.device.is_connected().await {
            retry(5, || {
                debug!("Connecting to device");
                self.adapter.connect_device(&self.device)
            })
            .await?;
        }
        self.characteristic.write(bytes.as_ref()).await?;

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
            .ok_or_else(|| anyhow!("No data received"))
    }
}
