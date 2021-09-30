use std::time::Duration;

use anyhow::anyhow;
use btleplug::api::{BDAddr, Central, CentralEvent, Manager as _, Peripheral as _, WriteType};
use btleplug::platform::{Adapter, Manager};
use futures_util::StreamExt;
use uuid::Uuid;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const PAIRING_SERVICE_UUID: &str = "a92ee101-5501-11e4-916c-0800200c9a66";

#[tokio::main]
async fn main() {
    let pairing_uuid: Uuid = PAIRING_SERVICE_UUID.parse().unwrap();

    let lock_address: BDAddr = LOCK_ADDRESS.into();
    println!("LOCK_ADDRESS: {:?}", lock_address);

    let adapter = get_bluetooth_adapter().await.unwrap();
    adapter.start_scan().await.unwrap();
    let mut events = adapter.events().await.unwrap();

    let mut device_addr = None;
    while let Some(event) = events.next().await {
        match event {
            CentralEvent::DeviceDiscovered(address) => {
                println!("Discover: {:?}", address);
                if address == lock_address {
                    device_addr.replace(address);
                    println!("Device found!");
                    break;
                }
            }
            _ => {}
        }
    }

    adapter.stop_scan().await.unwrap();

    let device = adapter.peripheral(device_addr.unwrap()).await.unwrap();

    for _ in 0..=5 {
        match device.connect().await {
            Ok(_) => break,
            Err(e) => println!("Error: {}", e),
        }
    }

    let characteristics = device.discover_characteristics().await.unwrap();

    let mut pairing_gdio = None;
    for characteristic in characteristics {
        println!("UUID: {}", characteristic.uuid);
        if characteristic.uuid == pairing_uuid {
            println!("found");
            pairing_gdio = Some(characteristic);
        }
    }

    let pairing_gdio = pairing_gdio.unwrap();
    // device.on_notification(Box::new(|value| println!("{:?}", value)));
    device.subscribe(&pairing_gdio).await.unwrap();

    let mut pub_key_request = vec![0x01, 0x00, 0x03, 0x00, 0x27, 0xA7];
    pub_key_request.reverse();

    device
        .write(&pairing_gdio, &pub_key_request, WriteType::WithResponse)
        .await
        .unwrap();

    println!("write done");

    std::thread::sleep(Duration::from_secs(30));
}

async fn get_bluetooth_adapter() -> Result<Adapter, anyhow::Error> {
    let manager = Manager::new().await?;

    let mut list_adapters = manager.adapters().await?;

    let adapter = list_adapters
        .drain(0..)
        .next()
        .ok_or_else(|| anyhow!("Kein Bluetooth-Adapter vorhanden."))?;

    Ok(adapter)
}
