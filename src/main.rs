use std::time::Duration;

use btleplug::api::{bleuuid::uuid_from_u16, BDAddr, Central, CentralEvent, Peripheral, WriteType};
#[cfg(target_os = "windows")]
use btleplug::winrtble::{adapter::Adapter, manager::Manager};
use uuid::Uuid;

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];
const PAIRING_SERVICE_UUID: &str = "a92ee101-5501-11e4-916c-0800200c9a66";

fn main() {
    let pairing_uuid: Uuid = PAIRING_SERVICE_UUID.parse().unwrap();

    println!("LOCK_ADDRESS: {:?}", LOCK_ADDRESS);
    let lock_address_reversed: Vec<u8> = LOCK_ADDRESS.iter().cloned().rev().collect();

    let adapter = get_bluetooth_adapter().unwrap();
    adapter.start_scan().unwrap();
    let events = adapter.event_receiver().unwrap();

    let mut device_addr = None;
    while let Ok(event) = events.recv() {
        match event {
            CentralEvent::DeviceDiscovered(address) => {
                println!("Discover: {:?}", address.address);
                if address.address == lock_address_reversed.as_slice() {
                    device_addr.replace(address);
                    println!("Device found!");
                    break;
                }
            }
            _ => {}
        }
    }

    adapter.stop_scan().unwrap();

    let device = adapter.peripheral(device_addr.unwrap()).unwrap();

    // TODO: Retrys, wenn connect() fehlschlägt
    device.connect().unwrap();

    let characteristics = device.discover_characteristics().unwrap();

    let mut pairing_gdio = None;
    for characteristic in characteristics {
        println!("UUID: {}", characteristic.uuid);
        if characteristic.uuid == pairing_uuid {
            println!("found");
            pairing_gdio = Some(characteristic);
        }
    }

    let pairing_gdio = pairing_gdio.unwrap();
    device.on_notification(Box::new(|value| println!("{:?}", value)));
    device.subscribe(&pairing_gdio).unwrap();

    let mut pub_key_request = vec![0x01, 0x00, 0x03, 0x00, 0x27, 0xA7];
    pub_key_request.reverse();

    device
        .write(&pairing_gdio, &pub_key_request, WriteType::WithResponse)
        .unwrap();

    println!("write done");

    std::thread::sleep(Duration::from_secs(30));
}

fn get_bluetooth_adapter() -> Result<Adapter, btleplug::Error> {
    let manager = Manager::new()?;

    let mut list_adapters = manager.adapters()?;

    let adapter = list_adapters
        .drain(0..)
        .next()
        .ok_or_else(|| btleplug::Error::Other("Kein Bluetooth-Adapter vorhanden.".to_string()))?;

    Ok(adapter)
}
