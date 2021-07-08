use std::time::Duration;

#[cfg(target_os = "windows")]
use btleplug::winrtble::{adapter::Adapter, manager::Manager};
use btleplug::api::{BDAddr, Central, CentralEvent, Peripheral, WriteType, bleuuid::uuid_from_u16};

const LOCK_ADDRESS: [u8; 6] = [0x54, 0xD2, 0x72, 0xAC, 0x8D, 0xC5];

fn main() {
    let manager = Manager::new().unwrap();

    let list_adapters = manager.adapters().unwrap();

    let adapter = list_adapters.get(0).ok_or("Kein Bluethoot-Adapter vorhanden.").unwrap();

    adapter.start_scan().unwrap();

    let events = adapter.event_receiver().unwrap();
    
    println!("LOCK_ADDRESS: {:?}", LOCK_ADDRESS);
    
    let reversed: Vec<u8> = LOCK_ADDRESS.iter().cloned().rev().collect();
    
    let mut device_addr = None;

    while let Ok(event) = events.recv() {
        match event {
            CentralEvent::DeviceDiscovered(address) => {
                println!("{:?}", address.address);
                if address.address == reversed.as_slice() {
                    device_addr.replace(address);
                    println!("Device found!");
                    break;
                }
            },
            _ => {}
        }
    }
    
    adapter.stop_scan().unwrap();
    
    let device = adapter.peripheral(device_addr.unwrap()).unwrap();
    
    device.connect().unwrap();
    
    let characteristics = device.discover_characteristics().unwrap();
    
    println!("{:?}", characteristics)
}
