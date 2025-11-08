mod schc;

use crate::schc::{Direction, RuleSet};
use anyhow::bail;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::sync::Arc;
use std::thread;
use tun_rs::{DeviceBuilder, Layer, SyncDevice};

fn open_tap(name: &str, ipv4: &str, ipv6: &str) -> anyhow::Result<Arc<SyncDevice>> {
    let device = DeviceBuilder::new()
        .name(name)
        .ipv4(ipv4, 24, None)
        .ipv6(ipv6, 64)
        .layer(Layer::L2)
        .build_sync()?;

    Ok(Arc::new(device))
}

fn process_frame(
    rules: &RuleSet,
    frame_bytes: &[u8],
    direction: Direction,
) -> anyhow::Result<Vec<u8>> {
    let Some(frame) = EthernetPacket::new(frame_bytes) else {
        bail!("ethernet frame was too short");
    };

    let ethertype = match frame.get_ethertype() {
        EtherTypes::Ipv4 => "IPv4".to_string(),
        EtherTypes::Ipv6 => "IPv6".to_string(),
        e => format!("{e}"),
    };

    match direction {
        Direction::Uplink => {
            // The frame is leaving the interface, so we have to compress
            let compressed = schc::compress_frame(rules, &frame, direction);
            println!(
                "C ({ethertype}): {} -> {}",
                frame_bytes.len(),
                compressed.len()
            );
            Ok(compressed)
        }
        Direction::Downlink => {
            // The frame is arriving through the interface, so we have to decompress
            let decompressed = schc::decompress_frame(rules, &frame);
            println!(
                "D ({ethertype}): {} -> {}",
                frame_bytes.len(),
                decompressed.len()
            );
            Ok(decompressed)
        }
    }
}

fn forward_frames(
    receiver: &SyncDevice,
    sender: &SyncDevice,
    direction: Direction,
) -> anyhow::Result<()> {
    let rules = schc::load_rules();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = receiver.recv(&mut buf)?;
        if n == 0 {
            break;
        }

        // Compress or decompress the frame
        match process_frame(&rules, &buf[..n], direction) {
            Ok(processed) => {
                // Forward to the other TAP
                sender.send(&processed)?;
            }
            Err(e) => {
                println!("WARN: dropping frame. Cause: {e}");
            }
        }
    }

    println!("Shutting down forwarder...");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <in_tap_ifname> <out_tap_ifname>", args[0]);
        std::process::exit(1);
    }

    let in_name = &args[1];
    let out_name = &args[2];

    let tap_in = open_tap(in_name, "10.10.0.22", "fe80::22")?;
    let tap_out = open_tap(out_name, "10.10.0.33", "fe80::33")?;

    let tap_in_cp = tap_in.clone();
    let tap_out_cp = tap_out.clone();
    thread::spawn(move || forward_frames(&tap_in_cp, &tap_out_cp, Direction::Uplink));
    thread::spawn(move || forward_frames(&tap_out, &tap_in, Direction::Downlink));

    // Wait for a newline before closing
    std::io::stdin().read_line(&mut String::new())?;
    Ok(())
}
