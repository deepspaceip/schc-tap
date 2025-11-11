mod schc;
mod schc_rules;
mod varint;

use anyhow::bail;
use clap::Parser;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use schc::Direction;
use schc_rules::{NetmaskPair, RuleOptions, RuleSet};
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
            let compressed = schc::compress_frame(rules, &frame);
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
    netmask_pairs: Vec<NetmaskPair>,
    direction: Direction,
) -> anyhow::Result<()> {
    let rules = schc_rules::load_rules(&RuleOptions {
        compress_netmask_pairs: netmask_pairs,
        ..RuleOptions::default()
    });
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

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    swap_netmask_pairs: bool,
    in_tap_ifname: String,
    out_tap_ifname: String,
    netmask_pairs: Vec<NetmaskPair>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let in_name = &cli.in_tap_ifname;
    let out_name = &cli.out_tap_ifname;
    let mut netmask_pairs = cli.netmask_pairs;
    if cli.swap_netmask_pairs {
        netmask_pairs = netmask_pairs.into_iter().map(|p| p.swapped()).collect();
    }

    let tap_in = open_tap(in_name, "10.10.0.22", "fe80::22")?;
    let tap_out = open_tap(out_name, "10.10.0.33", "fe80::33")?;

    let tap_in_cp = tap_in.clone();
    let tap_out_cp = tap_out.clone();
    let netmask_pairs_cp = netmask_pairs.clone();
    thread::spawn(move || {
        forward_frames(&tap_in_cp, &tap_out_cp, netmask_pairs_cp, Direction::Uplink)
    });
    thread::spawn(move || forward_frames(&tap_out, &tap_in, netmask_pairs, Direction::Downlink));

    // Wait for a newline before closing
    std::io::stdin().read_line(&mut String::new())?;
    Ok(())
}
