mod schc;
mod schc_rules;
mod varint;

use anyhow::{Context, bail};
use clap::Parser;
use log::{LevelFilter, error, info, warn};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv6::Ipv6Packet;
use schc::Direction;
use schc_rules::{NetmaskPair, RuleOptions, RuleSet};
use std::sync::{Arc, mpsc};
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
            info!(
                "C ({ethertype}): {} -> {}",
                frame_bytes.len(),
                compressed.len()
            );
            Ok(compressed)
        }
        Direction::Downlink => {
            // The frame is arriving through the interface, so we probably have to decompress
            if frame_was_probably_compressed(&frame) {
                let decompressed =
                    schc::decompress_frame(rules, &frame).context("failed to decompress frame")?;
                info!(
                    "D ({ethertype}): {} -> {}",
                    frame_bytes.len(),
                    decompressed.len()
                );
                Ok(decompressed)
            } else {
                info!("D ({ethertype}): {} (NOT decompressed)", frame_bytes.len(),);
                Ok(frame.packet().to_vec())
            }
        }
    }
}

fn frame_was_probably_compressed(frame: &EthernetPacket) -> bool {
    let has_forwardable_ethertype = frame.get_ethertype() == EtherTypes::Ipv6;

    let ipv6_packet = Ipv6Packet::new(frame.payload());
    let is_valid_ipv6_packet = ipv6_packet.is_some_and(|p| {
        p.get_version() == 6
            && p.get_payload_length() == p.packet().len() as u16 - 40
            && p.packet().len() == frame.payload().len()
    });

    // Valid IPv6 packet? Then the frame was not compressed (compressed frames have at least one
    // invalid byte at the beginning)
    has_forwardable_ethertype && !is_valid_ipv6_packet
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
                warn!("dropping frame. Failed to process: {e:?}");
            }
        }
    }

    Ok(())
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    swap_netmask_pairs: bool,
    #[arg(short, long, group = "verbosity")]
    verbose: bool,
    #[arg(short, long, group = "verbosity")]
    quiet: bool,
    in_tap_ifname: String,
    out_tap_ifname: String,
    netmask_pairs: Vec<NetmaskPair>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        LevelFilter::Warn
    } else if cli.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp(None)
        .init();

    let in_name = &cli.in_tap_ifname;
    let out_name = &cli.out_tap_ifname;
    let mut netmask_pairs = cli.netmask_pairs;
    if cli.swap_netmask_pairs {
        netmask_pairs = netmask_pairs.into_iter().map(|p| p.swapped()).collect();
    }

    let in_ipv4 = "10.10.0.22";
    let in_ipv6 = "fe80::22";
    let out_ipv4 = "10.10.0.33";
    let out_ipv6 = "fe80::33";
    let tap_in = open_tap(in_name, in_ipv4, in_ipv6)?;
    let tap_out = open_tap(out_name, out_ipv4, out_ipv6)?;
    info!("Created TAP interface {in_name} with addresses {in_ipv4} and {in_ipv6}");
    info!("Created TAP interface {out_name} with addresses {out_ipv4} and {out_ipv6}");

    let tap_in_cp = tap_in.clone();
    let tap_out_cp = tap_out.clone();
    let netmask_pairs_cp = netmask_pairs.clone();
    let t1 = thread::spawn(move || {
        forward_frames(&tap_in_cp, &tap_out_cp, netmask_pairs_cp, Direction::Uplink)
    });
    let t2 = thread::spawn(move || {
        forward_frames(&tap_out, &tap_in, netmask_pairs, Direction::Downlink)
    });

    info!("Forwarding ethernet frames from {in_name} to {out_name}...");
    info!("Forwarding ethernet frames from {out_name} to {in_name}...");

    // This is a bit cumbersome, but is the only way I found to be notified of errors/crashes in the
    // forwarding threads (without extra dependencies)
    let (done_tx, done_rx) = mpsc::channel();
    let done_tx_cp = done_tx.clone();
    let t1_name = format!("{in_name} -> {out_name}");
    let t2_name = format!("{out_name} -> {in_name}");
    thread::spawn(move || {
        done_tx_cp.send((t1_name, t1.join())).unwrap();
    });
    thread::spawn(move || {
        done_tx.send((t2_name, t2.join())).unwrap();
    });
    if let Ok((t_name, msg)) = done_rx.recv() {
        let extra = match msg {
            Ok(Ok(_)) => "(the thread exited cleanly)".to_string(),
            Ok(Err(e)) => format!("(the thread exited with an error: {e:?})"),
            Err(_) => "(the thread panicked)".to_string(),
        };
        error!("The forwarding thread for {t_name} terminated unexpectedly {extra}");
    }

    info!("Shutting down!");
    Ok(())
}
