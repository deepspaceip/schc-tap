use crate::schc::{
    CompressionDecompressionAction, Direction, DirectionIndicator, FieldDescriptor,
    FieldIdentifier, MatchingOperator, MatchingOperatorCandidate, Rule,
};
use anyhow::{Context, bail};
use bitvec::bitvec;
use bitvec::order::Msb0;
use bitvec::view::BitView;
use pnet::packet::ethernet::EthernetPacket;
use std::iter;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use tun_rs::ToIpv6Address;

pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn find(&self, frame: &EthernetPacket, direction: Direction) -> Option<(usize, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_rule_index, rule)| rule.matches(frame, direction))
    }
}

pub struct RuleOptions {
    pub compress_netmask_pairs: Vec<NetmaskPair>,
    pub compress_ipv6_without_udp: bool,
}

impl Default for RuleOptions {
    fn default() -> Self {
        Self {
            compress_netmask_pairs: Vec::new(),
            compress_ipv6_without_udp: true,
        }
    }
}

#[derive(Clone)]
pub struct NetmaskPair {
    pub source: Netmask,
    pub destination: Netmask,
}

impl NetmaskPair {
    pub fn swapped(self) -> NetmaskPair {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
}

impl FromStr for NetmaskPair {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(',').collect();
        if parts.len() != 2 {
            bail!("wrong number of parts: {}", parts.len());
        }

        let source = parts[0].trim().parse()?;
        let destination = parts[1].trim().parse()?;
        Ok(Self {
            source,
            destination,
        })
    }
}

#[derive(Clone)]
pub struct Netmask {
    pub ip_addr: IpAddr,
    pub mask_bit_count: u32,
}

impl FromStr for Netmask {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split('/').collect();
        if parts.len() != 2 {
            bail!("wrong number of parts: {}", parts.len());
        }

        let ip_addr: IpAddr = parts[0].parse().context("invalid IP address")?;
        let mask_bits: u32 = parts[1].parse().context("invalid mask")?;
        if mask_bits == 0 || mask_bits > 128 {
            bail!("invalid mask: {mask_bits}");
        }

        if !ip_addr.is_ipv6() {
            bail!("only ipv6 supported at the moment")
        }

        Ok(Self {
            ip_addr,
            mask_bit_count: mask_bits,
        })
    }
}

fn compress_ipv6_in_subnet(
    addr: Ipv6Addr,
    mask_bit_count: u32,
    di: DirectionIndicator,
) -> MatchingOperatorCandidate {
    let addr_bits = addr.to_bits().to_be_bytes();
    let addr = addr_bits.view_bits::<Msb0>();
    let addr_msb = &addr[0..mask_bit_count as usize];

    MatchingOperatorCandidate {
        direction: di,
        target_value: Some(addr_msb.to_bitvec()),
        matching_operator: MatchingOperator::Msb(mask_bit_count),
        compression_decompression_action: CompressionDecompressionAction::Lsb,
    }
}

fn ipv6_descriptors(
    address_compression: Option<&NetmaskPair>,
    flow_label_compression: bool,
) -> Vec<FieldDescriptor> {
    let mut descriptors = vec![
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6Version,
            length_bits: 4,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: Some(bitvec![u8, Msb0; 0, 1, 1, 0]), // 6
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::NotSent,
            }],
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6TrafficClass,
            length_bits: 8,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: Some(bitvec![u8, Msb0; 0; 6]),
                matching_operator: MatchingOperator::Msb(6),
                compression_decompression_action: CompressionDecompressionAction::Lsb,
            }],
        },
    ];

    if flow_label_compression {
        descriptors.push(FieldDescriptor {
            identifier: FieldIdentifier::IPv6FlowLabel,
            length_bits: 20,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: Some(bitvec![u8, Msb0; 0; 20]),
                matching_operator: MatchingOperator::Equal,
                compression_decompression_action: CompressionDecompressionAction::NotSent,
            }],
        });
    } else {
        descriptors.push(FieldDescriptor {
            identifier: FieldIdentifier::IPv6FlowLabel,
            length_bits: 20,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::ValueSent,
            }],
        });
    }

    descriptors.extend([
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6PayloadLength,
            length_bits: 16,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::Compute,
            }],
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6NextHeader,
            length_bits: 8,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::ValueSent,
            }],
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6HopLimit,
            length_bits: 8,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::ValueSent,
            }],
        },
    ]);

    if let Some(pair) = address_compression {
        // Compression for addresses
        descriptors.extend([
            FieldDescriptor {
                identifier: FieldIdentifier::IPv6SourceAddr,
                length_bits: 128,
                matching_operator_candidates: vec![
                    // Outgoing
                    compress_ipv6_in_subnet(
                        pair.source.ip_addr.ipv6().unwrap(),
                        pair.source.mask_bit_count,
                        DirectionIndicator::Uplink,
                    ),
                    // Incoming (addresses are swapped)
                    compress_ipv6_in_subnet(
                        pair.destination.ip_addr.ipv6().unwrap(),
                        pair.destination.mask_bit_count,
                        DirectionIndicator::Downlink,
                    ),
                ],
            },
            FieldDescriptor {
                identifier: FieldIdentifier::IPv6DestinationAddr,
                length_bits: 128,
                matching_operator_candidates: vec![
                    // Outgoing
                    compress_ipv6_in_subnet(
                        pair.destination.ip_addr.ipv6().unwrap(),
                        pair.destination.mask_bit_count,
                        DirectionIndicator::Uplink,
                    ),
                    // Incoming (ip addresses are swapped)
                    compress_ipv6_in_subnet(
                        pair.source.ip_addr.ipv6().unwrap(),
                        pair.source.mask_bit_count,
                        DirectionIndicator::Downlink,
                    ),
                ],
            },
        ]);
    } else {
        // No compression for addresses
        descriptors.extend([
            FieldDescriptor {
                identifier: FieldIdentifier::IPv6SourceAddr,
                length_bits: 128,
                matching_operator_candidates: vec![MatchingOperatorCandidate {
                    direction: DirectionIndicator::Bidirectional,
                    target_value: None,
                    matching_operator: MatchingOperator::Ignore,
                    compression_decompression_action: CompressionDecompressionAction::ValueSent,
                }],
            },
            FieldDescriptor {
                identifier: FieldIdentifier::IPv6DestinationAddr,
                length_bits: 128,
                matching_operator_candidates: vec![MatchingOperatorCandidate {
                    direction: DirectionIndicator::Bidirectional,
                    target_value: None,
                    matching_operator: MatchingOperator::Ignore,
                    compression_decompression_action: CompressionDecompressionAction::ValueSent,
                }],
            },
        ]);
    }

    descriptors
}

pub fn load_rules(opts: &RuleOptions) -> RuleSet {
    let udp_descriptors = [
        FieldDescriptor {
            identifier: FieldIdentifier::UdpPorts,
            length_bits: 32,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::ValueSent,
            }],
        },
        FieldDescriptor {
            identifier: FieldIdentifier::UdpLength,
            length_bits: 16,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::Compute,
            }],
        },
        FieldDescriptor {
            identifier: FieldIdentifier::UdpChecksum,
            length_bits: 16,
            matching_operator_candidates: vec![MatchingOperatorCandidate {
                direction: DirectionIndicator::Bidirectional,
                target_value: None,
                matching_operator: MatchingOperator::Ignore,
                compression_decompression_action: CompressionDecompressionAction::ValueSent,
            }],
        },
    ];

    let mut rules = Vec::new();

    // Each netmask pair gets its own rules, and fallback rules are generated at the end
    for pair in opts
        .compress_netmask_pairs
        .iter()
        .map(Some)
        .chain(iter::once(None))
    {
        rules.extend([
            // UDP over IPv6, flow label = 0
            Rule {
                field_descriptors: ipv6_descriptors(pair, true)
                    .into_iter()
                    .chain(udp_descriptors.iter().cloned())
                    .collect(),
            },
            // UDP over IPv6, flow label != 0
            Rule {
                field_descriptors: ipv6_descriptors(pair, false)
                    .iter()
                    .cloned()
                    .chain(udp_descriptors.iter().cloned())
                    .collect(),
            },
        ]);

        if !opts.compress_ipv6_without_udp {
            // Unknown over IPv6, flow label = 0
            rules.push(Rule {
                field_descriptors: ipv6_descriptors(pair, true),
            });

            // Unknown over IPv6, flow label != 0
            rules.push(Rule {
                field_descriptors: ipv6_descriptors(pair, false),
            });
        }
    }

    RuleSet { rules }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schc::*;
    use crate::varint;
    use pnet::packet::Packet;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::UdpPacket;

    const IPV6_UDP_ID: u8 = 1;
    const IPV6_UDP_WITH_FLOW_LABEL_ID: u8 = 2;
    const IPV6_UNKNOWN_ID: u8 = 3;
    const IPV6_UNKNOWN_WITH_FLOW_LABEL_ID: u8 = 4;

    fn udp_over_ipv6() -> Vec<u8> {
        // Obtained from https://www.cloudshark.org/captures/1737557e3427
        let hex_bytes = "00032d875970f01898e87af386dd60030e00003d114020010db800010000000000000000000126064700001000000000000068160826c46801bb003d8c48e400000001140130dfc5a047e6acd230b5c5e047ced9b0a6bbf000401862627a4b509a406812b71df9be5a8ce4f895dd266e54567d";
        let bytes = hex::decode(hex_bytes).unwrap();

        // Sanity check
        let frame = EthernetPacket::new(&bytes).unwrap();
        let ipv6_packet = Ipv6Packet::new(frame.payload()).unwrap();
        let udp_packet = UdpPacket::new(ipv6_packet.payload()).unwrap();
        assert_eq!(udp_packet.packet().len(), 61);
        assert_eq!(udp_packet.get_length(), 61);
        assert_eq!(udp_packet.get_checksum(), 0x8c48);

        bytes
    }

    fn icmp_over_ipv6() -> Vec<u8> {
        // Obtained from https://www.cloudshark.org/captures/84fd54ad03e0
        let hex_bytes = "38c9862d926100e04c361c4386dd6004824500103a4020010db800010000000000000000000120010db8000200000000000000000002800031e721c100075c9825e400024e0f";
        let bytes = hex::decode(hex_bytes).unwrap();

        // Sanity check
        let frame = EthernetPacket::new(&bytes).unwrap();
        let ipv6_packet = Ipv6Packet::new(frame.payload()).unwrap();
        let icmp_packet = IcmpPacket::new(ipv6_packet.payload()).unwrap();
        assert_eq!(icmp_packet.get_checksum(), 0x31e7);

        bytes
    }

    fn tcp_over_ipv4() -> Vec<u8> {
        // Obtained from https://www.cloudshark.org/captures/0012f52602a3
        let hex_bytes = "0026622f4787001d60b3018408004500003ccb5b4000400628e4c0a8018cae8fd5b8e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307";
        let mut bytes = hex::decode(hex_bytes).unwrap();

        // Sanity check
        let frame = EthernetPacket::new(bytes.as_mut_slice()).unwrap();
        let ipv4_packet = Ipv4Packet::new(frame.payload()).unwrap();
        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(tcp_packet.get_source(), 57678);

        bytes
    }

    fn patch_ipv6(mut bytes: Vec<u8>, with_flow_label: bool, with_ecn: bool) -> Vec<u8> {
        let mut ipv6_packet =
            MutableIpv6Packet::new(&mut bytes[ETHERNET_HEADER_LEN_BYTES..]).unwrap();

        if !with_flow_label {
            // Remove flow label
            assert_ne!(ipv6_packet.get_flow_label(), 0);
            ipv6_packet.set_flow_label(0);
        }

        if with_ecn {
            // Add ECN
            assert_eq!(ipv6_packet.get_traffic_class(), 0);
            ipv6_packet.set_traffic_class(0b0000_0011);
        }

        bytes
    }

    #[test]
    fn test_round_trip() {
        let rules = load_rules(&RuleOptions {
            compress_ipv6_without_udp: false,
            ..RuleOptions::default()
        });
        let test_cases = [
            (IPV6_UNKNOWN_ID, patch_ipv6(icmp_over_ipv6(), false, false)),
            (IPV6_UNKNOWN_ID, patch_ipv6(icmp_over_ipv6(), false, true)),
            (
                IPV6_UNKNOWN_WITH_FLOW_LABEL_ID,
                patch_ipv6(icmp_over_ipv6(), true, false),
            ),
            (
                IPV6_UNKNOWN_WITH_FLOW_LABEL_ID,
                patch_ipv6(icmp_over_ipv6(), true, true),
            ),
            (IPV6_UDP_ID, patch_ipv6(udp_over_ipv6(), false, false)),
            (IPV6_UDP_ID, patch_ipv6(udp_over_ipv6(), false, true)),
            (
                IPV6_UDP_WITH_FLOW_LABEL_ID,
                patch_ipv6(udp_over_ipv6(), true, false),
            ),
            (
                IPV6_UDP_WITH_FLOW_LABEL_ID,
                patch_ipv6(udp_over_ipv6(), true, true),
            ),
        ];

        for (i, (expected_rule_id, bytes)) in test_cases.into_iter().enumerate() {
            println!("Test case {i}");
            let frame = EthernetPacket::new(&bytes).unwrap();

            let compressed = compress_frame(&rules, &frame);
            assert_eq!(compressed[ETHERNET_HEADER_LEN_BYTES], expected_rule_id);
            assert!(
                compressed.len() < bytes.len(),
                "compressed is not shorter than bytes ({} >= {})",
                compressed.len(),
                bytes.len()
            );

            let compressed_frame = EthernetPacket::new(&compressed).unwrap();
            let decompressed = decompress_frame(&rules, &compressed_frame).unwrap();
            assert_eq!(decompressed.len(), bytes.len());
            assert_eq!(decompressed, bytes);

            let decompressed_frame = EthernetPacket::new(&decompressed).unwrap();
            assert_eq!(decompressed_frame.get_source(), frame.get_source());
            assert_eq!(
                decompressed_frame.get_destination(),
                frame.get_destination()
            );
        }
    }

    #[test]
    fn test_udp_over_ip_in_subnet() {
        let outgoing = "00032d875970f01898e87af386dd60030e00003d114020010db800010000000000000000000126064700001000000000000068160826c46801bb003d8c48e400000001140130dfc5a047e6acd230b5c5e047ced9b0a6bbf000401862627a4b509a406812b71df9be5a8ce4f895dd266e54567d";
        let outgoing_packet_bytes = hex::decode(outgoing).unwrap();

        let incoming = "f01898e87af300032d87597086dd600886c5002011382606470000100000000000006816082620010db800010000000000000000000101bbc4680020e0864a578a3234376115f40bf4bbd4ee70024004c439dd9c539f";
        let incoming_packet_bytes = hex::decode(incoming).unwrap();

        let source_addr = "2001:db8:1::1";
        let destination_addr = "2606:4700:10::6816:826";

        let mask_lengths_bits = [16, 64, 128];

        for mask_length_bits in mask_lengths_bits {
            let pair_string =
                format!("{source_addr}/{mask_length_bits},{destination_addr}/{mask_length_bits}");
            let subnet_pairs = vec![pair_string.parse().unwrap()];

            let rules_peer_a = load_rules(&RuleOptions {
                compress_netmask_pairs: subnet_pairs.clone(),
                ..RuleOptions::default()
            });

            let rules_peer_b = load_rules(&RuleOptions {
                compress_netmask_pairs: subnet_pairs.into_iter().map(|p| p.swapped()).collect(),
                ..RuleOptions::default()
            });

            let expected_compression_savings = mask_length_bits * 2 / 8;

            // --
            // Compression
            // --

            // Outgoing
            let outgoing_frame = EthernetPacket::new(&outgoing_packet_bytes).unwrap();
            let outgoing_compressed = compress_frame(&rules_peer_a, &outgoing_frame);
            let outgoing_len_without_addr_compression = 111;
            assert_ne!(outgoing_compressed[ETHERNET_HEADER_LEN_BYTES], NO_RULE_ID);
            assert_eq!(
                outgoing_compressed.len(),
                outgoing_len_without_addr_compression - expected_compression_savings
            );

            // Incoming (as a peer would compress it)
            let incoming_frame = EthernetPacket::new(&incoming_packet_bytes).unwrap();
            let incoming_compressed = compress_frame(&rules_peer_b, &incoming_frame);
            let incoming_len_without_addr_compression = 82;
            assert_ne!(incoming_compressed[ETHERNET_HEADER_LEN_BYTES], NO_RULE_ID);
            assert_eq!(
                incoming_compressed.len(),
                incoming_len_without_addr_compression - expected_compression_savings
            );

            // --
            // Decompression
            // --

            // Incoming (as received by the peer)
            let rule_id = varint::decode(&mut &outgoing_compressed[ETHERNET_HEADER_LEN_BYTES..]);
            println!("{}", rule_id);
            let outgoing_decompressed = decompress_frame(
                &rules_peer_b,
                &EthernetPacket::new(&outgoing_compressed).unwrap(),
            )
            .unwrap();
            assert_eq!(outgoing_decompressed.len(), outgoing_packet_bytes.len());
            assert_eq!(outgoing_decompressed, outgoing_packet_bytes);

            // Outgoing (as received by us)
            let incoming_decompressed = decompress_frame(
                &rules_peer_a,
                &EthernetPacket::new(&incoming_compressed).unwrap(),
            )
            .unwrap();
            assert_eq!(incoming_decompressed.len(), incoming_packet_bytes.len());
            assert_eq!(incoming_decompressed, incoming_packet_bytes);
        }
    }

    #[test]
    fn test_round_trip_ipv4() {
        let rules = load_rules(&RuleOptions::default());
        let bytes = tcp_over_ipv4();
        let frame = EthernetPacket::new(&bytes).unwrap();

        let compressed = compress_frame(&rules, &frame);
        assert_eq!(compressed[ETHERNET_HEADER_LEN_BYTES], NO_RULE_ID);
        assert_eq!(compressed.len(), bytes.len() + 1);

        let compressed_frame = EthernetPacket::new(&compressed).unwrap();
        let decompressed = decompress_frame(&rules, &compressed_frame).unwrap();

        assert_eq!(decompressed.len(), bytes.len());
        assert_eq!(decompressed, bytes);
    }
}
