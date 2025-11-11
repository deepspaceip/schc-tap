#![allow(clippy::match_like_matches_macro)]

use crate::varint;
use bitvec::bitvec;
use bitvec::field::BitField;
use bitvec::order::Msb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::io::{Cursor, Write};

const NO_RULE_ID: u8 = 0;

const ETHERNET_HEADER_LEN_BYTES: usize = 14;

struct Rule {
    field_descriptors: Vec<FieldDescriptor>,
}

impl Rule {
    // A rule matches when each field descriptor:
    // - Has an FID that is present in the packet
    // - Matches the packet's direction
    // - Matches the position (always true in our implementation)
    // - Applies the MO and checks that the result matches TV
    fn matches(&self, frame: &EthernetPacket, direction: Direction) -> bool {
        let packet_bits: &BitSlice<_, Msb0> = BitSlice::from_slice(frame.payload());

        if packet_bits.len() < 4 {
            return false;
        }

        let ip_version = packet_bits[0..4].load::<u8>();
        let is_ipv4_packet = ip_version == 4;
        let is_ipv6_packet = ip_version == 6;
        let carries_udp = (is_ipv4_packet
            && Ipv4Packet::new(frame.payload())
                .is_some_and(|p| p.get_next_level_protocol() == IpNextHeaderProtocols::Udp))
            || (is_ipv6_packet
                && Ipv6Packet::new(frame.payload())
                    .is_some_and(|p| p.get_next_header() == IpNextHeaderProtocols::Udp));

        let mut position_bits = 0;

        for fd in &self.field_descriptors {
            if position_bits >= packet_bits.len() {
                // Out of bounds
                return false;
            }

            let fid_matches = match fd.identifier {
                FieldIdentifier::IPv6Version
                | FieldIdentifier::IPv6TrafficClass
                | FieldIdentifier::IPv6FlowLabel
                | FieldIdentifier::IPv6PayloadLength
                | FieldIdentifier::IPv6NextHeader
                | FieldIdentifier::IPv6HopLimit
                | FieldIdentifier::IPv6Addresses => is_ipv6_packet,
                FieldIdentifier::UdpPorts
                | FieldIdentifier::UdpLength
                | FieldIdentifier::UdpChecksum => carries_udp,
            };

            let dir_matches = match (fd.direction, direction) {
                (DirectionIndicator::Uplink, Direction::Uplink)
                | (DirectionIndicator::Downlink, Direction::Downlink)
                | (DirectionIndicator::Bidirectional, _) => true,
                _ => false,
            };

            let mo_matches = match fd.matching_operator {
                MatchingOperator::Msb(msb) => {
                    let Some(target_value) = &fd.target_value else {
                        unreachable!("MSB always goes together with a target value")
                    };

                    if msb >= fd.length_bits {
                        unreachable!("MSB is always less than the field's length")
                    }

                    let field_value = &packet_bits[position_bits..position_bits + msb as usize];
                    field_value == target_value
                }
                MatchingOperator::Equal => {
                    let Some(target_value) = &fd.target_value else {
                        unreachable!("target value always goes together with Equal MO")
                    };

                    if fd.length_bits as usize != target_value.len() {
                        unreachable!(
                            "target value length should always equal field descriptor length"
                        )
                    }

                    let field_value =
                        &packet_bits[position_bits..position_bits + fd.length_bits as usize];
                    field_value == target_value
                }
                MatchingOperator::Ignore => true,
                MatchingOperator::MatchMapping => unimplemented!(),
            };

            let matches = fid_matches && dir_matches && mo_matches;
            println!("matches({:?}) = {matches}", fd.identifier);
            if !matches {
                return false;
            }

            // Advance to next field
            position_bits += fd.length_bits as usize;
        }

        true
    }

    fn compress(&self, rule_id: u64, frame: &EthernetPacket) -> Vec<u8> {
        let mut compressed: BitVec<u8, Msb0> = BitVec::new();
        compressed
            .write_all(&frame.packet()[..ETHERNET_HEADER_LEN_BYTES])
            .unwrap();
        varint::encode(&mut compressed, rule_id);

        let packet_bits: &BitSlice<_, Msb0> = BitSlice::from_slice(frame.payload());
        let mut position_bits = 0;

        for fd in &self.field_descriptors {
            if position_bits + fd.length_bits as usize >= packet_bits.len() {
                unreachable!("position is always within bounds at the compress step")
            }

            match fd.compression_decompression_action {
                CompressionDecompressionAction::NotSent => {
                    // Nothing to encode
                }
                CompressionDecompressionAction::ValueSent => {
                    let src_value =
                        &packet_bits[position_bits..position_bits + fd.length_bits as usize];
                    compressed.extend_from_bitslice(src_value);
                }
                CompressionDecompressionAction::Lsb => {
                    let MatchingOperator::Msb(msb) = fd.matching_operator else {
                        unreachable!(
                            "LSB is always used together with MSB, but found {:?}",
                            fd.matching_operator
                        );
                    };

                    if msb >= fd.length_bits {
                        unreachable!("MSB should be less than length_bits");
                    }

                    let src_value = &packet_bits
                        [position_bits + msb as usize..position_bits + fd.length_bits as usize];
                    compressed.extend_from_bitslice(src_value);
                }
                CompressionDecompressionAction::Compute => {
                    // Nothing to encode
                }
                CompressionDecompressionAction::MappingSent => unimplemented!(),
            }

            position_bits += fd.length_bits as usize;
        }

        // Copy all remaining bytes
        if position_bits % 8 != 0 {
            unreachable!("compression read wrong number of bits");
        }
        let position = position_bits / 8;
        compressed.write_all(&frame.payload()[position..]).unwrap();

        // Note: into_vec will automatically pad the contents
        compressed.set_uninitialized(false);
        compressed.into_vec()
    }

    fn decompress(&self, compressed_frame: &EthernetPacket, rule_id_len: usize) -> Vec<u8> {
        let mut decompressed: BitVec<u8, Msb0> = BitVec::new();
        decompressed
            .write_all(&compressed_frame.packet()[..ETHERNET_HEADER_LEN_BYTES])
            .unwrap();

        // Skip the leading rule id
        let compressed_bytes = &compressed_frame.payload()[rule_id_len..];
        let compressed_bits: &BitSlice<_, Msb0> = BitSlice::from_slice(compressed_bytes);
        let mut src_position_bits = 0;

        let mut compute_ipv6_payload_length = None;
        let mut compute_udp_payload_length = None;

        for fd in &self.field_descriptors {
            if src_position_bits + fd.length_bits as usize >= compressed_bits.len() {
                unreachable!("position is always within bounds at the compress step")
            }

            match fd.compression_decompression_action {
                CompressionDecompressionAction::NotSent => {
                    let Some(target_value) = &fd.target_value else {
                        unreachable!("target value is always present if not sent")
                    };

                    if target_value.len() != fd.length_bits as usize {
                        unreachable!(
                            "mismatched length: {} != {}",
                            target_value.len(),
                            fd.length_bits
                        );
                    }

                    decompressed.extend_from_bitslice(target_value);
                }
                CompressionDecompressionAction::ValueSent => {
                    let src_value = &compressed_bits
                        [src_position_bits..src_position_bits + fd.length_bits as usize];
                    decompressed.extend_from_bitslice(src_value);
                    src_position_bits += fd.length_bits as usize;
                }
                CompressionDecompressionAction::Lsb => {
                    let Some(target_value) = &fd.target_value else {
                        unreachable!("LSB always goes together with a target value")
                    };

                    let MatchingOperator::Msb(msb) = fd.matching_operator else {
                        unreachable!(
                            "LSB is always used together with MSB, but found {:?}",
                            fd.matching_operator
                        );
                    };

                    // Take the MSB bits from the target value, since they were not sent over the
                    // wire
                    decompressed.extend_from_bitslice(target_value);

                    if msb >= fd.length_bits {
                        unreachable!("MSB should be less than length_bits");
                    }

                    let lsb = fd.length_bits - msb;

                    let src_value =
                        &compressed_bits[src_position_bits..src_position_bits + lsb as usize];
                    decompressed.extend_from_bitslice(src_value);
                    src_position_bits += lsb as usize;
                }
                CompressionDecompressionAction::Compute => {
                    match fd.identifier {
                        FieldIdentifier::IPv6PayloadLength => {
                            if compute_ipv6_payload_length.is_some() {
                                // The code assumes only one ipv6 packet is present
                                unimplemented!()
                            }

                            compute_ipv6_payload_length = Some(decompressed.len())
                        }
                        FieldIdentifier::UdpLength => {
                            if compute_udp_payload_length.is_some() {
                                // The code assumes only one udp packet is present
                                unimplemented!()
                            }

                            compute_udp_payload_length = Some(decompressed.len())
                        }
                        fid => unreachable!(
                            "Compute is always used with IPv6 Payload Length or UDP Length, but found {fid:?}"
                        ),
                    }

                    if fd.length_bits != 16 {
                        unreachable!("IPv6 and UDP length are always 16 bits")
                    }

                    // We will overwrite this later
                    decompressed.write_all(&[0, 0]).unwrap();
                }
                CompressionDecompressionAction::MappingSent => unimplemented!(),
            }
        }

        // Copy all remaining bytes
        decompressed.extend_from_bitslice(&compressed_bits[src_position_bits..]);

        // Remove padding (i.e. all bits after the last whole byte)
        let padding_bits = decompressed.len() % 8;
        for _ in 0..padding_bits {
            decompressed.pop();
        }

        if decompressed.len() % 8 != 0 {
            unreachable!("decompressed frame is malformed");
        }

        // Write IPv6 payload length, if requested
        if let Some(pos) = compute_ipv6_payload_length {
            let ipv6_header_end_bits = pos + 288;
            let length_bits: u16 = decompressed.len().saturating_sub(ipv6_header_end_bits) as u16;
            let value = &mut decompressed[pos..pos + 16];
            value.store_be(length_bits / 8);
        }

        // Write UDP length, if requested
        if let Some(pos) = compute_udp_payload_length {
            let udp_header_end_bits = pos + 64;
            let length_bits: u16 = decompressed.len().saturating_sub(udp_header_end_bits) as u16;
            let value = &mut decompressed[pos..pos + 16];
            value.store_be(length_bits / 8);
        }

        decompressed.into_vec()
    }
}

#[derive(Clone)]
struct FieldDescriptor {
    /// Field Identifier (FID)
    identifier: FieldIdentifier,
    /// Field Length (FL)
    length_bits: u32,
    /// Direction Indicator (DI)
    direction: DirectionIndicator,
    /// Target Value (TV)
    target_value: Option<BitVec<u8, Msb0>>,
    /// Matching Operator (MO)
    matching_operator: MatchingOperator,
    /// Compression/Decompression Action (CDA)
    compression_decompression_action: CompressionDecompressionAction,
}

#[derive(Copy, Clone)]
pub enum Direction {
    Uplink,
    Downlink,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
enum DirectionIndicator {
    Uplink,
    Downlink,
    Bidirectional,
}

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
enum MatchingOperator {
    Equal,
    Ignore,
    Msb(u32),
    MatchMapping,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
enum CompressionDecompressionAction {
    NotSent,
    ValueSent,
    MappingSent,
    Lsb,
    Compute,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FieldIdentifier {
    IPv6Version,
    IPv6TrafficClass,
    IPv6FlowLabel,
    IPv6PayloadLength,
    IPv6NextHeader,
    IPv6HopLimit,
    IPv6Addresses,
    UdpPorts,
    UdpLength,
    UdpChecksum,
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    fn find(&self, frame: &EthernetPacket, direction: Direction) -> Option<(u64, &Rule)> {
        let (rule_id, rule) = self
            .rules
            .iter()
            .enumerate()
            .find(|(_rule_id, rule)| rule.matches(frame, direction))?;
        Some((rule_id as u64, rule))
    }
}

pub fn compress_frame(rules: &RuleSet, frame: &EthernetPacket, direction: Direction) -> Vec<u8> {
    // An SCHC packet is composed of:
    // - Compressed header
    // - The payload from the original packet
    //
    // The compressed header consists of a "rule id" and a compression residue (i.e. the output of
    // compressing the packet header with the Rule identified by that RuleID). The residue may be
    // empty.
    let Some((rule_index, rule)) = rules.find(frame, direction) else {
        // No rule found
        let mut compressed = Vec::with_capacity(frame.packet().len() + 1);
        compressed.extend_from_slice(&frame.packet()[..ETHERNET_HEADER_LEN_BYTES]);

        // Rule id 0 means we didn't compress
        compressed.push(NO_RULE_ID);

        // Now append the original payload
        compressed.extend_from_slice(frame.payload());

        return compressed;
    };

    let rule_id = rule_index + 1;
    rule.compress(rule_id, frame)
}

pub fn decompress_frame(rules: &RuleSet, frame: &EthernetPacket) -> Vec<u8> {
    let mut cursor = Cursor::new(frame.payload());
    let rule_id = varint::decode(&mut cursor) as usize;
    if rule_id == NO_RULE_ID as usize {
        // Not compressed, so skip the rule id and return the rest
        let mut decompressed = Vec::new();
        decompressed.extend_from_slice(&frame.packet()[..ETHERNET_HEADER_LEN_BYTES]);
        decompressed.extend_from_slice(&frame.payload()[1..]);
        return decompressed;
    }

    let rule_id_len = cursor.position() as usize;
    let rule_index = rule_id - 1;
    let rule = rules.rules.get(rule_index).unwrap();
    rule.decompress(frame, rule_id_len)
}

pub fn load_rules() -> RuleSet {
    let ipv6_descriptors = vec![
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6Version,
            length_bits: 4,
            direction: DirectionIndicator::Bidirectional,
            target_value: Some(bitvec![u8, Msb0; 0, 1, 1, 0]), // 6
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::NotSent,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6TrafficClass,
            length_bits: 8,
            direction: DirectionIndicator::Bidirectional,
            target_value: Some(bitvec![u8, Msb0; 0; 6]),
            matching_operator: MatchingOperator::Msb(6),
            compression_decompression_action: CompressionDecompressionAction::Lsb,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6FlowLabel,
            length_bits: 20,
            direction: DirectionIndicator::Bidirectional,
            target_value: Some(bitvec![u8, Msb0; 0; 20]),
            matching_operator: MatchingOperator::Equal,
            compression_decompression_action: CompressionDecompressionAction::NotSent,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6PayloadLength,
            length_bits: 16,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::Compute,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6NextHeader,
            length_bits: 8,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::ValueSent,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6HopLimit,
            length_bits: 8,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::ValueSent,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::IPv6Addresses,
            length_bits: 256,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::ValueSent,
        },
    ];

    let udp_descriptors = vec![
        FieldDescriptor {
            identifier: FieldIdentifier::UdpPorts,
            length_bits: 32,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::ValueSent,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::UdpLength,
            length_bits: 16,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::Compute,
        },
        FieldDescriptor {
            identifier: FieldIdentifier::UdpChecksum,
            length_bits: 16,
            direction: DirectionIndicator::Bidirectional,
            target_value: None,
            matching_operator: MatchingOperator::Ignore,
            compression_decompression_action: CompressionDecompressionAction::ValueSent,
        },
    ];

    let mut ipv6_descriptors_with_flow_label = ipv6_descriptors.clone();
    let fd = ipv6_descriptors_with_flow_label
        .iter_mut()
        .find(|fd| fd.identifier == FieldIdentifier::IPv6FlowLabel)
        .unwrap();
    fd.target_value = None;
    fd.matching_operator = MatchingOperator::Ignore;
    fd.compression_decompression_action = CompressionDecompressionAction::ValueSent;

    RuleSet {
        rules: vec![
            // UDP over IPv6, flow label = 0
            Rule {
                field_descriptors: ipv6_descriptors
                    .iter()
                    .cloned()
                    .chain(udp_descriptors.iter().cloned())
                    .collect(),
            },
            // UDP over IPv6, flow label != 0
            Rule {
                field_descriptors: ipv6_descriptors_with_flow_label
                    .iter()
                    .cloned()
                    .chain(udp_descriptors)
                    .collect(),
            },
            // Unknown over IPv6, flow label = 0
            Rule {
                field_descriptors: ipv6_descriptors,
            },
            // Unknown over IPv6, flow label != 0
            Rule {
                field_descriptors: ipv6_descriptors_with_flow_label,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
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
        let rules = load_rules();
        let test_cases = [
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
        ];

        for (expected_rule_id, bytes) in test_cases {
            let frame = EthernetPacket::new(&bytes).unwrap();

            let compressed = compress_frame(&rules, &frame, Direction::Downlink);
            assert_eq!(compressed[ETHERNET_HEADER_LEN_BYTES], expected_rule_id);
            assert!(
                compressed.len() < bytes.len(),
                "compressed is not shorter than bytes ({} >= {})",
                compressed.len(),
                bytes.len()
            );

            let compressed_frame = EthernetPacket::new(&compressed).unwrap();
            let decompressed = decompress_frame(&rules, &compressed_frame);
            assert_eq!(decompressed.len(), bytes.len());

            let decompressed_frame = EthernetPacket::new(&decompressed).unwrap();
            assert_eq!(decompressed_frame.get_source(), frame.get_source());
            assert_eq!(
                decompressed_frame.get_destination(),
                frame.get_destination()
            );
        }
    }

    #[test]
    fn test_round_trip_ipv4() {
        let rules = load_rules();
        let bytes = tcp_over_ipv4();
        let frame = EthernetPacket::new(&bytes).unwrap();

        let compressed = compress_frame(&rules, &frame, Direction::Uplink);
        assert_eq!(compressed[ETHERNET_HEADER_LEN_BYTES], NO_RULE_ID);
        assert_eq!(compressed.len(), bytes.len() + 1);

        let compressed_frame = EthernetPacket::new(&compressed).unwrap();
        let decompressed = decompress_frame(&rules, &compressed_frame);

        assert_eq!(decompressed.len(), bytes.len());
        assert_eq!(decompressed, bytes);
    }
}
