#![allow(clippy::match_like_matches_macro)]

use crate::schc_rules::RuleSet;
use crate::varint;
use anyhow::anyhow;
use bitvec::field::BitField;
use bitvec::order::Msb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use log::debug;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::io::{Cursor, Write};

pub(crate) const NO_RULE_ID: u8 = 0;

pub(crate) const ETHERNET_HEADER_LEN_BYTES: usize = 14;

pub struct Rule {
    pub field_descriptors: Vec<FieldDescriptor>,
}

impl Rule {
    // A rule matches when each field descriptor:
    // - Has an FID that is present in the packet
    // - Has an MO that matches the direction
    // - Matches the position (always true in our implementation)
    // - Applies the MO and checks that the result matches TV
    pub fn matches(&self, frame: &EthernetPacket, direction: Direction) -> bool {
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
                // Out of bounds, should never happen
                return false;
            }

            let fid_matches = match fd.identifier {
                FieldIdentifier::IPv6Version
                | FieldIdentifier::IPv6TrafficClass
                | FieldIdentifier::IPv6FlowLabel
                | FieldIdentifier::IPv6PayloadLength
                | FieldIdentifier::IPv6NextHeader
                | FieldIdentifier::IPv6HopLimit
                | FieldIdentifier::IPv6SourceAddr
                | FieldIdentifier::IPv6DestinationAddr => is_ipv6_packet,
                FieldIdentifier::UdpPorts
                | FieldIdentifier::UdpLength
                | FieldIdentifier::UdpChecksum => carries_udp,
            };

            let Some(selected_mo) = fd
                .matching_operator_candidates
                .iter()
                .find(|fd| fd.direction.matches(direction))
            else {
                // No field descriptor found for this direction
                debug!("matches({:?}) = false (no mo for direction)", fd.identifier);
                return false;
            };

            let mo_matches = match selected_mo.matching_operator {
                MatchingOperator::Msb(msb) => {
                    let Some(target_value) = &selected_mo.target_value else {
                        unreachable!("MSB always goes together with a target value")
                    };

                    if msb > fd.length_bits {
                        unreachable!("MSB is always <= the field's length")
                    }

                    let field_value = &packet_bits[position_bits..position_bits + msb as usize];
                    field_value == target_value
                }
                MatchingOperator::Equal => {
                    let Some(target_value) = &selected_mo.target_value else {
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

            let matches = fid_matches && mo_matches;
            debug!(
                "matches({:?}, {:?}) = {matches}",
                selected_mo.matching_operator, fd.identifier
            );
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

            // Note: need to compress using the descriptor that the receiver will match when reading
            let Some(selected_mo) = fd.mo_for_direction(Direction::Downlink) else {
                unreachable!("there's always a descriptor for compressing frames");
            };

            match selected_mo.compression_decompression_action {
                CompressionDecompressionAction::NotSent => {
                    // Nothing to encode
                }
                CompressionDecompressionAction::ValueSent => {
                    let src_value =
                        &packet_bits[position_bits..position_bits + fd.length_bits as usize];
                    compressed.extend_from_bitslice(src_value);
                }
                CompressionDecompressionAction::Lsb => {
                    let MatchingOperator::Msb(msb) = selected_mo.matching_operator else {
                        unreachable!(
                            "LSB is always used together with MSB, but found {:?}",
                            selected_mo.matching_operator
                        );
                    };

                    if msb > fd.length_bits {
                        unreachable!("MSB should be <= length_bits");
                    }

                    if msb < fd.length_bits {
                        let src_value = &packet_bits
                            [position_bits + msb as usize..position_bits + fd.length_bits as usize];
                        compressed.extend_from_bitslice(src_value);
                    }
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
            let Some(selected_mo) = fd.mo_for_direction(Direction::Downlink) else {
                unreachable!("there's always a descriptor for decompressing frames");
            };

            if src_position_bits + fd.length_bits as usize >= compressed_bits.len() {
                unreachable!("position is always within bounds at the compress step")
            }

            match selected_mo.compression_decompression_action {
                CompressionDecompressionAction::NotSent => {
                    let Some(target_value) = &selected_mo.target_value else {
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
                    let Some(target_value) = &selected_mo.target_value else {
                        unreachable!("LSB always goes together with a target value")
                    };

                    let MatchingOperator::Msb(msb) = selected_mo.matching_operator else {
                        unreachable!(
                            "LSB is always used together with MSB, but found {:?}",
                            selected_mo.matching_operator
                        );
                    };

                    // Take the MSB bits from the target value, since they were not sent over the
                    // wire
                    decompressed.extend_from_bitslice(target_value);

                    if msb > fd.length_bits {
                        unreachable!("MSB should be <= length_bits");
                    }

                    let lsb = fd.length_bits - msb;
                    if lsb > 0 {
                        let src_value =
                            &compressed_bits[src_position_bits..src_position_bits + lsb as usize];
                        decompressed.extend_from_bitslice(src_value);
                    }

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
            // Length is calculated only for the payload
            let ipv6_header_end_bits = pos + 288;
            let length_bits: u16 = decompressed.len().saturating_sub(ipv6_header_end_bits) as u16;
            let value = &mut decompressed[pos..pos + 16];
            value.store_be(length_bits / 8);
        }

        // Write UDP length, if requested
        if let Some(udp_length_pos) = compute_udp_payload_length {
            // Length is calculated for the whole packet (data starts 32 bits before the length header)
            let udp_header_start_bits = udp_length_pos.saturating_sub(32);
            let length_bits: u16 = decompressed.len().saturating_sub(udp_header_start_bits) as u16;
            let value = &mut decompressed[udp_length_pos..udp_length_pos + 16];
            value.store_be(length_bits / 8);
        }

        decompressed.into_vec()
    }
}

#[derive(Clone)]
pub struct FieldDescriptor {
    /// Field Identifier (FID)
    pub identifier: FieldIdentifier,
    /// Field Length (FL)
    pub length_bits: u32,
    /// Candidate matching operators, by direction
    pub matching_operator_candidates: Vec<MatchingOperatorCandidate>,
}

impl FieldDescriptor {
    pub fn mo_for_direction(&self, direction: Direction) -> Option<&MatchingOperatorCandidate> {
        self.matching_operator_candidates
            .iter()
            .find(|fd| fd.direction.matches(direction))
    }
}

#[derive(Clone)]
pub struct MatchingOperatorCandidate {
    /// Direction Indicator (DI)
    pub direction: DirectionIndicator,
    /// Target Value (TV)
    pub target_value: Option<BitVec<u8, Msb0>>,
    /// Matching Operator (MO)
    pub matching_operator: MatchingOperator,
    /// Compression/Decompression Action (CDA)
    pub compression_decompression_action: CompressionDecompressionAction,
}

#[derive(Copy, Clone)]
pub enum Direction {
    Uplink,
    Downlink,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum DirectionIndicator {
    Uplink,
    Downlink,
    Bidirectional,
}

impl DirectionIndicator {
    fn matches(self, direction: Direction) -> bool {
        match (self, direction) {
            (DirectionIndicator::Uplink, Direction::Uplink)
            | (DirectionIndicator::Downlink, Direction::Downlink)
            | (DirectionIndicator::Bidirectional, _) => true,
            _ => false,
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub enum MatchingOperator {
    Equal,
    Ignore,
    Msb(u32),
    MatchMapping,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum CompressionDecompressionAction {
    NotSent,
    ValueSent,
    MappingSent,
    Lsb,
    Compute,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FieldIdentifier {
    IPv6Version,
    IPv6TrafficClass,
    IPv6FlowLabel,
    IPv6PayloadLength,
    IPv6NextHeader,
    IPv6HopLimit,
    IPv6SourceAddr,
    IPv6DestinationAddr,
    UdpPorts,
    UdpLength,
    UdpChecksum,
}

pub fn compress_frame(rules: &RuleSet, frame: &EthernetPacket) -> Vec<u8> {
    // An SCHC packet is composed of:
    // - Compressed header
    // - The payload from the original packet
    //
    // The compressed header consists of a "rule id" and a compression residue (i.e. the output of
    // compressing the packet header with the Rule identified by that RuleID). The residue may be
    // empty.
    let Some((rule_index, rule)) = rules.find(frame, Direction::Uplink) else {
        // No rule found
        let mut compressed = Vec::with_capacity(frame.packet().len() + 1);
        compressed.extend_from_slice(&frame.packet()[..ETHERNET_HEADER_LEN_BYTES]);

        // Rule id 0 means we didn't compress
        compressed.push(NO_RULE_ID);

        // Now append the original payload
        compressed.extend_from_slice(frame.payload());

        return compressed;
    };

    let rule_id = rule_index as u64 + 1;
    rule.compress(rule_id, frame)
}

pub fn decompress_frame(rules: &RuleSet, frame: &EthernetPacket) -> anyhow::Result<Vec<u8>> {
    let mut cursor = Cursor::new(frame.payload());
    let rule_id = varint::decode(&mut cursor) as usize;
    if rule_id == NO_RULE_ID as usize {
        // Not compressed, so skip the rule id and return the rest
        let mut decompressed = Vec::new();
        decompressed.extend_from_slice(&frame.packet()[..ETHERNET_HEADER_LEN_BYTES]);
        decompressed.extend_from_slice(&frame.payload()[1..]);
        return Ok(decompressed);
    }

    let rule_id_len = cursor.position() as usize;
    let rule_index = rule_id - 1;
    let rule = rules
        .rules
        .get(rule_index)
        .ok_or(anyhow!("unknown SCHC rule"))?;
    Ok(rule.decompress(frame, rule_id_len))
}
