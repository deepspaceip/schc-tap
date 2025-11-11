use std::io::{Read, Write};

pub fn encode<W: Write>(writer: &mut W, x: u64) -> usize {
    leb128::write::unsigned(writer, x).unwrap()
}

pub fn decode<R: Read>(reader: &mut R) -> u64 {
    leb128::read::unsigned(reader).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_decode_assert(x: u64, expected_len: usize) {
        let mut buf = Vec::new();
        let written = encode(&mut buf, x);
        assert_eq!(written, buf.len());
        assert_eq!(
            written, expected_len,
            "encoded {x} uses unexpected number of bytes"
        );

        let decoded = decode(&mut buf.as_slice());
        assert_eq!(
            decoded, x,
            "wrong value after round trip encode/decode for {x}"
        );
    }

    #[test]
    fn test_encode_round_trips() {
        encode_decode_assert(0, 1);
        encode_decode_assert(42, 1);
        encode_decode_assert(128, 2);
    }
}
