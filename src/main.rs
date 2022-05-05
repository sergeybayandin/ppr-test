#[derive(Debug)]
#[allow(dead_code)]
struct Message {
    signature_length: u32,
    version: u8,
    message_type: u16,
    service_id: u16,
    payload_length: u32,
    encrypted: u16,
    data: Vec<u8>,
    signature: Vec<u8>,
}

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[allow(dead_code)]
struct MessageCodec {}

impl MessageCodec {
    const SIZE_OF_WITHOUT_VECS: usize =
        2 * std::mem::size_of::<u32>() + 3 * std::mem::size_of::<u16>() + std::mem::size_of::<u8>();

    fn new() -> Self {
        Self {}
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < Self::SIZE_OF_WITHOUT_VECS {
            return Ok(None);
        }

        let mut two_bytes = [0u8; 2];
        let mut four_bytes = [0u8; 4];

        four_bytes.copy_from_slice(&src[..4]);

        let signature_length = u32::from_le_bytes(four_bytes);

        let version = src[4];

        two_bytes.copy_from_slice(&src[5..7]);

        let message_type = u16::from_le_bytes(two_bytes);

        two_bytes.copy_from_slice(&src[7..9]);

        let service_id = u16::from_le_bytes(two_bytes);

        four_bytes.copy_from_slice(&src[9..13]);

        let payload_length = u32::from_le_bytes(four_bytes);

        two_bytes.copy_from_slice(&src[13..15]);

        let encrypted = u16::from_le_bytes(two_bytes);

        let delimiter = src.len() - signature_length as usize;
        let data = src[15..delimiter].to_vec();
        let signature = src[delimiter..].to_vec();

        src.advance(Self::SIZE_OF_WITHOUT_VECS + data.len() + signature.len());

        let item = Self::Item {
            signature_length,
            version,
            message_type,
            service_id,
            payload_length,
            encrypted,
            data,
            signature,
        };

        Ok(Some(item))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.signature_length as usize != item.signature.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Field signature_length doesnt equal singature.len()",
            ));
        }

        dst.reserve(Self::SIZE_OF_WITHOUT_VECS + item.data.len() + item.signature.len());

        dst.extend_from_slice(&item.signature_length.to_le_bytes());
        dst.extend_from_slice(&item.version.to_le_bytes());
        dst.extend_from_slice(&item.message_type.to_le_bytes());
        dst.extend_from_slice(&item.service_id.to_le_bytes());
        dst.extend_from_slice(&item.payload_length.to_le_bytes());
        dst.extend_from_slice(&item.encrypted.to_le_bytes());
        dst.extend_from_slice(&item.data);
        dst.extend_from_slice(&item.signature);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Message;
    use crate::MessageCodec;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn encode_message() {
        let mut bytes = BytesMut::new();
        let mut codec = MessageCodec::new();
        let msg = Message {
            signature_length: 3,
            version: 5,
            message_type: 12,
            service_id: 9,
            payload_length: 11,
            encrypted: 10,
            data: vec![3u8; 4],
            signature: vec![2u8; 3],
        };

        codec.encode(msg, &mut bytes).unwrap();

        assert_eq!(bytes.len(), MessageCodec::SIZE_OF_WITHOUT_VECS + 7);
        assert_eq!(bytes[..4], 3_u32.to_le_bytes());
        assert_eq!(bytes[4..5], 5_u8.to_le_bytes());
        assert_eq!(bytes[5..7], 12_u16.to_le_bytes());
        assert_eq!(bytes[7..9], 9_u16.to_le_bytes());
        assert_eq!(bytes[9..13], 11_u32.to_le_bytes());
        assert_eq!(bytes[13..15], 10_u16.to_le_bytes());
        assert_eq!(bytes[15..19], [3u8; 4]);
        assert_eq!(bytes[19..], [2u8; 3]);
    }

    #[test]
    fn decode_message() {
        let mut bytes = BytesMut::new();
        let mut codec = MessageCodec::new();
        let msg = Message {
            signature_length: 3,
            version: 5,
            message_type: 12,
            service_id: 9,
            payload_length: 11,
            encrypted: 10,
            data: vec![3u8; 4],
            signature: vec![2u8; 3],
        };

        codec.encode(msg, &mut bytes).unwrap();

        let msg = codec.decode(&mut bytes).unwrap().unwrap();

        assert_eq!(msg.signature_length, 3_u32);
        assert_eq!(msg.version, 5_u8);
        assert_eq!(msg.message_type, 12_u16);
        assert_eq!(msg.service_id, 9_u16);
        assert_eq!(msg.payload_length, 11_u32);
        assert_eq!(msg.encrypted, 10_u16);
        assert_eq!(msg.data, [3u8; 4]);
        assert_eq!(msg.signature, [2u8; 3]);
    }

    #[test]
    fn encode_invalid_message() {
        let mut bytes = BytesMut::new();
        let mut codec = MessageCodec::new();
        let msg = Message {
            signature_length: 5,
            version: 5,
            message_type: 12,
            service_id: 9,
            payload_length: 11,
            encrypted: 10,
            data: vec![3u8; 4],
            signature: vec![2u8; 3],
        };

        if let Ok(_) = codec.encode(msg, &mut bytes) {
            panic!();
        }
    }
}

fn main() {
    println!("Hello, PPR!");
}
