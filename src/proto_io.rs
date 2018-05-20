//! Protobuf message IO task structure.

use protobuf::{self, Message, ProtobufError};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::TcpStream;
use std::{cmp, io};

/// A magic key to put right before each message. An atavism of primitive serial
/// protocols.
///
/// TODO: Replace it with a proper handshake at connection initiation.
const FRAME_START: u32 = 0x2C0F_FEE5;

error_chain!{
    types {
        Error, ErrorKind, ResultExt, ProtoIoResult;
    }

    foreign_links {
        Io(io::Error);
        Protobuf(ProtobufError);
    }

    errors {
        Decode
        Encode
        FrameStartMismatch
    }
}

fn encode_u32_to_be(value: u32, buffer: &mut [u8]) -> ProtoIoResult<()> {
    if buffer.len() < 4 {
        return Err(ErrorKind::Encode.into());
    }
    let value = value.to_le();
    buffer[0] = ((value & 0xFF00_0000) >> 24) as u8;
    buffer[1] = ((value & 0x00FF_0000) >> 16) as u8;
    buffer[2] = ((value & 0x0000_FF00) >> 8) as u8;
    buffer[3] = (value & 0x0000_00FF) as u8;
    Ok(())
}

fn decode_u32_from_be(buffer: &[u8]) -> ProtoIoResult<u32> {
    if buffer.len() < 4 {
        return Err(ErrorKind::Decode.into());
    }
    let mut result = u32::from(buffer[0]);
    result <<= 8;
    result += u32::from(buffer[1]);
    result <<= 8;
    result += u32::from(buffer[2]);
    result <<= 8;
    result += u32::from(buffer[3]);
    Ok(result)
}

pub struct ProtoIo<S: Read + Write, M> {
    stream: S,
    buffer: [u8; 1024 * 4],
    _phantom: PhantomData<M>,
}

impl<M> ProtoIo<TcpStream, M> {
    pub fn try_clone(&self) -> Result<Self, ::std::io::Error> {
        Ok(ProtoIo {
            stream: self.stream.try_clone()?,
            buffer: [0; 1024 * 4],
            _phantom: PhantomData,
        })
    }
}

/// A message handling task.
impl<S: Read + Write, M: Message> ProtoIo<S, M>
//where T: Clone + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>
{
    pub fn from_stream(stream: S) -> Self {
        ProtoIo {
            stream,
            buffer: [0; 1024 * 4],
            _phantom: PhantomData,
        }
    }

    pub fn recv(&mut self) -> ProtoIoResult<M> {
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let frame_start = decode_u32_from_be(&self.buffer[0..4])?;
        if frame_start != FRAME_START {
            return Err(ErrorKind::FrameStartMismatch.into());
        };
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let size = decode_u32_from_be(&self.buffer[0..4])? as usize;

        let mut message_v: Vec<u8> = Vec::new();
        message_v.reserve(size);
        while message_v.len() < size {
            let num_to_read = cmp::min(self.buffer.len(), size - message_v.len());
            let (slice, _) = self.buffer.split_at_mut(num_to_read);
            self.stream.read_exact(slice)?;
            message_v.extend_from_slice(slice);
        }

        protobuf::parse_from_bytes(&message_v).map_err(|e| e.into())
    }

    pub fn send(&mut self, message: &M) -> ProtoIoResult<()> {
        let mut buffer: [u8; 4] = [0; 4];
        // Wrap stream
        let mut stream = protobuf::CodedOutputStream::new(&mut self.stream);
        // Write magic number
        encode_u32_to_be(FRAME_START, &mut buffer[0..4])?;
        stream.write_raw_bytes(&buffer)?;
        // Write message size
        encode_u32_to_be(message.compute_size(), &mut buffer[0..4])?;
        stream.write_raw_bytes(&buffer)?;
        // Write message
        message.write_to(&mut stream)?;
        // Flush
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use broadcast::BroadcastMessage;
    use proto::message::BroadcastProto;
    use proto_io::*;
    use std::io::Cursor;

    #[test]
    fn encode_decode_message() {
        let msg0 = BroadcastMessage::Ready(b"Test 0".to_vec());
        let msg1 = BroadcastMessage::Ready(b"Test 1".to_vec());
        let mut pio = ProtoIo::<_, BroadcastProto>::from_stream(Cursor::new(Vec::new()));
        pio.send(&msg0.clone().into()).expect("send msg0");
        pio.send(&msg1.clone().into()).expect("send msg1");
        println!("{:?}", pio.stream.get_ref());
        pio.stream.set_position(0);
        assert_eq!(msg0, pio.recv().expect("recv msg0").into());
        assert_eq!(msg1, pio.recv().expect("recv msg1").into());
    }
}
