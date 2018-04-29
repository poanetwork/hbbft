//! Protobuf message IO task structure.

use std::{cmp,io};
use std::io::Read;
use std::net::TcpStream;
use protobuf;
use protobuf::Message as ProtobufMessage;
use proto::*;

/// A magic key to put right before each message. An atavism of primitive serial
/// protocols.
///
/// TODO: Replace it with a proper handshake at connection initiation.
const FRAME_START: u32 = 0x2C0F_FEE5;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    EncodeError,
    DecodeError,
    FrameStartMismatch,
    // ProtocolError,
    ProtobufError(protobuf::ProtobufError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error { Error::IoError(err) }
}

impl From<protobuf::ProtobufError> for Error {
    fn from(err: protobuf::ProtobufError) -> Error { Error::ProtobufError(err) }
}

fn encode_u32_to_be(value: u32, buffer: &mut[u8]) -> Result<(), Error> {
    if buffer.len() < 4 {
        return Err(Error::EncodeError);
    }
    let value = value.to_le();
    buffer[0] = ((value & 0xFF00_0000) >> 24) as u8;
    buffer[1] = ((value & 0x00FF_0000) >> 16) as u8;
    buffer[2] = ((value & 0x0000_FF00) >> 8) as u8;
    buffer[3] = (value & 0x0000_00FF) as u8;
    Ok(())
}

fn decode_u32_from_be(buffer: &[u8]) -> Result<u32, Error> {
    if buffer.len() < 4 {
        return Err(Error::DecodeError);
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

pub struct ProtoIo {
    stream: TcpStream,
    buffer: [u8; 1024 * 4],
}

/// A message handling task.
impl ProtoIo
//where T: Clone + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>
{
    pub fn from_stream(stream: TcpStream) -> Self {
        ProtoIo {
            stream,
            buffer: [0; 1024 * 4],
        }
    }

    pub fn try_clone(&self) -> Result<ProtoIo, ::std::io::Error> {
        Ok(ProtoIo {
            stream: self.stream.try_clone()?,
            buffer: self.buffer,
        })
    }

    pub fn recv<T>(&mut self) -> Result<Message<T>, Error>
    where T: Clone + Send + Sync + From<Vec<u8>> // + Into<Vec<u8>>
    {
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let frame_start = decode_u32_from_be(&self.buffer[0..4])?;
        if frame_start != FRAME_START {
            return Err(Error::FrameStartMismatch);
        };
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let size = decode_u32_from_be(&self.buffer[0..4])? as usize;

        let mut message_v: Vec<u8> = Vec::new();
        message_v.reserve(size);
        while message_v.len() < size {
            let num_to_read = cmp::min(self.buffer.len(), size -
                                       message_v.len());
            let (slice, _) = self.buffer.split_at_mut(num_to_read);
            self.stream.read_exact(slice)?;
            message_v.extend_from_slice(slice);
        }

        Message::parse_from_bytes(&message_v)
            .map_err(Error::ProtobufError)
    }

    pub fn send<T>(&mut self, message: Message<T>) -> Result<(), Error>
    where T: Clone + Send + Sync + Into<Vec<u8>>
    {
        let mut buffer: [u8; 4] = [0; 4];
        // Wrap stream
        let mut stream = protobuf::CodedOutputStream::new(&mut self.stream);
        // Write magic number
        encode_u32_to_be(FRAME_START, &mut buffer[0..4])?;
        stream.write_raw_bytes(&buffer)?;
        let message_p = message.into_proto();
        // Write message size
        encode_u32_to_be(message_p.compute_size(), &mut buffer[0..4])?;
        stream.write_raw_bytes(&buffer)?;
        // Write message
        message_p.write_to(&mut stream)?;
        // Flush
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proto_io::*;

    /// Test the requirement that composing encoding with decoding yields the
    /// identity.
    #[test]
    fn encode_decode_identity() {
        let mut buffer: [u8; 4] = [0; 4];
        encode_u32_to_be(FRAME_START, &mut buffer[0..4]).unwrap();
        let frame_start = decode_u32_from_be(&buffer[0..4]).unwrap();
        assert_eq!(frame_start, FRAME_START);
    }
}
