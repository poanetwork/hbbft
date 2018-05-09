//! Protobuf message IO task structure.

use proto::*;
use protobuf;
use protobuf::Message as ProtobufMessage;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::{cmp, io};

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
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<protobuf::ProtobufError> for Error {
    fn from(err: protobuf::ProtobufError) -> Error {
        Error::ProtobufError(err)
    }
}

fn encode_u32_to_be(value: u32, buffer: &mut [u8]) -> Result<(), Error> {
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

pub struct ProtoIo<S: Read + Write> {
    stream: S,
    buffer: [u8; 1024 * 4],
}

impl ProtoIo<TcpStream> {
    pub fn try_clone(&self) -> Result<ProtoIo<TcpStream>, ::std::io::Error> {
        Ok(ProtoIo {
            stream: self.stream.try_clone()?,
            buffer: [0; 1024 * 4],
        })
    }
}

/// A message handling task.
impl<S: Read + Write> ProtoIo<S>
//where T: Clone + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>
{
    pub fn from_stream(stream: S) -> Self {
        ProtoIo {
            stream,
            buffer: [0; 1024 * 4],
        }
    }

    pub fn recv<T>(&mut self) -> Result<Message<T>, Error>
    where
        T: Clone + Send + Sync + AsRef<[u8]> + From<Vec<u8>>,
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
            let num_to_read = cmp::min(self.buffer.len(), size - message_v.len());
            let (slice, _) = self.buffer.split_at_mut(num_to_read);
            self.stream.read_exact(slice)?;
            message_v.extend_from_slice(slice);
        }

        Message::parse_from_bytes(&message_v).map_err(Error::ProtobufError)
    }

    pub fn send<T>(&mut self, message: Message<T>) -> Result<(), Error>
    where
        T: Clone + Send + Sync + AsRef<[u8]> + From<Vec<u8>>,
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
    use broadcast::BroadcastMessage;
    use proto_io::*;
    use std::io::Cursor;

    #[test]
    fn encode_decode_message() {
        let msg0: Message<Vec<u8>> =
            Message::Broadcast(BroadcastMessage::Ready(b"Test 0".to_vec()));
        let msg1: Message<Vec<u8>> =
            Message::Broadcast(BroadcastMessage::Ready(b"Test 1".to_vec()));
        let mut pio = ProtoIo::from_stream(Cursor::new(Vec::new()));
        pio.send(msg0.clone()).expect("send msg0");
        pio.send(msg1.clone()).expect("send msg1");
        println!("{:?}", pio.stream.get_ref());
        pio.stream.set_position(0);
        assert_eq!(msg0, pio.recv().expect("recv msg0"));
        assert_eq!(msg1, pio.recv().expect("recv msg1"));
    }
}
