//! Protobuf message IO task structure. The generic, shared behaviour is
//! contained in the implementation of `Task` while any specific behaviour
//! should be defined by means of the `MessageLoop` trait interface.

use std::{cmp,io};
use std::io::Read;
use std::net::TcpStream;
use protobuf;
use protobuf::Message as ProtoBufMessage;
use proto::message::{MessageProto};

/// A magic key to put right before each message. An atavism of primitive serial
/// protocols.
///
/// TODO: Replace it with a proper handshake at connection initiation.
const FRAME_START: u32 = 0x2C0FFEE5;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    EncodeError,
    DecodeError,
    FrameStartMismatch,
    ProtocolError,
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
    buffer[0] = ((value & 0xFF000000) >> 24) as u8;
    buffer[1] = ((value & 0x00FF0000) >> 16) as u8;
    buffer[2] = ((value & 0x0000FF00) >> 8) as u8;
    buffer[3] = (value & 0x000000FF) as u8;
    Ok(())
}

fn decode_u32_from_be(buffer: &[u8]) -> Result<u32, Error> {
    if buffer.len() < 4 {
        return Err(Error::DecodeError);
    }
    let mut result: u32 = buffer[0] as u32;
    result = result << 8;
    result += buffer[1] as u32;
    result = result << 8;
    result += buffer[2] as u32;
    result = result << 8;
    result += buffer[3] as u32;
    Ok(result)
}

/// A trait allowing custom definitions of the main loop and the received
/// message callback.
pub trait MessageLoop {
    fn run(&mut self);
    fn on_message_received(&mut self,
                           message: MessageProto)
                           -> Result<(), Error>;
}

pub struct Task {
    stream: TcpStream,
    buffer: [u8; 1024],
}

/// Placeholder `MessageLoop` definition for a generic `Task`.
impl MessageLoop for Task {
    fn run(&mut self) {}
    fn on_message_received(&mut self, _: MessageProto) -> Result<(), Error> {
        Ok(())
    }
}

/// A message handling task.
impl Task where Self: MessageLoop {
    pub fn new(stream: TcpStream) -> Task {
        Task {
            stream,
            buffer: [0; 1024]
        }
    }

    pub fn receive_message(&mut self) -> Result<MessageProto, Error> {
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let frame_start = decode_u32_from_be(&self.buffer[0..4])?;
        if frame_start != FRAME_START {
            return Err(Error::FrameStartMismatch);
        };
        self.stream.read_exact(&mut self.buffer[0..4])?;
        let size = decode_u32_from_be(&self.buffer[0..4])? as usize;

        let mut message: Vec<u8> = Vec::new();
        message.reserve(size);
        while message.len() < size {
            let num_to_read = cmp::min(self.buffer.len(), size - message.len());
            let (slice, _) = self.buffer.split_at_mut(num_to_read);
            self.stream.read_exact(slice)?;
            message.extend_from_slice(slice);
        }
        let message = protobuf::parse_from_bytes::<MessageProto>(&message)?;
        Ok(message)
    }

    pub fn send_message(&mut self, message: &MessageProto) -> Result<(), Error> {
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
    use task::*;

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
