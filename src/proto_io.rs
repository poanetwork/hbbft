//! Protobuf message IO task structure.
use std::io::{self, Read, Write};
use std::net::TcpStream;

use protobuf::{
    CodedInputStream,
    CodedOutputStream,
    Message as ProtobufMessage,
    ProtobufError
};

use proto::Message;

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
    ProtobufError(ProtobufError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<ProtobufError> for Error {
    fn from(err: ProtobufError) -> Error {
        Error::ProtobufError(err)
    }
}

pub struct ProtoIo<S: Read + Write> {
    stream: S,
}

impl ProtoIo<TcpStream> {
    pub fn try_clone(&self) -> Result<ProtoIo<TcpStream>, io::Error> {
        Ok(ProtoIo {
            stream: self.stream.try_clone()?,
        })
    }
}

/// A message handling task.
impl<S: Read + Write> ProtoIo<S>
    // where T: Clone + Send + Sync + From<Vec<u8>> + Into<Vec<u8>>
{
    pub fn from_stream(stream: S) -> Self {
        ProtoIo { stream }
    }

    pub fn recv<T>(&mut self) -> Result<Message<T>, Error>
    where
        T: Clone + Send + Sync + From<Vec<u8>>, // + Into<Vec<u8>>
    {
        let mut stream = CodedInputStream::new(&mut self.stream);
        // Read magic number
        if stream.read_raw_varint32()? != FRAME_START {
            return Err(Error::FrameStartMismatch);
        }
        Message::from_proto(stream.read_message()?).ok_or(Error::DecodeError)
    }

    pub fn send<T>(&mut self, message: Message<T>) -> Result<(), Error>
    where
        T: Clone + Send + Sync + Into<Vec<u8>>,
    {
        let mut stream = CodedOutputStream::new(&mut self.stream);
        // Write magic number
        stream.write_raw_varint32(FRAME_START)?;
        let message_p = message.into_proto();
        // Write message
        message_p.write_length_delimited_to(&mut stream)?;
        // Flush
        stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    
    use proto::{BroadcastMessage, Message};
    use super::ProtoIo;

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
        // TODO: Figure out why the cursor is wrong here.
        let len = pio.stream.get_ref().len() as u64;
        pio.stream.set_position(len / 2);
        assert_eq!(msg1, pio.recv().expect("recv msg1"));
    }
}
