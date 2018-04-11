//! Abstract interface to serialised IO.

use std::io;
use std::io::{Read, Write};

use proto::*;

/// Trait of types of streams carrying payload of type `Message<T>` and
/// returning errors of type `Error`.
///
/// This is a stream interface independent of the choice of serialisation
/// methods.
pub trait StreamIo<Stream, T, Error>: Sized
where Stream: Read + Write, T: Send + Sync // From implies Into
{
    fn from_stream(stream: Stream) -> Self;
    fn try_clone(&self) -> Result<Self, io::Error>;
    fn recv(&mut self) -> Result<Message<T>, Error>;
    fn send(&mut self, m: Message<T>) -> Result<(), Error>;
}
