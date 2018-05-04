//! Construction of messages from protobuf buffers.
pub mod message;

use merkle::proof::{Lemma, Positioned, Proof};
use proto::message::*;
use protobuf::core::parse_from_bytes;
use protobuf::error::{ProtobufError, ProtobufResult, WireError};
use protobuf::Message as ProtobufMessage;
use ring::digest::Algorithm;
use std::fmt;
use std::marker::{Send, Sync};

/// Kinds of message sent by nodes participating in consensus.
#[derive(Clone, Debug, PartialEq)]
pub enum Message<T: Send + Sync> {
    Broadcast(BroadcastMessage<T>),
    Agreement(AgreementMessage),
}

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
#[derive(Clone, PartialEq)]
pub enum BroadcastMessage<T: Send + Sync> {
    Value(Proof<T>),
    Echo(Proof<T>),
    Ready(Vec<u8>),
}

pub struct HexBytes<'a>(pub &'a [u8]);

impl<'a> fmt::Debug for HexBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.len() > 6 {
            for byte in &self.0[..3] {
                write!(f, "{:0x}", byte)?;
            }
            write!(f, "..")?;
            for byte in &self.0[(self.0.len() - 3)..] {
                write!(f, "{:0x}", byte)?;
            }
        } else {
            for byte in self.0 {
                write!(f, "{:0x}", byte)?;
            }
        }
        Ok(())
    }
}

struct HexProof<'a, T: 'a>(&'a Proof<T>);

impl<'a, T: Send + Sync + fmt::Debug> fmt::Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Proof {{ algorithm: {:?}, root_hash: {:?}, lemma for leaf #{}, value: {:?} }}",
            self.0.algorithm,
            HexBytes(&self.0.root_hash),
            ::broadcast::index_of_proof(self.0),
            self.0.value
        )
    }
}

impl<T: Send + Sync + fmt::Debug> fmt::Debug for BroadcastMessage<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BroadcastMessage::Value(ref v) => write!(f, "Value({:?})", HexProof(&v)),
            BroadcastMessage::Echo(ref v) => write!(f, "Echo({:?})", HexProof(&v)),
            BroadcastMessage::Ready(ref bytes) => write!(f, "Ready({:?})", HexBytes(bytes)),
        }
    }
}

/// Messages sent during the binary Byzantine agreement stage.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AgreementMessage {
    BVal(bool),
    Aux(bool),
}

impl<T: Send + Sync> Message<T> {
    /// Translation from protobuf to the regular type.
    ///
    /// TODO: add an `Algorithm` field to `MessageProto`. Either `Algorithm` has
    /// to be fully serialised and sent as a whole, or it can be passed over
    /// using an ID and the `Eq` instance to discriminate the finite set of
    /// algorithms in `ring::digest`.
    pub fn from_proto(mut proto: message::MessageProto) -> Option<Self>
    where
        T: From<Vec<u8>>,
    {
        if proto.has_broadcast() {
            BroadcastMessage::from_proto(
                proto.take_broadcast(),
                // TODO, possibly move Algorithm inside
                // BroadcastMessage
                &::ring::digest::SHA256,
            ).map(Message::Broadcast)
        } else if proto.has_agreement() {
            AgreementMessage::from_proto(proto.take_agreement()).map(Message::Agreement)
        } else {
            None
        }
    }

    pub fn into_proto(self) -> MessageProto
    where
        T: Into<Vec<u8>>,
    {
        let mut m = MessageProto::new();
        match self {
            Message::Broadcast(b) => {
                m.set_broadcast(b.into_proto());
            }
            Message::Agreement(a) => {
                m.set_agreement(a.into_proto());
            }
        }
        m
    }

    /// Parse a `Message` from its protobuf binary representation.
    ///
    /// TODO: pass custom errors from down the chain of nested parsers as
    /// opposed to returning `WireError::Other`.
    pub fn parse_from_bytes(bytes: &[u8]) -> ProtobufResult<Self>
    where
        T: From<Vec<u8>>,
    {
        let r = parse_from_bytes::<MessageProto>(bytes).map(Self::from_proto);

        match r {
            Ok(Some(m)) => Ok(m),
            Ok(None) => Err(ProtobufError::WireError(WireError::Other)),
            Err(e) => Err(e),
        }
    }

    /// Produce a protobuf representation of this `Message`.
    pub fn write_to_bytes(self) -> ProtobufResult<Vec<u8>>
    where
        T: Into<Vec<u8>>,
    {
        self.into_proto().write_to_bytes()
    }
}

impl<T: Send + Sync> BroadcastMessage<T> {
    pub fn into_proto(self) -> BroadcastProto
    where
        T: Into<Vec<u8>>,
    {
        let mut b = BroadcastProto::new();
        match self {
            BroadcastMessage::Value(p) => {
                let mut v = ValueProto::new();
                v.set_proof(ProofProto::from_proof(p));
                b.set_value(v);
            }
            BroadcastMessage::Echo(p) => {
                let mut e = EchoProto::new();
                e.set_proof(ProofProto::from_proof(p));
                b.set_echo(e);
            }
            BroadcastMessage::Ready(h) => {
                let mut r = ReadyProto::new();
                r.set_root_hash(h);
            }
        }
        b
    }

    pub fn from_proto(mut mp: BroadcastProto, algorithm: &'static Algorithm) -> Option<Self>
    where
        T: From<Vec<u8>>,
    {
        if mp.has_value() {
            mp.take_value()
                .take_proof()
                .into_proof(algorithm)
                .map(BroadcastMessage::Value)
        } else if mp.has_echo() {
            mp.take_echo()
                .take_proof()
                .into_proof(algorithm)
                .map(BroadcastMessage::Echo)
        } else if mp.has_ready() {
            let h = mp.take_ready().take_root_hash();
            Some(BroadcastMessage::Ready(h))
        } else {
            None
        }
    }
}

impl AgreementMessage {
    pub fn into_proto(self) -> AgreementProto {
        let mut p = AgreementProto::new();
        match self {
            AgreementMessage::BVal(b) => p.set_bval(b),
            AgreementMessage::Aux(b) => p.set_aux(b),
        }
        p
    }

    // TODO: Re-enable lint once implemented.
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn from_proto(mp: AgreementProto) -> Option<Self> {
        if mp.has_bval() {
            Some(AgreementMessage::BVal(mp.get_bval()))
        } else if mp.has_aux() {
            Some(AgreementMessage::Aux(mp.get_aux()))
        } else {
            None
        }
    }
}

/// Serialisation of `Proof` defined against its protobuf interface to work
/// around the restriction of not being allowed to extend the implementation of
/// `Proof` outside its crate.
impl ProofProto {
    pub fn from_proof<T>(proof: Proof<T>) -> Self
    where
        T: Into<Vec<u8>>,
    {
        let mut proto = Self::new();

        match proof {
            Proof {
                root_hash,
                lemma,
                value,
                ..
                // algorithm, // TODO: use
            } => {
                proto.set_root_hash(root_hash);
                proto.set_lemma(LemmaProto::from_lemma(lemma));
                proto.set_value(value.into());
            }
        }

        proto
    }

    pub fn into_proof<T>(mut self, algorithm: &'static Algorithm) -> Option<Proof<T>>
    where
        T: From<Vec<u8>>,
    {
        if !self.has_lemma() {
            return None;
        }

        self.take_lemma().into_lemma().map(|lemma| {
            Proof::new(
                algorithm,
                self.take_root_hash(),
                lemma,
                self.take_value().into(),
            )
        })
    }
}

impl LemmaProto {
    pub fn from_lemma(lemma: Lemma) -> Self {
        let mut proto = Self::new();

        match lemma {
            Lemma {
                node_hash,
                sibling_hash,
                sub_lemma,
            } => {
                proto.set_node_hash(node_hash);

                if let Some(sub_proto) = sub_lemma.map(|l| Self::from_lemma(*l)) {
                    proto.set_sub_lemma(sub_proto);
                }

                match sibling_hash {
                    Some(Positioned::Left(hash)) => proto.set_left_sibling_hash(hash),

                    Some(Positioned::Right(hash)) => proto.set_right_sibling_hash(hash),

                    None => {}
                }
            }
        }

        proto
    }

    pub fn into_lemma(mut self) -> Option<Lemma> {
        let node_hash = self.take_node_hash();

        let sibling_hash = if self.has_left_sibling_hash() {
            Some(Positioned::Left(self.take_left_sibling_hash()))
        } else if self.has_right_sibling_hash() {
            Some(Positioned::Right(self.take_right_sibling_hash()))
        } else {
            None
        };

        if self.has_sub_lemma() {
            // If a `sub_lemma` is present is the Protobuf,
            // then we expect it to unserialize to a valid `Lemma`,
            // otherwise we return `None`
            self.take_sub_lemma().into_lemma().map(|sub_lemma| Lemma {
                node_hash,
                sibling_hash,
                sub_lemma: Some(Box::new(sub_lemma)),
            })
        } else {
            // We might very well not have a sub_lemma,
            // in which case we just set it to `None`,
            // but still return a potentially valid `Lemma`.
            Some(Lemma {
                node_hash,
                sibling_hash,
                sub_lemma: None,
            })
        }
    }
}
