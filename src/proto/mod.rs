//! Construction of messages from protobuf buffers.
pub mod message;

use ring::digest::Algorithm;
use merkle::proof::{Proof, Lemma, Positioned};
//use protobuf::Message;
use self::message::*;
use protobuf::error::ProtobufResult;
use protobuf::core::parse_from_bytes;

/// Kinds of message sent by nodes participating in consensus.
enum Message<T> {
    Broadcast(BroadcastMessage<T>),
    Agreement(AgreementMessage<T>)
}

/// The three kinds of message sent during the reliable broadcast stage of the
/// consensus algorithm.
enum BroadcastMessage<T> {
    Value(Proof<T>),
    Echo(Proof<T>),
    Ready(Vec<u8>)
}

/// Messages sent during the binary Byzantine agreement stage.
enum AgreementMessage<T> {
    // TODO
    Phantom(T)
}

impl<T> Message<T> {
    pub fn from_protobuf(algorithm: &'static Algorithm,
                         mut proto: message::MessageProto) -> Option<Self>
        where T: From<Vec<u8>>,
    {
        if proto.has_broadcast() {
            proto.take_broadcast().into_broadcast(algorithm)
                .map(|b| Message::Broadcast(b))
        }
        else {
            // TODO
            None
        }
    }
}

impl BroadcastProto {
    pub fn into_broadcast<T>(mut self,
                             algorithm: &'static Algorithm)
                             -> Option<BroadcastMessage<T>>
        where T: From<Vec<u8>>,
    {
        if self.has_value() {
            self.take_value().take_proof().into_proof(algorithm)
                .map(|p| BroadcastMessage::Value(p))
        }
        else if self.has_echo() {
            self.take_echo().take_proof().into_proof(algorithm)
                .map(|p| BroadcastMessage::Echo(p))
        }
        else if self.has_ready() {
            let h = self.take_ready().take_root_hash();
            Some(BroadcastMessage::Ready(h))
        }
        else {
            None
        }
    }
}

impl ProofProto {
    pub fn into_proof<T>(mut self,
                         algorithm: &'static Algorithm)
                         -> Option<Proof<T>>
        where T: From<Vec<u8>>
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
            self.take_sub_lemma().into_lemma().map(|sub_lemma| {
                Lemma {
                    node_hash: node_hash,
                    sibling_hash: sibling_hash,
                    sub_lemma: Some(Box::new(sub_lemma)),
                }
            })
        } else {
            // We might very well not have a sub_lemma,
            // in which case we just set it to `None`,
            // but still return a potentially valid `Lemma`.
            Some(Lemma {
                node_hash: node_hash,
                sibling_hash: sibling_hash,
                sub_lemma: None,
            })
        }
    }
}
