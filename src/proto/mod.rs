//! Construction of messages from protobuf buffers.
pub mod message;

use merkle::proof::{Lemma, Positioned, Proof};
use ring::digest::Algorithm;

use agreement::bin_values::BinValues;
use agreement::{AgreementContent, AgreementMessage};
use broadcast::BroadcastMessage;
use common_coin::CommonCoinMessage;
use crypto::{Signature, SignatureShare};
use proto::message::*;

impl From<message::BroadcastProto> for BroadcastMessage {
    fn from(proto: message::BroadcastProto) -> BroadcastMessage {
        BroadcastMessage::from_proto(proto, &::ring::digest::SHA256)
            .expect("invalid broadcast message")
    }
}

impl From<BroadcastMessage> for message::BroadcastProto {
    fn from(msg: BroadcastMessage) -> message::BroadcastProto {
        msg.into_proto()
    }
}

impl BroadcastMessage {
    pub fn into_proto(self) -> BroadcastProto {
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
                b.set_ready(r);
            }
        }
        b
    }

    pub fn from_proto(mut mp: BroadcastProto, algorithm: &'static Algorithm) -> Option<Self> {
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
    pub fn into_proto(self) -> message::AgreementProto {
        let mut p = message::AgreementProto::new();
        p.set_epoch(self.epoch);
        match self.content {
            AgreementContent::BVal(b) => {
                p.set_bval(b);
            }
            AgreementContent::Aux(b) => {
                p.set_aux(b);
            }
            AgreementContent::Conf(v) => {
                let bin_values = match v {
                    BinValues::None => 0,
                    BinValues::False => 1,
                    BinValues::True => 2,
                    BinValues::Both => 3,
                };
                p.set_conf(bin_values);
            }
            AgreementContent::Term(b) => {
                p.set_term(b);
            }
            AgreementContent::Coin(ccm) => {
                let v = ccm.to_sig().0.to_vec();
                p.set_coin(v);
            }
        }
        p
    }

    // TODO: Re-enable lint once implemented.
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn from_proto(mp: message::AgreementProto) -> Option<Self> {
        let epoch = mp.get_epoch();
        if mp.has_bval() {
            Some(AgreementContent::BVal(mp.get_bval()).with_epoch(epoch))
        } else if mp.has_aux() {
            Some(AgreementContent::Aux(mp.get_aux()).with_epoch(epoch))
        } else if mp.has_conf() {
            match mp.get_conf() {
                0 => Some(BinValues::None),
                1 => Some(BinValues::False),
                2 => Some(BinValues::True),
                3 => Some(BinValues::Both),
                _ => None,
            }.map(|bin_values| AgreementContent::Conf(bin_values).with_epoch(epoch))
        } else if mp.has_term() {
            Some(AgreementContent::Term(mp.get_term()).with_epoch(epoch))
        } else if mp.has_coin() {
            Signature::from_bytes(mp.get_coin())
                .map(SignatureShare)
                .map(|sig| {
                    AgreementContent::Coin(Box::new(CommonCoinMessage::new(sig))).with_epoch(epoch)
                })
        } else {
            None
        }
    }
}

/// Serialisation of `Proof` defined against its protobuf interface to work
/// around the restriction of not being allowed to extend the implementation of
/// `Proof` outside its crate.
impl ProofProto {
    pub fn from_proof<T: AsRef<[u8]>>(proof: Proof<T>) -> Self {
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
                proto.set_value(value.as_ref().to_vec());
            }
        }

        proto
    }

    pub fn into_proof<T: From<Vec<u8>>>(
        mut self,
        algorithm: &'static Algorithm,
    ) -> Option<Proof<T>> {
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
