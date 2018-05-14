//! Construction of messages from protobuf buffers.

pub mod message;

use std::fmt::{self, Debug, Display, Formatter};

use merkle::proof::{Lemma, Positioned, Proof};
use ring::digest::Algorithm;

use agreement::AgreementMessage;
use broadcast::BroadcastMessage;
use proto::message::{
    AgreementProto,
    BroadcastProto,
    EchoProto,
    LemmaProto,
    ProofProto,
    ReadyProto,
    ValueProto
};

/// Wrapper for a byte array, whose `Debug` implementation outputs shortened hexadecimal strings.
pub struct HexBytes<'a>(pub &'a [u8]);

impl<'a> Debug for HexBytes<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if self.0.len() > 6 {
            for byte in &self.0[..3] {
                write!(f, "{:02x}", byte)?;
            }
            write!(f, "..")?;
            for byte in &self.0[(self.0.len() - 3)..] {
                write!(f, "{:02x}", byte)?;
            }
        } else {
            for byte in self.0 {
                write!(f, "{:02x}", byte)?;
            }
        }
        Ok(())
    }
}

/// Wrapper for a list of byte arrays, whose `Debug` implementation outputs shortened hexadecimal
/// strings.
pub struct HexList<'a, T: 'a>(pub &'a [T]);

impl<'a, T: AsRef<[u8]>> Debug for HexList<'a, T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let v: Vec<_> = self.0.iter().map(|t| HexBytes(t.as_ref())).collect();
        write!(f, "{:?}", v)
    }
}

pub struct HexProof<'a, T: 'a>(pub &'a Proof<T>);

impl<'a, T: AsRef<[u8]>> Debug for HexProof<'a, T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Proof {{ algorithm: {:?}, root_hash: {:?}, lemma for leaf #{}, value: {:?} }}",
            self.0.algorithm,
            HexBytes(&self.0.root_hash),
            path_of_lemma(&self.0.lemma),
            HexBytes(&self.0.value.as_ref())
        )
    }
}

impl From<BroadcastProto> for BroadcastMessage {
    fn from(proto: BroadcastProto) -> BroadcastMessage {
        BroadcastMessage::from_proto(proto, &::ring::digest::SHA256)
            .expect("invalid broadcast message")
    }
}

impl From<BroadcastMessage> for BroadcastProto {
    fn from(msg: BroadcastMessage) -> BroadcastProto {
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
    pub fn into_proto(self) -> AgreementProto {
        let mut p = AgreementProto::new();
        match self {
            AgreementMessage::BVal((e, b)) => {
                p.set_epoch(e);
                p.set_bval(b);
            }
            AgreementMessage::Aux((e, b)) => {
                p.set_epoch(e);
                p.set_aux(b);
            }
        }
        p
    }

    // TODO: Re-enable lint once implemented.
    #[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
    pub fn from_proto(mp: AgreementProto) -> Option<Self> {
        let epoch = mp.get_epoch();
        if mp.has_bval() {
            Some(AgreementMessage::BVal((epoch, mp.get_bval())))
        } else if mp.has_aux() {
            Some(AgreementMessage::Aux((epoch, mp.get_aux())))
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

/// The path of a lemma in a Merkle tree
struct BinaryPath(Vec<bool>);

/// The path of the lemma, as a binary string
fn path_of_lemma(mut lemma: &Lemma) -> BinaryPath {
    let mut result = Vec::new();
    loop {
        match lemma.sibling_hash {
            None => (),
            Some(Positioned::Left(_)) => result.push(true),
            Some(Positioned::Right(_)) => result.push(false),
        }
        lemma = match lemma.sub_lemma.as_ref() {
            Some(lemma) => lemma,
            None => return BinaryPath(result),
        }
    }
}

impl Display for BinaryPath {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for b in &self.0 {
            if *b {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}
