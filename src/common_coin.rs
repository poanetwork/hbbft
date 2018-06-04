//! Common coin from a given set of keys.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::rc::Rc;

use pairing::bls12_381::Bls12;

use crypto::{PublicKey, PublicKeySet, SecretKey, SecretKeySet, Signature};
use messaging::{DistAlgorithm, NetworkInfo, Target, TargetedMessage};

error_chain! {
    errors {
        NotImplemented {
            description("not implemented")
        }
    }
}

#[derive(Debug)]
struct CommonCoinMessage {}

#[derive(Debug)]
struct CommonCoin<N>
where
    N: Debug,
{
    netinfo: Rc<NetworkInfo<N>>,
    output: Option<Signature<Bls12>>,
    messages: VecDeque<TargetedMessage<CommonCoinMessage, N>>,
}

impl<N> DistAlgorithm for CommonCoin<N>
where
    N: Clone + Debug + Ord,
{
    type NodeUid = N;
    type Input = ();
    type Output = Signature<Bls12>;
    type Message = CommonCoinMessage;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<()> {
        // FIXME
        Err(ErrorKind::NotImplemented.into())
    }

    /// Receive input from a remote node.
    fn handle_message(&mut self, sender_id: &Self::NodeUid, message: Self::Message) -> Result<()> {
        // FIXME
        Err(ErrorKind::NotImplemented.into())
    }

    /// Take the next Agreement message for multicast to all other nodes.
    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, Self::NodeUid>> {
        self.messages.pop_front()
    }

    /// Consume the output. Once consumed, the output stays `None` forever.
    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.take()
    }

    /// Whether the algorithm has terminated.
    fn terminated(&self) -> bool {
        // FIXME
        false
    }

    fn our_id(&self) -> &Self::NodeUid {
        self.netinfo.our_uid()
    }
}

impl<N> CommonCoin<N>
where
    N: Clone + Debug + Ord,
{
    pub fn new(netinfo: Rc<NetworkInfo<N>>) -> Self {
        CommonCoin {
            netinfo,
            output: None,
            messages: VecDeque::new(),
        }
    }
}
