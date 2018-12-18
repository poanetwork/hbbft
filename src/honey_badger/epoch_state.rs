use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::mem::replace;
use std::result;
use std::sync::Arc;

use crate::crypto::Ciphertext;
use bincode;
use log::error;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::{Deserialize, Serialize};

use super::{Batch, Error, FaultKind, FaultLog, MessageContent, Result, Step};
use crate::fault_log::Fault;
use crate::subset::{self as cs, Subset, SubsetOutput};
use crate::threshold_decrypt::{self as td, ThresholdDecrypt};
use crate::{Contribution, NetworkInfo, NodeIdT};

type CsStep<N> = cs::Step<N>;

/// The status of an encrypted contribution.
#[derive(Debug)]
enum DecryptionState<N> {
    /// Decryption is still ongoing; we are waiting for decryption shares and/or ciphertext.
    Ongoing(Box<ThresholdDecrypt<N>>),
    /// Decryption is complete. This contains the plaintext.
    Complete(Vec<u8>),
}

impl<N: NodeIdT> DecryptionState<N> {
    /// Creates a new `ThresholdDecrypt` instance, waiting for shares and a ciphertext.
    fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        DecryptionState::Ongoing(Box::new(ThresholdDecrypt::new(netinfo)))
    }

    /// Handles a message containing a decryption share.
    fn handle_message(&mut self, sender_id: &N, msg: td::Message) -> td::Result<td::Step<N>> {
        match self {
            DecryptionState::Ongoing(ref mut td) => td.handle_message(sender_id, msg),
            DecryptionState::Complete(_) => Ok(td::Step::default()),
        }
    }

    /// Handles a ciphertext input.
    fn set_ciphertext(&mut self, ciphertext: Ciphertext) -> td::Result<td::Step<N>> {
        match self {
            DecryptionState::Ongoing(ref mut td) => {
                td.set_ciphertext(ciphertext)?;
                td.start_decryption()
            }
            DecryptionState::Complete(_) => Ok(td::Step::default()),
        }
    }
}

/// The status of the subset algorithm.
#[derive(Debug)]
enum SubsetState<N> {
    /// The algorithm is ongoing: the set of accepted contributions is still undecided.
    Ongoing(Subset<N, EpochId>),
    /// The algorithm is complete. This contains the set of accepted proposers.
    Complete(BTreeSet<N>),
}

impl<N: NodeIdT> SubsetState<N> {
    /// Provides input to the Subset instance, unless it has already completed.
    fn handle_input(&mut self, proposal: Vec<u8>) -> Result<CsStep<N>> {
        match self {
            SubsetState::Ongoing(ref mut cs) => cs.propose(proposal),
            SubsetState::Complete(_) => return Ok(cs::Step::default()),
        }
        .map_err(Error::InputSubset)
    }

    /// Handles a message in the Subset instance, unless it has already completed.
    fn handle_message(&mut self, sender_id: &N, msg: cs::Message<N>) -> Result<CsStep<N>> {
        match self {
            SubsetState::Ongoing(ref mut cs) => cs.handle_message(sender_id, msg),
            SubsetState::Complete(_) => return Ok(cs::Step::default()),
        }
        .map_err(Error::HandleSubsetMessage)
    }

    /// Returns the number of contributions that we have already received or, after completion, how
    /// many have been accepted.
    pub fn received_proposals(&self) -> usize {
        match self {
            SubsetState::Ongoing(ref cs) => cs.received_proposals(),
            SubsetState::Complete(ref proposer_ids) => proposer_ids.len(),
        }
    }

    /// Returns the IDs of the accepted proposers, if that has already been decided.
    pub fn accepted_ids(&self) -> Option<&BTreeSet<N>> {
        match self {
            SubsetState::Ongoing(_) => None,
            SubsetState::Complete(ref ids) => Some(ids),
        }
    }
}

/// A flag used when constructing an `EpochState` to determine which behavior to use when receiving
/// proposals from a `Subset` instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubsetHandlingStrategy {
    /// Sets the `EpochState` to return proposals as they are contributed.
    Incremental,
    /// Sets the `EpochState` to return all received proposals once consensus has been finalized.
    AllAtEnd,
}

/// Used in an `EpochState` to encapsulate the state necessary to maintain each
/// `SubsetHandlingStrategy`.
#[derive(Debug, Clone)]
enum SubsetHandler<N> {
    Incremental,
    AllAtEnd(Vec<(N, Vec<u8>)>),
}

/// The result of a call to `SubsetHandler::handle(...)`.
struct SubsetHandleData<N> {
    /// The number of contributions propagated from the handler.
    contributions: Vec<(N, Vec<u8>)>,
    /// Indicates whether the underlying `Subset` algorithm has achieved consensus and whether
    /// there may be more contributions or not.
    is_done: bool,
}

impl<N> SubsetHandler<N> {
    fn handle(&mut self, o: SubsetOutput<N>) -> SubsetHandleData<N> {
        use self::SubsetHandler::*;
        use self::SubsetOutput::*;
        let contributions;
        let is_done;
        match o {
            Contribution(proposer_id, data) => {
                let proposal = (proposer_id, data);
                contributions = match self {
                    Incremental => vec![proposal],
                    AllAtEnd(cs) => {
                        cs.push(proposal);
                        vec![]
                    }
                };
                is_done = false;
            }
            Done => {
                contributions = match self {
                    Incremental => vec![],
                    AllAtEnd(cs) => replace(cs, vec![]),
                };
                is_done = true;
            }
        }

        SubsetHandleData {
            contributions,
            is_done,
        }
    }
}

impl<N> From<SubsetHandlingStrategy> for SubsetHandler<N> {
    fn from(s: SubsetHandlingStrategy) -> Self {
        use self::SubsetHandlingStrategy::*;
        match s {
            Incremental => SubsetHandler::Incremental,
            AllAtEnd => SubsetHandler::AllAtEnd(Vec::new()),
        }
    }
}

/// The sub-algorithms and their intermediate results for a single epoch.
#[derive(Debug)]
pub struct EpochState<C, N> {
    /// Our epoch number.
    epoch: u64,
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The status of the subset algorithm.
    subset: SubsetState<N>,
    /// The status of threshold decryption, by proposer.
    decryption: BTreeMap<N, DecryptionState<N>>,
    /// Nodes found so far in `Subset` output.
    accepted_proposers: BTreeSet<N>,
    /// Determines the behavior upon receiving proposals from `subset`.
    subset_handler: SubsetHandler<N>,
    /// Whether contributions should be encrypted in this epoch.
    require_decryption: bool,
    _phantom: PhantomData<C>,
}

impl<C, N> EpochState<C, N>
where
    C: Contribution + Serialize + DeserializeOwned,
    N: NodeIdT,
{
    /// Creates a new `Subset` instance.
    pub fn new(
        netinfo: Arc<NetworkInfo<N>>,
        hb_id: u64,
        epoch: u64,
        subset_handling_strategy: SubsetHandlingStrategy,
        require_decryption: bool,
    ) -> Result<Self> {
        let epoch_id = EpochId { hb_id, epoch };
        let cs = Subset::new(netinfo.clone(), epoch_id).map_err(Error::CreateSubset)?;
        Ok(EpochState {
            epoch,
            netinfo,
            subset: SubsetState::Ongoing(cs),
            decryption: BTreeMap::default(),
            accepted_proposers: Default::default(),
            subset_handler: subset_handling_strategy.into(),
            require_decryption,
            _phantom: PhantomData,
        })
    }

    /// If the instance hasn't terminated yet, inputs our encrypted contribution.
    pub fn propose<R: Rng>(&mut self, proposal: &C, rng: &mut R) -> Result<Step<C, N>> {
        let ser_prop = bincode::serialize(&proposal).map_err(|err| Error::ProposeBincode(*err))?;
        let cs_step = self.subset.handle_input(if self.require_decryption {
            let ciphertext = self
                .netinfo
                .public_key_set()
                .public_key()
                .encrypt_with_rng(rng, ser_prop);
            bincode::serialize(&ciphertext).map_err(|err| Error::ProposeBincode(*err))?
        } else {
            ser_prop
        })?;
        self.process_subset(cs_step)
    }

    /// Returns the number of contributions that we have already received or, after completion, how
    /// many have been accepted.
    pub fn received_proposals(&self) -> usize {
        self.subset.received_proposals()
    }

    /// Handles a message for the Subset or a Threshold Decrypt instance.
    pub fn handle_message_content(
        &mut self,
        sender_id: &N,
        content: MessageContent<N>,
    ) -> Result<Step<C, N>> {
        match content {
            MessageContent::Subset(cs_msg) => {
                let cs_step = self.subset.handle_message(sender_id, cs_msg)?;
                self.process_subset(cs_step)
            }
            MessageContent::DecryptionShare { proposer_id, share } => {
                if let Some(ref ids) = self.subset.accepted_ids() {
                    if !ids.contains(&proposer_id) {
                        let fault_kind = FaultKind::UnexpectedDecryptionShare;
                        return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                    }
                }
                let td_step = match self.decryption.entry(proposer_id.clone()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        entry.insert(DecryptionState::new(self.netinfo.clone()))
                    }
                }
                .handle_message(sender_id, share)
                .map_err(Error::ThresholdDecrypt)?;
                self.process_decryption(proposer_id, td_step)
            }
        }
    }

    /// When contributions of transactions have been decrypted for all valid proposers in this
    /// epoch, moves those contributions into a batch, outputs the batch and updates the epoch.
    pub fn try_output_batch(&self) -> Option<(Batch<C, N>, FaultLog<N>)> {
        let proposer_ids = self.subset.accepted_ids()?;
        let mut plaintexts = Vec::new();
        // Collect accepted plaintexts. Return if some are not decrypted yet.
        for id in proposer_ids {
            match self.decryption.get(id) {
                None | Some(DecryptionState::Ongoing(_)) => return None,
                Some(DecryptionState::Complete(ref pt)) => plaintexts.push((id.clone(), pt)),
            }
        }

        let mut fault_log = FaultLog::default();
        let mut batch = Batch {
            epoch: self.epoch,
            contributions: BTreeMap::new(),
        };
        // Deserialize the output. If it fails, the proposer of that item is faulty.
        for (id, plaintext) in plaintexts {
            match bincode::deserialize::<C>(plaintext) {
                Ok(contrib) => {
                    batch.contributions.insert(id, contrib);
                }
                Err(_) => fault_log.append(id, FaultKind::BatchDeserializationFailed),
            }
        }
        Some((batch, fault_log))
    }

    /// Checks whether the subset has output, and if it does, sends out our decryption shares.
    fn process_subset(&mut self, cs_step: CsStep<N>) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let cs_outputs = step.extend_with(cs_step, FaultKind::SubsetFault, |cs_msg| {
            MessageContent::Subset(cs_msg).with_epoch(self.epoch)
        });
        let mut has_seen_done = false;
        for cs_output in cs_outputs {
            if has_seen_done {
                // TODO: Is there any way we can statically guarantee that?
                error!("`SubsetOutput::Done` was not the last `SubsetOutput`");
            }

            let SubsetHandleData {
                contributions,
                is_done,
            } = self.subset_handler.handle(cs_output);

            for (k, v) in contributions {
                step.extend(if self.require_decryption {
                    self.send_decryption_share(k.clone(), &v)?
                } else {
                    self.decryption
                        .insert(k.clone(), DecryptionState::Complete(v));
                    Step::default()
                });
                self.accepted_proposers.insert(k);
            }

            if is_done {
                self.subset = SubsetState::Complete(self.accepted_proposers.clone());
                let faulty_shares: Vec<_> = self
                    .decryption
                    .keys()
                    .filter(|id| !self.accepted_proposers.contains(id))
                    .cloned()
                    .collect();
                for id in faulty_shares {
                    if let Some(DecryptionState::Ongoing(td)) = self.decryption.remove(&id) {
                        for id in td.sender_ids() {
                            let fault_kind = FaultKind::UnexpectedDecryptionShare;
                            step.fault_log.append(id.clone(), fault_kind);
                        }
                    }
                }
                has_seen_done = true;
            }
        }
        Ok(step)
    }

    /// Processes a Threshold Decrypt step.
    fn process_decryption(&mut self, proposer_id: N, td_step: td::Step<N>) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let opt_output = step.extend_with(td_step, FaultKind::DecryptionFault, |share| {
            MessageContent::DecryptionShare {
                proposer_id: proposer_id.clone(),
                share,
            }
            .with_epoch(self.epoch)
        });
        if let Some(output) = opt_output.into_iter().next() {
            self.decryption
                .insert(proposer_id, DecryptionState::Complete(output));
        }
        Ok(step)
    }

    /// Given the output of the Subset algorithm, inputs the ciphertexts into the Threshold
    /// Decrypt instances and sends our own decryption shares.
    fn send_decryption_share(&mut self, proposer_id: N, v: &[u8]) -> Result<Step<C, N>> {
        let ciphertext: Ciphertext = match bincode::deserialize(v) {
            Ok(ciphertext) => ciphertext,
            Err(_) => {
                return Ok(Fault::new(proposer_id, FaultKind::DeserializeCiphertext).into());
            }
        };
        let td_result = match self.decryption.entry(proposer_id.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(DecryptionState::new(self.netinfo.clone())),
        }
        .set_ciphertext(ciphertext);
        match td_result {
            Ok(td_step) => self.process_decryption(proposer_id, td_step),
            Err(td::Error::InvalidCiphertext(_)) => {
                Ok(Fault::new(proposer_id, FaultKind::InvalidCiphertext).into())
            }
            Err(err) => Err(Error::ThresholdDecrypt(err)),
        }
    }
}

/// A session identifier for a `Subset` sub-algorithm run within an epoch. It consists of the epoch
/// number, and an optional `HoneyBadger` session identifier.
#[derive(Clone, Debug, Serialize)]
struct EpochId {
    hb_id: u64,
    epoch: u64,
}

impl Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}/{}", self.hb_id, self.epoch)
    }
}
