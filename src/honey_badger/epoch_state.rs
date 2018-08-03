use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::Arc;

use bincode;
use crypto::Ciphertext;
use rand::Rand;
use serde::{Deserialize, Serialize};

use super::{Batch, ErrorKind, MessageContent, Result, Step};
use common_subset::{self, CommonSubset};
use fault_log::{Fault, FaultKind, FaultLog};
use messaging::{DistAlgorithm, NetworkInfo};
use threshold_decryption::{self as td, ThresholdDecryption};
use traits::{Contribution, NodeUidT};

/// The status of an encrypted contribution.
#[derive(Debug)]
enum DecryptionState<N> {
    /// Decryption is still ongoing; we are waiting for decryption shares and/or ciphertext.
    Ongoing(Box<ThresholdDecryption<N>>),
    /// Decryption is complete. This contains the plaintext.
    Complete(Vec<u8>),
}

impl<N> DecryptionState<N>
where
    N: NodeUidT + Rand,
{
    /// Creates a new `ThresholdDecryption` instance, waiting for shares and a ciphertext.
    fn new(netinfo: Arc<NetworkInfo<N>>) -> Self {
        DecryptionState::Ongoing(Box::new(ThresholdDecryption::new(netinfo)))
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
            DecryptionState::Ongoing(ref mut td) => td.input(ciphertext),
            DecryptionState::Complete(_) => Ok(td::Step::default()),
        }
    }

    /// Returns the plaintext, if it has already been decrypted.
    fn plaintext(&self) -> Option<&[u8]> {
        match self {
            DecryptionState::Ongoing(_) => None,
            DecryptionState::Complete(ref plaintext) => Some(&plaintext[..]),
        }
    }
}

/// The status of the subset algorithm.
#[derive(Debug)]
enum SubsetState<N: Rand> {
    /// The algorithm is ongoing: the set of accepted contributions is still undecided.
    Ongoing(CommonSubset<N>),
    /// The algorithm is complete. This contains the set of accepted proposers.
    Complete(BTreeSet<N>),
}

/// The sub-algorithms and their intermediate results for a single epoch.
#[derive(Debug)]
pub struct EpochState<C, N: Rand> {
    /// Our epoch number.
    epoch: u64,
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The status of the subset algorithm.
    subset: SubsetState<N>,
    /// The status of threshold decryption, by proposer.
    decryption: BTreeMap<N, DecryptionState<N>>,
    _phantom: PhantomData<C>,
}

impl<C, N> EpochState<C, N>
where
    C: Contribution + Serialize + for<'r> Deserialize<'r>,
    N: NodeUidT + Rand,
{
    /// Creates a new `CommonSubset` instance.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, epoch: u64) -> Result<Self> {
        let cs = CommonSubset::new(netinfo.clone(), epoch).map_err(ErrorKind::CreateCommonSubset)?;
        Ok(EpochState {
            epoch,
            netinfo,
            subset: SubsetState::Ongoing(cs),
            decryption: BTreeMap::default(),
            _phantom: PhantomData,
        })
    }

    /// If the instance hasn't terminated yet, inputs our encrypted contribution.
    pub fn propose(&mut self, ciphertext: &Ciphertext) -> Result<Step<C, N>> {
        let ser_ct = bincode::serialize(ciphertext).map_err(|err| ErrorKind::ProposeBincode(*err))?;
        let cs_step = match self.subset {
            SubsetState::Ongoing(ref mut cs) => cs.input(ser_ct),
            SubsetState::Complete(_) => return Ok(Step::default()),
        }.map_err(ErrorKind::InputCommonSubset)?;
        self.process_subset(cs_step)
    }

    /// Returns the number of contributions that we have already received.
    pub fn received_proposals(&self) -> usize {
        match self.subset {
            SubsetState::Ongoing(ref cs) => cs.received_proposals(),
            SubsetState::Complete(_) => self.netinfo.num_nodes(),
        }
    }

    /// Handles a message for the Common Subset or a Threshold Decryption instance.
    pub fn handle_message_content(
        &mut self,
        sender_id: &N,
        content: MessageContent<N>,
    ) -> Result<Step<C, N>> {
        match content {
            MessageContent::CommonSubset(cs_msg) => {
                let cs_step = match self.subset {
                    SubsetState::Ongoing(ref mut cs) => cs.handle_message(sender_id, cs_msg),
                    SubsetState::Complete(_) => return Ok(Step::default()),
                }.map_err(ErrorKind::HandleCommonSubsetMessage)?;
                self.process_subset(cs_step)
            }
            MessageContent::DecryptionShare { proposer_id, share } => {
                if let SubsetState::Complete(ref subset) = self.subset {
                    if !subset.contains(&proposer_id) {
                        let fault_kind = FaultKind::UnexpectedDecryptionShare;
                        return Ok(Fault::new(sender_id.clone(), fault_kind).into());
                    }
                }
                let td_step = match self.decryption.entry(proposer_id.clone()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        entry.insert(DecryptionState::new(self.netinfo.clone()))
                    }
                }.handle_message(sender_id, share)
                    .map_err(ErrorKind::ThresholdDecryption)?;
                self.process_decryption(proposer_id, td_step)
            }
        }
    }

    /// When contributions of transactions have been decrypted for all valid proposers in this
    /// epoch, moves those contributions into a batch, outputs the batch and updates the epoch.
    pub fn try_output_batch(&self) -> Option<(Batch<C, N>, FaultLog<N>)> {
        let proposer_ids = match self.subset {
            SubsetState::Ongoing(_) => return None, // The set is not yet decided.
            SubsetState::Complete(ref proposer_ids) => proposer_ids,
        };
        let plaintexts: BTreeMap<N, &[u8]> = self
            .decryption
            .iter()
            .flat_map(|(id, dec_state)| dec_state.plaintext().map(|pt| (id.clone(), pt)))
            .collect();
        if !proposer_ids.iter().eq(plaintexts.keys()) {
            return None; // Not all accepted contributions are decrypted yet.
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
        debug!(
            "{:?} Epoch {} output {:?}",
            self.netinfo.our_uid(),
            self.epoch,
            batch.contributions.keys().collect::<Vec<_>>()
        );
        Some((batch, fault_log))
    }

    /// Checks whether the subset has output, and if it does, sends out our decryption shares.
    fn process_subset(&mut self, cs_step: common_subset::Step<N>) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let mut cs_outputs = step.extend_with(cs_step, |cs_msg| {
            MessageContent::CommonSubset(cs_msg).with_epoch(self.epoch)
        });
        if let Some(cs_output) = cs_outputs.pop_front() {
            self.subset = SubsetState::Complete(cs_output.keys().cloned().collect());
            step.extend(self.send_decryption_shares(cs_output)?);
        }
        if !cs_outputs.is_empty() {
            error!("Multiple outputs from a single Common Subset instance.");
        }
        Ok(step)
    }

    /// Processes a Threshold Decryption step.
    fn process_decryption(&mut self, proposer_id: N, td_step: td::Step<N>) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let opt_output = step.extend_with(td_step, |share| {
            MessageContent::DecryptionShare {
                proposer_id: proposer_id.clone(),
                share,
            }.with_epoch(self.epoch)
        });
        if let Some(output) = opt_output.into_iter().next() {
            self.decryption
                .insert(proposer_id, DecryptionState::Complete(output));
        }
        Ok(step)
    }

    /// Given the output of the Subset algorithm, inputs the ciphertexts into the Threshold
    /// Decryption instances and sends our own decryption shares.
    fn send_decryption_shares(&mut self, cs_output: BTreeMap<N, Vec<u8>>) -> Result<Step<C, N>> {
        let mut step = Step::default();
        let faulty_shares: Vec<_> = self
            .decryption
            .keys()
            .filter(|id| !cs_output.contains_key(id))
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
        for (proposer_id, v) in cs_output {
            let ciphertext: Ciphertext = match bincode::deserialize(&v) {
                Ok(ciphertext) => ciphertext,
                Err(err) => {
                    warn!(
                        "Cannot deserialize ciphertext from {:?}: {:?}",
                        proposer_id, err
                    );
                    let fault_kind = FaultKind::InvalidCiphertext;
                    step.fault_log.append(proposer_id, fault_kind);
                    continue;
                }
            };
            let td_result = match self.decryption.entry(proposer_id.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(DecryptionState::new(self.netinfo.clone())),
            }.set_ciphertext(ciphertext);
            match td_result {
                Ok(td_step) => step.extend(self.process_decryption(proposer_id, td_step)?),
                Err(td::Error::InvalidCiphertext(_)) => {
                    warn!("Invalid ciphertext from {:?}", proposer_id);
                    let fault_kind = FaultKind::ShareDecryptionFailed;
                    step.fault_log.append(proposer_id.clone(), fault_kind);
                }
                Err(err) => return Err(ErrorKind::ThresholdDecryption(err).into()),
            }
        }
        Ok(step)
    }
}
