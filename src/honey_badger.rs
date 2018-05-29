use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::rc::Rc;
use std::{cmp, iter};

use bincode;
use rand;
use serde::de::DeserializeOwned;
use serde::Serialize;

use common_subset::{self, CommonSubset};
use messaging::{DistAlgorithm, NetworkInfo, TargetedMessage};

error_chain!{
    types {
        Error, ErrorKind, ResultExt, HoneyBadgerResult;
    }

    links {
        CommonSubset(common_subset::Error, common_subset::ErrorKind);
    }

    foreign_links {
        Bincode(Box<bincode::ErrorKind>);
    }

    errors {
        UnknownSender
    }
}

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
pub struct HoneyBadger<T, N: Eq + Hash + Ord + Clone> {
    /// Shared network data.
    netinfo: Rc<NetworkInfo<N>>,
    /// The buffer of transactions that have not yet been included in any output batch.
    buffer: Vec<T>,
    /// The earliest epoch from which we have not yet received output.
    epoch: u64,
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include,
    /// indexed by epoch.
    common_subsets: BTreeMap<u64, CommonSubset<N>>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and recommend a batch size. It should be proportional to
    // `num_nodes * num_nodes * log(num_nodes)`.
    batch_size: usize,
    /// The messages that need to be sent to other nodes.
    messages: MessageQueue<N>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<T>>,
}

impl<T, N> DistAlgorithm for HoneyBadger<T, N>
where
    T: Ord + Serialize + DeserializeOwned + Debug,
    N: Eq + Hash + Ord + Clone + Debug,
{
    type NodeUid = N;
    type Input = T;
    type Output = Batch<T>;
    type Message = Message<N>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> HoneyBadgerResult<()> {
        self.add_transactions(iter::once(input))
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> HoneyBadgerResult<()> {
        if !self.netinfo.all_uids().contains(sender_id) {
            return Err(ErrorKind::UnknownSender.into());
        }
        match message {
            Message::CommonSubset(epoch, cs_msg) => {
                self.handle_common_subset_message(sender_id, epoch, cs_msg)
            }
        }
    }

    fn next_message(&mut self) -> Option<TargetedMessage<Self::Message, N>> {
        self.messages.pop_front()
    }

    fn next_output(&mut self) -> Option<Self::Output> {
        self.output.pop_front()
    }

    fn terminated(&self) -> bool {
        false
    }

    fn our_id(&self) -> &N {
        self.netinfo.our_uid()
    }
}

// TODO: Use a threshold encryption scheme to encrypt the proposed transactions.
impl<T, N> HoneyBadger<T, N>
where
    T: Ord + Serialize + DeserializeOwned + Debug,
    N: Eq + Hash + Ord + Clone + Debug,
{
    /// Returns a new Honey Badger instance with the given parameters, starting at epoch `0`.
    pub fn new<TI>(
        netinfo: Rc<NetworkInfo<N>>,
        batch_size: usize,
        txs: TI,
    ) -> HoneyBadgerResult<Self>
    where
        TI: IntoIterator<Item = T>,
    {
        let mut honey_badger = HoneyBadger {
            netinfo,
            buffer: txs.into_iter().collect(),
            epoch: 0,
            common_subsets: BTreeMap::new(),
            batch_size,
            messages: MessageQueue(VecDeque::new()),
            output: VecDeque::new(),
        };
        honey_badger.propose()?;
        Ok(honey_badger)
    }

    /// Adds transactions into the buffer.
    pub fn add_transactions<I: IntoIterator<Item = T>>(&mut self, txs: I) -> HoneyBadgerResult<()> {
        self.buffer.extend(txs);
        Ok(())
    }

    /// Proposes a new batch in the current epoch.
    fn propose(&mut self) -> HoneyBadgerResult<()> {
        let proposal = self.choose_transactions()?;
        let cs = match self.common_subsets.entry(self.epoch) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(CommonSubset::new(self.netinfo.clone())?),
        };
        cs.input(proposal)?;
        self.messages.extend_with_epoch(self.epoch, cs);
        Ok(())
    }

    /// Returns a random choice of `batch_size / all_uids.len()` buffered transactions, and
    /// serializes them.
    fn choose_transactions(&self) -> HoneyBadgerResult<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let amount = cmp::max(1, self.batch_size / self.netinfo.all_uids().len());
        let batch_size = cmp::min(self.batch_size, self.buffer.len());
        let sample = match rand::seq::sample_iter(&mut rng, &self.buffer[..batch_size], amount) {
            Ok(choice) => choice,
            Err(choice) => choice, // Fewer than `amount` were available, which is fine.
        };
        debug!(
            "{:?} Proposing in epoch {}: {:?}",
            self.netinfo.our_uid(),
            self.epoch,
            sample
        );
        Ok(bincode::serialize(&sample)?)
    }

    /// Handles a message for the common subset sub-algorithm.
    fn handle_common_subset_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        message: common_subset::Message<N>,
    ) -> HoneyBadgerResult<()> {
        {
            // Borrow the instance for `epoch`, or create it.
            let cs = match self.common_subsets.entry(epoch) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    if epoch < self.epoch {
                        return Ok(()); // Epoch has already terminated. Message is obsolete.
                    } else {
                        entry.insert(CommonSubset::new(self.netinfo.clone())?)
                    }
                }
            };
            // Handle the message and put the outgoing messages into the queue.
            cs.handle_message(sender_id, message)?;
            self.messages.extend_with_epoch(epoch, cs);
        }
        // If this is the current epoch, the message could cause a new output.
        if epoch == self.epoch {
            self.process_output()?;
        }
        self.remove_terminated(epoch);
        Ok(())
    }

    /// Checks whether the current epoch has output, and if it does, advances the epoch and
    /// proposes a new batch.
    fn process_output(&mut self) -> Result<(), Error> {
        let old_epoch = self.epoch;
        while let Some(ser_batches) = self.take_current_output() {
            // Deserialize the output.
            let transactions: BTreeSet<T> = ser_batches
                .into_iter()
                .map(|(_, ser_batch)| bincode::deserialize::<Vec<T>>(&ser_batch))
                .collect::<Result<Vec<Vec<T>>, _>>()?
                .into_iter()
                .flat_map(|txs| txs)
                .collect();
            // Remove the output transactions from our buffer.
            self.buffer.retain(|tx| !transactions.contains(tx));
            debug!(
                "{:?} Epoch {} output {:?}",
                self.netinfo.our_uid(),
                self.epoch,
                transactions
            );
            // Queue the output and advance the epoch.
            self.output.push_back(Batch {
                epoch: self.epoch,
                transactions,
            });
            self.epoch += 1;
        }
        // If we have moved to a new epoch, propose a new batch of transactions.
        if self.epoch > old_epoch {
            self.propose()?;
        }
        Ok(())
    }

    /// Returns the output of the current epoch's `CommonSubset` instance, if any.
    fn take_current_output(&mut self) -> Option<BTreeMap<N, Vec<u8>>> {
        self.common_subsets
            .get_mut(&self.epoch)
            .and_then(CommonSubset::next_output)
    }

    /// Removes all `CommonSubset` instances from _past_ epochs that have terminated.
    fn remove_terminated(&mut self, from_epoch: u64) {
        for epoch in from_epoch..self.epoch {
            if self
                .common_subsets
                .get(&epoch)
                .map_or(false, CommonSubset::terminated)
            {
                debug!(
                    "{:?} Epoch {} has terminated.",
                    self.netinfo.our_uid(),
                    epoch
                );
                self.common_subsets.remove(&epoch);
            }
        }
    }
}

/// A batch of transactions the algorithm has output.
#[derive(Clone)]
pub struct Batch<T> {
    pub epoch: u64,
    pub transactions: BTreeSet<T>,
}

/// A message sent to or received from another node's Honey Badger instance.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Debug, Clone)]
pub enum Message<N> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(u64, common_subset::Message<N>),
    // TODO: Decryption share.
}

/// The queue of outgoing messages in a `HoneyBadger` instance.
#[derive(Deref, DerefMut)]
struct MessageQueue<N>(VecDeque<TargetedMessage<Message<N>, N>>);

impl<N: Clone + Debug + Eq + Hash + Ord> MessageQueue<N> {
    /// Appends to the queue the messages from `cs`, wrapped with `epoch`.
    fn extend_with_epoch(&mut self, epoch: u64, cs: &mut CommonSubset<N>) {
        let convert = |msg: TargetedMessage<common_subset::Message<N>, N>| {
            msg.map(|cs_msg| Message::CommonSubset(epoch, cs_msg))
        };
        self.extend(cs.message_iter().map(convert));
    }
}
