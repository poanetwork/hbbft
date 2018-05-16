use std::collections::{HashSet, VecDeque};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::iter;

use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;

use common_subset::{self, CommonSubset};
use messaging::{DistAlgorithm, TargetedMessage};

/// An instance of the Honey Badger Byzantine fault tolerant consensus algorithm.
pub struct HoneyBadger<T, N: Eq + Hash + Ord + Clone + Display> {
    /// The buffer of transactions that have not yet been included in any batch.
    buffer: VecDeque<T>,
    /// The current epoch, i.e. the number of batches that have been output so far.
    epoch: u64,
    /// The Asynchronous Common Subset instance that decides which nodes' transactions to include.
    // TODO: Common subset could be optimized to output before it is allowed to terminate. In that
    // case, we would need to keep track of one or two previous instances, too.
    common_subset: CommonSubset<N>,
    /// This node's ID.
    id: N,
    /// The set of all node IDs of the participants (including ourselves).
    all_uids: HashSet<N>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and recommend a batch size. It should be proportional to
    // `num_nodes * num_nodes * log(num_nodes)`.
    batch_size: usize,
    /// The messages that need to be sent to other nodes.
    messages: VecDeque<TargetedMessage<Message<N>, N>>,
    /// The outputs from completed epochs.
    output: VecDeque<Batch<T>>,
}

impl<T, N> DistAlgorithm for HoneyBadger<T, N>
where
    T: Ord + Serialize + DeserializeOwned,
    N: Eq + Hash + Ord + Clone + Display + Debug,
{
    type NodeUid = N;
    type Input = T;
    type Output = Batch<T>;
    type Message = Message<N>;
    type Error = Error;

    fn input(&mut self, input: Self::Input) -> Result<(), Self::Error> {
        self.add_transactions(iter::once(input))
    }

    fn handle_message(&mut self, sender_id: &N, message: Self::Message) -> Result<(), Self::Error> {
        if !self.all_uids.contains(sender_id) {
            return Err(Error::UnknownSender);
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
        &self.id
    }
}

// TODO: Use a threshold encryption scheme to encrypt the proposed transactions.
// TODO: We only contribute a proposal to the next round once we have `batch_size` buffered
// transactions. This should be more configurable: `min_batch_size`, `max_batch_size` and maybe a
// timeout? The paper assumes that all nodes will often have more or less the same set of
// transactions in the buffer; if the sets are disjoint on average, we can just send our whole
// buffer instead of 1/n of it.
impl<T, N> HoneyBadger<T, N>
where
    T: Ord + Serialize + DeserializeOwned,
    N: Eq + Hash + Ord + Clone + Display + Debug,
{
    /// Returns a new Honey Badger instance with the given parameters, starting at epoch `0`.
    pub fn new<I>(id: N, all_uids_iter: I, batch_size: usize) -> Result<Self, Error>
    where
        I: IntoIterator<Item = N>,
    {
        let all_uids: HashSet<N> = all_uids_iter.into_iter().collect();
        if !all_uids.contains(&id) {
            return Err(Error::OwnIdMissing);
        }
        Ok(HoneyBadger {
            buffer: VecDeque::new(),
            epoch: 0,
            common_subset: CommonSubset::new(id.clone(), &all_uids)?,
            id,
            batch_size,
            all_uids,
            messages: VecDeque::new(),
            output: VecDeque::new(),
        })
    }

    /// Adds transactions into the buffer.
    pub fn add_transactions<I>(&mut self, txs: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = T>,
    {
        self.buffer.extend(txs);
        if self.buffer.len() < self.batch_size {
            return Ok(());
        }
        let share = bincode::serialize(&self.buffer)?;
        for targeted_msg in self.common_subset.send_proposed_value(share)? {
            let msg = targeted_msg.map(|cs_msg| Message::CommonSubset(self.epoch, cs_msg));
            self.messages.push_back(msg);
        }
        Ok(())
    }

    /// Handles a message for the common subset sub-algorithm.
    fn handle_common_subset_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        message: common_subset::Message<N>,
    ) -> Result<(), Error> {
        if epoch != self.epoch {
            // TODO: Do we need to cache messages for future epochs?
            return Ok(());
        }
        let (cs_out, cs_msgs) = self.common_subset.handle_message(sender_id, message)?;

        for targeted_msg in cs_msgs {
            let msg = targeted_msg.map(|cs_msg| Message::CommonSubset(epoch, cs_msg));
            self.messages.push_back(msg);
        }
        // FIXME: Handle the node IDs in `ser_batches`.
        let batches: Vec<Vec<T>> = if let Some(ser_batches) = cs_out {
            ser_batches
                .values()
                .map(|ser_batch| bincode::deserialize(&ser_batch))
                .collect::<Result<_, _>>()?
        } else {
            return Ok(());
        };
        let mut transactions: Vec<T> = batches.into_iter().flat_map(|txs| txs).collect();
        transactions.sort();
        self.epoch += 1;
        self.common_subset = CommonSubset::new(self.id.clone(), &self.all_uids)?;
        self.add_transactions(None)?;
        self.output.push_back(Batch {
            epoch,
            transactions,
        });
        Ok(())
    }
}

/// A batch of transactions the algorithm has output.
pub struct Batch<T> {
    pub epoch: u64,
    pub transactions: Vec<T>,
}

/// A message sent to or received from another node's Honey Badger instance.
#[cfg_attr(feature = "serialization-serde", derive(Serialize))]
#[derive(Debug)]
pub enum Message<N> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(u64, common_subset::Message<N>),
    // TODO: Decryption share.
}

/// A Honey Badger error.
#[derive(Debug)]
pub enum Error {
    OwnIdMissing,
    UnknownSender,
    CommonSubset(common_subset::Error),
    Bincode(Box<bincode::ErrorKind>),
}

impl From<common_subset::Error> for Error {
    fn from(err: common_subset::Error) -> Error {
        Error::CommonSubset(err)
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        Error::Bincode(err)
    }
}
