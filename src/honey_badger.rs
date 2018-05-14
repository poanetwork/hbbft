use std::collections::{HashSet, VecDeque};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use bincode;
use serde::de::DeserializeOwned;
use serde::Serialize;

use common_subset::{self, CommonSubset};
use messaging::TargetedMessage;

/// A Honey Badger error.
pub enum Error {
    OwnIdMissing,
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

type HoneyBadgerOutput<T, N> = (Option<Batch<T>>, Vec<TargetedMessage<Message<N>, N>>);

/// A batch of transactions the algorithm has output.
pub struct Batch<T> {
    pub epoch: u64,
    pub transactions: Vec<T>,
}

/// A message sent to or received from another node's Honey Badger instance.
pub enum Message<N> {
    /// A message belonging to the common subset algorithm in the given epoch.
    CommonSubset(u64, common_subset::Message<N>),
    // TODO: Decryption share.
}

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
    all_ids: HashSet<N>,
    /// The target number of transactions to be included in each batch.
    // TODO: Do experiments and recommend a batch size. It should be proportional to
    // `num_nodes * num_nodes * log(num_nodes)`.
    batch_size: usize,
}

// TODO: Use a threshold encryption scheme to encrypt the proposed transactions.
// TODO: We only contribute a proposal to the next round once we have `batch_size` buffered
// transactions. This should be more configurable: `min_batch_size`, `max_batch_size` and maybe a
// timeout? The paper assumes that all nodes will often have more or less the same set of
// transactions in the buffer; if the sets are disjoint on average, we can just send our whole
// buffer instead of 1/n of it.
impl<T, N> HoneyBadger<T, N>
where
    T: Ord + AsRef<[u8]> + Serialize + DeserializeOwned,
    N: Eq + Hash + Ord + Clone + Display + Debug,
{
    /// Returns a new Honey Badger instance with the given parameters, starting at epoch `0`.
    pub fn new<I>(id: N, all_ids_iter: I, batch_size: usize) -> Result<Self, Error>
    where
        I: IntoIterator<Item = N>,
    {
        let all_ids: HashSet<N> = all_ids_iter.into_iter().collect();
        if !all_ids.contains(&id) {
            return Err(Error::OwnIdMissing);
        }
        Ok(HoneyBadger {
            buffer: VecDeque::new(),
            epoch: 0,
            common_subset: CommonSubset::new(id.clone(), &all_ids)?,
            id,
            batch_size,
            all_ids,
        })
    }

    /// Adds transactions into the buffer.
    pub fn add_transactions<I>(&mut self, txs: I) -> Result<HoneyBadgerOutput<T, N>, Error>
    where
        I: IntoIterator<Item = T>,
    {
        self.buffer.extend(txs);
        if self.buffer.len() < self.batch_size {
            return Ok((None, Vec::new()));
        }
        // TODO: Handle the case `all_ids.len() == 1`.
        let share = bincode::serialize(&self.buffer)?;
        let msgs = self.common_subset
            .send_proposed_value(share)?
            .into_iter()
            .map(|targeted_msg| {
                targeted_msg.map(|cs_msg| Message::CommonSubset(self.epoch, cs_msg))
            })
            .collect();
        Ok((None, msgs))
    }

    /// Handles a message from another node, and returns the next batch, if any, and the messages
    /// to be sent out.
    pub fn handle_message(
        &mut self,
        sender_id: &N,
        message: Message<N>,
    ) -> Result<HoneyBadgerOutput<T, N>, Error> {
        match message {
            Message::CommonSubset(epoch, cs_msg) => {
                self.handle_common_subset_message(sender_id, epoch, cs_msg)
            }
        }
    }

    fn handle_common_subset_message(
        &mut self,
        sender_id: &N,
        epoch: u64,
        message: common_subset::Message<N>,
    ) -> Result<HoneyBadgerOutput<T, N>, Error> {
        if epoch != self.epoch {
            // TODO: Do we need to cache messages for future epochs?
            return Ok((None, Vec::new()));
        }
        let (cs_out, cs_msgs) = self.common_subset.handle_message(sender_id, message)?;
        let mut msgs: Vec<TargetedMessage<Message<N>, N>> = cs_msgs
            .into_iter()
            .map(|targeted_msg| targeted_msg.map(|cs_msg| Message::CommonSubset(epoch, cs_msg)))
            .collect();
        let output = if let Some(ser_batches) = cs_out {
            let mut transactions: Vec<T> = ser_batches
                .into_iter()
                .map(|ser_batch| bincode::deserialize::<Vec<T>>(&ser_batch))
                .collect::<Result<Vec<_>, Box<bincode::ErrorKind>>>()?
                .into_iter()
                .flat_map(|txs| txs)
                .collect();
            transactions.sort();
            self.epoch += 1;
            self.common_subset = CommonSubset::new(self.id.clone(), &self.all_ids)?;
            let (_, new_epoch_msgs) = self.add_transactions(None)?;
            msgs.extend(new_epoch_msgs);
            Some(Batch {
                epoch,
                transactions,
            })
        } else {
            None
        };
        Ok((output, msgs))
    }
}
