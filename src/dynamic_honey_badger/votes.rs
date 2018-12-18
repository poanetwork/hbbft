use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::crypto::Signature;
use bincode;
use serde::Serialize;
use serde_derive::{Deserialize, Serialize};

use super::{Change, Error, FaultKind, Result};
use crate::fault_log;
use crate::{NetworkInfo, NodeIdT};

pub type FaultLog<N> = fault_log::FaultLog<N, FaultKind>;

/// A buffer and counter collecting pending and committed votes for validator set changes.
///
/// This is reset whenever the set of validators changes or a change reaches _f + 1_ votes. We call
/// the epochs since the last reset the current _era_.
#[derive(Debug)]
pub struct VoteCounter<N: Ord> {
    /// Shared network data.
    netinfo: Arc<NetworkInfo<N>>,
    /// The epoch when voting was reset.
    era: u64,
    /// Pending node transactions that we will propose in the next epoch.
    pending: BTreeMap<N, SignedVote<N>>,
    /// Collected votes for adding or removing nodes. Each node has one vote, and casting another
    /// vote revokes the previous one.
    committed: BTreeMap<N, Vote<N>>,
}

impl<N> VoteCounter<N>
where
    N: NodeIdT + Serialize,
{
    /// Creates a new `VoteCounter` object with empty buffer and counter.
    pub fn new(netinfo: Arc<NetworkInfo<N>>, era: u64) -> Self {
        VoteCounter {
            era,
            netinfo,
            pending: BTreeMap::new(),
            committed: BTreeMap::new(),
        }
    }

    /// Creates a signed vote for the given change, and inserts it into the pending votes buffer.
    pub fn sign_vote_for(&mut self, change: Change<N>) -> Result<&SignedVote<N>> {
        let voter = self.netinfo.our_id().clone();
        let vote = Vote {
            change,
            era: self.era,
            num: self.pending.get(&voter).map_or(0, |sv| sv.vote.num + 1),
        };
        let ser_vote = bincode::serialize(&vote).map_err(|err| Error::SerializeVote(*err))?;
        let signed_vote = SignedVote {
            vote,
            voter: voter.clone(),
            sig: self.netinfo.secret_key().sign(ser_vote),
        };
        self.pending.remove(&voter);
        Ok(self.pending.entry(voter).or_insert(signed_vote))
    }

    /// Inserts a pending vote into the buffer, if it has a higher number than the existing one.
    pub fn add_pending_vote(
        &mut self,
        sender_id: &N,
        signed_vote: SignedVote<N>,
    ) -> Result<FaultLog<N>> {
        if signed_vote.vote.era != self.era
            || self
                .pending
                .get(&signed_vote.voter)
                .map_or(false, |sv| sv.vote.num >= signed_vote.vote.num)
        {
            return Ok(FaultLog::new()); // The vote is obsolete or already exists.
        }
        if !self.validate(&signed_vote)? {
            return Ok(FaultLog::init(
                sender_id.clone(),
                FaultKind::InvalidVoteSignature,
            ));
        }
        self.pending.insert(signed_vote.voter.clone(), signed_vote);
        Ok(FaultLog::new())
    }

    /// Returns an iterator over all pending votes that are newer than their voter's committed
    /// vote.
    pub fn pending_votes(&self) -> impl Iterator<Item = &SignedVote<N>> {
        self.pending.values().filter(move |signed_vote| {
            self.committed
                .get(&signed_vote.voter)
                .map_or(true, |vote| vote.num < signed_vote.vote.num)
        })
    }

    /// Inserts committed votes into the counter, if they have higher numbers than the existing
    /// ones.
    pub fn add_committed_votes<I>(
        &mut self,
        proposer_id: &N,
        signed_votes: I,
    ) -> Result<FaultLog<N>>
    where
        I: IntoIterator<Item = SignedVote<N>>,
    {
        let mut fault_log = FaultLog::new();
        for signed_vote in signed_votes {
            fault_log.extend(self.add_committed_vote(proposer_id, signed_vote)?);
        }
        Ok(fault_log)
    }

    /// Inserts a committed vote into the counter, if it has a higher number than the existing one.
    pub fn add_committed_vote(
        &mut self,
        proposer_id: &N,
        signed_vote: SignedVote<N>,
    ) -> Result<FaultLog<N>> {
        if self
            .committed
            .get(&signed_vote.voter)
            .map_or(false, |vote| vote.num >= signed_vote.vote.num)
        {
            return Ok(FaultLog::new()); // The vote is obsolete or already exists.
        }
        if signed_vote.vote.era != self.era || !self.validate(&signed_vote)? {
            return Ok(FaultLog::init(
                proposer_id.clone(),
                FaultKind::InvalidCommittedVote,
            ));
        }
        self.committed.insert(signed_vote.voter, signed_vote.vote);
        Ok(FaultLog::new())
    }

    /// Returns the change that has at least _f + 1_ votes, if any.
    pub fn compute_winner(&self) -> Option<&Change<N>> {
        let mut vote_counts: HashMap<&Change<N>, usize> = HashMap::new();
        for vote in self.committed.values() {
            let change = &vote.change;
            let entry = vote_counts.entry(change).or_insert(0);
            *entry += 1;
            if *entry > self.netinfo.num_faulty() {
                return Some(change);
            }
        }
        None
    }

    /// Returns `true` if the signature is valid.
    fn validate(&self, signed_vote: &SignedVote<N>) -> Result<bool> {
        let ser_vote =
            bincode::serialize(&signed_vote.vote).map_err(|err| Error::SerializeVote(*err))?;
        let pk_opt = self.netinfo.public_key(&signed_vote.voter);
        Ok(pk_opt.map_or(false, |pk| pk.verify(&signed_vote.sig, ser_vote)))
    }
}

/// A vote fore removing or adding a validator.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
struct Vote<N: Ord> {
    /// The change this vote is for.
    change: Change<N>,
    /// The epoch in which the current era began.
    era: u64,
    /// The vote number: VoteCounter can be changed by casting another vote with a higher number.
    num: u64,
}

/// A signed vote for removing or adding a validator.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Hash, Clone)]
pub struct SignedVote<N: Ord> {
    vote: Vote<N>,
    voter: N,
    sig: Signature,
}

impl<N: Ord> SignedVote<N> {
    pub fn era(&self) -> u64 {
        self.vote.era
    }

    pub fn voter(&self) -> &N {
        &self.voter
    }
}

#[cfg(test)]
mod tests {
    use std::iter;
    use std::sync::Arc;

    use super::{Change, FaultKind, SignedVote, VoteCounter};
    use crate::fault_log::FaultLog;
    use crate::NetworkInfo;
    use rand;

    /// Returns a vector of `node_num` `VoteCounter`s, and some signed example votes.
    ///
    /// If `signed_votes` is the second entry of the return value, then `signed_votes[i][j]` is the
    /// the vote by node `i` for making `j` the only validator. Each node signed this for nodes
    /// `0`, `1`, ... in order.
    fn setup(node_num: usize, era: u64) -> (Vec<VoteCounter<usize>>, Vec<Vec<SignedVote<usize>>>) {
        let mut rng = rand::rngs::OsRng::new().expect("could not initialize OsRng");
        // Create keys for threshold cryptography.
        let netinfos = NetworkInfo::generate_map(0..node_num, &mut rng)
            .expect("Failed to generate `NetworkInfo` map");
        let pub_keys = netinfos[&0].public_key_map().clone();

        // Create a `VoteCounter` instance for each node.
        let create_counter =
            |(_, netinfo): (_, NetworkInfo<_>)| VoteCounter::new(Arc::new(netinfo), era);
        let mut counters: Vec<_> = netinfos.into_iter().map(create_counter).collect();

        // Sign a few votes.
        let sign_votes = |counter: &mut VoteCounter<usize>| {
            (0..node_num)
                .map(|j| Change::NodeChange(iter::once((j, pub_keys[&j])).collect()))
                .map(|change| counter.sign_vote_for(change).expect("sign vote").clone())
                .collect::<Vec<_>>()
        };
        let signed_votes: Vec<_> = counters.iter_mut().map(sign_votes).collect();
        (counters, signed_votes)
    }

    #[test]
    fn test_pending_votes() {
        let node_num = 4;
        let era = 5;
        // Create the counter instances and the matrix of signed votes.
        let (mut counters, sv) = setup(node_num, era);
        // We will only use counter number 0.
        let ct = &mut counters[0];

        // Node 0 already contains its own vote for `Remove(3)`. Add two more.
        let faults = ct
            .add_pending_vote(&1, sv[1][2].clone())
            .expect("add pending");
        assert!(faults.is_empty());
        let faults = ct
            .add_pending_vote(&2, sv[2][1].clone())
            .expect("add pending");
        assert!(faults.is_empty());
        // Include a vote with a wrong signature.
        let fake_vote = SignedVote {
            sig: sv[2][1].sig.clone(),
            ..sv[3][1].clone()
        };
        let faults = ct.add_pending_vote(&1, fake_vote).expect("add pending");
        let expected_faults = FaultLog::init(1, FaultKind::InvalidVoteSignature);
        assert_eq!(faults, expected_faults);
        assert_eq!(
            ct.pending_votes().collect::<Vec<_>>(),
            vec![&sv[0][3], &sv[1][2], &sv[2][1]]
        );

        // Now add an older vote by node 1 and a newer one by node 2. Only the latter should be
        // included.
        let faults = ct
            .add_pending_vote(&3, sv[1][1].clone())
            .expect("add pending");
        assert!(faults.is_empty());
        let faults = ct
            .add_pending_vote(&1, sv[2][2].clone())
            .expect("add pending");
        assert!(faults.is_empty());
        assert_eq!(
            ct.pending_votes().collect::<Vec<_>>(),
            vec![&sv[0][3], &sv[1][2], &sv[2][2]]
        );

        // Adding a committed vote removes it from the pending ones, unless it is older.
        let vote_batch = vec![sv[1][3].clone(), sv[2][1].clone(), sv[0][3].clone()];
        ct.add_committed_votes(&1, vote_batch)
            .expect("add committed");
        assert_eq!(ct.pending_votes().collect::<Vec<_>>(), vec![&sv[2][2]]);
    }

    #[test]
    fn test_committed_votes() {
        let node_num = 4; // At most one faulty node.
        let era = 5;
        // Create the counter instances and the matrix of signed votes.
        let (mut counters, sv) = setup(node_num, era);
        // We will only use counter number 0.
        let ct = &mut counters[0];

        let mut vote_batch = vec![sv[1][1].clone()];
        // Include a vote with a wrong signature.
        vote_batch.push(SignedVote {
            sig: sv[2][1].sig.clone(),
            ..sv[3][1].clone()
        });
        let faults = ct
            .add_committed_votes(&1, vote_batch)
            .expect("add committed");
        let expected_faults = FaultLog::init(1, FaultKind::InvalidCommittedVote);
        assert_eq!(faults, expected_faults);
        assert_eq!(ct.compute_winner(), None);

        // Adding the second vote for `Remove(1)` should return the change: It has f + 1 votes.
        let faults = ct
            .add_committed_vote(&1, sv[2][1].clone())
            .expect("add committed");
        assert!(faults.is_empty());
        match ct.compute_winner() {
            Some(Change::NodeChange(pub_keys)) => assert!(pub_keys.keys().eq(iter::once(&1))),
            winner => panic!("Unexpected winner: {:?}", winner),
        }
    }
}
