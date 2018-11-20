#![deny(unused_must_use)]
//! Tests the BinaryAgreement protocol with a MTIM adversary.

extern crate env_logger;
extern crate failure;
extern crate hbbft;
extern crate integer_sqrt;
extern crate proptest;
extern crate rand;
extern crate threshold_crypto;

pub mod net;

use std::iter;
use std::sync::{Arc, Mutex};

use hbbft::binary_agreement::{BinaryAgreement, MessageContent, SbvMessage};
use hbbft::threshold_sign::ThresholdSign;
use hbbft::{DaStep, DistAlgorithm, NetworkInfo};

use net::adversary::{NetMutHandle, QueuePosition};
use net::err::CrankError;
use net::{Adversary, NetBuilder, NetMessage};

type NodeId = usize;
type SessionId = u8;
type Algo = BinaryAgreement<NodeId, SessionId>;

/// The state of the current epoch's coin. In some epochs this is fixed, in others it starts
/// with in `InProgress`.
#[derive(Debug)]
enum CoinState<N> {
    /// The value was fixed in the current epoch, or the coin has already terminated.
    Decided(bool),
    /// The coin value is not known yet.
    InProgress(Box<ThresholdSign<N>>),
}

impl<N> CoinState<N> {
    /// Returns the value, if this coin has already decided.
    fn value(&self) -> Option<bool> {
        match self {
            CoinState::Decided(value) => Some(*value),
            CoinState::InProgress(_) => None,
        }
    }
}

impl<N> From<bool> for CoinState<N> {
    fn from(value: bool) -> Self {
        CoinState::Decided(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageType {
    BVal,
    Aux,
    Coin,
}

fn message_type_and_content(msg: &MessageContent) -> Option<(MessageType, Option<bool>)> {
    match msg {
        MessageContent::SbvBroadcast(sbv_msg) => match sbv_msg {
            SbvMessage::BVal(v) => Some((MessageType::BVal, Some(*v))),
            SbvMessage::Aux(v) => Some((MessageType::Aux, Some(*v))),
        },
        MessageContent::Coin(_) => Some((MessageType::Coin, None)),
        _ => None,
    }
}

/// A boolean XOR a value from the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoolFromState {
    AEstimated(bool),
    CoinValue(bool),
}

struct Stage {
    source_groups: &'static [usize],
    dest_groups: &'static [usize],
    msg_type: MessageType,
    msg_contents: Option<BoolFromState>,
    msg_count: usize,
}

// Group IDs
const A0: usize = 0;
const A1: usize = 1;
const B: usize = 2;
const F: usize = 3;

// Comments from https://github.com/amiller/HoneyBadgerBFT/issues/59#issue-310368284
const STAGES: &[Stage] = &[
    // x sends BVAL(\neg v) to the nodes in A0
    Stage {
        source_groups: &[F],
        dest_groups: &[A0],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::AEstimated(true)),
        msg_count: NODES_PER_GROUP,
    },
    // and BVAL(v) to the nodes in A1.
    Stage {
        source_groups: &[F],
        dest_groups: &[A1],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::AEstimated(false)),
        msg_count: NODES_PER_GROUP,
    },
    // Also, all votes from nodes in B are delivered to all nodes in A.
    Stage {
        source_groups: &[B],
        dest_groups: &[A0, A1],
        msg_type: MessageType::BVal,
        msg_contents: None,
        msg_count: NODES_PER_GROUP * (NODES_PER_GROUP * 2),
    },
    // Messages within A0 are delivered.
    // Thus nodes in A0 see |B|+|F|=f+1 votes for \neg v;
    // so all nodes in A0 broadcast BVAL(\neg v)
    // and all nodes in A0 see |A0|+|B|+|F|=2f+1 votes for \neg v;
    // so all nodes in A0 broadcast AUX(\neg v).
    Stage {
        source_groups: &[A0],
        dest_groups: &[A0],
        msg_type: MessageType::BVal,
        msg_contents: None,
        msg_count: NODES_PER_GROUP * (NODES_PER_GROUP - 1),
    },
    // Then all messages within A1 are delivered,
    Stage {
        source_groups: &[A1],
        dest_groups: &[A1],
        msg_type: MessageType::BVal,
        msg_contents: None,
        msg_count: NODES_PER_GROUP * (NODES_PER_GROUP - 1),
    },
    // as well as the BVAL(v) messages from A0 to A1.
    // Thus the nodes in A1 see |A0|+|A1|+|F|=2f+1 votes for v and broadcast AUX(v).
    Stage {
        source_groups: &[A0],
        dest_groups: &[A1],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::AEstimated(false)),
        msg_count: NODES_PER_GROUP * NODES_PER_GROUP,
    },
    // After this all messages within A are delivered
    Stage {
        source_groups: &[A0, A1],
        dest_groups: &[A0, A1],
        msg_type: MessageType::BVal,
        msg_contents: None,
        msg_count: (NODES_PER_GROUP * 2) * (NODES_PER_GROUP * 2 - 1),
    },
    Stage {
        source_groups: &[A0, A1],
        dest_groups: &[A0, A1],
        msg_type: MessageType::Aux,
        msg_contents: None,
        msg_count: (NODES_PER_GROUP * 2) * (NODES_PER_GROUP * 2 - 1),
    },
    // and x sends both BVAL(0) and BVAL(1) to every node in A.
    // Thus every node in A broadcasts both BVAL(0) and BVAL(1) and sets bin_values=\{0,1\}.
    Stage {
        source_groups: &[F],
        dest_groups: &[A0, A1],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::AEstimated(false)),
        msg_count: NODES_PER_GROUP * 2,
    },
    Stage {
        source_groups: &[F],
        dest_groups: &[A0, A1],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::AEstimated(true)),
        msg_count: NODES_PER_GROUP * 2,
    },
    // !! Not mentioned in the GitHub issue, but seems necessary.
    // F sends Aux(_) to A, because nodes in A need 2f+1 Aux messages
    // before they broadcast their coins.
    Stage {
        source_groups: &[F],
        dest_groups: &[A0, A1],
        msg_type: MessageType::Aux,
        msg_contents: Some(BoolFromState::AEstimated(false)),
        msg_count: NODES_PER_GROUP * 2,
    },
    // Now all nodes in A broadcast their threshold shares over the coin,
    // so since |A|+|F|=2f+1, the adversary can construct the random coin value s.
    Stage {
        source_groups: &[A0, A1],
        dest_groups: &[F],
        msg_type: MessageType::Coin,
        msg_contents: None,
        msg_count: NODES_PER_GROUP * 2,
    },
    // The nodes in F send BVAL(\neg s) to all the nodes in B,
    // and all the BVAL(\neg s) messages from nodes in A are delivered to all nodes in B.
    // Thus all the nodes in B broadcast AUX(\neg s).
    Stage {
        source_groups: &[A0, A1, F],
        dest_groups: &[B],
        msg_type: MessageType::BVal,
        msg_contents: Some(BoolFromState::CoinValue(true)),
        msg_count: (NODES_PER_GROUP * 2 + 1) * NODES_PER_GROUP,
    },
    // Deliver all AUX(\neg s) messages; there are 2f+1 of them,
    // since either every node in A0 broadcast AUX(\neg s)
    // or every node in A1 broadcast AUX(\neg s).
    // Thus all nodes in B see 2f+1 AUX(\neg s) messages
    // and get to the end of the round with bin_values=\neg s.
    // Thus the nodes in B continue to the next round voting \neg s
    // while the nodes in A continue to the next round voting s.
    Stage {
        source_groups: &[A0, A1, B, F],
        dest_groups: &[B],
        msg_type: MessageType::Aux,
        msg_contents: Some(BoolFromState::CoinValue(true)),
        msg_count: (NODES_PER_GROUP + 1) * (NODES_PER_GROUP)
            + (NODES_PER_GROUP * (NODES_PER_GROUP - 1)),
    },
    // At this point all messages from the round are delivered, and the process repeats.
];

/// An adversary for the reordering attack.
/// Described here: https://github.com/amiller/HoneyBadgerBFT/issues/59#issue-310368284
/// Excluding the first node, which is F,
/// A0 is the first third of nodes, A1 is the second third, and the rest are B.
struct AbaCommonCoinAdversary {
    stage: usize,
    stage_progress: usize,
    sent_stage_messages: bool,
    epoch: u64,
    coin_state: CoinState<NodeId>,
    /// The estimated value for nodes in A.
    a_estimated: bool,
    // TODO this is really hacky but there's no better way to get this value
    netinfo_mutex: Arc<Mutex<Option<Arc<NetworkInfo<NodeId>>>>>,
}

const NODES_PER_GROUP: usize = 2;
const NUM_NODES: usize = (NODES_PER_GROUP * 3 + 1);

impl AbaCommonCoinAdversary {
    fn new(netinfo_mutex: Arc<Mutex<Option<Arc<NetworkInfo<NodeId>>>>>) -> Self {
        Self::new_with_epoch(netinfo_mutex, 0, false)
    }

    fn new_with_epoch(
        netinfo_mutex: Arc<Mutex<Option<Arc<NetworkInfo<NodeId>>>>>,
        epoch: u64,
        a_estimated: bool,
    ) -> Self {
        AbaCommonCoinAdversary {
            stage: 0,
            stage_progress: 0,
            sent_stage_messages: false,
            epoch,
            coin_state: match epoch % 3 {
                0 => CoinState::Decided(true),
                1 => CoinState::Decided(false),
                2 => {
                    let netinfo = netinfo_mutex
                        .lock()
                        .unwrap()
                        .as_ref()
                        .cloned()
                        .expect("Adversary netinfo mutex not populated");
                    let coin_id = bincode::serialize(&(0 as SessionId, epoch))
                        .expect("Failed to serialize coin_id");
                    let mut coin = ThresholdSign::new_with_document(netinfo, coin_id)
                        .expect("Failed to set the coin's ID");
                    let _ = coin
                        .handle_input(())
                        .expect("Calling handle_input on Coin failed");
                    CoinState::InProgress(Box::new(coin))
                }
                _ => unreachable!(),
            },
            netinfo_mutex,
            a_estimated,
        }
    }

    fn eval_state_bool(&self, state_bool: BoolFromState) -> bool {
        match state_bool {
            BoolFromState::AEstimated(v) => self.a_estimated ^ v,
            BoolFromState::CoinValue(v) => {
                self.coin_state
                    .value()
                    .expect("State relied upon coin value before it was known")
                    ^ v
            }
        }
    }

    fn inject_stage_messages(&mut self, net: &mut NetMutHandle<Algo>) {
        if self.sent_stage_messages {
            return;
        }
        self.sent_stage_messages = true;
        if let Some(stage) = STAGES.get(self.stage) {
            if stage.source_groups.iter().any(|&x| x == F) {
                let contents = self.eval_state_bool(
                    stage
                        .msg_contents
                        .expect("Stage has adversary as source but no contents"),
                );
                let message_content = match stage.msg_type {
                    MessageType::BVal => MessageContent::SbvBroadcast(SbvMessage::BVal(contents)),
                    MessageType::Aux => MessageContent::SbvBroadcast(SbvMessage::Aux(contents)),
                    MessageType::Coin => {
                        panic!("Stage expected adversary node to send Coin message");
                    }
                };
                let message = message_content.with_epoch(self.epoch);
                for &dst_grp in stage.dest_groups {
                    if dst_grp == F {
                        continue;
                    }
                    for i in 0..NODES_PER_GROUP {
                        let dst = 1 + NODES_PER_GROUP * dst_grp + i;
                        net.inject_message(
                            QueuePosition::Front,
                            NetMessage::<Algo>::new(0, message.clone(), dst),
                        )
                    }
                }
            }
        }
    }

    /// Should be called whenever stage_progress is changed.
    fn on_stage_progress_update(&mut self) {
        let stage_finished = STAGES
            .get(self.stage)
            .map(|x| {
                (x.msg_type == MessageType::Coin && self.coin_state.value().is_some())
                    || self.stage_progress >= x.msg_count
            }).unwrap_or(false);
        if stage_finished {
            self.stage += 1;
            self.stage_progress = 0;
            self.sent_stage_messages = false;
            self.on_stage_progress_update();
        }
    }

    fn stage_matches_msg(&self, message: &NetMessage<Algo>) -> bool {
        if let Some(stage) = STAGES.get(self.stage) {
            let from = *message.from();
            let src_group = if from == 0 {
                3
            } else {
                (from - 1) / NODES_PER_GROUP
            };
            let to = *message.to();
            let dst_group = if to == 0 {
                3
            } else {
                (to - 1) / NODES_PER_GROUP
            };
            if let Some((ty, content)) = message_type_and_content(&message.payload().content) {
                let content_matches = match (stage.msg_contents, content) {
                    (Some(x), Some(y)) => self.eval_state_bool(x) == y,
                    _ => true,
                };
                return stage.source_groups.iter().any(|&x| x == src_group)
                    && stage.dest_groups.iter().any(|&x| x == dst_group)
                    && stage.msg_type == ty
                    && content_matches;
            }
        }
        false
    }
}

impl Adversary<Algo> for AbaCommonCoinAdversary {
    fn pre_crank(&mut self, mut net: NetMutHandle<Algo>) {
        self.inject_stage_messages(&mut net);
        net.sort_messages_by(|a, b| {
            a.payload()
                .epoch
                .cmp(&b.payload().epoch)
                .then_with(|| self.stage_matches_msg(b).cmp(&self.stage_matches_msg(a)))
        });
        let mut redo_crank = false;
        if let Some(msg) = net.get_messages().front() {
            if msg.payload().epoch == self.epoch && self.stage_matches_msg(&msg) {
                self.stage_progress += 1;
                self.on_stage_progress_update();
            }
            if msg.payload().epoch > self.epoch {
                // This assert should fail if the attack is prevented:
                // assert_eq!(self.stage, STAGES.len());
                let netinfo = self.netinfo_mutex.clone();
                *self = Self::new_with_epoch(
                    netinfo,
                    msg.payload().epoch,
                    self.coin_state
                        .value()
                        .expect("Coin value not known at end of epoch"),
                );
                redo_crank = true;
            }
        }
        if redo_crank {
            self.pre_crank(net);
        }
    }

    fn tamper(
        &mut self,
        _: NetMutHandle<Algo>,
        msg: NetMessage<Algo>,
    ) -> Result<DaStep<Algo>, CrankError<Algo>> {
        if let MessageContent::Coin(ref coin_msg) = msg.payload().content {
            let mut new_coin_state = None;
            if let CoinState::InProgress(ref mut coin) = self.coin_state {
                let res = coin.handle_message(msg.from(), *coin_msg.clone());
                if let Ok(step) = res {
                    if let Some(coin) = step.output.into_iter().next() {
                        new_coin_state = Some(coin.parity().into());
                    }
                }
            }
            if let Some(new_coin_state) = new_coin_state {
                self.coin_state = new_coin_state;
            }
        }
        Ok(DaStep::<Algo>::default())
    }
}

#[test]
fn reordering_attack() {
    let _ = env_logger::try_init();
    let ids: Vec<NodeId> = (0..NUM_NODES).collect();
    let adversary_netinfo: Arc<Mutex<Option<Arc<NetworkInfo<NodeId>>>>> = Default::default();
    let (mut net, _) = NetBuilder::new(ids.iter().cloned())
        .adversary(AbaCommonCoinAdversary::new(adversary_netinfo.clone()))
        .crank_limit(10000)
        .using(move |info| {
            let netinfo = Arc::new(info.netinfo);
            if info.id == 0 {
                *adversary_netinfo.lock().unwrap() = Some(netinfo.clone());
            }
            BinaryAgreement::new(netinfo, 0).expect("failed to create BinaryAgreement instance")
        }).num_faulty(1)
        .build()
        .unwrap();

    for id in ids {
        if id == 0 {
            // This is the faulty node.
        } else if id < (1 + NODES_PER_GROUP * 2) {
            // Group A
            let _ = net.send_input(id, false).unwrap();
        } else {
            // Group B
            let _ = net.send_input(id, true).unwrap();
        }
    }

    while !net.nodes().skip(1).all(|n| n.algorithm().terminated()) {
        net.crank_expect();
    }

    // Verify that all instances output the same value.
    let mut estimated = None;
    for node in net.nodes().skip(1) {
        if let Some(b) = estimated {
            assert!(iter::once(&b).eq(node.outputs()));
        } else {
            assert_eq!(1, node.outputs().len());
            estimated = Some(node.outputs()[0]);
        }
    }
}
