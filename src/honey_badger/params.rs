use serde_derive::{Deserialize, Serialize};

use super::{EncryptionSchedule, SubsetHandlingStrategy};

/// Parameters controlling Honey Badger's behavior and performance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// The maximum number of future epochs for which we handle messages simultaneously.
    pub max_future_epochs: u64,
    /// Strategy used to handle the output of the `Subset` algorithm.
    pub subset_handling_strategy: SubsetHandlingStrategy,
    /// Schedule for adding threshold encryption to some percentage of rounds
    pub encryption_schedule: EncryptionSchedule,
}

impl Default for Params {
    fn default() -> Params {
        Params {
            max_future_epochs: 3,
            subset_handling_strategy: SubsetHandlingStrategy::Incremental,
            encryption_schedule: EncryptionSchedule::Always,
        }
    }
}
