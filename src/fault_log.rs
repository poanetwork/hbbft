//! Functionality for logging faulty node behavior encountered by each
//! algorithm.
//!
//! Each algorithm can propogate their faulty node logs upwards to a calling algorithm via
//! `DistAlgorihm`'s `.handle_input()` and `.handle_message()` trait methods.

pub use failure::Fail;

/// A structure representing the context of a faulty node. This structure
/// describes which node is faulty (`node_id`) and which faulty behavior
/// that the node exhibited ('kind').
#[derive(Clone, Debug, PartialEq)]
pub struct Fault<N, F: Fail> {
    /// The faulty node's ID.
    pub node_id: N,
    /// The kind of fault the node is blamed for.
    pub kind: F,
}

impl<N, F> Fault<N, F>
where
    F: Fail,
{
    /// Creates a new fault, blaming `node_id` for the `kind`.
    pub fn new(node_id: N, kind: F) -> Self {
        Fault { node_id, kind }
    }

    /// Applies `f_fault` to `kind`, leaves `node_id` unchanged
    pub fn map<F2, FF>(self, f_fault: FF) -> Fault<N, F2>
    where
        F2: Fail,
        FF: Fn(F) -> F2,
    {
        Fault {
            node_id: self.node_id,
            kind: f_fault(self.kind),
        }
    }
}

/// Creates a new `FaultLog` where `self` is the first element in the log
/// vector.
impl<N, F> Into<FaultLog<N, F>> for Fault<N, F>
where
    F: Fail,
{
    fn into(self) -> FaultLog<N, F> {
        FaultLog(vec![self])
    }
}

/// A structure used to contain reports of faulty node behavior.
#[derive(Debug, PartialEq)]
pub struct FaultLog<N, F: Fail>(pub Vec<Fault<N, F>>);

impl<N, F> FaultLog<N, F>
where
    F: Fail,
{
    /// Creates an empty `FaultLog`.
    pub fn new() -> Self {
        FaultLog::default()
    }

    /// Creates a new `FaultLog` initialized with a single log.
    pub fn init(node_id: N, kind: F) -> Self {
        Fault::new(node_id, kind).into()
    }

    /// Creates a new `Fault` and pushes it onto the fault log.
    pub fn append(&mut self, node_id: N, kind: F) {
        self.0.push(Fault::new(node_id, kind));
    }

    /// Consumes a `Fault` and pushes it onto the fault log.
    pub fn append_fault(&mut self, fault: Fault<N, F>) {
        self.0.push(fault);
    }

    /// Consumes `new_logs`, appending its logs onto the end of `self`.
    pub fn extend(&mut self, new_logs: FaultLog<N, F>) {
        self.0.extend(new_logs.0);
    }

    /// Consumes `self`, appending its logs onto the end of `logs`.
    pub fn merge_into(self, logs: &mut FaultLog<N, F>) {
        logs.extend(self);
    }

    /// Returns `true` if there are no fault entries in the log.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Applies `f_fault` to each element in log, modifying its `kind` only
    pub fn map<F2, FF>(self, f_fault: FF) -> FaultLog<N, F2>
    where
        F2: Fail,
        FF: Fn(F) -> F2,
    {
        FaultLog(self.into_iter().map(|f| f.map(&f_fault)).collect())
    }
}

impl<N, F> Default for FaultLog<N, F>
where
    F: Fail,
{
    fn default() -> Self {
        FaultLog(vec![])
    }
}

impl<N, F> IntoIterator for FaultLog<N, F>
where
    F: Fail,
{
    type Item = Fault<N, F>;
    type IntoIter = std::vec::IntoIter<Fault<N, F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<N, F> std::iter::FromIterator<Fault<N, F>> for FaultLog<N, F>
where
    F: Fail,
{
    fn from_iter<I: IntoIterator<Item = Fault<N, F>>>(iter: I) -> Self {
        let mut log = FaultLog::new();
        for i in iter {
            log.append_fault(i);
        }
        log
    }
}
