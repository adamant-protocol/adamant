//! Adamant-native typed-stack abstraction for the type-safety
//! pass (whitepaper §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from `vendor/move-abstract-stack/src/lib.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (169 LOC upstream). The
//! abstraction stores runs of equal values compressed (a
//! `Vec<(u64, T)>` with a separate `len` counter) so that
//! pushing 1000 copies of the same type uses a single entry
//! rather than 1000 entries.
//!
//! # Adamant deviations
//!
//! - **Adamant-native fork** (Q1(a) at D-5a plan-gate; **9th
//!   deliberate-Adamant-decision instance**). Adamant's
//!   resistant-proof posture per §6.2.1.8 mandates that
//!   vendored Sui crates do not appear in the production
//!   binary's dependency graph. `move-abstract-stack` is
//!   consumed by the type-safety pass (a deploy-time pass);
//!   porting Adamant-native rather than carrying it as a
//!   transitional production dependency follows the
//!   vendored-Sui-crates-port canonical principle (empirically
//!   grounded across D-1a CFG / D-1b `AbstractInterpreter` /
//!   D-2 `LoopSummary` / D-5a `AbstractStack`).
//! - No deviations in algorithm or shape — this is a faithful
//!   port. The `T: Eq + Clone + Debug` trait bound is
//!   preserved.

use std::cmp::Ordering;
use std::fmt::{self, Debug};
use std::num::NonZeroU64;

/// An abstract stack that compresses runs of equal values to
/// reduce space usage.
#[derive(Default, Debug)]
pub(super) struct AbstractStack<T> {
    /// Each entry is `(run_length, value)`. Runs are appended
    /// when pushing a value equal to the top of the stack;
    /// otherwise a new entry is created.
    values: Vec<(u64, T)>,
    /// Logical length of the stack as if there were no run
    /// compression.
    len: u64,
}

impl<T: Eq + Clone + Debug> AbstractStack<T> {
    /// Build an empty stack.
    pub(super) fn new() -> Self {
        Self {
            values: vec![],
            len: 0,
        }
    }

    /// Returns `true` if the stack is empty.
    pub(super) fn is_empty(&self) -> bool {
        debug_assert!(!self.values.is_empty() || self.len == 0);
        debug_assert!(
            self.values.is_empty()
                || self
                    .values
                    .last()
                    .expect("non-empty values vec checked above")
                    .0
                    <= self.len
        );
        self.values.is_empty()
    }

    /// Returns the logical length of the stack.
    pub(super) fn len(&self) -> u64 {
        debug_assert!(self.len != 0 || self.values.is_empty());
        debug_assert!(
            self.len == 0
                || (!self.values.is_empty()
                    && self
                        .values
                        .last()
                        .expect("non-empty values vec checked above")
                        .0
                        <= self.len)
        );
        self.len
    }

    /// Push a single value on the stack.
    pub(super) fn push(&mut self, item: T) -> Result<(), AbsStackError> {
        self.push_n(item, 1)
    }

    /// Push `n` copies of an item on the stack.
    pub(super) fn push_n(&mut self, item: T, n: u64) -> Result<(), AbsStackError> {
        if n == 0 {
            return Ok(());
        }
        let Some(new_len) = self.len.checked_add(n) else {
            return Err(AbsStackError::Overflow);
        };
        self.len = new_len;
        match self.values.last_mut() {
            Some((count, last_item)) if &item == last_item => {
                debug_assert!(*count > 0);
                *count += n;
            }
            _ => self.values.push((n, item)),
        }
        Ok(())
    }

    /// Pop a single value off the stack.
    pub(super) fn pop(&mut self) -> Result<T, AbsStackError> {
        self.pop_eq_n(NonZeroU64::new(1).expect("1 is non-zero"))
    }

    /// Pop `n` values off the stack, erroring if the stack
    /// has fewer than `n` items or if the top `n` items are
    /// not all equal.
    pub(super) fn pop_eq_n(&mut self, n: NonZeroU64) -> Result<T, AbsStackError> {
        let n: u64 = n.get();
        if self.is_empty() || n > self.len {
            return Err(AbsStackError::Underflow);
        }
        let (count, last) = self
            .values
            .last_mut()
            .expect("non-empty checked via is_empty above");
        debug_assert!(*count > 0);
        let ret = match (*count).cmp(&n) {
            Ordering::Less => return Err(AbsStackError::ElementNotEqual),
            Ordering::Equal => {
                let (_, last) = self.values.pop().expect("non-empty");
                last
            }
            Ordering::Greater => {
                *count -= n;
                last.clone()
            }
        };
        self.len -= n;
        Ok(ret)
    }

    /// Pop any `n` items off the stack. Items do not need to
    /// be equal — this is the "drop top N values regardless of
    /// type" operation.
    pub(super) fn pop_any_n(&mut self, n: NonZeroU64) -> Result<(), AbsStackError> {
        let n: u64 = n.get();
        if self.is_empty() || n > self.len {
            return Err(AbsStackError::Underflow);
        }
        let mut rem: u64 = n;
        while rem > 0 {
            let (count, _last) = self
                .values
                .last_mut()
                .expect("non-empty maintained while rem > 0");
            debug_assert!(*count > 0);
            match (*count).cmp(&rem) {
                Ordering::Less | Ordering::Equal => {
                    rem -= *count;
                    self.values.pop().expect("non-empty");
                }
                Ordering::Greater => {
                    *count -= rem;
                    break;
                }
            }
        }
        self.len -= n;
        Ok(())
    }
}

/// Errors returned by [`AbstractStack`] operations.
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub(super) enum AbsStackError {
    /// `pop_eq_n` was called with `n` greater than the
    /// run-length of the top value (the top `n` items are not
    /// all equal).
    ElementNotEqual,
    /// Pop attempted on an empty stack or with `n` greater
    /// than the stack's logical length.
    Underflow,
    /// `push_n` would overflow `u64::MAX` logical length.
    Overflow,
}

impl fmt::Display for AbsStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ElementNotEqual => write!(f, "popped element is not equal to specified item"),
            Self::Underflow => write!(f, "popped more values than are on the stack"),
            Self::Overflow => write!(f, "pushed too many elements on the stack"),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the abstract typed-stack.
    //! Faithful port of upstream's `unit_tests`; covers push,
    //! pop, run-length compression, and error paths.

    use super::*;

    #[test]
    fn new_is_empty() {
        let s: AbstractStack<u8> = AbstractStack::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn push_pop_roundtrip() {
        let mut s = AbstractStack::new();
        s.push(1u8).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.pop().unwrap(), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn push_n_compresses_runs() {
        let mut s = AbstractStack::new();
        s.push_n(7u8, 5).unwrap();
        assert_eq!(s.len(), 5);
        // Single entry under the hood; popping 5 equal values
        // returns the value.
        let v = s.pop_eq_n(NonZeroU64::new(5).unwrap()).unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn push_different_creates_new_entry() {
        let mut s = AbstractStack::new();
        s.push(1u8).unwrap();
        s.push(2u8).unwrap();
        s.push(2u8).unwrap();
        assert_eq!(s.len(), 3);
        // Top run is two 2s.
        let two = s.pop_eq_n(NonZeroU64::new(2).unwrap()).unwrap();
        assert_eq!(two, 2);
        let one = s.pop().unwrap();
        assert_eq!(one, 1);
    }

    #[test]
    fn pop_empty_underflow() {
        let mut s: AbstractStack<u8> = AbstractStack::new();
        assert_eq!(s.pop().unwrap_err(), AbsStackError::Underflow);
    }

    #[test]
    fn pop_eq_n_across_runs_errors() {
        let mut s = AbstractStack::new();
        s.push(1u8).unwrap();
        s.push(2u8).unwrap();
        // Top is one 2; popping 2-equal returns ElementNotEqual.
        assert_eq!(
            s.pop_eq_n(NonZeroU64::new(2).unwrap()).unwrap_err(),
            AbsStackError::ElementNotEqual,
        );
    }

    #[test]
    fn push_n_overflow() {
        let mut s = AbstractStack::new();
        s.push_n(1u8, u64::MAX).unwrap();
        assert_eq!(s.push(1u8).unwrap_err(), AbsStackError::Overflow);
    }

    #[test]
    fn pop_any_n_across_runs() {
        let mut s = AbstractStack::new();
        s.push_n(1u8, 3).unwrap();
        s.push_n(2u8, 4).unwrap();
        assert_eq!(s.len(), 7);
        s.pop_any_n(NonZeroU64::new(5).unwrap()).unwrap();
        // 5 popped: 4 of value 2 + 1 of value 1; 2 of value 1
        // remain.
        assert_eq!(s.len(), 2);
        let one = s.pop().unwrap();
        assert_eq!(one, 1);
    }

    #[test]
    fn pop_n_equal_to_run_length_drops_entry() {
        let mut s = AbstractStack::new();
        s.push_n(5u8, 3).unwrap();
        let v = s.pop_eq_n(NonZeroU64::new(3).unwrap()).unwrap();
        assert_eq!(v, 5);
        assert!(s.is_empty());
    }
}
