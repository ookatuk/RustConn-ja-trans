//! Telling the user that `keepassxc-cli` is waiting on a hardware-key touch.
//!
//! A Challenge-Response unlock (`keepassxc-cli … -y <slot>`) blocks until the
//! key is touched. RustConn runs the CLI with `-q` and reads its output only
//! after it exits, so KeePassXC's own "please present or touch your YubiKey"
//! never reaches the user: the key blinks and nothing on screen says why
//! (issue #350). This module is the signal a presentation layer hangs a cue on
//! — a banner in the GUI, a line on stderr in the CLI — without the headless
//! core knowing which.
//!
//! The signal brackets one `keepassxc-cli` run that carries `-y`, not one
//! physical touch. A run that writes is challenged twice: once to open the
//! database and once more to save it, because KeePassXC re-derives the KDBX 4
//! key from a fresh random seed on every save (`Kdbx4Writer::writeDatabase`
//! calls `Database::setKey` with `updateTransformSalt`, and the composite key's
//! challenge-response part is computed from that seed). The CLI does not say
//! which phase it is in, so the cue stays up for the whole run.

use std::sync::{Arc, Mutex, PoisonError};

/// Receives the start and end of every `keepassxc-cli` run that may wait on a touch.
///
/// Called on whichever thread runs the database operation — in the GUI that
/// is a worker thread — so an implementation that drives a UI must hand the
/// event over to its own thread. Every [`touch_started`](Self::touch_started)
/// is followed by exactly one [`touch_finished`](Self::touch_finished) on the
/// same observer, whatever became of the run: success, failure, timeout, or a
/// child that never started.
pub trait TouchObserver: Send + Sync {
    /// A run that waits on the hardware key has started.
    fn touch_started(&self);

    /// That run has ended.
    fn touch_finished(&self);
}

/// The observer in force, if any.
///
/// Replaceable rather than set-once, so a test can install its own and take
/// it away again. The lock is held only to read or swap the `Arc`, never while
/// an observer runs, so an observer may call [`set_touch_observer`] itself.
static OBSERVER: Mutex<Option<Arc<dyn TouchObserver>>> = Mutex::new(None);

/// Installs the observer for hardware-key touch notifications, or removes it with `None`.
///
/// Process-wide: the GUI installs one at startup and the CLI installs one
/// before a command that opens a KeePass database. A run already in progress
/// finishes on the observer it started with, so its start and end always
/// reach the same receiver.
pub fn set_touch_observer(observer: Option<Arc<dyn TouchObserver>>) {
    // The guarded value is replaced whole, so a poisoned lock holds nothing
    // half-written and recovering it is safe.
    *OBSERVER.lock().unwrap_or_else(PoisonError::into_inner) = observer;
}

/// Brackets one `keepassxc-cli` run that carries `-y`.
///
/// [`TouchGuard::begin`] reports the start; dropping the guard reports the
/// end. Drop runs on every way out of the scope — an early `?`, a timeout, a
/// panic that unwinds — which is what keeps a GUI's in-flight count from
/// sticking above zero after an error.
#[must_use = "the touch cue ends when the guard is dropped; bind it for the length of the run"]
pub(crate) struct TouchGuard {
    /// The observer the start went to, so the end goes to the same one even
    /// if another is installed in between.
    observer: Option<Arc<dyn TouchObserver>>,
}

impl TouchGuard {
    /// Reports the start of a run to the installed observer, if there is one.
    pub(crate) fn begin() -> Self {
        // Cloned out under the lock and called outside it.
        let observer = OBSERVER
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone);
        if let Some(observer) = &observer {
            observer.touch_started();
        }
        Self { observer }
    }
}

impl Drop for TouchGuard {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer.touch_finished();
        }
    }
}

/// Helpers for tests that observe touch notifications, here and in `status`.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::thread::ThreadId;

    use super::TouchObserver;

    /// Held by every test that installs an observer: there is one per process,
    /// and the test harness runs tests on parallel threads.
    static INSTALL_LOCK: Mutex<()> = Mutex::new(());

    /// Takes [`INSTALL_LOCK`] for the length of a test.
    pub(crate) fn exclusive() -> MutexGuard<'static, ()> {
        INSTALL_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts the notifications raised on the thread that created it, and no others.
    ///
    /// Filtering by thread is what lets a counting test run alongside tests that
    /// exercise a YubiKey slot without installing anything: their runs reach
    /// this observer too, from their own threads, and are ignored.
    pub(crate) struct CountingObserver {
        thread: ThreadId,
        started: AtomicUsize,
        finished: AtomicUsize,
    }

    impl CountingObserver {
        /// An observer that counts what the current thread raises.
        pub(crate) fn for_this_thread() -> Self {
            Self {
                thread: std::thread::current().id(),
                started: AtomicUsize::new(0),
                finished: AtomicUsize::new(0),
            }
        }

        /// How many runs have started.
        pub(crate) fn started(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }

        /// How many runs have finished.
        pub(crate) fn finished(&self) -> usize {
            self.finished.load(Ordering::SeqCst)
        }

        fn is_own_thread(&self) -> bool {
            std::thread::current().id() == self.thread
        }
    }

    impl TouchObserver for CountingObserver {
        fn touch_started(&self) {
            if self.is_own_thread() {
                self.started.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn touch_finished(&self) {
            if self.is_own_thread() {
                self.finished.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::test_support::{CountingObserver, exclusive};
    use super::{TouchGuard, TouchObserver, set_touch_observer};

    fn install(observer: &Arc<CountingObserver>) {
        // Method-call `.clone()`, not `Arc::clone`: the result is coerced to
        // `Arc<dyn TouchObserver>` on assignment, which the UFCS form prevents.
        #[expect(
            clippy::clone_on_ref_ptr,
            reason = "the clone must unsize to Arc<dyn TouchObserver>, which Arc::clone cannot"
        )]
        let installed: Arc<dyn TouchObserver> = observer.clone();
        set_touch_observer(Some(installed));
    }

    #[test]
    fn a_guard_reports_its_start_and_its_end() {
        let _exclusive = exclusive();
        let observer = Arc::new(CountingObserver::for_this_thread());
        install(&observer);

        let guard = TouchGuard::begin();
        assert_eq!((observer.started(), observer.finished()), (1, 0));
        drop(guard);
        assert_eq!((observer.started(), observer.finished()), (1, 1));

        set_touch_observer(None);
    }

    /// A start and its end reach the same observer, even across a swap.
    #[test]
    fn a_run_finishes_on_the_observer_it_started_with() {
        let _exclusive = exclusive();
        let first = Arc::new(CountingObserver::for_this_thread());
        let second = Arc::new(CountingObserver::for_this_thread());
        install(&first);

        let guard = TouchGuard::begin();
        install(&second);
        drop(guard);

        assert_eq!((first.started(), first.finished()), (1, 1));
        assert_eq!((second.started(), second.finished()), (0, 0));

        set_touch_observer(None);
    }

    #[test]
    fn a_guard_with_no_observer_installed_does_nothing() {
        let _exclusive = exclusive();
        set_touch_observer(None);
        // Nothing to assert beyond "does not panic": there is no receiver.
        drop(TouchGuard::begin());
    }

    /// The guard is what an early `?` or a panic leaves behind, so its end
    /// must arrive on unwind too.
    #[test]
    fn a_panic_during_the_run_still_reports_the_end() {
        let _exclusive = exclusive();
        let observer = Arc::new(CountingObserver::for_this_thread());
        install(&observer);

        let unwound = std::panic::catch_unwind(|| {
            let _guard = TouchGuard::begin();
            panic!("the run failed");
        });

        assert!(unwound.is_err());
        assert_eq!((observer.started(), observer.finished()), (1, 1));

        set_touch_observer(None);
    }
}
