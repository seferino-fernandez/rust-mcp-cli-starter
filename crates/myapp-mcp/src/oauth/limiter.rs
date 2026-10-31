//! A global limiter on wrong consent PINs submitted to `POST /oauth/approve`.
//!
//! [`PinLimiter`] is a pure state machine: every method takes the current
//! time, so the handler passes `Instant::now()` and tests drive synthetic time.
//!
//! - Wrong PINs from every client and caller count together in a rolling
//!   [`FAILURE_WINDOW`]. The [`MAX_FAILURES`]th failure in the window starts a
//!   backoff of [`BASE_BACKOFF`].
//! - During a backoff every PIN check is refused. Refused attempts are not
//!   failures and do not extend the backoff.
//! - After a backoff ends, the next wrong PIN immediately starts a backoff
//!   twice as long as the previous one, capped at [`MAX_BACKOFF`].
//! - A correct PIN resets everything, and so does [`QUIET_RESET`] with no
//!   failures, counted after the latest backoff ends (or after the last
//!   failure, if no backoff is in effect). Time inside a backoff never counts,
//!   so once backoffs reach [`MAX_BACKOFF`] the cap is held until then.
//!
//! The limiter is global on purpose. A per-IP limiter would be spoofable,
//! or meaningless behind a proxy that gives every caller the same address.
//! The cost is that anyone who can reach `/oauth/approve` can lock the owner
//! out too, for up to [`MAX_BACKOFF`] (15 minutes) at a time. That was
//! chosen over a shorter cap: a one-minute cap would let a dictionary attack
//! try about 1,440 PINs a day, enough to find a weak PIN.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Wrong PINs within [`FAILURE_WINDOW`] that start the first backoff.
pub const MAX_FAILURES: usize = 5;
/// The rolling window in which wrong PINs are counted.
pub const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// The length of the first backoff after a reset.
pub const BASE_BACKOFF: Duration = Duration::from_secs(60);
/// The longest a backoff can grow by doubling, and so the longest a remote
/// party can delay the owner per lockout.
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// Time without a failure that resets the limiter, counted from the later of
/// the last failure and the end of the latest backoff.
pub const QUIET_RESET: Duration = Duration::from_secs(15 * 60);

/// Counts wrong consent PINs and decides when PIN checks are refused.
#[derive(Debug, Default)]
pub struct PinLimiter {
    /// Failures within the rolling window, oldest first. Only consulted until
    /// the first backoff after a reset.
    recent_failures: VecDeque<Instant>,
    last_failure: Option<Instant>,
    /// Wrong PINs since the last reset, for the backoff warning.
    failures_since_reset: u32,
    backoff_until: Option<Instant>,
    /// The length of the latest backoff since the last reset, if any.
    last_backoff: Option<Duration>,
}

impl PinLimiter {
    /// `Ok` when a PIN may be checked at `now`, or `Err` with the time left
    /// in the current backoff. A refusal changes nothing.
    pub fn check(&mut self, now: Instant) -> Result<(), Duration> {
        self.reset_if_quiet(now);
        match self.backoff_until {
            Some(until) if until > now => Err(until.saturating_duration_since(now)),
            _ => Ok(()),
        }
    }

    /// Records a wrong PIN at `now` and returns the length of the backoff it
    /// started, if it started one. A failure recorded during a backoff (a
    /// caller that skipped [`PinLimiter::check`]) is ignored, so it never
    /// extends the backoff.
    pub fn record_failure(&mut self, now: Instant) -> Option<Duration> {
        self.reset_if_quiet(now);
        if self.backoff_until.is_some_and(|until| until > now) {
            return None;
        }
        self.last_failure = Some(now);
        self.failures_since_reset = self.failures_since_reset.saturating_add(1);

        let backoff =
            match self.last_backoff {
                Some(previous) => previous.saturating_mul(2).min(MAX_BACKOFF),
                None => {
                    self.recent_failures.push_back(now);
                    while self.recent_failures.front().is_some_and(|first| {
                        now.saturating_duration_since(*first) >= FAILURE_WINDOW
                    }) {
                        self.recent_failures.pop_front();
                    }
                    if self.recent_failures.len() < MAX_FAILURES {
                        return None;
                    }
                    self.recent_failures.clear();
                    BASE_BACKOFF
                }
            };
        self.backoff_until = Some(now.checked_add(backoff).unwrap_or(now));
        self.last_backoff = Some(backoff);
        Some(backoff)
    }

    /// Records a correct PIN, which resets the limiter.
    pub fn record_success(&mut self, _now: Instant) {
        *self = Self::default();
    }

    /// Wrong PINs since the last reset.
    pub fn failures_since_reset(&self) -> u32 {
        self.failures_since_reset
    }

    /// Resets the limiter once [`QUIET_RESET`] has passed since the later of
    /// the last failure and the end of the latest backoff.
    fn reset_if_quiet(&mut self, now: Instant) {
        let quiet_since = match (self.last_failure, self.backoff_until) {
            (Some(last), Some(until)) => Some(last.max(until)),
            (last, None) => last,
            (None, until) => until,
        };
        if quiet_since.is_some_and(|since| now.saturating_duration_since(since) >= QUIET_RESET) {
            *self = Self::default();
        }
    }
}

/// Whole seconds left in `remaining`, rounded up and at least 1, for a
/// `Retry-After` header.
pub fn retry_after_secs(remaining: Duration) -> u64 {
    let whole = remaining.as_secs();
    let rounded = if remaining.subsec_nanos() > 0 {
        whole.saturating_add(1)
    } else {
        whole
    };
    rounded.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(start: Instant, offset: Duration) -> Instant {
        start.checked_add(offset).unwrap()
    }

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    /// Records `count` failures one second apart starting at `start`, and
    /// returns the time of the last and what it returned.
    fn fail_times(
        limiter: &mut PinLimiter,
        start: Instant,
        count: u64,
    ) -> (Instant, Option<Duration>) {
        let mut last = (start, None);
        for offset in 0..count {
            let now = after(start, secs(offset));
            assert_eq!(limiter.check(now), Ok(()), "failure {offset} was refused");
            last = (now, limiter.record_failure(now));
        }
        last
    }

    /// Drives a fresh limiter from `start` through 60, 120, 240, 480 and a
    /// capped 900 s backoff, each wrong PIN arriving as the previous backoff
    /// ends. Returns the time the 900 s backoff started.
    fn drive_to_max_backoff(limiter: &mut PinLimiter, start: Instant) -> Instant {
        let (mut now, started) = fail_times(limiter, start, 5);
        let mut backoff = started.unwrap();
        assert_eq!(backoff, BASE_BACKOFF);
        // 120, 240, 480, then 960 capped to 900.
        for expected in [120, 240, 480, 900] {
            now = after(now, backoff);
            assert_eq!(limiter.check(now), Ok(()));
            backoff = limiter.record_failure(now).unwrap();
            assert_eq!(backoff, secs(expected));
            assert_eq!(limiter.check(now), Err(backoff));
        }
        assert_eq!(backoff, MAX_BACKOFF);
        now
    }

    #[test]
    fn four_failures_in_the_window_do_not_back_off() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        for offset in 0..4 {
            let now = after(start, secs(offset));
            assert_eq!(limiter.check(now), Ok(()));
            assert_eq!(limiter.record_failure(now), None);
        }
        assert_eq!(limiter.check(after(start, secs(4))), Ok(()));
    }

    #[test]
    fn fifth_failure_in_the_window_starts_the_base_backoff() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        let (fifth, started) = fail_times(&mut limiter, start, 5);
        assert_eq!(started, Some(BASE_BACKOFF));
        assert_eq!(limiter.failures_since_reset(), 5);
        assert_eq!(limiter.check(fifth), Err(BASE_BACKOFF));
        assert_eq!(limiter.check(after(fifth, secs(59))), Err(secs(1)));
        assert_eq!(limiter.check(after(fifth, BASE_BACKOFF)), Ok(()));
    }

    #[test]
    fn failures_older_than_the_window_roll_off() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        // Four failures, then the fifth a full window after the first.
        fail_times(&mut limiter, start, 4);
        let fifth = after(start, FAILURE_WINDOW);
        assert_eq!(limiter.record_failure(fifth), None);
        // A sixth while the second through fifth are still in the window
        // backs off.
        assert_eq!(
            limiter.record_failure(after(fifth, Duration::from_millis(500))),
            Some(BASE_BACKOFF)
        );
    }

    #[test]
    fn refused_checks_do_not_extend_the_backoff() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        let (fifth, _) = fail_times(&mut limiter, start, 5);
        for offset in 0..60 {
            let now = after(fifth, secs(offset));
            assert!(limiter.check(now).is_err(), "check at +{offset}s");
            // A failure that slipped past `check` is ignored too.
            assert_eq!(limiter.record_failure(now), None);
        }
        assert_eq!(limiter.check(after(fifth, BASE_BACKOFF)), Ok(()));
    }

    #[test]
    fn success_after_the_backoff_resets_to_a_fresh_run_of_five() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        let (fifth, _) = fail_times(&mut limiter, start, 5);
        let ended = after(fifth, BASE_BACKOFF);
        assert_eq!(limiter.check(ended), Ok(()));
        limiter.record_success(ended);
        assert_eq!(limiter.failures_since_reset(), 0);

        let (fourth, started) = fail_times(&mut limiter, after(ended, secs(1)), 4);
        assert_eq!(
            started, None,
            "four failures after a reset must not back off"
        );
        let next = after(fourth, secs(1));
        assert_eq!(limiter.record_failure(next), Some(BASE_BACKOFF));
        assert_eq!(limiter.check(after(next, secs(59))), Err(secs(1)));
        assert_eq!(limiter.check(after(next, BASE_BACKOFF)), Ok(()));
    }

    #[test]
    fn each_failure_after_a_backoff_doubles_it_up_to_the_cap() {
        let mut limiter = PinLimiter::default();
        drive_to_max_backoff(&mut limiter, Instant::now());
        assert_eq!(limiter.failures_since_reset(), 9);
    }

    #[test]
    fn the_fifteen_minute_cap_is_held_after_each_backoff_ends() {
        let mut limiter = PinLimiter::default();
        let mut started = drive_to_max_backoff(&mut limiter, Instant::now());
        // A wrong PIN as the 900 s backoff ends, or just short of 15 quiet
        // minutes after it ends, starts another 900 s backoff every time.
        let almost_quiet = QUIET_RESET.checked_sub(secs(1)).unwrap();
        for wait_after_end in [Duration::ZERO, secs(1), almost_quiet, Duration::ZERO] {
            let now = after(after(started, MAX_BACKOFF), wait_after_end);
            assert_eq!(limiter.check(now), Ok(()));
            assert_eq!(limiter.record_failure(now), Some(MAX_BACKOFF));
            assert_eq!(limiter.check(now), Err(MAX_BACKOFF));
            started = now;
        }
        assert_eq!(limiter.failures_since_reset(), 13);
    }

    #[test]
    fn fifteen_quiet_minutes_after_a_full_backoff_ends_reset_the_limiter() {
        let mut limiter = PinLimiter::default();
        let started = drive_to_max_backoff(&mut limiter, Instant::now());
        let quiet = after(after(started, MAX_BACKOFF), QUIET_RESET);
        assert_eq!(limiter.check(quiet), Ok(()));
        let (fourth, started) = fail_times(&mut limiter, quiet, 4);
        assert_eq!(started, None, "a reset limiter needs five fresh failures");
        assert_eq!(limiter.failures_since_reset(), 4);
        let fifth = after(fourth, secs(1));
        assert_eq!(limiter.record_failure(fifth), Some(BASE_BACKOFF));
        assert_eq!(limiter.check(after(fifth, BASE_BACKOFF)), Ok(()));
    }

    #[test]
    fn fifteen_quiet_minutes_reset_the_next_backoff() {
        // Escalates to a 120 s backoff started at `ended`, the moment the
        // first 60 s backoff ends, and returns when the 120 s one ends.
        fn escalated(limiter: &mut PinLimiter) -> Instant {
            let (fifth, _) = fail_times(limiter, Instant::now(), 5);
            let ended = after(fifth, BASE_BACKOFF);
            assert_eq!(limiter.record_failure(ended), Some(secs(120)));
            after(ended, secs(120))
        }

        // The quiet minutes are counted after the backoff ends, not from the
        // failure that started it: just short of 15 minutes after the end,
        // the limiter is still escalated.
        let mut limiter = PinLimiter::default();
        let backoff_end = escalated(&mut limiter);
        let almost = after(backoff_end, QUIET_RESET.checked_sub(secs(1)).unwrap());
        assert_eq!(limiter.record_failure(almost), Some(secs(240)));

        // Fifteen minutes after the end, it has reset: one failure no longer
        // backs off, and the fifth starts 60 s again.
        let mut limiter = PinLimiter::default();
        let backoff_end = escalated(&mut limiter);
        let quiet = after(backoff_end, QUIET_RESET);
        assert_eq!(limiter.check(quiet), Ok(()));
        let (_, started) = fail_times(&mut limiter, quiet, 4);
        assert_eq!(started, None);
        assert_eq!(
            limiter.record_failure(after(quiet, secs(4))),
            Some(BASE_BACKOFF)
        );
    }

    #[test]
    fn just_short_of_fifteen_quiet_minutes_keeps_escalating() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        let (fifth, _) = fail_times(&mut limiter, start, 5);
        let almost = after(fifth, QUIET_RESET.checked_sub(secs(1)).unwrap());
        assert_eq!(limiter.record_failure(almost), Some(secs(120)));
    }

    #[test]
    fn quiet_reset_also_clears_a_partial_window() {
        let start = Instant::now();
        let mut limiter = PinLimiter::default();
        fail_times(&mut limiter, start, 4);
        let later = after(start, QUIET_RESET.checked_add(secs(3)).unwrap());
        assert_eq!(limiter.record_failure(later), None);
        assert_eq!(limiter.failures_since_reset(), 1);
    }

    #[test]
    fn retry_after_rounds_up_to_whole_seconds_and_at_least_one() {
        assert_eq!(retry_after_secs(secs(60)), 60);
        assert_eq!(retry_after_secs(Duration::from_millis(59_001)), 60);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
    }
}
