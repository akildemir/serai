use core::time::Duration;

/// The target block time.
pub const TARGET_BLOCK_TIME: Duration = Duration::from_secs(6);

#[cfg_attr(not(test), expect(unused))]
const MINUTE: Duration = Duration::from_mins(1);
/// One hour, as Serai considers it.
pub const HOUR: Duration = Duration::from_hours(1);
/// One day, as Serai considers it.
///
/// This is defined as exactly 24 hours, regardless of the context. It does not consider leap
/// seconds or any smudging which may happen during some days following certain calendars.
pub const DAY: Duration = HOUR.checked_mul(24).unwrap();
/// One week, as Serai considers it.
///
/// This is defined as exactly 7 days, as Serai considers a day, regardless of the context. It does
/// not consider leap seconds/days or any smudging which may happen during some weeks following
/// certain calendars.
pub const WEEK: Duration = DAY.checked_mul(7).unwrap();

/// The intended duration for a session.
///
/// Mainnet uses a week; this testnet build lengthens it to a month so set rotation (currently
/// known-broken, not under test) isn't hit during normal testnet operation.
pub const SESSION_LENGTH: Duration = DAY.checked_mul(30).unwrap();
/// The intended duration for a session, represented in the amount of block proposal slots.
pub const SESSION_LENGTH_IN_SLOTS: u64 = SESSION_LENGTH.as_secs() / TARGET_BLOCK_TIME.as_secs();

/// The duration for which a retirement signal is locked in before the protocol retires,
/// represented in the amount of block proposal slots.
#[doc(hidden)]
/// Kept at 4x the session length (the mainnet ratio) — the signals pallet requires the lock-in
/// to exceed two full sessions.
pub const RETIREMENT_LOCK_IN_DURATION_IN_SLOTS: u64 =
  SESSION_LENGTH.checked_mul(4).unwrap().as_secs() / TARGET_BLOCK_TIME.as_secs();

#[allow(unknown_lints)] // `clippy::duration_suboptimal_units` was added with 1.95
#[expect(clippy::duration_suboptimal_units)]
#[test]
fn constants() {
  assert_eq!(MINUTE, Duration::from_secs(60));
  assert_eq!(HOUR, Duration::from_secs(60 * 60));
  assert_eq!(DAY, Duration::from_secs(24 * 60 * 60));
  assert_eq!(WEEK, Duration::from_secs(7 * 24 * 60 * 60));

  assert_eq!(SESSION_LENGTH, Duration::from_secs(30 * 24 * 60 * 60));

  assert_eq!(
    SESSION_LENGTH_IN_SLOTS,
    u64::try_from(SESSION_LENGTH.as_nanos() / TARGET_BLOCK_TIME.as_nanos()).unwrap()
  );
  assert_eq!(SESSION_LENGTH_IN_SLOTS, (30 * 24 * 60 * 60) / 6);

  assert_eq!(RETIREMENT_LOCK_IN_DURATION_IN_SLOTS, (4 * 30 * 24 * 60 * 60) / 6);
}
