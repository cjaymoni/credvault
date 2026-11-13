//! Anonymous reach telemetry: how many installations of the app reach this
//! server, on which platform, from which country.
//!
//! Three rules shape everything below, because this is a password manager and
//! an analytics module inside one has to justify itself line by line.
//!
//! 1. **Nothing here is tied to an account.** The only event this module sends
//!    is raised by `GET /api/capabilities`, which the app calls *before* the
//!    sign-in screen, when the server does not yet know who is asking. No
//!    handler that has resolved a session calls into this module, and nothing
//!    in an event's shape has room for a user id, an email, or a secret name.
//! 2. **No address is sent anywhere or kept.** The client address is consumed
//!    to derive [`Analytics::anonymous_id`] and then dropped. What leaves this
//!    process is a two-letter country, a platform, a version string, and an
//!    opaque id that stops being derivable once the day rolls over or the
//!    process restarts, whichever comes first.
//! 3. **It is off unless an operator switches it on.** No API key, no
//!    [`Analytics`], no outbound request — which is the state every
//!    self-hosted server is in by default. See `--posthog-api-key`.
//!
//! What the number counts, stated plainly because it will be read as an
//! install base and is not one. The unit is a distinct (address, build) pair
//! per UTC day, with IPv6 folded to a /64. An office of twenty people behind
//! one NAT counts as one; a laptop that moves between home, a train and an
//! office counts as three. It is a usable trend and a poor absolute.
//!
//! What this buys, and what it does not: the app's installers are downloaded
//! from GitHub, and GitHub reports a count per release asset and nothing else.
//! So the download count says how many copies were fetched and this module
//! says how many distinct installations then opened and pointed themselves at
//! a server, where from, and on what. Neither is a count of people, and the
//! two must not be added together.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, Utc};

use crate::ratelimit::limiter_key;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// PostHog's EU cloud. The default because the privacy policy this server is
/// deployed under describes EU/UK users, and because an operator who wants
/// another region or their own instance says so explicitly rather than
/// discovering after the fact where the data went.
pub const DEFAULT_HOST: &str = "https://eu.i.posthog.com";

/// Raised when an app first reaches a server on a given day.
///
/// Named for what is actually observed rather than for what one wishes it
/// meant. It is not "installed" — nothing here can see an installation — and
/// it is not "launched", because an app that is never pointed at a reachable
/// server raises nothing at all.
pub const APP_REACHED_SERVER: &str = "app_reached_server";

/// How many events may be waiting to be sent before new ones are dropped.
///
/// `/api/capabilities` is unauthenticated and deliberately not rate limited —
/// it is how a client discovers whether this server offers Google sign-in
/// before it can be asked for any credential. That makes it the one route an
/// anonymous flood can drive for free, so the queue in front of PostHog is
/// bounded and a full queue drops the event rather than making a request wait
/// on an outbound HTTP call. Telemetry that degrades under load is correct;
/// a sign-in screen that stalls because of telemetry is not.
const QUEUE_CAPACITY: usize = 1_024;

/// Events per outbound request. PostHog's `/batch/` accepts far more; this is
/// sized so a flush is one small request rather than one large one.
const BATCH_SIZE: usize = 50;

/// How long a partially filled batch waits for company before being sent.
const FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Ceiling on one outbound request to PostHog. Short on purpose: a batch that
/// cannot be delivered promptly is discarded, because the alternative is a
/// background task that falls further behind a bounded queue that is then
/// dropping live events in favour of stale ones.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest a rotation check will ever wait, whatever the clock is doing.
const ROTATION_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Longest `User-Agent` this module will look at. Anything longer is treated
/// as absent rather than parsed: the header is attacker-controlled, and the
/// only thing a long one can express is an attempt to put something large
/// into an analytics property.
const MAX_USER_AGENT_LEN: usize = 256;

/// Longest version string accepted out of a `User-Agent`.
const MAX_VERSION_LEN: usize = 32;

/// How the app may name itself in a `User-Agent`, current spelling first.
///
/// The product was renamed from credvault to klavyn. Both are read, because a
/// server is upgraded before the apps that talk to it are: an app from before
/// the rename is a real installation, and dropping its spelling would report
/// every one of them as the unknown build rather than as what it is. Drop
/// `credvault/` once no build older than the rename is still in use -- the
/// version in each event is what tells you when that is.
const CLIENT_NAME_PREFIXES: [&str; 2] = ["klavyn/", "credvault/"];

/// Hex characters of the digest used as a distinct id. 128 bits: far past
/// collision trouble at this volume, and shorter than a full digest so that
/// nothing about the id invites being treated as a key.
const ANONYMOUS_ID_HEX_LEN: usize = 32;

/// One drop is a dropped event; a sustained run of them is a misconfiguration
/// or a flood, and either way the operator should see one line about it rather
/// than one line per request.
const DROPS_BETWEEN_WARNINGS: u64 = 1_000;

/// The platforms the desktop app is built for, plus the catch-all.
///
/// An allow-list rather than a sanitiser, because the value arrives in a
/// header: an unrecognised platform becomes [`PLATFORM_UNKNOWN`] and nothing
/// a client writes is ever forwarded verbatim as a property value.
const KNOWN_PLATFORMS: [&str; 5] = ["macos", "windows", "linux", "android", "ios"];

/// What an unparseable or absent platform is reported as.
pub const PLATFORM_UNKNOWN: &str = "unknown";

/// What an unparseable or absent version is reported as.
pub const VERSION_UNKNOWN: &str = "unknown";

/// Values `CF-IPCountry` carries that are shaped like a country and are not
/// one. `XX` is Cloudflare's "could not determine"; `T1` is Tor, listed for
/// completeness rather than need, since its digit already disqualifies it.
const NOT_REALLY_COUNTRIES: [&str; 2] = ["XX", "T1"];

/// One queued event, already resolved to the values that will be sent.
///
/// Built on the request thread and carried to the sender, so that nothing
/// derived from the client address outlives the request that supplied it.
#[derive(Debug, Clone, PartialEq)]
struct QueuedEvent {
    name: &'static str,
    distinct_id: String,
    properties: Value,
    /// Stamped when the event happened, not when it is finally sent: batching
    /// delays delivery by up to [`FLUSH_INTERVAL`] and a restart can delay it
    /// forever, and neither should move an event in time.
    at: DateTime<Utc>,
}

impl QueuedEvent {
    /// The wire shape PostHog's capture API expects for one event in a batch.
    fn to_payload(&self) -> Value {
        json!({
            "event": self.name,
            "distinct_id": self.distinct_id,
            "timestamp": self.at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "properties": self.properties,
        })
    }
}

/// What the app told us about itself in its `User-Agent`, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientBuild {
    /// One of [`KNOWN_PLATFORMS`], or [`PLATFORM_UNKNOWN`].
    pub platform: &'static str,
    /// A version as the app spells it, or [`VERSION_UNKNOWN`].
    pub version: String,
}

impl Default for ClientBuild {
    fn default() -> Self {
        Self { platform: PLATFORM_UNKNOWN, version: VERSION_UNKNOWN.to_string() }
    }
}

/// Read `<name>/<version> (<platform>)` out of a `User-Agent`, for any
/// name in [`CLIENT_NAME_PREFIXES`].
///
/// Deliberately strict and total: every path returns a [`ClientBuild`] built
/// from constants and from a version that has been checked character by
/// character, so no attacker-chosen bytes reach an analytics property. A
/// browser, a `curl`, or a probe sending something else is reported as the
/// unknown build rather than being rejected — `/api/capabilities` answers
/// everyone, and telemetry does not get to decide otherwise.
pub fn parse_client_build(user_agent: Option<&str>) -> ClientBuild {
    let Some(user_agent) = user_agent.filter(|value| value.len() <= MAX_USER_AGENT_LEN) else {
        return ClientBuild::default();
    };
    let Some(rest) = CLIENT_NAME_PREFIXES.iter().find_map(|prefix| user_agent.strip_prefix(prefix)) else {
        return ClientBuild::default();
    };
    let (version, platform) = match rest.split_once(' ') {
        Some((version, platform)) => (version, platform.trim()),
        None => (rest, ""),
    };
    let platform = platform.strip_prefix('(').and_then(|value| value.strip_suffix(')')).unwrap_or("");
    ClientBuild {
        platform: KNOWN_PLATFORMS.into_iter().find(|known| *known == platform).unwrap_or(PLATFORM_UNKNOWN),
        version: sanitized_version(version),
    }
}

/// A version string, or [`VERSION_UNKNOWN`] if it is not one.
///
/// Digits, dots and the marks a pre-release suffix uses. Nothing else: this
/// value becomes a property in an analytics event, and the set is small enough
/// that no escaping question arises anywhere downstream.
fn sanitized_version(version: &str) -> String {
    let plausible = !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'));
    if plausible {
        version.to_string()
    } else {
        VERSION_UNKNOWN.to_string()
    }
}

/// An ISO 3166-1 alpha-2 country, if the proxy in front supplied a credible
/// one.
///
/// Cloudflare sets `CF-IPCountry`, and alongside real countries it sets `T1`
/// for Tor — which the letters-only test below already rejects — and `XX` when
/// it could not tell, which it does not: `XX` is two capital letters, so it
/// would be recorded as a country by that name and would sit in the dashboard
/// looking like a place. It is named in [`NOT_REALLY_COUNTRIES`] for that
/// reason. Both become no country at all, which is the truth, and which a
/// chart can show as such.
///
/// The header is only consulted when the operator has said a proxy is in
/// front — see [`crate::ratelimit::client_ip`], which decides the same
/// question for the address and for the same reason: without a proxy that
/// overwrites it, the header is whatever the client typed.
pub fn parse_country(header: Option<&str>) -> Option<String> {
    let value = header?;
    let is_two_letters = value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase());
    (is_two_letters && !NOT_REALLY_COUNTRIES.contains(&value)).then(|| value.to_string())
}

/// The secret mixed into a day's ids, and the day it belongs to.
///
/// Replaced in place when the day changes, which is what makes yesterday's
/// ids unrecoverable rather than merely unpublished. That matters more than
/// it first looks. The only other inputs are a client address and a build,
/// and the IPv4 space is small enough to walk, so a salt that outlived its
/// day would turn a stored set of ids back into a set of addresses, which is
/// exactly what [`Analytics::anonymous_id`] exists to prevent.
///
/// Two things that sentence does *not* claim, because neither is true.
/// Deriving an id copies the salt into a `Sha256` block buffer on the
/// deriving thread's stack, and that frame is not wiped, so the most recent
/// derivation leaves a transient copy behind until something writes over it.
/// And on shutdown nothing here is overwritten at all: there is no graceful
/// shutdown (see [`drain`]), so `Drop` never runs and the pages are released
/// to the kernel rather than scrubbed. What is claimed is narrower, and is
/// what the retention argument actually needs: the only copy this process
/// *keeps* is overwritten when the day turns.
struct DailySalt {
    /// The UTC day these bytes belong to, or `None` before the first
    /// rotation has seeded them.
    ///
    /// An `Option` rather than a sentinel date: [`Analytics::anonymous_id`]
    /// is public and takes the day from its caller, so a sentinel would be a
    /// day someone could ask for, and asking for it would derive an id from
    /// the all-zero bytes below. `None` is not a `NaiveDate` and cannot be
    /// passed in, which makes the unseeded state unreachable from outside
    /// rather than merely documented as unreachable.
    day: Option<NaiveDate>,
    bytes: Zeroizing<[u8; 32]>,
}

/// A live connection to PostHog: a bounded queue and the task draining it.
pub struct Analytics {
    queue: mpsc::Sender<QueuedEvent>,
    /// The secret behind [`Analytics::anonymous_id`]. Never persisted and
    /// never reused across days, so a restart starts a fresh id space and so
    /// does midnight. That costs some double counting and is the side of the
    /// trade worth being on.
    ///
    /// A `std::sync` lock rather than Tokio's: the critical section is a hash
    /// over a few dozen bytes with no await in it, and taking an async lock
    /// on every unauthenticated request to hold it that briefly would cost
    /// more than it saves.
    salt: std::sync::RwLock<DailySalt>,
    /// Events dropped because the queue was full, for the warning in
    /// [`Analytics::capture_reach`].
    dropped: AtomicU64,
}

impl std::fmt::Debug for Analytics {
    /// No salt, and no derived value, in any log line that formats this.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analytics").field("dropped", &self.dropped.load(Ordering::Relaxed)).finish_non_exhaustive()
    }
}

impl Analytics {
    /// Start sending to `host` with `api_key`, spawning the task that drains
    /// the queue.
    ///
    /// Must be called from inside a Tokio runtime. `build_router` deliberately
    /// does not do this: it is synchronous, it is what the tests call, and a
    /// router that spawns a network task merely by being built would make
    /// every test that builds one an analytics client.
    ///
    /// # Errors
    ///
    /// If `host` is not a URL, or if an HTTP client cannot be built. Both are
    /// configuration errors worth refusing to start over, rather than running
    /// a server whose operator believes it is reporting and which is not.
    pub fn start(api_key: String, host: &str) -> Result<Arc<Self>, AnalyticsError> {
        let host = host.trim_end_matches('/').to_string();
        let parsed = url::Url::parse(&host).map_err(|e| AnalyticsError::Host(e.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(AnalyticsError::Host(format!("{} is not an http(s) address", parsed.scheme())));
        }
        let http = reqwest::Client::builder()
            .timeout(SEND_TIMEOUT)
            .build()
            .map_err(|e| AnalyticsError::Client(e.to_string()))?;

        // No salt is generated here. It is seeded in place on first use, by
        // the same rotation that replaces it at midnight -- see [`DailySalt`].
        // Filling a stack-local array and moving it in would leave a copy of
        // the secret in a frame nothing zeroizes.
        let salt = std::sync::RwLock::new(DailySalt { day: None, bytes: Zeroizing::new([0u8; 32]) });

        let (queue, receiver) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(drain(receiver, http, host, api_key));
        let analytics = Arc::new(Self { queue, salt, dropped: AtomicU64::new(0) });

        // The salt has to stop being a secret *at* midnight, not at the next
        // request after midnight. Rotation driven only by incoming requests
        // is lazy: a server that is quiet from Monday to Friday keeps
        // Monday's salt live in memory all week, while the privacy policy
        // tells users that once a day has passed nobody can recompute that
        // day's ids. This task closes that gap.
        //
        // A `Weak`, so the task never keeps the handle alive: when the server
        // drops its `Analytics`, the upgrade fails and the loop ends.
        let ticking = Arc::downgrade(&analytics);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(until_next_midnight(Utc::now())).await;
                if !rotate_once(&ticking, Utc::now().date_naive()) {
                    return;
                }
            }
        });
        Ok(analytics)
    }

    /// Run `derive` against the salt for `day`, replacing it first if the day
    /// has turned over.
    ///
    /// The new bytes are written over the old ones in place, so the previous
    /// day's secret is gone rather than merely unreferenced -- which is the
    /// whole of the unlinkability claim in [`DailySalt`]. The read path is
    /// the common one and takes no write lock; the write path runs once a day
    /// and re-checks the date under the lock, because two requests can race
    /// through the read and both find the day stale.
    fn with_salt<R>(&self, day: NaiveDate, derive: impl FnOnce(&[u8; 32]) -> R) -> R {
        // A poisoned lock means a previous holder panicked mid-derivation.
        // Nothing it could have left behind is unsound -- the salt is bytes
        // and the day is a date -- and refusing to count would turn an
        // unrelated panic into a dead analytics path, so the contents are
        // taken as they stand.
        {
            let held = self.salt.read().unwrap_or_else(|poisoned| poisoned.into_inner());
            if held.day == Some(day) {
                return derive(&held.bytes);
            }
        }
        let mut held = self.salt.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Any difference rotates, a day that has gone *backwards* included --
        // an NTP step across midnight, or a VM restored from a snapshot.
        // Fresh bytes are always the safe direction, and the cost is paid in
        // accuracy rather than privacy: each extra rotation splits one
        // installation into two, exactly as a restart does.
        if held.day != Some(day) {
            rand::thread_rng().fill_bytes(held.bytes.as_mut());
            held.day = Some(day);
        }
        derive(&held.bytes)
    }

    /// An opaque, unlinkable id for one installation on one day.
    ///
    /// The address and the build go in, a digest comes out, and only the
    /// digest leaves this process. Two things keep this from being a tracking
    /// identifier: `day` is hashed in, and the salt behind it is replaced
    /// when the day turns over, so yesterday's ids cannot be recomputed by
    /// anyone -- including whoever holds this machine. Within a single UTC
    /// day two events are recognisable as one installation, which is exactly
    /// enough to count installations and not enough to follow one.
    ///
    /// The build is part of the id, so updating the app reads as a new
    /// installation. That is the intended meaning: an upgrade *is* a fresh
    /// download, which is the number this is here to corroborate.
    ///
    /// `day` is a rotation trigger as well as an input, which is why this is
    /// crate-private rather than public: asking for a day that is not the one
    /// the salt is currently seeded for *discards that salt* and re-seeds for
    /// the day asked about. For the two real callers -- this module's
    /// `capture_reach` and the rotation task, both of which pass today -- that
    /// is exactly the wanted behaviour. A caller passing a parsed or
    /// remembered date would silently split the day's count and throw away a
    /// live secret, so the precondition is: pass the current UTC day, or a
    /// day you intend to rotate to.
    ///
    /// The address is folded through [`limiter_key`] first, for the reason
    /// that function exists: an IPv6 subscriber usually holds a whole /64, and
    /// counting individual addresses would let one of them walk their own
    /// range and mint installations by the billion on a route that is not
    /// rate limited. A /64 is one subscriber, which is also the closest this
    /// number can honestly get to one installation.
    pub(crate) fn anonymous_id(&self, ip: IpAddr, build: &ClientBuild, day: NaiveDate) -> String {
        let digest = self.with_salt(day, |salt| {
            let mut hasher = Sha256::new();
            // Labelled and length-prefixed, so that no two different inputs
            // can produce the same byte stream -- a version ending in the
            // characters a platform begins with must not collide with the
            // pair split the other way.
            hasher.update(b"credvault/anonymous-id/v2");
            // Raw octets rather than the text form, so no formatted copy of
            // the address is left on the heap, and so that `::ffff:1.2.3.4`
            // and `1.2.3.4` cannot be counted as two installations. The day
            // likewise goes in as a number rather than as a formatted date.
            let mut field = |bytes: &[u8]| {
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            };
            field(salt.as_slice());
            field(&day.num_days_from_ce().to_le_bytes());
            match limiter_key(ip) {
                IpAddr::V4(address) => field(&address.octets()),
                IpAddr::V6(address) => field(&address.octets()),
            }
            field(build.platform.as_bytes());
            field(build.version.as_bytes());
            hasher.finalize()
        });
        let mut hex = String::with_capacity(ANONYMOUS_ID_HEX_LEN);
        for byte in digest.iter().take(ANONYMOUS_ID_HEX_LEN / 2) {
            // Writing to a String cannot fail; the Result is discarded rather
            // than unwrapped so a formatting change can never panic a request.
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// Queue the one event this module sends. Never blocks, never fails a
    /// request, and drops the event if the queue is full.
    pub fn capture_reach(&self, ip: IpAddr, build: &ClientBuild, country: Option<String>) {
        let now = Utc::now();
        let event = QueuedEvent {
            name: APP_REACHED_SERVER,
            distinct_id: self.anonymous_id(ip, build, now.date_naive()),
            properties: json!({
                "platform": build.platform,
                "app_version": build.version,
                "country": country,
                // PostHog's GeoIP enrichment prefers an event's `$ip` and
                // otherwise falls back to the address the event was sent
                // from. Sent from here that is this server, so left alone
                // every event would arrive stamped with the hosting data
                // centre's geography sitting next to the real `country`
                // above -- two countries per event, one of them meaningless.
                //
                // `$geoip_disable` is the documented switch and is what does
                // the work. The null `$ip` is kept beside it because the two
                // are independent: if a future ingest honoured one and not
                // the other, the failure should be no geography rather than
                // the server's. Neither is a privacy measure -- the address
                // that would be resolved is ours, not a user's -- they are
                // what keeps the chart honest.
                "$geoip_disable": true,
                "$ip": Value::Null,
                // No person profile. Without this, PostHog would build a
                // durable record per distinct id — for ids that are designed
                // to be meaningless tomorrow, and for a product whose privacy
                // policy says it does not keep a profile of anyone.
                "$process_person_profile": false,
            }),
            at: now,
        };
        if self.queue.try_send(event).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped % DROPS_BETWEEN_WARNINGS == 1 {
                tracing::warn!(
                    dropped,
                    "analytics queue is full; dropping reach events. The server is unaffected: either \
                     PostHog is unreachable or /api/capabilities is being flooded."
                );
            }
        }
    }
}

/// One pass of the rotation loop. `false` once the server has dropped its
/// handle, which is how the task ends.
///
/// Rotating *is* asking for `today`'s salt, so this goes through the ordinary
/// write path in [`Analytics::with_salt`] rather than a second one that could
/// drift away from it. The two cannot both rotate for the same day: that
/// function re-checks the date under the write lock.
///
/// They can rotate for *different* days, in one narrow window. A request that
/// read the clock microseconds before midnight and was then descheduled past
/// this task will ask for yesterday, find the day differs, and rotate
/// backwards -- discarding the salt just made, after which the next request
/// rotates forward again. It costs accuracy and never privacy (both salts are
/// fresh, and the rule is that any difference rotates), and it splits one
/// installation into two the way a restart does.
///
/// The upgraded handle is confined to the match arm and nothing is awaited
/// while it is held, so this task never keeps an `Analytics` alive.
fn rotate_once(ticking: &std::sync::Weak<Analytics>, today: NaiveDate) -> bool {
    match ticking.upgrade() {
        Some(analytics) => {
            analytics.with_salt(today, |_| ());
            true
        }
        None => false,
    }
}

/// How long until the next UTC midnight, capped at [`ROTATION_CHECK_INTERVAL`].
///
/// The cap is what makes the rotation loop self-correcting. Sleeping all the
/// way to a midnight computed once means a clock that steps forward parks the
/// task past the rotation it was waiting for. Waking at least hourly means
/// the worst a clock jump can do is delay a rotation by an hour, because the
/// next pass recomputes from the time it actually is.
fn until_next_midnight(now: DateTime<Utc>) -> Duration {
    let midnight = now.date_naive().succ_opt().and_then(|tomorrow| tomorrow.and_hms_opt(0, 0, 0));
    let remaining = midnight
        .and_then(|midnight| (midnight.and_utc() - now).to_std().ok())
        // A date at the end of what chrono can represent has no tomorrow.
        // Falling back to the interval keeps the loop ticking rather than
        // leaving it to decide what to do with an impossible clock.
        .unwrap_or(ROTATION_CHECK_INTERVAL)
        // Never zero: at exactly midnight a zero sleep would spin the loop
        // until the second ticked over.
        .max(Duration::from_secs(1));
    remaining.min(ROTATION_CHECK_INTERVAL)
}

/// Why analytics could not be started.
#[derive(Debug, thiserror::Error)]
pub enum AnalyticsError {
    #[error("posthog host is not usable: {0}")]
    Host(String),
    #[error("could not build an http client for posthog: {0}")]
    Client(String),
}

/// Drain the queue into PostHog until the sender is dropped.
///
/// Errors are logged and the batch is dropped. There is deliberately no retry:
/// a retry queue would hold events across an outage, and what it would be
/// holding is a list of countries and times that this module has just gone to
/// some trouble not to keep.
///
/// The closed-channel arm flushes and stops, but be clear about when that
/// happens: the server is served by a bare `axum::serve` with no graceful
/// shutdown, and the [`Analytics`] handle lives in the router state, so on a
/// SIGTERM the process dies with the sender still alive and this arm is never
/// reached. In production the arm that matters is the timeout, and a restart
/// drops whatever is queued -- up to [`FLUSH_INTERVAL`] of events, plus
/// anything in flight. That is a real hole in the count on every deploy. It
/// is left rather than papered over because the alternative is to hold events
/// somewhere across the restart, and nothing here should outlive the process.
/// The arm stays because it is correct for the tests that do close the
/// channel, and because it is what should run if graceful shutdown is ever
/// added to `main`.
async fn drain(mut receiver: mpsc::Receiver<QueuedEvent>, http: reqwest::Client, host: String, api_key: String) {
    let endpoint = format!("{host}/batch/");
    let mut batch: Vec<QueuedEvent> = Vec::with_capacity(BATCH_SIZE);
    loop {
        let closed = match tokio::time::timeout(FLUSH_INTERVAL, receiver.recv()).await {
            Ok(Some(event)) => {
                batch.push(event);
                // Take whatever else is already waiting without going back to
                // the timer, so a burst leaves as one request.
                while batch.len() < BATCH_SIZE {
                    match receiver.try_recv() {
                        Ok(event) => batch.push(event),
                        Err(_) => break,
                    }
                }
                false
            }
            // The sender is gone: the server is shutting down. Flush and stop.
            Ok(None) => true,
            // Nothing arrived within the interval; send whatever is held.
            Err(_) => false,
        };
        if !batch.is_empty() {
            send(&http, &endpoint, &api_key, &batch).await;
            batch.clear();
        }
        if closed {
            return;
        }
    }
}

/// POST one batch. Failures are logged with the count, never with a payload.
async fn send(http: &reqwest::Client, endpoint: &str, api_key: &str, batch: &[QueuedEvent]) {
    let body = json!({
        "api_key": api_key,
        "batch": batch.iter().map(QueuedEvent::to_payload).collect::<Vec<_>>(),
    });
    match http.post(endpoint).json(&body).send().await {
        Ok(response) if response.status().is_success() => {
            tracing::debug!(events = batch.len(), "sent analytics batch");
        }
        Ok(response) => {
            tracing::warn!(
                events = batch.len(),
                status = %response.status(),
                "posthog refused an analytics batch; dropping it"
            );
        }
        Err(error) => {
            // reqwest's Display includes the URL it was calling, which is the
            // configured host and the `/batch/` path. The key is in the body
            // and never in the URL, so nothing secret is in this line -- but
            // it is worth being explicit that the URL *is* in it, rather than
            // leaving a reader to assume the error has been stripped.
            tracing::warn!(events = batch.len(), %error, "could not reach posthog; dropping a batch");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn a_day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 13).unwrap()
    }

    fn an_address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    /// Needs a runtime because starting one spawns the sending task. Nothing
    /// is sent: the tests below queue nothing, and the unreachable host is
    /// there so that a test which accidentally did would fail to deliver it.
    async fn an_analytics() -> Arc<Analytics> {
        Analytics::start("phc_test".to_string(), "http://127.0.0.1:1").unwrap()
    }

    #[test]
    fn a_build_is_read_out_of_the_apps_user_agent() {
        let build = parse_client_build(Some("klavyn/0.1.3 (macos)"));
        assert_eq!(build.platform, "macos");
        assert_eq!(build.version, "0.1.3");
    }

    /// An app from before the rename still counts as the installation it is.
    /// If this ever fails, every pre-rename build is silently reported as the
    /// unknown build -- a cliff in the chart that looks like people leaving.
    #[test]
    fn a_build_from_before_the_rename_reads_the_same() {
        let old = parse_client_build(Some("credvault/0.3.1 (linux)"));
        let new = parse_client_build(Some("klavyn/0.3.1 (linux)"));
        assert_eq!(old, new);
        assert_eq!(old.platform, "linux");
        assert_eq!(old.version, "0.3.1");
    }

    /// The prefix has to be the start of the header, not merely present in
    /// it, under either spelling.
    #[test]
    fn a_name_that_only_contains_ours_is_not_ours() {
        for user_agent in ["notklavyn/1.0.0 (linux)", "evil credvault/1.0.0 (linux)", "x-klavyn/1.0.0 (linux)"] {
            assert_eq!(parse_client_build(Some(user_agent)), ClientBuild::default(), "{user_agent:?} is not this app");
        }
    }

    #[test]
    fn every_platform_the_app_ships_on_is_recognised() {
        for platform in KNOWN_PLATFORMS {
            let build = parse_client_build(Some(&format!("credvault/1.0.0 ({platform})")));
            assert_eq!(build.platform, platform, "{platform} is a platform this app is built for");
        }
    }

    #[test]
    fn anything_that_is_not_the_app_is_the_unknown_build() {
        // A browser, a probe, an absent header, an empty one, and a client
        // that names itself ours without saying anything else.
        for user_agent in [
            None,
            Some(""),
            Some("curl/8.4.0"),
            Some("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
            Some("credvault/"),
            Some("klavyn/"),
        ] {
            assert_eq!(
                parse_client_build(user_agent),
                ClientBuild::default(),
                "{user_agent:?} should be reported as the unknown build"
            );
        }
    }

    /// The header is attacker-controlled and its parts become property values
    /// in an analytics event. Nothing a client writes may arrive there
    /// verbatim, so a platform outside the list and a version outside the
    /// character set both become constants.
    #[test]
    fn nothing_a_client_invents_reaches_a_property() {
        let hostile = [
            "credvault/0.1.3 (<script>alert(1)</script>)",
            "credvault/\"},\"evil\":\"1 (macos)",
            "credvault/../../etc/passwd (macos)",
            "credvault/0.1.3 (macos\u{0000})",
            "credvault/\u{202e}1.0.0 (linux)",
        ];
        for user_agent in hostile {
            let build = parse_client_build(Some(user_agent));
            assert!(
                KNOWN_PLATFORMS.contains(&build.platform) || build.platform == PLATFORM_UNKNOWN,
                "{user_agent:?} produced the platform {:?}",
                build.platform
            );
            assert!(
                build.version == VERSION_UNKNOWN
                    || build.version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')),
                "{user_agent:?} produced the version {:?}",
                build.version
            );
        }
    }

    /// Our app, without a platform it could name. The version is still ours
    /// and has still been validated, so it is kept: a build number with no
    /// platform beside it is worth more than nothing at all.
    #[test]
    fn our_app_without_a_platform_keeps_its_version() {
        for user_agent in ["credvault/0.1.3", "credvault/0.1.3 ()", "credvault/0.1.3 (plan9)"] {
            let build = parse_client_build(Some(user_agent));
            assert_eq!(build.version, "0.1.3", "{user_agent}");
            assert_eq!(build.platform, PLATFORM_UNKNOWN, "{user_agent}");
        }
    }

    #[test]
    fn an_enormous_user_agent_is_not_parsed_at_all() {
        let huge = format!("credvault/{} (macos)", "9".repeat(MAX_USER_AGENT_LEN));
        assert_eq!(parse_client_build(Some(&huge)), ClientBuild::default());
    }

    #[test]
    fn a_long_but_legal_version_is_kept_and_a_longer_one_is_not() {
        let longest = "9".repeat(MAX_VERSION_LEN);
        assert_eq!(sanitized_version(&longest), longest);
        assert_eq!(sanitized_version(&"9".repeat(MAX_VERSION_LEN + 1)), VERSION_UNKNOWN);
        assert_eq!(sanitized_version(""), VERSION_UNKNOWN);
        assert_eq!(sanitized_version("0.2.0-rc.1+build_7"), "0.2.0-rc.1+build_7");
    }

    #[test]
    fn only_a_two_letter_country_is_believed() {
        assert_eq!(parse_country(Some("GH")).as_deref(), Some("GH"));
        assert_eq!(parse_country(Some("DE")).as_deref(), Some("DE"));
        // Cloudflare's own "could not tell" and "came over Tor", plus the
        // shapes a client sending the header by hand would use.
        for header in [None, Some(""), Some("XX"), Some("T1"), Some("gh"), Some("GHA"), Some("G"), Some("G1")] {
            assert_eq!(parse_country(header), None, "{header:?} is not a country worth recording");
        }
    }

    #[tokio::test]
    async fn one_installation_is_the_same_id_all_day() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let morning = telemetry.anonymous_id(an_address(), &build, a_day());
        let evening = telemetry.anonymous_id(an_address(), &build, a_day());
        assert_eq!(morning, evening, "a day's events must count as one installation");
        assert_eq!(morning.len(), ANONYMOUS_ID_HEX_LEN);
        assert!(morning.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The whole privacy argument for this module rests on this: an id must
    /// not survive the day, so two events a day apart cannot be joined up.
    #[tokio::test]
    async fn the_same_installation_is_a_different_id_tomorrow() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let today = telemetry.anonymous_id(an_address(), &build, a_day());
        let tomorrow = telemetry.anonymous_id(an_address(), &build, a_day().succ_opt().unwrap());
        assert_ne!(today, tomorrow, "an id must not be linkable across days");
    }

    /// The claim the privacy policy makes, and the one the whole design rests
    /// on: once a day has turned over, yesterday's ids cannot be recomputed —
    /// not by PostHog, and not by whoever holds this machine. That is only
    /// true if the salt is *replaced*, not merely mixed with a date. Ask for
    /// an id on day two, which rotates the salt, then ask for day one again:
    /// the same inputs must now give a different answer, because the bytes
    /// that produced the first one no longer exist.
    #[tokio::test]
    async fn yesterdays_ids_cannot_be_recomputed_after_the_day_turns() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let today = telemetry.anonymous_id(an_address(), &build, a_day());
        let _tomorrow = telemetry.anonymous_id(an_address(), &build, a_day().succ_opt().unwrap());
        let today_again = telemetry.anonymous_id(an_address(), &build, a_day());
        assert_ne!(today, today_again, "the salt must be overwritten when the day turns, not just mixed with a date");
    }

    /// The rotation task's own step. Lazy rotation was the gap this closed:
    /// a server quiet from Monday to Friday used to keep Monday's salt live
    /// all week, while the privacy policy said it was replaced each day.
    #[tokio::test]
    async fn the_rotation_step_replaces_the_salt_without_a_request() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let today = telemetry.anonymous_id(an_address(), &build, a_day());

        // No request involved: this is what the timer calls at midnight.
        let ticking = Arc::downgrade(&telemetry);
        assert!(rotate_once(&ticking, a_day().succ_opt().unwrap()), "a live handle keeps the loop running");

        assert_ne!(
            today,
            telemetry.anonymous_id(an_address(), &build, a_day()),
            "the clock alone must be able to retire a day's salt"
        );
    }

    /// The task holds only a `Weak`, so a dropped server ends it rather than
    /// leaving a timer running against a handle nothing else refers to.
    #[tokio::test]
    async fn the_rotation_task_stops_when_the_server_lets_go() {
        let telemetry = an_analytics().await;
        let ticking = Arc::downgrade(&telemetry);
        assert!(rotate_once(&ticking, a_day()));

        drop(telemetry);
        assert!(!rotate_once(&ticking, a_day()), "a dead handle must end the loop");
    }

    /// The flip side: within one day the salt must *not* churn, or the count
    /// would be one installation per request.
    #[tokio::test]
    async fn the_salt_survives_many_requests_on_the_same_day() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let first = telemetry.anonymous_id(an_address(), &build, a_day());
        for _ in 0..50 {
            assert_eq!(telemetry.anonymous_id(an_address(), &build, a_day()), first);
        }
    }

    /// One IPv6 subscriber usually holds a whole /64. Counting addresses
    /// rather than subscribers would let one of them mint installations by
    /// the billion, on a route with no rate limit in front of it.
    #[tokio::test]
    async fn one_ipv6_subscriber_is_one_installation() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let within_one_prefix: Vec<IpAddr> = [1u16, 2, 0xffff]
            .iter()
            .map(|host| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, *host)))
            .collect();
        let ids: std::collections::HashSet<String> =
            within_one_prefix.iter().map(|ip| telemetry.anonymous_id(*ip, &build, a_day())).collect();
        assert_eq!(ids.len(), 1, "a /64 is one subscriber and must count once");

        // A different /64 is a different subscriber and must still count
        // separately, or the folding would have swallowed the signal.
        let elsewhere = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert!(!ids.contains(&telemetry.anonymous_id(elsewhere, &build, a_day())));
    }

    /// `::ffff:203.0.113.7` and `203.0.113.7` are the same machine, and
    /// hashing the text form made them two installations.
    #[tokio::test]
    async fn an_ipv4_mapped_address_is_not_a_second_installation() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let mapped = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7107));
        assert_eq!(
            telemetry.anonymous_id(an_address(), &build, a_day()),
            telemetry.anonymous_id(mapped, &build, a_day())
        );
    }

    /// And on this: two servers, or the same server after a restart, must not
    /// produce an id anyone could line up with the other's.
    #[tokio::test]
    async fn two_processes_do_not_share_an_id_space() {
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let one = an_analytics().await.anonymous_id(an_address(), &build, a_day());
        let other = an_analytics().await.anonymous_id(an_address(), &build, a_day());
        assert_ne!(one, other, "the per-process salt must make these unrelated");
    }

    #[tokio::test]
    async fn different_installations_are_different_ids() {
        let telemetry = an_analytics().await;
        let linux = parse_client_build(Some("credvault/0.1.3 (linux)"));
        let macos = parse_client_build(Some("credvault/0.1.3 (macos)"));
        let upgraded = parse_client_build(Some("credvault/0.1.4 (linux)"));
        let elsewhere = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        let baseline = telemetry.anonymous_id(an_address(), &linux, a_day());
        for (other, why) in [
            (telemetry.anonymous_id(elsewhere, &linux, a_day()), "a different address"),
            (telemetry.anonymous_id(an_address(), &macos, a_day()), "a different platform"),
            (telemetry.anonymous_id(an_address(), &upgraded, a_day()), "a different version"),
        ] {
            assert_ne!(baseline, other, "{why} should count separately");
        }
    }

    /// Fields are length-prefixed so that no two different inputs can hash the
    /// same bytes. Without that, a version ending in a platform's first
    /// characters would collide with the pair split the other way.
    #[tokio::test]
    async fn adjacent_fields_cannot_be_confused_for_one_another() {
        let telemetry = an_analytics().await;
        let one = ClientBuild { platform: "linux", version: "1.0".to_string() };
        let other = ClientBuild { platform: "linux", version: "1".to_string() };
        assert_ne!(
            telemetry.anonymous_id(an_address(), &one, a_day()),
            telemetry.anonymous_id(an_address(), &other, a_day())
        );
    }

    #[test]
    fn an_event_carries_no_address_and_asks_for_no_profile() {
        let event = QueuedEvent {
            name: APP_REACHED_SERVER,
            distinct_id: "abc123".to_string(),
            properties: json!({
                "platform": "macos",
                "app_version": "0.1.3",
                "country": "GH",
                "$geoip_disable": true,
                "$ip": Value::Null,
                "$process_person_profile": false,
            }),
            at: DateTime::parse_from_rfc3339("2026-11-13T09:30:00Z").unwrap().with_timezone(&Utc),
        };
        let payload = event.to_payload();
        assert_eq!(payload["event"], APP_REACHED_SERVER);
        assert_eq!(payload["distinct_id"], "abc123");
        assert_eq!(payload["timestamp"], "2026-11-13T09:30:00.000Z");
        assert_eq!(payload["properties"]["country"], "GH");
        // These are what stop PostHog building a durable record from an id
        // meant to be meaningless tomorrow, and what stop it stamping every
        // event with the hosting data centre's geography.
        assert!(payload["properties"]["$ip"].is_null());
        assert_eq!(payload["properties"]["$geoip_disable"], true);
        assert_eq!(payload["properties"]["$process_person_profile"], false);
    }

    #[test]
    fn a_missing_country_is_sent_as_an_absent_one_not_a_guess() {
        let properties = json!({ "country": Option::<String>::None });
        assert!(properties["country"].is_null(), "no country must not become an empty string or a default");
    }

    #[tokio::test]
    async fn a_host_that_is_not_an_address_stops_the_server_starting() {
        assert!(Analytics::start("phc_test".to_string(), "not a url").is_err());
        // A scheme the client cannot speak is a configuration mistake worth
        // the same stop, rather than a server that silently reports nowhere.
        assert!(Analytics::start("phc_test".to_string(), "ftp://posthog.example").is_err());
        assert!(Analytics::start("phc_test".to_string(), DEFAULT_HOST).is_ok());
    }

    /// A full queue must cost the request nothing. Capture far more than the
    /// queue holds against a host that cannot be reached, and every call must
    /// still return.
    #[tokio::test]
    async fn a_flood_is_dropped_rather_than_made_to_wait() {
        let telemetry = an_analytics().await;
        let build = parse_client_build(Some("credvault/0.1.3 (linux)"));
        for _ in 0..(QUEUE_CAPACITY * 2) {
            telemetry.capture_reach(an_address(), &build, Some("GH".to_string()));
        }
        assert!(telemetry.dropped.load(Ordering::Relaxed) > 0, "the bounded queue should have shed load");
    }

    /// Nothing that formats this type may print the salt, which is the only
    /// thing standing between a stored id and the address it came from.
    ///
    /// Asserting the absence of the word "salt" would pass just as happily
    /// if the bytes were printed under another name, so this looks for the
    /// bytes themselves.
    #[tokio::test]
    async fn the_salt_is_not_printable() {
        let telemetry = an_analytics().await;
        // Seed it, so there is a real secret to leak rather than zeros.
        let _ = telemetry.anonymous_id(an_address(), &ClientBuild::default(), a_day());
        let printed = format!("{telemetry:?}");
        assert!(!printed.contains("salt"), "{printed}");
        let longest_hex_run = printed.split(|c: char| !c.is_ascii_hexdigit()).map(str::len).max().unwrap_or(0);
        assert!(longest_hex_run < 32, "a run of {longest_hex_run} hex characters looks like key material: {printed}");
    }

    #[test]
    fn the_rotation_timer_waits_for_midnight_and_never_longer_than_an_hour() {
        let day = |h, m| NaiveDate::from_ymd_opt(2026, 11, 13).unwrap().and_hms_opt(h, m, 0).unwrap().and_utc();
        // Early in the day the cap is what decides, not midnight.
        assert_eq!(until_next_midnight(day(3, 0)), ROTATION_CHECK_INTERVAL);
        // Inside the last hour it waits exactly as long as is left.
        assert_eq!(until_next_midnight(day(23, 30)), Duration::from_secs(30 * 60));
        // And never zero, which would spin the loop for a second.
        assert!(until_next_midnight(day(23, 59)) >= Duration::from_secs(1));
        assert!(until_next_midnight(day(0, 0)) <= ROTATION_CHECK_INTERVAL);
    }
}
