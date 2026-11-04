//! In-process per-client token buckets for the unauthenticated endpoints, so a
//! default deployment is safe without a reverse proxy in front of it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;

/// Hard cap on tracked clients. Idle buckets are pruned first; if every bucket
/// is busy, the least recently seen tenth are evicted in one batch, so the
/// O(n) scan runs once per batch of new clients rather than once per request.
const MAX_TRACKED_CLIENTS: usize = 10_000;
const EVICT_BATCH: usize = MAX_TRACKED_CLIENTS / 10;

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// A token bucket per client: `capacity` requests may burst, then one more is
/// allowed every `refill_every`.
pub struct RateLimiter {
    capacity: u32,
    refill_every: Duration,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

/// The unit that is limited. An IPv6 subscriber usually controls an entire
/// /64, so limiting individual addresses would hand them 2^64 free buckets.
pub fn limiter_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        },
    }
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_every: Duration) -> Self {
        assert!(capacity > 0, "rate limiter capacity must be positive");
        Self { capacity, refill_every, buckets: Mutex::new(HashMap::new()) }
    }

    /// Take one token for `ip`, or return how long until one is available.
    pub fn try_acquire(&self, ip: IpAddr) -> Result<(), Duration> {
        self.try_acquire_at(ip, Instant::now())
    }

    /// Number of clients currently tracked (for tests and metrics).
    pub fn tracked(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    fn try_acquire_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let key = limiter_key(ip);
        let capacity = f64::from(self.capacity);
        let mut buckets = self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if buckets.len() >= MAX_TRACKED_CLIENTS && !buckets.contains_key(&key) {
            make_room(&mut buckets, now, capacity, self.refill_every);
        }
        let bucket = buckets.entry(key).or_insert_with(|| Bucket { tokens: capacity, last_refill: now });
        bucket.tokens = refilled(bucket, now, capacity, self.refill_every);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - bucket.tokens;
        Err(self.refill_every.mul_f64(deficit))
    }
}

/// Drop idle (full) buckets; if none are idle, drop the oldest `EVICT_BATCH`.
fn make_room(buckets: &mut HashMap<IpAddr, Bucket>, now: Instant, capacity: f64, refill_every: Duration) {
    buckets.retain(|_, bucket| refilled(bucket, now, capacity, refill_every) < capacity);
    if buckets.len() < MAX_TRACKED_CLIENTS {
        return;
    }
    let mut by_age: Vec<(Instant, IpAddr)> = buckets.iter().map(|(key, bucket)| (bucket.last_refill, *key)).collect();
    let cutoff = EVICT_BATCH.min(by_age.len()) - 1;
    by_age.select_nth_unstable(cutoff);
    for (_, key) in &by_age[..=cutoff] {
        buckets.remove(key);
    }
}

fn refilled(bucket: &Bucket, now: Instant, capacity: f64, refill_every: Duration) -> f64 {
    let elapsed = now.saturating_duration_since(bucket.last_refill);
    let refill = elapsed.as_secs_f64() / refill_every.as_secs_f64();
    (bucket.tokens + refill).min(capacity)
}

/// State for the `limit` middleware: which bucket set to use and whether to
/// believe `X-Forwarded-For` (only when a trusted proxy sets it).
#[derive(Clone)]
pub struct AuthLimit {
    pub limiter: Arc<RateLimiter>,
    pub trust_forwarded_for: bool,
}

/// Resolve the address a request should be limited by.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trust_forwarded_for: bool) -> IpAddr {
    if trust_forwarded_for {
        // Proxies may append a second header line instead of extending the
        // first, so take the last line, then its rightmost entry: that is the
        // one our own proxy wrote. Everything before it came from the client.
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.rsplit(',').next())
            .and_then(|last| last.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    peer.ip()
}

pub async fn limit(
    State(limit): State<AuthLimit>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let ip = client_ip(peer, request.headers(), limit.trust_forwarded_for);
    limit.limiter.try_acquire(ip).map_err(|wait| {
        tracing::warn!(%ip, path = %request.uri().path(), "rate limited");
        ApiError::TooManyRequests { retry_after_secs: wait.as_secs().max(1) }
    })?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn burst_then_refill() {
        let limiter = RateLimiter::new(3, Duration::from_secs(10));
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.try_acquire_at(ip(1), start).is_ok());
        }
        let wait = limiter.try_acquire_at(ip(1), start).unwrap_err();
        assert_eq!(wait, Duration::from_secs(10));

        // Another address has its own bucket.
        assert!(limiter.try_acquire_at(ip(2), start).is_ok());

        // Half a refill period later there is still no whole token.
        assert!(limiter.try_acquire_at(ip(1), start + Duration::from_secs(5)).is_err());
        assert!(limiter.try_acquire_at(ip(1), start + Duration::from_secs(10)).is_ok());
        assert!(limiter.try_acquire_at(ip(1), start + Duration::from_secs(10)).is_err());
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let limiter = RateLimiter::new(2, Duration::from_secs(1));
        let start = Instant::now();
        assert!(limiter.try_acquire_at(ip(1), start).is_ok());
        let later = start + Duration::from_secs(3600);
        assert!(limiter.try_acquire_at(ip(1), later).is_ok());
        assert!(limiter.try_acquire_at(ip(1), later).is_ok());
        assert!(limiter.try_acquire_at(ip(1), later).is_err());
    }

    #[test]
    fn ipv6_addresses_share_one_bucket_per_64() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(limiter.try_acquire_at(a, start).is_ok());
        assert!(limiter.try_acquire_at(b, start).is_ok());
        assert!(limiter.try_acquire_at(a, start).is_err(), "rotating the host half must not reset the budget");
        assert!(limiter.try_acquire_at(other, start).is_ok(), "a different /64 is a different client");
        assert_eq!(limiter.tracked(), 2);

        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(limiter_key(mapped), ip(1));
    }

    #[test]
    fn full_buckets_are_pruned_when_table_is_large() {
        let limiter = RateLimiter::new(1, Duration::from_secs(1));
        let start = Instant::now();
        for i in 0..MAX_TRACKED_CLIENTS {
            let addr = IpAddr::from((i as u32 + 1).to_be_bytes());
            limiter.try_acquire_at(addr, start).unwrap();
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_CLIENTS);
        // Every bucket is full again after one period, so the next new
        // address triggers a prune that empties the table.
        limiter.try_acquire_at(ip(9), start + Duration::from_secs(1)).unwrap();
        assert_eq!(limiter.tracked(), 1);
    }

    #[test]
    fn table_never_exceeds_the_cap_during_a_spray() {
        // Capacity 2 and no time passing: no bucket is ever idle, so pruning
        // frees nothing and the oldest batch must be evicted instead.
        let limiter = RateLimiter::new(2, Duration::from_secs(3600));
        let start = Instant::now();
        for i in 0..(MAX_TRACKED_CLIENTS + 5 * EVICT_BATCH) as u32 {
            let addr = IpAddr::from((i + 1).to_be_bytes());
            limiter.try_acquire_at(addr, start + Duration::from_millis(u64::from(i))).unwrap();
            assert!(limiter.tracked() <= MAX_TRACKED_CLIENTS, "table grew past the cap at insert {i}");
        }
        // The first addresses were the oldest and are gone; a late one survives.
        let early = IpAddr::from(1u32.to_be_bytes());
        let late = IpAddr::from((MAX_TRACKED_CLIENTS as u32 + 5 * EVICT_BATCH as u32).to_be_bytes());
        let buckets = limiter.buckets.lock().unwrap();
        assert!(!buckets.contains_key(&early));
        assert!(buckets.contains_key(&late));
    }

    #[test]
    fn client_ip_honours_forwarded_header_only_when_trusted() {
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 198.51.100.7".parse().unwrap());
        assert_eq!(client_ip(peer, &headers, false), peer.ip());
        assert_eq!(client_ip(peer, &headers, true), "198.51.100.7".parse::<IpAddr>().unwrap());

        // A proxy that adds a second header line instead of appending.
        let mut two_lines = HeaderMap::new();
        two_lines.append("x-forwarded-for", "203.0.113.9".parse().unwrap()); // client-supplied
        two_lines.append("x-forwarded-for", "198.51.100.7".parse().unwrap()); // our proxy
        assert_eq!(client_ip(peer, &two_lines, true), "198.51.100.7".parse::<IpAddr>().unwrap());

        let mut garbage = HeaderMap::new();
        garbage.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(peer, &garbage, true), peer.ip());
        assert_eq!(client_ip(peer, &HeaderMap::new(), true), peer.ip());
    }
}
