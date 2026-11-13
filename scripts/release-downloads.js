// Sends GitHub's release download counts to PostHog.
//
// This is the other half of the reach telemetry, and the halves answer
// different questions. `crates/server/src/analytics.rs` counts installations
// that opened and reached a server, with a country. This counts installer
// files pulled from the releases page, by asset and by release, and GitHub
// reports no country, no referrer, and nothing about who pulled them -- a
// running total per asset is the whole of what that API returns. So:
//
//   downloads here  = copies fetched, including CI, mirrors and repeat pulls
//   reach events    = installations that then ran and found a server
//
// The two must not be added together, and the gap between them is not a
// dropout rate.
//
// GitHub's counts are cumulative, so each run sends the total as it stands
// rather than a delta. In PostHog, graph these with the "latest value" or
// "maximum" aggregation on `download_count`; summing them counts every run.
//
// Run with:
//   GITHUB_REPOSITORY=owner/name \
//   POSTHOG_API_KEY=phc_... \
//   [POSTHOG_HOST=https://eu.i.posthog.com] \
//   [GITHUB_TOKEN=...] \
//   node scripts/release-downloads.js
"use strict";

/// Matches the server's default, and for the same reason: an operator who
/// wants another region says so rather than finding out later.
const DEFAULT_POSTHOG_HOST = "https://eu.i.posthog.com";

/// GitHub pages releases; 100 is its maximum per page.
const RELEASES_PER_PAGE = 100;

/// How many pages are walked before giving up. A project with more than this
/// many releases wants a date window, not a longer loop.
const MAX_RELEASE_PAGES = 10;

/// The event name, matching the server's naming: what was observed, not what
/// it is hoped to mean.
const EVENT = "release_asset_downloaded_total";

/// Events per request to PostHog. The server chunks at 50 for the same
/// reason: one oversized request fails as a whole and loses the entire run,
/// where several small ones lose at most the chunks that actually failed.
const BATCH_SIZE = 200;

/// Ceiling on any one network call. Without it a hung connection stalls the
/// scheduled job until the runner's own limit kills it, hours later, with no
/// error that says what happened.
const REQUEST_TIMEOUT_MS = 30_000;

/// Asset names carry a version and a platform and nothing else, but they come
/// from a release GitHub serves us, so they are length-bounded before being
/// sent on as property values.
const MAX_PROPERTY_LEN = 200;

/// The PostHog address to send to, checked the way the server checks its own.
///
/// A typo in the repository variable would otherwise fail the 04:37 cron as a
/// bare `fetch` TypeError, hours after anybody could connect it to the change
/// that caused it.
function validHost(configured) {
  const host = (configured || DEFAULT_POSTHOG_HOST).trim() || DEFAULT_POSTHOG_HOST;
  let parsed;
  try {
    parsed = new URL(host);
  } catch {
    throw new Error(`POSTHOG_HOST is not a URL: ${JSON.stringify(host)}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`POSTHOG_HOST must be http or https, not ${parsed.protocol}`);
  }
  return host;
}

function required(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`${name} is not set`);
  }
  return value.trim();
}

/// Shorten anything over-long rather than dropping it: a truncated asset name
/// is still recognisable, and a missing one would silently lose a platform
/// from the chart.
function bounded(value) {
  const text = String(value ?? "");
  return text.length <= MAX_PROPERTY_LEN ? text : `${text.slice(0, MAX_PROPERTY_LEN)}…`;
}

/// The platform an installer is for, read off its file extension.
///
/// An allow-list, so an asset nobody anticipated lands in "other" rather than
/// inventing a platform. Checked longest-suffix-first: `.tar.gz` must not be
/// decided by `.gz`, and `.app.tar.gz` must not be decided by `.tar.gz`.
const PLATFORM_BY_SUFFIX = [
  [".dmg", "macos"],
  [".app.tar.gz", "macos"],
  [".msi", "windows"],
  [".exe", "windows"],
  [".appimage", "linux"],
  [".deb", "linux"],
  [".rpm", "linux"],
  [".apk", "android"],
];

function platformOf(assetName) {
  const name = assetName.toLowerCase();
  const match = PLATFORM_BY_SUFFIX.filter(([suffix]) => name.endsWith(suffix)).sort(
    (a, b) => b[0].length - a[0].length,
  )[0];
  return match ? match[1] : "other";
}

async function fetchReleases(repository, token) {
  const headers = {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
    // A generic client name on purpose. GitHub asks automated callers to
    // identify themselves; it does not need to be told whose machine this is.
    "user-agent": "klavyn-release-downloads",
  };
  if (token) {
    headers.authorization = `Bearer ${token}`;
  }

  const releases = [];
  for (let page = 1; page <= MAX_RELEASE_PAGES; page += 1) {
    // Each half escaped separately: owner and name are path segments, so a
    // stray slash or space must not be able to point this somewhere else.
    // GITHUB_REPOSITORY comes from Actions and is well formed today, which is
    // the reason this is cheap rather than the reason to skip it.
    const path = repository.split("/").map(encodeURIComponent).join("/");
    const url = `https://api.github.com/repos/${path}/releases?per_page=${RELEASES_PER_PAGE}&page=${page}`;
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    if (!response.ok) {
      // The body is included because GitHub explains rate limiting and a bad
      // repository name there, and without it this fails as a bare number.
      throw new Error(`GitHub returned ${response.status} for ${repository}: ${await response.text()}`);
    }
    const pageOfReleases = await response.json();
    // GitHub returns an array here; anything else means the endpoint or the
    // response changed, and spreading it would throw a bare TypeError with
    // nothing in it to debug from.
    if (!Array.isArray(pageOfReleases)) {
      throw new Error(`GitHub returned ${typeof pageOfReleases} instead of a list of releases for ${repository}`);
    }
    releases.push(...pageOfReleases);
    if (pageOfReleases.length < RELEASES_PER_PAGE) {
      return releases;
    }
  }
  throw new Error(`more than ${MAX_RELEASE_PAGES * RELEASES_PER_PAGE} releases; this script needs a date window`);
}

/// One event per asset per release.
///
/// `distinct_id` is the asset itself, not a person: PostHog requires the
/// field, and there is no person here to put in it. The person profile is
/// switched off for the same reason the server switches it off -- there is
/// nobody for PostHog to keep a profile of.
function eventsFor(releases) {
  const events = [];
  for (const release of releases) {
    for (const asset of release.assets ?? []) {
      events.push({
        event: EVENT,
        distinct_id: `release-asset/${bounded(asset.name)}`,
        timestamp: new Date().toISOString(),
        properties: {
          release: bounded(release.tag_name),
          prerelease: Boolean(release.prerelease),
          asset: bounded(asset.name),
          platform: platformOf(String(asset.name ?? "")),
          download_count: Number(asset.download_count) || 0,
          released_at: release.published_at ?? null,
          $process_person_profile: false,
          // Sent from a GitHub runner, so without this every nightly event
          // would be stamped with the runner's geography — a chart of where
          // Actions happens to run, sitting next to counts that have no
          // location at all. Same switch the server sends, same reason.
          $geoip_disable: true,
          $ip: null,
        },
      });
    }
  }
  return events;
}

/// Split a list into chunks of at most `size`.
function chunked(items, size) {
  const chunks = [];
  for (let start = 0; start < items.length; start += size) {
    chunks.push(items.slice(start, start + size));
  }
  return chunks;
}

/// Send the events in chunks, and keep going past a chunk that fails.
///
/// Carrying on matters more than it looks. Stopping at the first failure
/// would lose that chunk *and every chunk after it*, which is worse than the
/// single-request version this chunking replaced — the whole argument for
/// chunking is that a failure costs one chunk rather than the run. So
/// failures are collected and thrown at the end, which still fails the job
/// loudly while letting the chunks that would have succeeded succeed.
///
/// Returns the number of events delivered.
async function sendToPosthog(host, apiKey, events) {
  const endpoint = `${host.replace(/\/+$/, "")}/batch/`;
  const chunks = chunked(events, BATCH_SIZE);
  const failures = [];
  let delivered = 0;

  for (const chunk of chunks) {
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: apiKey, batch: chunk }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!response.ok) {
        // The status and PostHog's explanation, never the request body:
        // that holds the API key.
        throw new Error(`PostHog returned ${response.status}: ${await response.text()}`);
      }
      delivered += chunk.length;
    } catch (error) {
      failures.push(`${chunk.length} events: ${error.message}`);
    }
  }

  if (failures.length > 0) {
    throw new Error(
      `${failures.length} of ${chunks.length} batches failed; ` +
        `${delivered} events delivered. ${failures.join("; ")}`,
    );
  }
  return delivered;
}

async function main() {
  const repository = required("GITHUB_REPOSITORY");
  const apiKey = required("POSTHOG_API_KEY");
  const host = validHost(process.env.POSTHOG_HOST);
  const token = process.env.GITHUB_TOKEN?.trim();

  const releases = await fetchReleases(repository, token);
  const events = eventsFor(releases);
  if (events.length === 0) {
    console.log(`no release assets on ${repository}; nothing to send`);
    return;
  }
  const delivered = await sendToPosthog(host, apiKey, events);

  const total = events.reduce((sum, event) => sum + event.properties.download_count, 0);
  console.log(`sent ${delivered} asset totals from ${releases.length} releases (${total} downloads in all)`);
}

// Exported for apps/desktop/ui-tests/release-downloads.test.js -- which lives
// there rather than beside this file because that directory is the one CI
// points `node --test` at; its own header says so.
module.exports = {
  platformOf,
  eventsFor,
  fetchReleases,
  bounded,
  chunked,
  validHost,
  sendToPosthog,
  EVENT,
  BATCH_SIZE,
  DEFAULT_POSTHOG_HOST,
};

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
