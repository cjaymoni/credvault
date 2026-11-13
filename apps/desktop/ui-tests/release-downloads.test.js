// Tests for scripts/release-downloads.js, which sends GitHub's per-asset
// download totals to PostHog.
//
// It lives here rather than beside the script because this directory is the
// one `node --test` is pointed at in CI (.github/workflows/ci.yml), the same
// reason legal.test.js reaches back into scripts/ for its subject.
//
// Run with: node --test apps/desktop/ui-tests/
const test = require("node:test");
const assert = require("node:assert");
const {
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
} = require("../../../scripts/release-downloads.js");

/// A release in the shape GitHub's API returns, cut down to the fields the
/// script reads.
function aRelease(overrides = {}) {
  return {
    tag_name: "v0.1.3",
    prerelease: false,
    published_at: "2026-11-12T10:00:00Z",
    assets: [{ name: "credvault_0.1.3_aarch64.dmg", download_count: 42 }],
    ...overrides,
  };
}

test("each installer is attributed to the platform it installs on", () => {
  const expected = {
    "credvault_0.1.3_aarch64.dmg": "macos",
    "credvault.app.tar.gz": "macos",
    "credvault_0.1.3_x64_en-US.msi": "windows",
    "credvault_0.1.3_x64-setup.exe": "windows",
    "credvault_0.1.3_amd64.AppImage": "linux",
    "credvault_0.1.3_amd64.deb": "linux",
    "credvault-0.1.3-1.x86_64.rpm": "linux",
    "credvault_0.1.3.apk": "android",
  };
  for (const [asset, platform] of Object.entries(expected)) {
    assert.equal(platformOf(asset), platform, asset);
  }
});

// `.app.tar.gz` also ends in `.tar.gz`, and `.tar.gz` also ends in `.gz`. The
// longest suffix has to win, or a macOS bundle is filed under whatever the
// shorter rule says.
test("the most specific extension decides, not the shortest", () => {
  assert.equal(platformOf("credvault.app.tar.gz"), "macos");
});

test("an asset nobody anticipated is not given an invented platform", () => {
  for (const asset of ["latest.json", "credvault-0.1.3.sha256", "SOURCE.tar.gz", "", "credvault"]) {
    assert.equal(platformOf(asset), "other", JSON.stringify(asset));
  }
});

test("one event per asset, carrying the release it belongs to", () => {
  const events = eventsFor([
    aRelease(),
    aRelease({
      tag_name: "v0.1.4-rc.1",
      prerelease: true,
      assets: [
        { name: "credvault_0.1.4_x64_en-US.msi", download_count: 7 },
        { name: "credvault_0.1.4_amd64.deb", download_count: 3 },
      ],
    }),
  ]);

  assert.equal(events.length, 3);
  assert.ok(events.every((event) => event.event === EVENT));

  const windows = events.find((event) => event.properties.platform === "windows");
  assert.equal(windows.properties.release, "v0.1.4-rc.1");
  assert.equal(windows.properties.prerelease, true);
  assert.equal(windows.properties.download_count, 7);
});

// Nobody downloaded it is a fact, and a release whose assets are all at zero
// must still appear rather than vanishing from the chart.
test("a release nobody has downloaded still reports zero", () => {
  const events = eventsFor([aRelease({ assets: [{ name: "credvault_0.1.3_amd64.deb", download_count: 0 }] })]);
  assert.equal(events.length, 1);
  assert.equal(events[0].properties.download_count, 0);
});

test("a release with no assets contributes nothing rather than failing", () => {
  assert.deepEqual(eventsFor([aRelease({ assets: [] })]), []);
  assert.deepEqual(eventsFor([aRelease({ assets: undefined })]), []);
  assert.deepEqual(eventsFor([]), []);
});

// A count GitHub omits, or returns as something other than a number, must not
// become NaN: PostHog would store it as null and the series would break where
// nothing was actually wrong.
test("a missing or unusable download count reads as zero", () => {
  for (const count of [undefined, null, "many", NaN, {}]) {
    const events = eventsFor([aRelease({ assets: [{ name: "credvault.deb", download_count: count }] })]);
    assert.equal(events[0].properties.download_count, 0, String(count));
  }
});

// These values come from a release served to us, so they are bounded before
// becoming property values, the same way the server bounds a User-Agent.
test("an absurd asset or tag name is shortened rather than sent whole", () => {
  const huge = "x".repeat(5000);
  const events = eventsFor([aRelease({ tag_name: huge, assets: [{ name: huge, download_count: 1 }] })]);
  assert.ok(events[0].properties.asset.length < 250, events[0].properties.asset.length);
  assert.ok(events[0].properties.release.length < 250);
  assert.equal(bounded("short"), "short");
});

// There is no person here. The distinct id names the asset, and the profile
// is switched off for the same reason the server switches it off.
test("no event asks PostHog to keep a profile of anybody", () => {
  const [event] = eventsFor([aRelease()]);
  assert.equal(event.properties.$process_person_profile, false);
  assert.ok(event.distinct_id.startsWith("release-asset/"));
});

// These run on a GitHub runner. Without them every nightly event would be
// stamped with the runner's geography, sitting beside download counts that
// have no location at all.
test("no event lets PostHog geolocate the runner it was sent from", () => {
  const [event] = eventsFor([aRelease()]);
  assert.equal(event.properties.$geoip_disable, true);
  assert.equal(event.properties.$ip, null);
});

test("events are split into chunks no bigger than the batch size", () => {
  const events = Array.from({ length: BATCH_SIZE * 2 + 1 }, (_, index) => index);
  const chunks = chunked(events, BATCH_SIZE);
  assert.equal(chunks.length, 3);
  assert.ok(chunks.every((chunk) => chunk.length <= BATCH_SIZE));
  // Nothing dropped and nothing duplicated.
  assert.deepEqual(chunks.flat(), events);
});

test("chunking an empty list sends nothing rather than one empty request", () => {
  assert.deepEqual(chunked([], BATCH_SIZE), []);
});

// A typo in the repository variable should fail where somebody is reading,
// not at 04:37 as a bare fetch error.
test("an unusable PostHog host is refused before anything is sent", () => {
  assert.equal(validHost(undefined), DEFAULT_POSTHOG_HOST);
  assert.equal(validHost("   "), DEFAULT_POSTHOG_HOST);
  assert.equal(validHost("https://eu.i.posthog.com"), "https://eu.i.posthog.com");
  assert.throws(() => validHost("eu.i.posthog.com"), /not a URL/);
  assert.throws(() => validHost("ftp://posthog.example"), /http or https/);
});

// ----- sending ---------------------------------------------------------------
//
// The chunking loop exists so that one bad batch costs one batch. That claim
// is made in the README, in the commit and in the module comment, and it runs
// unattended from a 04:37 cron where nobody sees it fail — so it is asserted
// here rather than assumed.

const A_HOST = "https://eu.i.posthog.com";
const A_KEY = "phc_only_a_test_value";

/// Enough events to make exactly `count` chunks.
function eventsForChunks(count) {
  return Array.from({ length: BATCH_SIZE * count }, (_, index) => ({ event: "test", index }));
}

/// Stand in for `fetch`, answering each call from `outcomes` in order and
/// recording what it was asked to send.
function fetchReturning(outcomes) {
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    const outcome = outcomes[calls.length - 1];
    if (outcome instanceof Error) {
      throw outcome;
    }
    return outcome;
  };
  return { fetch, calls };
}

const ok = { ok: true, status: 200, text: async () => "" };
const tooBig = { ok: false, status: 413, text: async () => "payload too large" };

test("every chunk is sent, and the delivered count is all of them", async (t) => {
  const { fetch, calls } = fetchReturning([ok, ok, ok]);
  t.mock.method(globalThis, "fetch", fetch);

  const delivered = await sendToPosthog(A_HOST, A_KEY, eventsForChunks(3));

  assert.equal(calls.length, 3);
  assert.equal(delivered, BATCH_SIZE * 3);
  assert.ok(calls.every((call) => call.url === `${A_HOST}/batch/`));
  assert.ok(calls.every((call) => call.body.batch.length === BATCH_SIZE));
});

// The whole point of chunking. Stopping at the first failure would lose that
// chunk and every chunk after it, which is worse than one big request.
test("a failed chunk does not abandon the chunks after it", async (t) => {
  const { fetch, calls } = fetchReturning([ok, tooBig, ok]);
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(
    () => sendToPosthog(A_HOST, A_KEY, eventsForChunks(3)),
    (error) => {
      assert.match(error.message, /1 of 3 batches failed/);
      // Only what actually landed is counted as delivered.
      assert.match(error.message, new RegExp(`${BATCH_SIZE * 2} events delivered`));
      assert.match(error.message, /413/);
      return true;
    },
  );
  assert.equal(calls.length, 3, "all three chunks must be attempted");
});

test("a connection that throws is a failed chunk, not a crashed run", async (t) => {
  const { fetch, calls } = fetchReturning([new Error("socket hang up"), ok]);
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(() => sendToPosthog(A_HOST, A_KEY, eventsForChunks(2)), /1 of 2 batches failed/);
  assert.equal(calls.length, 2);
});

// The failure summary is what lands in the Actions log, which is a place
// people paste from.
test("a failure report never quotes the API key", async (t) => {
  const { fetch } = fetchReturning([tooBig]);
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(
    () => sendToPosthog(A_HOST, A_KEY, eventsForChunks(1)),
    (error) => {
      assert.ok(!error.message.includes(A_KEY), error.message);
      return true;
    },
  );
});

test("nothing to send makes no request at all", async (t) => {
  const { fetch, calls } = fetchReturning([]);
  t.mock.method(globalThis, "fetch", fetch);

  assert.equal(await sendToPosthog(A_HOST, A_KEY, []), 0);
  assert.equal(calls.length, 0);
});

// ----- reading the releases --------------------------------------------------
//
// Every failure here is loud — it throws and fails the job — which is why it
// is less dangerous than a half-delivered send. It is still the other place
// this script branches, and the page-walking is easy to get subtly wrong.

const A_REPO = "cjaymoni/credvault";

/// `RELEASES_PER_PAGE` is not exported; the script's page size is 100, and a
/// short page is what tells it to stop.
const PAGE_SIZE = 100;

function aPageOf(count, tag = "v0.1.0") {
  return Array.from({ length: count }, () => aRelease({ tag_name: tag }));
}

function githubReturning(outcomes) {
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({ url, options });
    const outcome = outcomes[calls.length - 1];
    if (outcome instanceof Error) {
      throw outcome;
    }
    return outcome;
  };
  return { fetch, calls };
}

const page = (body) => ({ ok: true, status: 200, json: async () => body });

test("paging stops on the first short page", async (t) => {
  const { fetch, calls } = githubReturning([page(aPageOf(PAGE_SIZE)), page(aPageOf(PAGE_SIZE)), page(aPageOf(7))]);
  t.mock.method(globalThis, "fetch", fetch);

  const releases = await fetchReleases(A_REPO, undefined);

  assert.equal(releases.length, PAGE_SIZE * 2 + 7);
  assert.equal(calls.length, 3, "a short page means there is no next one");
  assert.match(calls[2].url, /page=3/);
});

test("a single full page that is also the last one still terminates", async (t) => {
  // Every page full, forever: the ceiling is what stops this, and it must
  // stop rather than paging until the runner gives up.
  const { fetch, calls } = githubReturning(Array.from({ length: 20 }, () => page(aPageOf(PAGE_SIZE))));
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(() => fetchReleases(A_REPO, undefined), /needs a date window/);
  assert.ok(calls.length <= 10, `walked ${calls.length} pages before giving up`);
});

test("a repository name is escaped rather than pasted into the path", async (t) => {
  const { fetch, calls } = githubReturning([page([])]);
  t.mock.method(globalThis, "fetch", fetch);

  await fetchReleases("owner/name with spaces", undefined);
  assert.match(calls[0].url, /owner\/name%20with%20spaces\/releases/);
});

test("a token is sent when there is one, and the call works without one", async (t) => {
  const { fetch, calls } = githubReturning([page([]), page([])]);
  t.mock.method(globalThis, "fetch", fetch);

  await fetchReleases(A_REPO, "ghs_token");
  assert.equal(calls[0].options.headers.authorization, "Bearer ghs_token");

  await fetchReleases(A_REPO, undefined);
  assert.equal(calls[1].options.headers.authorization, undefined);
});

// GitHub answers an unknown repository with an object, not a list. Spreading
// that would throw a bare TypeError with nothing in it to debug from.
test("an answer that is not a list of releases says so", async (t) => {
  const { fetch } = githubReturning([page({ message: "Not Found" })]);
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(() => fetchReleases(A_REPO, undefined), /instead of a list of releases/);
});

test("an error from GitHub carries its explanation, not just a number", async (t) => {
  const { fetch } = githubReturning([{ ok: false, status: 403, text: async () => "API rate limit exceeded" }]);
  t.mock.method(globalThis, "fetch", fetch);

  await assert.rejects(() => fetchReleases(A_REPO, undefined), /403.*rate limit/s);
});
