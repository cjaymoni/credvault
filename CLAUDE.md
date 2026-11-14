# klavyn — working notes for Claude

## Cutting a release

This is the procedure for now. Follow it rather than inventing one, and if a
step turns out to be wrong, change this file in the same commit that changes
the practice.

Releases are built **locally** and attached to a release created through the
API. The `release.yml` workflow exists and builds macOS, Windows and Linux on
a tag push, but it is not how releases have actually been cut: v0.2.0 and
v0.3.0 each carry only a `.dmg` and an `.apk`, both built by hand. Do not push
a `vX.Y.Z` tag with `git push` unless the user asks for the full pipeline —
see "What does and does not trigger CI" below.

### 0. If the server side moved, deploy it before publishing anything

Not every release needs this. One that raises `PROTOCOL_VERSION`, renames a
setting, or moves anything in `deploy/` does: the artifacts are what testers
install, and the moment they are published people start running them against
whatever server is live. Migrate and verify the server first — a real sign-in,
not just `/health`, which answers perfectly well from an empty database — and
publish only once it is serving.

The 0.4.0 rename is the worst case of this and the reason the step exists.
Its settings are all renamed, so a server redeployed without its `.env`
rewritten starts with no registration token, and no token means *open to
anyone*.

### 1. Everything is merged to `main` first

Build from `main` after the feature has merged, never from the feature branch.
`git checkout main && git pull`.

### 2. Bump the version

Six files, and nothing else. Any `0.x` version string elsewhere in the tree is
a test fixture and must stay frozen (`crates/server/tests/api.rs` sends a
deliberately fixed `credvault/0.2.0 (linux)` User-Agent -- which since the
rename also keeps the pre-rename spelling exercised, so leave the name alone
as well as the number; `analytics.rs` has a version-parser case).

- `Cargo.toml` — workspace `version`; the crates inherit it with
  `version.workspace = true`, so they cannot drift
- `apps/desktop/tauri.conf.json`
- `apps/desktop/gen/apple/klavyn-desktop_iOS/Info.plist`
- `apps/desktop/gen/apple/project.yml`
- `Cargo.lock` — via `cargo update -w`, never by hand
- `.github/release-notes.md` — see below

Pick the number honestly. A patch is for a fix. New collection, new public API
in `klavyn-server`, or a new public field on a `pub` struct that is not
`#[non_exhaustive]` all require a minor under cargo's 0.x rules — that last one
is a breaking change for anything constructing the struct by literal from
outside the crate. 0.3.0 was a minor for exactly those three reasons.

### 3. Rewrite the release notes

`.github/release-notes.md`, the `## What is new in __TAG__` section.

- **Never hardcode the version in the body.** Only `__TAG__` is substituted, so
  a hardcoded `0.3.0` ships stale on the next patch tag.
- **Carry forward disclosures that are still true.** Replacing the section once
  deleted 0.2.0's warning that project names are stored unencrypted, and
  projects still shipped. Anything that is not per-version belongs in
  `docs/privacy.md`, not here — put it there and leave a pointer.
- **Check the same-release warning against the protocol constants** in
  `crates/core/src/api.rs` (`PROTOCOL_VERSION`, `MIN_SERVER_PROTOCOL`,
  `MIN_CLIENT_PROTOCOL`). Telling people to upgrade a server that does not need
  it wastes their time; the warning near the top and the self-hoster line
  further down must agree.

If `docs/privacy.md` or `docs/terms.md` changed, run `node scripts/build-legal.js`
and commit the regenerated `apps/desktop/ui/legal.js`. The in-app copy is what
users read before signing up, and a stale one is a false statement, not a
formatting slip.

### 4. Build macOS

```sh
cd apps/desktop
cargo tauri build --target universal-apple-darwin --bundles dmg -- --locked
```

Produces `target/universal-apple-darwin/release/bundle/dmg/klavyn_<version>_universal.dmg`.
Confirm it really is universal — `lipo -info target/universal-apple-darwin/release/klavyn-desktop`
must print `x86_64 arm64`.

**If it fails at `bundle_dmg.sh` with `couldn't unmount "diskN" - Resource busy`:**
the app compiled fine and only the packaging failed, leaving a volume mounted.
`hdiutil info` to find it, `hdiutil detach /dev/diskN -force`, delete the
leftover `bundle/macos/rw.*.dmg`, and run the same command again.

### 5. Build and sign Android

```sh
cd apps/desktop
export ANDROID_HOME=$HOME/Library/Android/sdk \
       NDK_HOME=$HOME/Library/Android/sdk/ndk/29.0.14206865 \
       JAVA_HOME=$(/usr/libexec/java_home -v 17)
B=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$B/aarch64-linux-android24-clang \
       CC_aarch64_linux_android=$B/aarch64-linux-android24-clang \
       AR_aarch64_linux_android=$B/llvm-ar
cargo tauri android build --target aarch64 --apk
```

The output is named `app-universal-release-unsigned.apk` but contains only
`arm64-v8a` — check with `unzip -l <apk> | grep lib/`. Name the artifact
`klavyn_<version>_arm64.apk`, which is what the notes promise.

There is **no signing config** in the Android project, so that APK will not
install. Align and sign it with the debug keystore — this is what the notes
mean by "signed with a test key":

```sh
Z=$HOME/Library/Android/sdk/build-tools/37.0.0
"$Z/zipalign" -p -f 4 <unsigned.apk> aligned.apk
"$Z/apksigner" sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --ks-key-alias androiddebugkey --key-pass pass:android \
  --out klavyn_<version>_arm64.apk aligned.apk
"$Z/apksigner" verify --print-certs klavyn_<version>_arm64.apk
```

Verify prints `CN=Android Debug`. Build the **release** APK and sign it, not a
debug build — a debug build carries assertions and different configuration.

### 6. Create the release as a draft, then publish

Substitute the tag yourself, with the same guard CI uses:

```sh
sed "s|__TAG__|v0.3.0|g" .github/release-notes.md > /tmp/notes.md
grep -q __TAG__ /tmp/notes.md && echo "a placeholder survived" && exit 1
gh release create v0.3.0 --draft --target main --title "v0.3.0" \
  --notes-file /tmp/notes.md <dmg> <apk>
```

Check it before publishing — draft state, tag, target, and both asset sizes —
then `gh release edit v0.3.0 --draft=false`.

**Never move a published tag.** If a build is wrong, cut the next patch
version; people may already have the old artifacts.

### What does and does not trigger CI

`release.yml` listens for a `push` of a `v*` tag. Creating a release through
the API (`gh release create`) creates the tag without raising that event, so
**no Windows or Linux installers are built** and the test suite is not re-run
on the tagged commit. That is the current trade: faster, and matching what
past releases actually shipped. If the user wants all platforms, push the tag
with `git push origin vX.Y.Z` instead and let the pipeline create the draft,
then add the Android APK by hand — CI cannot build it.

## Before any commit

`cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `node --test apps/desktop/ui-tests/`, and
`bash deploy/tests/cloudflare-origin.test.sh` (the firewall script's parsing
decides whether the origin is open, and every review pass so far has found a
string-handling bug in it). A commit
hook also requires a code review pass before pushing.

## Names that must never be renamed

The product is moving from credvault to klavyn. Nine byte strings are staying
as they are, permanently, and they are not an oversight:

- `SALT_DOMAIN`, `AUTH_INFO`, `ENC_INFO`, `SELF_WRAP_INFO` — `crates/core/src/kdf.rs`
- `SEALED_BOX_KDF_INFO`, `SEALED_BOX`, `PRIVATE_KEY` — `crates/core/src/identity.rs`
- `SELF_WRAP`, `SECRET_PAYLOAD` — `crates/core/src/secret.rs`

They all read `b"credvault/kdf/..."` or `b"credvault/aead/..."`, so a
`s/credvault/klavyn/` over the tree rewrites every one of them. They are HKDF
info strings and AES-GCM associated data — inputs to the key derivation
itself. Changing one changes every existing user's keys, and because the
server holds only ciphertext and there is no password reset, every vault
written under the old value becomes unreadable by anyone, for good. Backups do
not help: they hold the same ciphertext.

These are format identifiers, not branding. Nobody ever sees them. An old name
in a wire format is normal and costs nothing.

Two tripwires guard them: `derivation_is_pinned_to_known_answers` in `kdf.rs`
covers the first four, and `domain_strings_are_frozen` in `identity.rs` and
`secret.rs` covers the other five. **A failure there is never fixed by pasting
in the new value.** Put the constant back, or follow the versioned migration
path in the WARNING at the top of `kdf.rs` — bump `aead::SEALED_FORMAT` for
anything that feeds a blob, or `api::PROTOCOL_VERSION` and
`api::MIN_CLIENT_PROTOCOL` for `AUTH_INFO` — which is a format migration where
every client re-encrypts, not a rename.

Two more strings were frozen for weaker reasons, and moved with a planned
rollout rather than never:

- The User-Agent. The app now sends `klavyn/<version> (<platform>)`, and the
  server reads both spellings — `CLIENT_NAME_PREFIXES` in
  `crates/server/src/analytics.rs`. The order matters on the way out: a server
  that reads both must be deployed before any app sending the new one reaches
  it, or every one of those installs is counted as the unknown build. Drop
  `credvault/` from that list only once no pre-rename build is still in use;
  the version on each event is what tells you when that is.
- The server hostname. `auth_hash` mixes the canonical server address into
  each user's credential, so moving the app to a new address would lock
  existing accounts out. `PREVIOUS_DEFAULT_SERVERS` in
  `apps/desktop/src/lib.rs` is what carries them across: a sign-in that the
  current binding is refused for retries each superseded default once, and on
  success exchanges it through `POST /account/server-address`.

  Two rules about that list. It is only ever reached for `DEFAULT_SERVER`
  itself -- these are credentials for other hostnames, and sending one to
  whatever address a person typed would hand it exactly the replay the
  binding exists to prevent. And the addresses in it are this app's own past
  defaults, shipped in the binary; a server must never get to name one, or it
  could have a credential minted for someone else's hostname. Empty the list
  once no account can still be on an old binding.

## How the test server is actually deployed

`deploy/` describes two things, and they are not the same. The compose stack
with Caddy is the reference deployment for a fresh VPS. The maintainer's host
does not use it: nginx already on the box terminates TLS with a **Cloudflare
Origin Certificate**, Caddy is never started, and the app publishes only to
`127.0.0.1:8787`. Its files are `deploy/nginx/` and
`deploy/docker-compose.override.yml.example`; the section is "Running behind
an existing nginx".

Three consequences worth holding on to, because each one contradicts a step
in the reference path:

- **Never a bare `docker compose up -d` there.** It would start Caddy, which
  collides with nginx on 80 and 443. Name the service: `up -d --build klavyn`.
- **The records stay proxied.** An origin certificate is trusted only by
  Cloudflare, so a grey-clouded record serves something no browser accepts —
  the opposite of the Let's Encrypt path, which needs grey to issue.
- **`cloudflare-origin.sh` is unnecessary there** *provided both of the
  things that make it unnecessary are actually true*, and they are worth
  checking rather than assuming — getting this wrong leaves the origin
  believing a header anyone can write. nginx restores the real client
  address via `deploy/nginx/cloudflare-realip.conf`, which goes in
  `/etc/nginx/snippets/` and is `include`d from the klavyn server block:
  `klavyn-proxy.conf` forwards `$remote_addr` as `X-Forwarded-For`, so
  without that file it forwards the Cloudflare edge and every client behind
  one edge shares a rate-limit budget. **Never `conf.d/`** — that is `http`
  level, so it would rewrite `$remote_addr` for the other production site on
  that box, and anything there keying `allow`/`deny`/`limit_req` on the
  client address would start accepting an attacker-chosen one. `nginx -t`
  passes either way, and `nginx -T | grep set_real_ip_from` prints the same
  thing from both contexts, so nothing catches it afterwards. And the
  firewall must be narrowed to Cloudflare's ranges — `ufw status` says, and
  a `set_real_ip_from` list that trusts `0.0.0.0/0` trusts whoever reaches
  the box directly. The script refuses to run when it finds a web-port ALLOW
  rule it did not write, application profiles such as `Nginx Full` included.

That host also serves another production site, so `nginx -t` before a reload
is not a formality.

## Claims about privacy are load-bearing

`docs/privacy.md` is shown in the app before sign-up, so a sentence there is a
promise, not documentation. Two releases' worth of review findings were all
the same shape: the prose claimed more than the code delivered. When changing
anything in `crates/server/src/analytics.rs`, re-read the claims in that file,
`docs/privacy.md`, `README.md`, `deploy/README.md` and `deploy/.env.example`
together, and make the code true rather than the sentence vaguer.

## Mobile development

Building and installing on simulators and devices has its own set of
workarounds that are not in this file; see the "iOS simulator" and "Android
emulator" sections of `README.md`.
