# credvault — working notes for Claude

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

### 1. Everything is merged to `main` first

Build from `main` after the feature has merged, never from the feature branch.
`git checkout main && git pull`.

### 2. Bump the version

Six files, and nothing else. Any `0.x` version string elsewhere in the tree is
a test fixture and must stay frozen (`crates/server/tests/api.rs` sends a
deliberately fixed `credvault/0.2.0 (linux)` User-Agent; `analytics.rs` has a
version-parser case).

- `Cargo.toml` — workspace `version`; the crates inherit it with
  `version.workspace = true`, so they cannot drift
- `apps/desktop/tauri.conf.json`
- `apps/desktop/gen/apple/credvault-desktop_iOS/Info.plist`
- `apps/desktop/gen/apple/project.yml`
- `Cargo.lock` — via `cargo update -w`, never by hand
- `.github/release-notes.md` — see below

Pick the number honestly. A patch is for a fix. New collection, new public API
in `credvault-server`, or a new public field on a `pub` struct that is not
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

Produces `target/universal-apple-darwin/release/bundle/dmg/credvault_<version>_universal.dmg`.
Confirm it really is universal — `lipo -info target/universal-apple-darwin/release/credvault-desktop`
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
`credvault_<version>_arm64.apk`, which is what the notes promise.

There is **no signing config** in the Android project, so that APK will not
install. Align and sign it with the debug keystore — this is what the notes
mean by "signed with a test key":

```sh
Z=$HOME/Library/Android/sdk/build-tools/37.0.0
"$Z/zipalign" -p -f 4 <unsigned.apk> aligned.apk
"$Z/apksigner" sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --ks-key-alias androiddebugkey --key-pass pass:android \
  --out credvault_<version>_arm64.apk aligned.apk
"$Z/apksigner" verify --print-certs credvault_<version>_arm64.apk
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
`cargo test --workspace`, and `node --test apps/desktop/ui-tests/`. A commit
hook also requires a code review pass before pushing.

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
