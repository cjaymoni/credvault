# credvault

A password manager you host yourself, with end-to-end encryption and the
ability to share a single secret with another person.

- **Desktop app** (`apps/desktop`): Tauri 2, runs on macOS, Windows, and Linux.
- **Server** (`crates/server`): Axum + SQLite. Stores only ciphertext.
- **Core** (`crates/core`): the cryptography, shared by both.

## How the security works

The server never sees a password, a username, or a key that could decrypt one.

1. Your account password is stretched with Argon2id into a master key on your
   device. Two sub-keys are derived from it: an *auth hash* that is sent to the
   server as your login credential (the server hashes it again with Argon2
   before storing), and an *encryption key* that protects your private key.
2. Every account has an X25519 key pair. The private key is encrypted with the
   encryption key above and stored on the server, so you can log in from any
   device and recover it.
3. Every secret has its own random AES-256-GCM key. The username, password,
   URL, and notes are encrypted with it. Only the secret's *name* is stored in
   plaintext so lists and invites can show it; the name is authenticated as
   associated data, so the server cannot present one secret's contents under
   another secret's name.
4. That key is wrapped once per person who may read the secret. Your own copy
   is encrypted under a key derived from your master key, so nobody else,
   the server included, can produce one. Everyone else's copy is sealed to
   their X25519 public key. Inviting someone wraps the key for them. Revoking
   someone generates a new key, re-encrypts the secret, and re-wraps it for
   everyone who still has access, so a revoked person cannot read later
   updates even if they kept the old key. Pending invites are cancelled by a
   revoke because they carried the old key. Every rotation bumps a key
   version; a device still holding the old key gets a conflict instead of
   writing under it.

### Sharing and key fingerprints

Public keys come from the server, so a malicious server could hand you its own
key instead of your friend's and read whatever you share. To prevent that, the
app shows a short **fingerprint** of every key:

- Your own fingerprint is in the header after you log in ("Your key: …").
- When you invite someone, the app shows the fingerprint of the key the server
  returned for them. Ask them (by phone, in person, any channel that is not the
  server) to read theirs out, and only confirm if it matches.
- The app remembers keys it has confirmed. If the server later returns a
  different key for the same person, you are warned before anything is
  encrypted to it.

If you skip the comparison and just click confirm, you are trusting the server
operator for that one secret.

### Consequences worth knowing

- If you forget your account password there is no recovery. Nobody can reset it.
- Someone you share with can read that one secret, not your other secrets.
- The server operator can see who shares with whom and the names of secrets,
  but not their contents. The operator cannot alter, relabel or replace a
  secret you own. For a secret shared *with* you the operator could show you
  fabricated contents (your copy of its key is a sealed box anyone can make),
  but cannot learn the real ones, and you cannot write to it, so nothing
  leaks. Secrets created before this release are upgraded to the protected
  form automatically the first time you open the app.
- The auth hash is derived from your email and password only, not from the
  server address. The same email and password therefore produce the same login
  credential on every credvault server, so do not reuse a password across
  servers you do not trust equally.
- The app refuses plain `http://` for anything except `localhost`, so use HTTPS
  (a reverse proxy is fine) for any server that is not on your own machine.
- Anyone with an account can check whether an email has an account on the
  same server (this is what makes inviting by email work). On a server with
  open registration, anyone at all can, because registering a taken email
  returns a conflict; use `--registration-token` to close that off.

## Build

Requires Rust (https://rustup.rs). On Linux, Tauri also needs
`libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, and `librsvg2-dev`.

```sh
cargo test --workspace            # core + server + desktop tests
cargo build --release -p credvault-server
cargo install tauri-cli --version "^2" --locked
cd apps/desktop && cargo tauri build     # produces an installer in target/release/bundle
```

## Run

Start the server (defaults to 127.0.0.1:8787 and `~/.credvault-server`):

```sh
./target/release/credvault-server
./target/release/credvault-server --bind 0.0.0.0:8787 --data-dir /srv/credvault
```

Options (each also settable as an environment variable):

| Flag | Env | Effect |
|---|---|---|
| `--registration-token TOKEN` | `CREDVAULT_REGISTRATION_TOKEN` | Only people who enter this token can create an account. Recommended for any server others can reach. |
| `--closed-registration` | `CREDVAULT_CLOSED_REGISTRATION` | No new accounts at all. |
| `--trust-forwarded-for` | `CREDVAULT_TRUST_FORWARDED_FOR` | Rate-limit by the rightmost `X-Forwarded-For` address. Only behind a reverse proxy that sets that header. |

Login and registration are rate limited per client address (10 logins then
one every 6 s; 5 registrations then one per minute). The data directory is
created with owner-only permissions.

Open the desktop app, enter the server URL, your email, and a password of at
least 8 characters, then click **Create account** (enter the registration
token too if the server requires one). From then on, **Log in**.

To share a secret with someone: they create an account on the same server
first. Then you open the secret, type their email under **Sharing**, click
**Invite**, compare the fingerprint the app shows with the one in their app's
header, and confirm. They see the invite the next time they log in or refresh,
and accept or decline it. You can revoke their access at any time.

Copied passwords are cleared from the clipboard after 30 seconds (unless you
have copied something else since), and a revealed password is hidden again
after 30 seconds.

## Layout

```
crates/core      cryptography and API wire types (32 unit tests)
crates/server    HTTP API and SQLite schema (11 unit + 15 end-to-end tests)
apps/desktop     Tauri app: src/ (Rust commands, 6 unit tests), ui/ (index.html, styles.css, app.js)
```

## iOS simulator

The app is a library crate with a Tauri mobile entry point, so it also builds
for iOS. Prerequisites: Xcode with an iOS simulator runtime, `xcodegen` and
CocoaPods (both from Homebrew), and the Rust targets:

```sh
rustup target add aarch64-apple-ios-sim aarch64-apple-ios
cd apps/desktop && cargo tauri ios init     # once; generates gen/apple
```

`cargo tauri ios dev "iPhone 17"` builds and launches when the simulator
runtime matches the Xcode SDK version. If it only prints "Opening Xcode" (the
runtime is older than the SDK), leave it running and build from a second
terminal; the Xcode build script needs the CLI's options server:

```sh
cd apps/desktop
xcodebuild -project gen/apple/credvault-desktop.xcodeproj -scheme credvault-desktop_iOS \
  -configuration debug -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath /tmp/credvault-ios CODE_SIGNING_ALLOWED=NO build
xcrun simctl install booted /tmp/credvault-ios/Build/Products/debug-iphonesimulator/credvault.app
xcrun simctl launch booted com.credvault.desktop
```

The simulator shares the Mac's network, so `http://127.0.0.1:8787` reaches a
server started on the host. The UI is embedded at build time; rebuild after
changing anything in `ui/`.

## Android emulator

Prerequisites: Android Studio with an SDK, an NDK, a JDK 17, an arm64 AVD,
and the Rust targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
export ANDROID_HOME=~/Library/Android/sdk NDK_HOME=$ANDROID_HOME/ndk/<version> JAVA_HOME=$(/usr/libexec/java_home)
cd apps/desktop && cargo tauri android init     # once; generates gen/android
cargo tauri android dev <avd-name>
```

Inside the emulator `127.0.0.1` is the emulator itself, so forward the port to
the server on the host before logging in; the default server URL then works:

```sh
adb reverse tcp:8787 tcp:8787
```

If a phone is also plugged in, `android dev` can stall on a device prompt
after building. The debug APK is already at
`gen/android/app/build/outputs/apk/arm64/debug/`; install it with
`adb -s <emulator> install -r` and launch it while the CLI is still running
(the debug APK loads the UI from the CLI's dev server).

To rebuild with Gradle directly (`gen/android/gradlew :app:assembleArm64Debug`)
point cargo at the NDK linker first, or the link step falls back to the host
`cc` and fails:

```sh
B=$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$B/aarch64-linux-android24-clang \
       CC_aarch64_linux_android=$B/aarch64-linux-android24-clang AR_aarch64_linux_android=$B/llvm-ar
```

## Development

```sh
cargo run -p credvault-server                  # terminal 1
cd apps/desktop && cargo tauri dev             # terminal 2
cargo fmt --all && cargo clippy --workspace --all-targets
```
