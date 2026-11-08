# credvault

A password manager you host yourself, with end-to-end encryption and the
ability to share a single secret with another person.

- **Desktop app** (`apps/desktop`): Tauri 2, runs on macOS, Windows, and Linux.
- **Server** (`crates/server`): Axum + SQLite. Stores only ciphertext.
- **Core** (`crates/core`): the cryptography, shared by both.

> **Pre-release.** Formats are not frozen and nothing is migrated between
> builds. Run a client and a server built from the same commit, against a
> database that commit created. The server holds only ciphertext, so it cannot
> rewrite a vault into a new format on anyone's behalf.

## How the security works

The server never sees a password, a username, or a key that could decrypt one.

1. Your account password is stretched with Argon2id into a master key on your
   device. Two sub-keys are derived from it: an *auth hash* that is sent to the
   server as your login credential (the server hashes it again with Argon2
   before storing), and an *encryption key* that protects your private key.
   The auth hash is bound to the server's address, so the same email and
   password produce a different credential on every server and one operator
   cannot replay what its users send to it. The encryption key is deliberately
   not bound that way: it protects data at rest and must keep working wherever
   the data is.
2. Every account has an X25519 key pair. The private key is encrypted with the
   encryption key above and stored on the server, so you can log in from any
   device and recover it.
3. Every secret has its own random AES-256-GCM key. The username, password,
   URL, notes, and any extra fields you add are encrypted with it, as one
   blob, so the server cannot even tell which of them a secret has. Only the
   secret's *name* is stored in plaintext so lists and invites can show it;
   the name is authenticated as associated data, so the server cannot present
   one secret's contents under another secret's name.
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
- To invite someone the first time, you enter their fingerprint along with
  their email. Ask them (by phone, in person, any channel that is not the
  server) to read it out. The server answers the lookup only if the
  fingerprint matches the key it holds, so you never encrypt to a key you were
  not already expecting.
- The app remembers keys it has confirmed, so sharing with the same person
  again needs no typing. If the server later offers a different key for them,
  the lookup fails and you are told to get their current fingerprint directly
  rather than being shown a key to wave through.

Because the fingerprint is required up front, the server also cannot be used
to find out who has an account: a wrong fingerprint, a wrong address and an
address nobody has registered all give the same answer.

### Sign in with Google (optional)

Off unless the operator sets `CREDVAULT_GOOGLE_CLIENT_ID` and
`CREDVAULT_GOOGLE_CLIENT_SECRET`; clients ask the server what it offers and
only show the button where it works.

Google establishes *who you are*. It cannot produce key material, so it
replaces the login credential and nothing else: after signing in you still
enter your passphrase, and the master key is still stretched from it with
Argon2id on your device. The server stores no password for such an account.

- The address Google vouches for becomes the account email, and therefore the
  key-derivation salt. It is recorded once and never updated afterwards: if
  Google later changes your address, the account is still found by Google's
  immutable subject id, and the salt stays as it was. Changing it would make
  every secret in the vault undecryptable.
- An address that already has a password account is never adopted
  automatically. Whoever controls that Google address today could otherwise
  claim an account created by whoever held it before. Linking starts from
  inside a signed-in session instead ("Link Google" in the account panel).
- Linking asks for your passphrase, and so does removing a link. A linked
  Google account signs in on its own and survives both a passphrase change and
  signing out everywhere, so an unlocked app or a stolen session token is not
  enough to add one. The account panel names the address that can sign in, and
  re-reads it from the server each time you open it, so a link added from
  somewhere else shows up. Removing one also signs out every device, including
  the ones that link had signed in: a token does not record where it came
  from, so the only way to be sure none of its sessions survive is to end them
  all. You stay signed in where you asked for the removal. An account created
  *through* Google cannot remove its link: it is the only thing that opens
  that account.
- "Sign out other devices" in the account panel ends every session for the
  account except the one you are using, and asks for nothing but the button.
  Both halves are deliberate. It is the move to make first if you think someone
  else is signed in as you: every other per-account limit can be used up by
  whoever is already signed in, and this one is limited by where the request
  comes from rather than by whose account it is, so it still works when the
  rest are refusing. And you stay signed in here, so you can go
  straight on to remove a Google sign-in they added — if this signed you out
  too, you would be sitting through a sign-in while they came back. To sign out
  this device as well, use "Log out" afterwards.
- A first sign-in still needs the server's registration token, if it has one.
  A verified Google address is not by itself permission to have an account on
  someone else's server.
- The sign-in page opens in your system browser, not in the app's window, so
  you can see the URL you are typing a Google password into. The app builds
  that address itself, from Google's endpoint held as a constant in the app
  and the opaque values the server returns, so the page you land on and the
  permissions it asks for are not the server's to choose. The one thing still
  the server's is the OAuth client it is registered as with Google. The app
  listens on a loopback port for the redirect and nothing else.
- The consent screen names the app the server is registered as with Google.
  That name comes from whoever runs the server, so on a server you do not
  trust it can read as anything; what it can ask for is still only your
  address.
- The client secret stays on the server, which performs the code exchange, so
  it is never shipped inside the app.

**What it costs.** Someone who takes over your Google account can reach the
server as you: they see the names of your secrets, who you share with, and the
encrypted blobs, and they can delete them. They cannot read any secret, because
the passphrase never leaves your device and Google never had it. Weigh that
against the convenience before enabling it.

#### Setting it up

1. In the Google Cloud console, create an OAuth client of type **Desktop app**.
   That type is required: the app listens on whatever loopback port the
   operating system gives it, and other client types only accept redirect URIs
   registered in advance.
2. Put the client id and secret in the server's environment:

   ```sh
   CREDVAULT_GOOGLE_CLIENT_ID=....apps.googleusercontent.com
   CREDVAULT_GOOGLE_CLIENT_SECRET=...
   ```

3. Restart the server. `GET /api/capabilities` reports `google_sign_in: true`
   once it is on.

### Consequences worth knowing

- If you forget your account password there is no recovery. Nobody can reset
  it. This is true of a Google account here too: Google can let you back into
  the server, not into the vault. You can *change* it while you still know it
  — the app re-wraps every key under the new one in a single step, and signs
  out every other device — but nothing can recover one you have lost.
- Someone you share with can read that one secret, not your other secrets.
- Changing your passphrase needs the old one. For an account created through
  Google there is nothing the server can check, so a stolen session can replace
  the stored keys and make the vault unopenable. A stolen session can already
  delete every secret, so this adds no reach — but it fails as "wrong
  passphrase" rather than as anything obviously destructive. Sign out of
  devices you do not recognise.
- The server operator can see who shares with whom and the names of secrets,
  but not their contents. The operator cannot alter, relabel or replace a
  secret you own. For a secret shared *with* you the operator could show you
  fabricated contents (your copy of its key is a sealed box anyone can make),
  but cannot learn the real ones, and you cannot write to it, so nothing
  leaks.
- Your login credential is tied to the server address you type. Moving a
  server to a new domain therefore invalidates every login on it: the vaults
  are intact and still decrypt, but accounts have to be created again at the
  new address. Pick the address before inviting people, and keep it.
- The app refuses plain `http://` for anything except `localhost`, so use HTTPS
  (a reverse proxy is fine) for any server that is not on your own machine.
- Anyone with an account can check whether an email has an account on the
  same server (this is what makes inviting by email work). On a server with
  open registration, anyone at all can, because registering a taken email
  returns a conflict; use `--registration-token` to close that off.

### Versions

Three numbers describe what a given app and server speak, and each sits where
something can read it and act on it.

**The protocol**, at `GET /health`. Unauthenticated, and it carries these two
numbers and nothing else — not the build version, which would only tell a
passer-by which advisories to look up.

```json
{ "status": "ok", "protocol": 3, "min_client_protocol": 1 }
```

`protocol` is what the server speaks; `min_client_protocol` is the oldest
client it serves. The app reads both before it derives a key or sends a
credential, and stops with a plain message when the two cannot work together.
A server ahead of the app works normally for everything the app's protocol
covers.

Protocol 3 moved the Google sign-in URL. The server used to compose the address
the browser opens and the app checked it; now the server sends only the parts
the app cannot know, and the app builds the address from its own constants. The
page the browser goes to, and the permissions it asks for, are no longer
anything a server can choose. Protocol 2 added the passphrase proof on linking,
the unlink route, and the replacement session that signing out other devices
hands back.

This app will not talk to a server older than protocol 3. A protocol-2 server
answers the sign-in request in the old shape and the app cannot build an address
from it; a protocol-1 server would also accept a link request, ignore the proof,
and answer in a shape the app reads as failure — leaving a Google sign-in on the
account that the app cannot show you and that server cannot remove.

**Upgrading to protocol 3.** The sentence above about a newer server working
normally has one exception, and it decides the order to update in. An app older
than protocol 3 connects to a protocol-3 server, unlocks the vault and works
throughout — until someone presses "Continue with Google", where it looks for
an authorization address the server no longer sends and fails without a useful
message. For an account that has a passphrase, that is an annoyance until the
app is updated. For an account created *through* Google, whose link is the only
thing that opens it, it is no way in at all.

There is no order that avoids that. Updating those apps first does not help
and makes it worse: a protocol-3 app refuses a protocol-2 server outright, at
the check it runs before any credential is sent, so the people on that device
lose passphrase sign-in as well and gain nothing — they could not sign in with
Google either way. A Google-created account cannot be given a passphrase in
advance to escape through: the passphrase-change route refuses those accounts
outright, because they have no password to change and no second route sets
one.

So: if every account on the server signs in with a passphrase, update the
server first and the apps at your leisure. If any account signs in only with
Google, move the server and those apps together and expect a window between
the two. Staging the app update on those devices beforehand shortens the
window; nothing removes it.

**The encryption scheme**, on every encrypted blob — your private key, each
secret's key, each secret's contents. It covers the key derivation behind the
blob, the cipher, and how the associated data is built. The number is in the
clear, so a reader tells a scheme it cannot run from a wrong passphrase before
it tries, and it is authenticated, so it cannot be edited and a build that
reads two schemes cannot be walked back to the weaker one. A correct passphrase
meeting an unfamiliar scheme is told exactly that, rather than being told the
password was wrong.

**The field layout**, inside each secret's ciphertext, for the shape of the
fields themselves. A build that meets a secret written under a higher number
refuses to open it instead of reading the parts it recognises — a client that
dropped a field it did not know and then saved the secret back would destroy
data it never showed you.

All three are gates, not shims: each build reads its own formats and refuses
the rest, loudly and by name.

## Build

Requires Rust (https://rustup.rs). On Linux, Tauri also needs
`libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, and `librsvg2-dev`.

```sh
cargo test --workspace            # core + server + desktop tests
node --test apps/desktop/ui-tests/   # the editor logic in apps/desktop/ui/fields.js
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
least 12 characters, then click **Create account** (enter the registration
token too if the server requires one). From then on, **Log in**.

To share a secret with someone: they create an account on the same server
first. Then you open the secret and, under **Sharing**, type their email and
the fingerprint from their app's header, which they read out to you over some
channel other than the server. Click **Invite** and confirm. Sharing with the
same person later needs only their email, because the app has pinned their
key. They see the invite the next time they log in or refresh, and accept or
decline it. You can revoke their access at any time.

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
