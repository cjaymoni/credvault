A pre-release build for testing. Please read the two warnings before you put
anything in it.

**Do not store a password you cannot afford to lose.** The storage formats are
not frozen yet. Each build reads its own formats and refuses the rest rather
than guessing, so the next release can make an existing vault unreadable — and
there is no password recovery, by design: nobody, including whoever runs the
server, can reset your passphrase or decrypt your vault for you. Use throwaway
credentials, or expect to type everything in again.

**The app and the server have to come from the same release.** The app checks
what the server speaks before it sends anything and will tell you plainly if
the two cannot work together.

## Installing

The installers are not code-signed, so each system will question them once.

- **macOS** — open the `.dmg` and drag the app to Applications. The first
  launch is refused. Go to **System Settings → Privacy & Security**, scroll to
  the message naming credvault, and click **Open Anyway**; the app then starts
  after one more confirmation and opens normally from then on. (The old
  right-click → **Open** shortcut no longer works for unsigned apps.) If
  macOS says the app "is damaged and can't be opened", that is the quarantine
  flag rather than a bad download — clear it with
  `xattr -dr com.apple.quarantine /Applications/credvault.app` and try again.
- **Windows** — SmartScreen shows "Windows protected your PC" on the installer.
  Choose **More info**, then **Run anyway**.
- **Linux** — install the `.deb` with `sudo apt install ./credvault_*.deb`, or
  make the `.AppImage` executable (`chmod +x`) and run it.
- **Android** — download the `.apk` and open it. Android will ask you to allow
  installing from this source; the build is signed with a test key, not a
  Play Store one, so it will not update itself and will warn you once. It is
  built for arm64, which covers every current phone but not an x86 emulator.
  The `.apk` is built by hand rather than by the release pipeline, so it
  appears only when someone has built one; a release without it means the
  Android app has not changed.

## Getting an account

During pre-release the Server URL field arrives pre-filled with the
maintainer's test server, so you can create an account without being handed
an address. Leaving it as it is means your account is created there, on a
machine someone else runs. That server currently accepts anyone who can reach
it: no registration token, no invitation. A server that does ask for one shows
the token field already open and marked required, and whoever invited you
sends the token privately. If the app cannot reach the server to ask, it shows
a **Does the server require a registration token?** button instead, because
not every server wants one.

Enter your email and a passphrase of at least 12 characters and press **Create
account**. Or press **Continue with Google**, which opens your browser, hands
the result back to the app, and then asks for a passphrase of your own to
encrypt the vault with. Google is how the server knows who you are; it is
never how your secrets are decrypted, and it never sees that passphrase.

The sign-in screen links to a Terms of Service and a Privacy Policy. Both are
drafts: the app says so above them, and the operator's details in them are
still blank.

The address is only a default: whatever you type replaces it and is
remembered. Running your own server is described in
[deploy/README.md](https://github.com/cjaymoni/credvault/blob/__TAG__/deploy/README.md),
and a server you run has to come from this same release.

To share a secret with someone, both of you need accounts on the same server.
You will also need their key fingerprint, read to you over a channel that is
not the server — the app shows yours in the header after you log in. That step
is what stops a dishonest server from handing you its own key in place of your
friend's.

## What to report

Anything that confused you, anything that looked wrong, and anything that lost
data. Include the platform, the release tag, and what you had just done.
