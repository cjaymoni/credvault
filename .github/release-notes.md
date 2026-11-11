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

## Getting an account

You need the address of a credvault server and, if the person running it has
closed registration, the registration token they will give you. Enter the
server address, your email, and a passphrase of at least 12 characters, then
**Create account**.

No server is attached to this release; it is built from the same source, and
running one is described in
[deploy/README.md](https://github.com/cjaymoni/credvault/blob/__TAG__/deploy/README.md).
Remember that it has to come from this same release.

To share a secret with someone, both of you need accounts on the same server.
You will also need their key fingerprint, read to you over a channel that is
not the server — the app shows yours in the header after you log in. That step
is what stops a dishonest server from handing you its own key in place of your
friend's.

## What to report

Anything that confused you, anything that looked wrong, and anything that lost
data. Include the platform, the release tag, and what you had just done.
