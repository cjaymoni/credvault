A pre-release build for testing. Please read the two warnings before you put
anything in it.

**Do not store a password you cannot afford to lose.** The storage formats are
not frozen yet. Each build reads its own formats and refuses the rest rather
than guessing, so the next release can make an existing vault unreadable — and
there is no password recovery, by design: nobody, including whoever runs the
server, can reset your passphrase or decrypt your vault for you. Use throwaway
credentials, or expect to type everything in again.

**The app checks the server before it sends anything, and will refuse one
that is too old.** This release does not raise that minimum: a __TAG__ app
works against a 0.2.0 server. Anything older than 0.2.0 is refused, and
refusing happens before any credential is sent, so the vault does not open at
all rather than opening without the new features. If you run your own server
and are coming from 0.1.x, **upgrade the server first, then the app**.

## What is new in __TAG__

**credvault is now klavyn.** Same app, same vault, same people behind it — the
name changed and nothing else did. The window says klavyn, the installers are
named `klavyn_*` instead of `credvault_*`, and the maintainer's test server
has moved to `vault.klavyn.com`.

**If you are testing against the maintainer's server, there is nothing to do.**
Sign in exactly as before, with the same address and the same passphrase. Your
sign-in credential is tied to the server's name — that is deliberate, so a
credential given to one server is useless at another — which means the move
would normally have locked you out. The app carries the account across on your
next sign-in, by itself, and you will not see it happen. Your secrets are not
re-encrypted and nothing about them changes: the keys that open your vault
were never tied to the server's name in the first place.

On macOS this arrives as a separate app rather than an update, because the
name is part of how the system identifies it. Install it and drag the old one
to the bin; nothing of yours lives in it. On Android you will have to uninstall
the old one first, for the same reason.

**If you run your own server, this upgrade has steps.** Every setting is
renamed from `CREDVAULT_*` to `KLAVYN_*`, the database file and the Docker
volumes are renamed with it, and a server started without its settings will
not find them. Read **Renaming from credvault** in
[deploy/README.md](https://github.com/cjaymoni/klavyn/blob/__TAG__/deploy/README.md)
before you upgrade, and take a backup first. Nothing is lost if you follow it;
the names simply have to be carried across deliberately. Your own server's
address has not changed, so your users are unaffected by the part above.

The protocol moved for one new route, which exists so an account can follow a
server that changes address. This release does not raise the minimum server
version — see the warning at the top — so an app from this release still
works against an older server; it just cannot do that one thing there.

**Sharing is quicker, and the phone caught up with the desktop.** You can
invite several people to one secret in one go: type or paste their addresses,
compare everyone's key fingerprint side by side on one screen, and send the
invites together. Each person in the sharing list now has a menu holding what
you can do about them -- let them see which project it is in, revoke access,
cancel an invite -- rather than a row of controls beside their address. The
search box has a clear button, the buttons in the toolbar say what they do
instead of being bare icons, and a number of things that were cut off, stacked
oddly or repeated on a phone screen are fixed.

**Two things carried over, because they are easy to miss and neither is new
enough to announce again.** The app tells whatever server you point it at
which version and which operating system it is, on every request, and the
maintainer's test server counts those requests as a rough trend — never
anything about your account or your vault. A server you run yourself counts
nothing at all unless you switch it on and point it at your own analytics
project: it is off by default and makes no outbound analytics request. And a
project's name is stored unencrypted, the same way a secret's name already is,
so whoever runs the server can see that you keep a project called Perspectiv
and which of your secrets are filed under it; the secrets themselves stay
encrypted on your device. If a grouping is itself sensitive, do not put it in
a project name. The count and the project names are described in full in the
privacy policy, which the app shows you before you sign up and again from
**Terms and privacy** in the account menu.

## Installing

The installers are not code-signed, so each system will question them once.

- **macOS** — open the `.dmg` and drag the app to Applications. The first
  launch is refused. Go to **System Settings → Privacy & Security**, scroll to
  the message naming klavyn, and click **Open Anyway**; the app then starts
  after one more confirmation and opens normally from then on. (The old
  right-click → **Open** shortcut no longer works for unsigned apps.) If
  macOS says the app "is damaged and can't be opened", that is the quarantine
  flag rather than a bad download — clear it with
  `xattr -dr com.apple.quarantine /Applications/klavyn.app` and try again.
- **Windows** — SmartScreen shows "Windows protected your PC" on the installer.
  Choose **More info**, then **Run anyway**.
- **Linux** — install the `.deb` with `sudo apt install ./klavyn_*.deb`, or
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
[deploy/README.md](https://github.com/cjaymoni/klavyn/blob/__TAG__/deploy/README.md),
and a server you run has to be 0.2.0 or newer.

To share a secret with someone, both of you need accounts on the same server.
You will also need their key fingerprint, read to you over a channel that is
not the server — the app shows yours in the header after you log in. That step
is what stops a dishonest server from handing you its own key in place of your
friend's.

## What to report

Anything that confused you, anything that looked wrong, and anything that lost
data. Include the platform, the release tag, and what you had just done.
