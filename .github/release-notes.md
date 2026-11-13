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

**Counting how many builds reach the server.** The app has always asked the
server which sign-in methods it offers, before the sign-in screen is drawn.
It now says which version of the app is asking and which operating system it
is on, the way a web browser does, and the test server counts those requests.

The point of it is dull and practical: installers were being downloaded and
nothing said whether anybody ran them, on what, or whether old builds were
still in use.

**It is a trend, not a headcount.** Everyone in one office behind a single
internet connection counts as one. A laptop that moves between home, a train
and an office counts as several. Updating the app reads as a new
installation. It tells us which platforms and which versions are in use; it
does not tell us how many people there are, and we are not going to pretend
otherwise.

What each count holds: the operating system, the app version, the country the
request came from, the time, and a scrambled reference number. The scrambling
uses a random value the server makes up, keeps only in memory and replaces
every midnight UTC, so two requests from you on the same day look like one
installation and the same two a day apart cannot be recognised as related, by
us or by anyone we send them to. Your IP address is used to produce that
number and is then discarded — it is not part of the count. The ordinary web
server logs still record it for 14 days, as they always have; the privacy
policy covers that, and this changes nothing about it.

What is **not** counted: anything to do with your account or your vault.
Signing in, creating a secret, reading one, sharing one — none of it is
counted anywhere. The counting happens before you have signed in, so there is
no account for it to be attached to, and vault contents were never readable
by the server in the first place.

**The version and platform go to whatever server you point the app at**, on
every request, not only the one described above. That is one line of ordinary
HTTP and no more than a web browser sends, but it is new, and a server you do
not run will see it.

Separately, how many times each installer has been downloaded from the
releases page is now recorded too. GitHub has always counted that and the
count has always been public; it says nothing about who downloaded anything.

The privacy policy in the app describes all of this. It previously said the
service used no analytics at all, which was true when it was written and is
not any more, so it was rewritten rather than left standing.

A server you run yourself counts nothing unless you switch it on and point it
at your own analytics project. It is off by default and makes no outbound
analytics request at all.

**A reminder carried over from 0.2.0, because projects still ship and this is
easy to miss:** a project's name is stored unencrypted, the same way a
secret's name already is, because the server has to be able to send back a
heading it can draw. So whoever runs the server can see that you keep a
project called Perspectiv and which of your secrets are filed under it. The
secrets themselves are unchanged: still encrypted on your device, still
unreadable to the server. If a grouping is itself sensitive, do not put it in
a project name. This is now in the privacy policy as well, where it belongs.

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
and a server you run has to be 0.2.0 or newer.

To share a secret with someone, both of you need accounts on the same server.
You will also need their key fingerprint, read to you over a channel that is
not the server — the app shows yours in the header after you log in. That step
is what stops a dishonest server from handing you its own key in place of your
friend's.

## What to report

Anything that confused you, anything that looked wrong, and anything that lost
data. Include the platform, the release tag, and what you had just done.
