# Privacy Policy

**credvault test service — credvault.alphadesigns.dev**

Last updated: 13 November 2026

Status: **test service.** Read "What this test service is" below before you put anything in it.

---

## Who runs this

This service is run by `[OPERATOR NAME]` (`[LEGAL ENTITY, IF ANY]`), referred to
below as "we" or "us". You can reach us at `[CONTACT EMAIL]`.

The credvault software is open source. Anyone can run their own server. This
policy covers only the server at `credvault.alphadesigns.dev`, which the test
builds of the app connect to by default. If you point the app at a different
server, that server's operator decides what happens to your data, not us.

## What this test service is

This is a pre-release test. Two consequences you should understand before
signing up:

- **The database may be deleted without notice.** Please use made-up entries,
  not real passwords.
- **Anyone who knows the address can currently create an account.** We have
  deliberately left registration open while testers are joining. We will close
  it again.

## The short version

Your vault is encrypted on your own device before anything is sent to us. We
hold the encrypted blobs and cannot read them. We *can* see who you are, what
you have named each entry, and who you have shared entries with.

## What we hold, and whether we can read it

**We cannot read:**

- Usernames, passwords, web addresses, notes, and any custom fields you add.
  These are encrypted together as one blob with a key we never have, so we
  cannot even tell which of those fields an entry contains.
- Your master passphrase. It never leaves your device in any form.
- Your account's private key. We store it, but encrypted with a key derived
  from your passphrase.

**Your copy of the app also tells our server which version it is and which
operating system it is running on**, in the same way a web browser does. That
is how the count described further down knows which platforms are in use. It
says nothing about your machine beyond those two things.

**We can read:**

- **Your email address.** Used to identify your account and to let other users
  share entries with you.
- **The name you give each entry.** Entry names are stored in the clear so that
  lists and sharing invitations can display them. If you call something
  "Barclays — joint account", we can see that. Name entries accordingly.
- **The name of any project you file entries under, and which entries are in
  it.** Projects are stored in the clear for the same reason entry names are:
  the server has to be able to send back a heading it can draw. So we can see
  that you keep a project called "Barclays — joint account" and which of your
  entries sit under it. The entries themselves are unaffected — still
  encrypted on your device, still unreadable to us. If a grouping is itself
  sensitive, do not put it in a project name.
- **Who has access to what.** Which accounts can read which entries, who
  invited whom, and when.
- **Any message you attach to a sharing invitation.** These are stored in the
  clear. Do not put anything confidential in one.
- **When things happened.** When your account was created, and when each entry
  was created and last changed.
- **A verifier derived from your passphrase.** This is what proves it is you at
  sign-in. It is a one-way value and cannot be turned back into your
  passphrase, but it is derived from it, so a weak passphrase is weak here too.

**If you sign in with Google**, we also hold the account identifier Google
gives us and the email address on that Google account. We use these only to
recognise you at sign-in. Google itself will know that you use this service.
Signing in with Google does not give Google access to your vault — your
passphrase still does that, and Google never sees it.

## What our systems record about your visits

- **Web server logs** record the IP address a request came from, the time, and
  which part of the service was called. They are kept for 14 days and then
  deleted. They do not contain your vault contents.
- **Application logs** record events such as a request being rate-limited, with
  the account number involved. They do not contain passphrases, session tokens,
  or vault contents.
- **Cloudflare** sits in front of the service to provide encryption in transit
  and protection against attacks. Your connection reaches Cloudflare before it
  reaches us, so Cloudflare processes your IP address under its own privacy
  terms.
- **A count of installations.** When the app starts, it asks the server which
  sign-in methods are available, before you have typed anything. We count those
  requests so we can tell which builds and which platforms are actually in
  use. It is a trend and not a headcount — everyone behind one office
  connection counts as one, a laptop that moves counts as several, and
  updating the app counts as a new installation. What is recorded for each one is: the operating system, the version of
  the app, the country the request came from, the time it arrived, and a
  scrambled reference number.
  Nothing else.

## What the installation count cannot tell us

That count is the only analytics in this service, and it is deliberately built
so that it cannot be turned into a record of you.

- **It does not know who you are.** It is recorded before you sign in, so there
  is no account to attach it to, and nothing in it is ever linked to your email
  address or to anything in your vault. Signing in, reading an entry, creating
  one, and sharing one are not counted at all.
- **It does not record your IP address.** The country does not come from your
  address at all — Cloudflare, which sits in front of the service, tells our
  server which country a request arrived from, and that is the only thing we
  use. Your address itself is used once, to produce the reference number
  below, and is then discarded. It is not stored and it is not sent on.
- **The reference number stops working at midnight.** It is a one-way scramble
  of your address and the app version, mixed with a random value our server
  generates and never writes down. That random value is thrown away and
  replaced at midnight, by a clock rather than by whoever happens to open the
  app next, and again whenever the server restarts — so once a day has passed,
  nobody can work out what yesterday's numbers were, including us.
  Two requests from you on the same day look like one installation; the same
  two a day apart cannot be recognised as related, by us or by anyone we send
  them to. That is what makes this a tally rather than a trail.
- **There is no tracking in the app itself.** No third-party script, no
  advertising, no profiling, no cookies, and no record of which screens you
  open or what you do in them.

The counts are processed on our behalf by **PostHog**, on their EU
infrastructure, and are configured so that PostHog does not build a profile of
anyone. Nothing about you is sold or shared with anyone for marketing.

**We also count downloads.** The installers are on our GitHub releases page,
and GitHub tells us how many times each file has been fetched. That is a count
of files, not of people: it does not say who downloaded anything or where from,
and we cannot connect it to an account or to the count above.

## Where your data is

On a single rented server in `[DATA CENTRE LOCATION]`, operated by Contabo.
Backups of the database — the same encrypted blobs — are taken nightly and kept
for 30 days.

The installation counts described above are the one exception: those are held
by PostHog on their EU infrastructure, and they contain no account data and no
vault data of any kind.

## How long we keep it

- Your account and entries: until you delete them, or until this test service
  is shut down.
- Sign-in sessions: 30 days, then they expire automatically. You can end all
  other sessions from within the app at any time.
- Web server logs: 14 days.
- Installation counts: `[RETENTION, e.g. 12 months]` in PostHog. They stop
  being traceable to anyone long before that — the reference number is useless
  the next day — so what remains is a chart.
- Backups: 30 days. An entry you delete may persist in a backup for up to 30
  days afterwards.

## Deleting your data

Email us at `[CONTACT EMAIL]` and we will delete your account, your entries,
and your sharing relationships. Say which email address the account uses.

Two limits worth knowing. Entries that other people still have access to may
survive in their vaults — sharing gives them their own copy of the key.
And deleted data remains in backups for up to 30 days before those rotate out.

## There is no password recovery

We cannot reset your passphrase, recover your vault, or help you get back in.
This is not a policy choice we can make an exception to — we do not hold
anything capable of decrypting your data. If you forget your passphrase, the
contents are gone permanently. The entry names and the fact of your account
would remain, because those are not encrypted.

## If something goes wrong

If we become aware of a breach affecting your data, we will tell affected users
by email as soon as we reasonably can, and describe what was exposed. Because
vault contents are encrypted with keys we never hold, a breach of our server
would expose email addresses, entry names, sharing relationships, and encrypted
blobs — not the contents of those blobs.

## Your rights

Depending on where you live, you may have the right to access, correct, or
delete your personal data, to object to its processing, or to receive a copy of
it. Write to `[CONTACT EMAIL]` and we will respond within 30 days.

`[If you have users in the EU/UK, name a lawful basis for processing here —
most likely performance of a contract for the account data and legitimate
interests for the security logs — and say whether you are a controller or
processor. This needs a lawyer's eye.]`

## Children

This service is not intended for anyone under 16, and we do not knowingly
create accounts for them.

## Changes

If we change this policy in a way that affects what we collect or what we do
with it, we will tell account holders by email before the change takes effect.
The date at the top shows the current version.

## Contact

`[CONTACT EMAIL]`
