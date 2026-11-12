# Privacy Policy

**credvault test service — credvault.alphadesigns.dev**

Last updated: 12 November 2026

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

**We can read:**

- **Your email address.** Used to identify your account and to let other users
  share entries with you.
- **The name you give each entry.** Entry names are stored in the clear so that
  lists and sharing invitations can display them. If you call something
  "Barclays — joint account", we can see that. Name entries accordingly.
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

We do not use analytics, advertising, or tracking of any kind. There are no
third-party scripts in the app. Nothing about you is sold or shared with anyone
for marketing.

## Where your data is

On a single rented server in `[DATA CENTRE LOCATION]`, operated by Contabo.
Backups of the database — the same encrypted blobs — are taken nightly and kept
for 30 days.

## How long we keep it

- Your account and entries: until you delete them, or until this test service
  is shut down.
- Sign-in sessions: 30 days, then they expire automatically. You can end all
  other sessions from within the app at any time.
- Web server logs: 14 days.
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
