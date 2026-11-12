# Running credvault on a VPS

Caddy terminates TLS and proxies to the server over an internal Docker
network. The server itself publishes no ports.

## Prerequisites

- A domain with an A (and AAAA, if you have IPv6) record pointing at the VPS.
  Caddy gets a certificate for it on first start; without working DNS that
  fails and the site will not come up.
- Docker Engine with the Compose plugin.
- Ports 80 and 443 reachable from the internet. Port 80 is required for the
  ACME HTTP challenge, not just for redirects.

## First run

```sh
git clone <your-repo> credvault && cd credvault/deploy
cp .env.example .env
openssl rand -base64 32          # paste into CREDVAULT_REGISTRATION_TOKEN
chmod 600 .env                   # the token is a credential
$EDITOR .env                     # set domain and ACME email too
docker compose up -d --build
curl https://vault.example.com/health   # expects: {"status":"ok","protocol":3,...}
```

The first build compiles the whole dependency tree and takes a while on a
small VPS; a 1 GB instance may need swap to get through linking.

## Firewall

The application port is never published, but close everything else anyway:

```sh
ufw default deny incoming
ufw allow OpenSSH
ufw allow 80,443/tcp
ufw enable
```

## Accounts

Who may create an account is one of three states, and `.env` as shipped
chooses the middle one:

- **A token.** Set `CREDVAULT_REGISTRATION_TOKEN`; clients send it as
  `registration_token` when creating an account. Give it only to people who
  should have accounts here. Rotate it by editing `.env` and running
  `docker compose up -d`; existing accounts are unaffected.
- **Blank: anyone who can reach the server.** This is what an unset variable
  means, and what the shipped `.env.example` gives you. The app then shows no
  token field at all. Fine on loopback; on a public host it is a decision to
  make on purpose, because anyone on the internet can then create an account
  and store data you are hosting.
- **Closed.** Set `CREDVAULT_CLOSED_REGISTRATION=true` and leave the token
  unset. Existing accounts keep working. Setting both at once stops the
  server rather than letting it guess.

The server prints which state it is in on every start, so

```sh
docker compose logs credvault | grep "registration policy"
```

tells you what a host was last started with. It is one line per start, not a
running status: if you need to know what a long-running container is doing
now, restart it or read the policy you configured.

## Sign in with Google (optional)

Leave `CREDVAULT_GOOGLE_CLIENT_ID` and `CREDVAULT_GOOGLE_CLIENT_SECRET` blank
to keep the server password-only.

To enable it, create an OAuth client of type **Desktop app** in the Google
Cloud console — that type is required, because the app listens on whatever
loopback port the operating system gives it — then put the id and secret in
`.env` and run `docker compose up -d`.

Google replaces the server login only. Users still type a passphrase, and that
is what derives the vault key, so the server still holds nothing it can
decrypt. What does change: anyone who takes over a linked Google account can
reach this server as that user, and will see secret names, who shares with
whom, and the encrypted blobs. They cannot read any secret.

Confirm it is on:

```sh
curl -s https://vault.example.com/api/capabilities
# {"password_sign_in":true,"google_sign_in":true,...}
```

## Backups

Run `backup.sh` nightly as root. There is no password recovery and the server
holds only ciphertext, so this database is the single point of failure for
every vault on it.

```sh
# /etc/cron.d/credvault-backup
30 3 * * * root /opt/credvault/deploy/backup.sh >> /var/log/credvault-backup.log 2>&1
```

Copy the results off the machine — `rclone`, `restic`, or `scp` to somewhere
you control. A backup that only exists on the VPS does not survive the failure
you are backing up against.

Restore by stopping the stack, replacing `credvault.db` in the `credvault_data`
volume with a backup, deleting any `-wal` and `-shm` files beside it, and
starting again.

## Upgrades

Migrations run automatically at startup and there are no down migrations, so
the order matters:

```sh
./backup.sh                      # first, always
git pull
docker compose up -d --build
docker compose logs -f credvault
```

Upgrade the server before clients update. Compatibility is not something to
look up: the server publishes what it speaks at `/health`, and the app checks
it before sending anything, so a client that can no longer be served says so
instead of failing one request at a time.

```sh
curl -s https://vault.example.com/health
# {"status":"ok","protocol":3,"min_client_protocol":1}
```

If an upgrade raises `min_client_protocol`, clients below it stop working the
moment you deploy, so make sure the new app is available first.

## Logs

```sh
docker compose logs -f credvault
```

`RUST_LOG=credvault_server=debug,tower_http=debug` in `.env` turns up the
detail. Logs include request paths and client addresses; they never include
secret contents, which the server cannot read in the first place.
