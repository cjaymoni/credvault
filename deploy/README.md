# Running klavyn on a VPS

Caddy terminates TLS and proxies to the server over an internal Docker
network. The server itself publishes no ports.

> **This file describes the reference deployment, not the one the maintainer
> runs.** Everything below works on a fresh VPS and is what a self-hoster
> should follow. The maintainer's own server does something different: TLS is
> terminated by an **nginx already on the host**, with a Cloudflare Origin
> Certificate rather than Let's Encrypt, Caddy is never started, and the
> firewall is already restricted to Cloudflare. That setup is in
> "Running behind an existing nginx" near the end, and its files are in
> `deploy/nginx/`. Read whichever matches your host; the two differ in how
> TLS is obtained and how the caller's address survives the proxy, and taking
> steps from the wrong one is how a certificate fails to issue or a rate
> limit starts counting the wrong thing.

## Prerequisites

- Domains with A (and AAAA, if you have IPv6) records pointing at the VPS.
  Three names: the API subdomain (`KLAVYN_DOMAIN`), the site's apex
  (`KLAVYN_SITE_DOMAIN`), and `www` of that apex. Caddy gets a certificate
  for each on first start; without working DNS that fails and the site will
  not come up.
- Docker Engine with the Compose plugin.
- Ports 80 and 443 reachable from the internet. Port 80 is required for the
  ACME HTTP challenge, not just for redirects.

## First run

```sh
git clone <your-repo> klavyn && cd klavyn/deploy
cp .env.example .env
openssl rand -base64 32          # paste into KLAVYN_REGISTRATION_TOKEN
chmod 600 .env                   # the token is a credential
$EDITOR .env                     # set domain and ACME email too
docker compose up -d --build
curl https://vault.example.com/health   # expects: {"status":"ok","protocol":3,...}
```

## The marketing site

The same Caddy serves a static site on `KLAVYN_SITE_DOMAIN`, from
`deploy/site`, mounted read-only. If your site builds somewhere else, copy or
symlink the output into that directory.
`www` of that name is a permanent redirect to it rather than a second copy.

Put *built* output there, not sources — the whole directory is public. If the
site needs a runtime rather than files on disk, add it as another compose
service on the `internal` network and change that Caddy block from
`root`/`file_server` to a `reverse_proxy`.

Changing the site is not a rebuild of the server: replace the files and, if
you changed the Caddyfile too, `docker compose up -d caddy`.

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

If you put Cloudflare in front, the section below replaces that last rule with
a narrower one. Do it in the order written there, not now.

## Putting Cloudflare in front

Optional, and it changes two things that are easy to get subtly wrong, so the
order matters.

**What it buys.** Protection against floods, and `CF-IPCountry`, which is the
only source of the country in the installation count — `docs/privacy.md`
describes both, so turning this off later means editing that file, not just a
setting.

**What it costs.** Cloudflare terminates the connection, so the origin no
longer sees the caller's address by default and has to recover it. Get that
wrong and everyone behind one edge shares a rate-limit budget and counts as
one installation. "Restricting the origin to Cloudflare" below is where that
is dealt with, and it differs depending on whether Caddy or nginx is the edge.

### Which certificate, and therefore which order

Two ways to hold a certificate at the origin, and they want **opposite**
things from the proxy. Pick first; the order below follows from it.

**Let's Encrypt, issued by Caddy** — the reference deployment above. Caddy
needs the HTTP challenge to reach it, and a proxied record intercepts that.
So the records start grey:

1. **DNS only (grey cloud) for all three names**, with 80 and 443 open as in
   the Firewall section. Start the stack and let Caddy get its certificates.
2. **Confirm all three answer**, the API included:
   `curl https://vault.example.com/health`.
3. **Turn the proxy on (orange cloud)** and set SSL/TLS to **Full (strict)**.
4. **Restrict the origin** (below), once the proxy is confirmed working.

Renewal is the part that fails quietly here: Caddy renews about 30 days
before expiry over that same HTTP challenge, now through a proxied record.
Leave **Always Use HTTPS off** in Cloudflare — Caddy already redirects, and
that setting is what swallows the challenge. Watch the first renewal
(`docker compose logs caddy | grep -i certificate`) rather than assuming it.
The durable fix is the DNS challenge, which needs a Caddy image built with
the Cloudflare DNS module and an API token.

**A Cloudflare Origin Certificate** — what the maintainer's host uses. It is
issued by Cloudflare and only trusted *by* Cloudflare, so it is the exact
opposite case: there is no challenge to complete, nothing to issue, and a
grey-clouded record serves a certificate no browser accepts. **Go proxied
from the start.** Generate the key and CSR on the server so the private key
never leaves it, and paste only the CSR into Cloudflare:

```sh
umask 077
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /etc/ssl/cloudflare/example.com.key \
  -out /root/example.com.csr -subj "/CN=example.com"
```

Save the issued certificate beside it, then check the pair matches before
reloading anything — a mismatch is the common way nginx refuses to start:

```sh
openssl x509 -noout -modulus -in /etc/ssl/cloudflare/example.com.pem | openssl md5
openssl rsa  -noout -modulus -in /etc/ssl/cloudflare/example.com.key | openssl md5
```

Either way set SSL/TLS to **Full (strict)**. Flexible gives a redirect loop
against an origin already serving HTTPS, and plain Full accepts any
certificate at all, including an expired or self-signed one. Strict accepts
Cloudflare's own origin certificates, so it is correct for both paths.

### Restricting the origin to Cloudflare

Only needed where the origin takes the caller's address from a header. The
Caddyfile does, from `CF-Connecting-IP`, because Caddy's own peer is a
Cloudflare edge and the address it would otherwise record is the edge's. The
server reads the rightmost `X-Forwarded-For` entry as the one its proxy
wrote, so getting this wrong means everyone behind one edge shares a
rate-limit budget — one password guesser spends it for all of them — and the
installation count becomes one per edge per day.

That header is an ordinary header to anyone connecting directly, so it is
only worth believing while nothing but Cloudflare can reach the host:

```sh
./cloudflare-origin.sh --dry-run    # read the ranges first; changes nothing
sudo ./cloudflare-origin.sh
ufw status                          # confirm SSH is still allowed
```

**You may skip this where nginx is already in front with real-IP
restoration** — but only once you have checked both halves of that sentence,
because skipping on an assumption is how the origin ends up believing a
header anyone can write. nginx resolving the caller itself replaces the
header rewrite, not the firewall:

```sh
nginx -T | grep -E 'set_real_ip_from|real_ip_header|real_ip_recursive'
ufw status numbered
```

Both of these print what you are judging rather than answering for you, which
is deliberate: a check that can only say "fine" is worse than no check,
because it is believed.

**Read every `set_real_ip_from` line.** All of them must be Cloudflare
ranges. A single `0.0.0.0/0` or `::/0` means the origin believes
`CF-Connecting-IP` from whoever sends it, and that is the whole exposure.

**Read every ALLOW row.** Not just the ones with `80` or `443` in them —
`ufw allow 'Nginx Full'`, `'WWW Full'` and `'Apache Full'` open those ports
without printing a digit, and a rule scoped to an interface prints as
`80 on eth0`. `ufw app info '<name>'` says what a named profile opens.

If either half is wrong, anyone who reaches the origin directly names their
own address and country, and nothing else here will catch it. Fix it —
install `deploy/nginx/cloudflare-realip.conf` as below, and narrow the
firewall either by hand or with `--force` — before deciding the script is
unnecessary. `./cloudflare-origin.sh --dry-run` reads the same table and
names anything it would object to, without changing anything.

The script refuses to run when it finds a web-port ALLOW rule it did not
write, including one spelled as an application profile such as `Nginx Full`.
Two flags waive two different things, deliberately kept apart: `--force`
accepts those pre-existing rules, and `--no-ipv6` says this host has no IPv6
address, which is the only case where leaving v6 unfiltered is not a hole.
Passing `--force` does not waive the IPv6 check, because an operator getting
past `Nginx Full` has not thereby decided anything about v6.

**On the Caddy stack, check Docker's userland proxy is off first.** Caddy
falls back to its peer address when a request carries no `CF-Connecting-IP`,
and that fallback is only meaningful while the publish path preserves the
peer. Where `docker-proxy` terminates the connection instead of iptables —
the usual path for a published IPv6 port on a daemon without `ip6tables` —
every request arrives from the bridge gateway, and the whole internet shares
one rate-limit bucket:

```sh
grep -s userland-proxy /etc/docker/daemon.json \
  || echo 'not set, so it is ON -- which is the case this step exists to catch'
docker compose logs caddy | tail -20    # the peer should not be 172.x.0.1
```

Then check the origin is seeing real callers rather than edges. This is the
step that catches a header rewrite that did not take effect, and it is far
easier to notice now than as mysterious rate limiting later:

```sh
docker compose logs klavyn | grep -i "rate limited"
tail -50 /var/log/nginx/access.log      # if nginx is the edge
```

If what you see are Cloudflare addresses, stop and fix it before users arrive.

### Two things to know afterwards

**Grey-clouding again will black-hole the site.** Once the firewall refuses
everything that is not Cloudflare, a record switched back to DNS-only is
unreachable. Re-open 80/443 first.

Re-run `cloudflare-origin.sh` when Cloudflare changes its ranges — weekly
from cron is plenty. That one fetches its list every run, so it keeps itself
current; the two static copies do not. `scripts/refresh-cf-ranges.sh` prints
both, validated:

```sh
scripts/refresh-cf-ranges.sh --nginx > /tmp/realip.conf   # the whole snippet
sudo install -m 644 /tmp/realip.conf /etc/nginx/snippets/cloudflare-realip.conf
sudo nginx -t && sudo systemctl reload nginx

scripts/refresh-cf-ranges.sh --caddy                      # paste into deploy/Caddyfile
```

A stale copy degrades quietly rather than failing: the firewall opens to a
newly added edge while Caddy or nginx still does not trust it, so everyone
behind that edge shares one rate-limit bucket. Nobody attributes that to a
range list.

## Running behind an existing nginx

What the maintainer's host does, and a reasonable pattern for any box that
already serves other sites: nginx owns 80 and 443, the app publishes only to
loopback, and Caddy never starts.

The files are in the repo rather than only on the server:

- `deploy/nginx/klavyn.conf.example` — the API on `vault.`, the site on the
  apex, and `www` redirecting to it. `/health` and `/api` are proxied and
  everything else is refused, and the security headers match the Caddyfile
  block for block — HSTS and `nosniff` everywhere, `Referrer-Policy` on the
  API only, and `server_tokens off` standing in for Caddy's `-Server`. An example,
  with `example.com` throughout: copy it and edit, and keep your edited copy
  out of the repo. A checked-in live file is one nobody deploys from, which
  drifts from the host it claims to describe.
- `deploy/nginx/klavyn-proxy.conf` — the shared proxy headers. Not an
  example: it names no host, so it installs verbatim. `X-Forwarded-For`
  is **set, not appended**: the server reads the rightmost entry, and
  `$remote_addr` is the real caller only because the file below has already
  rewritten it.
- `deploy/nginx/cloudflare-realip.conf` — `set_real_ip_from` for each
  Cloudflare range, `real_ip_header CF-Connecting-IP`, recursion off. It goes
  in `snippets/` and is `include`d from the klavyn server block, **not** in
  `conf.d/`: files there are included at `http` level, so a copy dropped
  there rewrites `$remote_addr` for every other site on the box. If one of
  those is not behind Cloudflare, or keys `allow`/`deny`/`limit_req` on
  `$remote_addr`, that hands it an attacker-chosen address — and `nginx -t`
  passes either way. **The proxy snippet is wrong without this file**:
  `$remote_addr` would still be the Cloudflare edge, so the server would
  record edge addresses, and everyone behind one edge would share a
  rate-limit budget and count as one installation — exactly the failure this
  whole section exists to prevent.
- `deploy/docker-compose.override.yml.example` — publishes the app on
  `127.0.0.1:8787` only. Docker inserts its own iptables rules ahead of ufw,
  so a `0.0.0.0` publish would be reachable from the internet even with the
  firewall restricted.

Install them, then bring up only the app service — never a bare
`docker compose up -d`, which would start Caddy and collide with nginx on 80
and 443:

```sh
cp deploy/docker-compose.override.yml.example deploy/docker-compose.override.yml
cp deploy/nginx/cloudflare-realip.conf /etc/nginx/snippets/
cp deploy/nginx/klavyn-proxy.conf /etc/nginx/snippets/
cp deploy/nginx/klavyn.conf.example /etc/nginx/sites-available/klavyn
$EDITOR /etc/nginx/sites-available/klavyn     # replace example.com throughout
ln -sfn /etc/nginx/sites-available/klavyn /etc/nginx/sites-enabled/klavyn
nginx -t && systemctl reload nginx     # reload only if the test passes
docker compose up -d --build klavyn    # the service by name, not the stack
```

`nginx -t` before the reload is not optional on a host serving other sites: a
bad block takes them all down, and testing first means the worst case is a
symlink to remove.

Then confirm the origin records real callers rather than edges, because every
claim in this section rests on it:

```sh
nginx -T | grep -E 'set_real_ip_from|real_ip_header'   # read them; all must be CF ranges
tail -50 /var/log/nginx/access.log                     # caller addresses, not 104.16.x / 172.64.x
```

A count is not a check here: `grep -c` answers "how many", and the thing that
matters is *which*. One `set_real_ip_from 0.0.0.0/0` counts as one.

Cloudflare addresses there mean `cloudflare-realip.conf` is not loading, and
the rate limiter and installation count are both wrong until it does.

Nothing in this setup reads `KLAVYN_ACME_EMAIL` or `KLAVYN_SITE_DOMAIN` —
they belong to Caddy — but compose still requires them to be present, so keep
them in `.env`.

## Accounts

Who may create an account is one of three states, and `.env` as shipped
chooses the middle one:

- **A token.** Set `KLAVYN_REGISTRATION_TOKEN`; clients send it as
  `registration_token` when creating an account. Give it only to people who
  should have accounts here. Rotate it by editing `.env` and running
  `docker compose up -d`; existing accounts are unaffected.
- **Blank: anyone who can reach the server.** This is what an unset variable
  means, and what the shipped `.env.example` gives you. The app then shows no
  token field at all. Fine on loopback; on a public host it is a decision to
  make on purpose, because anyone on the internet can then create an account
  and store data you are hosting.
- **Closed.** Set `KLAVYN_CLOSED_REGISTRATION=true` and leave the token
  unset. Existing accounts keep working. `yes`, `on` and `1` mean the same, as
  do capitals and stray whitespace. `false`, `0` and blank all mean this
  setting is not in use. Anything else -- including `off` and `no`, which read
  both ways on a variable with this name -- stops the server and names what it
  takes, rather than guessing at what you meant. Setting both a token and
  closed at once stops it too.

The server prints which state it is in on every start, so

```sh
docker compose logs klavyn | grep "registration policy"
```

tells you what a host was last started with. It is one line per start, not a
running status: if you need to know what a long-running container is doing
now, restart it or read the policy you configured. No line at all means the
container did not start -- `docker compose ps` will show it restarting, and
the reason is above the last line of its log.

## Sign in with Google (optional)

Leave `KLAVYN_GOOGLE_CLIENT_ID` and `KLAVYN_GOOGLE_CLIENT_SECRET` blank
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

## Counting installations (optional)

Leave `KLAVYN_POSTHOG_API_KEY` blank — the default — and the server makes
no outbound analytics request and counts nothing.

To enable it, create a PostHog project, put its **project** key (`phc_...`,
the one designed to be public, not a personal API key) in `.env`, and run
`docker compose up -d`. Set `KLAVYN_POSTHOG_HOST` as well for the US region
or for a self-hosted PostHog; blank means PostHog's EU cloud.

What gets counted is one event each time an app asks this server what it
supports, which it does at startup — before the sign-in screen, and so before
there is an account to attribute it to. Each event carries the operating
system, the app version, the country, and an opaque id built from the client
address, the build, the day, and a random salt. The address computes that id
and is then discarded: it is never stored and never sent. The salt lives only
in memory and is overwritten with fresh bytes at midnight UTC, by a timer
rather than by whenever the next request happens to arrive, and a restart
starts a fresh one. So two requests look like one installation within a day,
and once the day has turned nobody can recompute yesterday's ids — the only
copy the server keeps is gone.

Read it as a trend, not a headcount: the unit is a distinct address and build
per day, so an office behind one NAT counts once and a laptop that moves
counts several times.

Nothing on an authenticated route reports anything: signing in, reading a
secret, creating one and sharing one are not counted. PostHog is told not to
keep a profile. There is no third-party script in the app.

Confirm it is on — the server says so at startup, in both states:

```sh
docker compose logs klavyn | grep "reach telemetry"
# INFO klavyn_server: anonymous reach telemetry is on host=https://eu.i.posthog.com
```

**This changes what your privacy policy has to say.** `docs/privacy.md`
already describes the feature, but it is a draft with placeholders in it, and
the policy itself promises to email account holders before a change to what is
collected takes effect. Do that before you set the key, not after.

Downloads are counted separately, by `.github/workflows/release-downloads.yml`,
which copies GitHub's per-asset totals into the same project once a night. It
needs `POSTHOG_API_KEY` as a repository secret. The two numbers answer
different questions and must not be added together: one counts files fetched
from the releases page, the other counts installations that ran and found a
server.

## Backups

Run `backup.sh` nightly as root. There is no password recovery and the server
holds only ciphertext, so this database is the single point of failure for
every vault on it.

```sh
# /etc/cron.d/klavyn-backup
30 3 * * * root /opt/klavyn/deploy/backup.sh >> /var/log/klavyn-backup.log 2>&1
```

Copy the results off the machine — `rclone`, `restic`, or `scp` to somewhere
you control. A backup that only exists on the VPS does not survive the failure
you are backing up against.

Restore by stopping the stack, replacing `klavyn.db` in the `klavyn_data`
volume with a backup, deleting any `-wal` and `-shm` files beside it, and
starting again.

## Upgrades

Migrations run automatically at startup and there are no down migrations, so
the order matters:

```sh
./backup.sh                      # first, always
git pull
docker compose up -d --build
docker compose logs -f klavyn
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

## Renaming from credvault

A one-time migration for a host that ran the credvault stack. Everything the
rename touches is a name, not data — but the new names point at nothing, so
the data has to be carried across deliberately or the server comes up healthy
and empty.

Three things move: the Docker volumes (the project name changed, so
`credvault_data` is not `klavyn_data`), the database file inside the data
volume, and the settings in `.env` (`CREDVAULT_*` became `KLAVYN_*` — and an
unset registration token means **open to anyone**, so getting this wrong
leaves the door open rather than shut).

Take a backup first, with the old script, while the old checkout is still
in place — the new `backup.sh` looks for `klavyn_data`, which does not exist
yet. Copy it off the machine and check it opens.

```sh
# 1. Stop the old stack. The project name is part of the identity, so this
#    has to name it explicitly once the new compose file is in place.
docker compose -p credvault down

# 2. Copy each volume. `cp -a` preserves the uid 10001 ownership the server
#    needs. The caddy volumes carry the TLS certificates: copying them avoids
#    re-issuing, and Let's Encrypt rate-limits duplicate certificates.
for v in data caddy_data caddy_config; do
  docker volume create "klavyn_$v" >/dev/null
  docker run --rm -v "credvault_$v:/from" -v "klavyn_$v:/to" alpine:3.20 \
    sh -c 'cp -a /from/. /to/'
done

# 3. Rename the database inside the new volume. The -wal and -shm files go
#    too; the server is stopped, so there is nothing mid-write.
docker run --rm -v klavyn_data:/data alpine:3.20 sh -c '
  for s in "" -wal -shm; do
    [ -e "/data/credvault.db$s" ] && mv "/data/credvault.db$s" "/data/klavyn.db$s"
  done; ls -l /data'

# 4. Rewrite the settings. Check the result by eye before starting: this file
#    is what decides whether registration is open.
sed -i 's/^CREDVAULT_/KLAVYN_/' .env && grep '^KLAVYN_' .env

# 5. Start, and confirm.
docker compose up -d --build
docker compose logs klavyn | grep "registration policy"
curl -s https://vault.example.com/health
```

Sign in with a real account before you go any further. That is the check that
the database actually came across; `/health` answers fine against an empty one.

Only once you are satisfied, remove the old volumes — this is irreversible, so
it is deliberately not part of the steps above:

```sh
docker volume rm credvault_data credvault_caddy_data credvault_caddy_config
```

If you keep a local development database, it moved too: `mv
~/.credvault-server ~/.klavyn-server`, and rename `credvault.db` inside it the
same way.

## Logs

```sh
docker compose logs -f klavyn
```

`RUST_LOG=klavyn_server=debug,tower_http=debug` in `.env` turns up the
detail. Logs include request paths and client addresses; they never include
secret contents, which the server cannot read in the first place.
