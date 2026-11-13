#!/usr/bin/env bash
# Restrict 80/443 to Cloudflare, so CF-Connecting-IP cannot be forged.
#
# The Caddyfile takes the caller's address from CF-Connecting-IP, which is an
# ordinary request header: anyone who can reach this host directly can write
# whatever they like in it and be rate-limited as somebody else, or spend
# somebody else's budget. That header is only worth believing while Cloudflare
# is the sole thing that can open a connection here. This is what makes that
# true, and it is not optional once the records are proxied.
#
# Re-run it when Cloudflare changes its ranges, which it does occasionally.
# A cron entry once a week is enough:
#   0 4 * * 1 root /opt/klavyn/deploy/cloudflare-origin.sh >> /var/log/klavyn-cf.log 2>&1
#
# Usage: ./cloudflare-origin.sh [--dry-run]
set -euo pipefail

DRY_RUN=""
[ "${1:-}" = "--dry-run" ] && DRY_RUN="yes"

if [ -z "$DRY_RUN" ] && [ "$(id -u)" -ne 0 ]; then
  echo "cloudflare-origin: run as root — this edits the firewall" >&2
  exit 1
fi

# Fetched rather than pinned: a stale list silently refuses real traffic from
# a range Cloudflare has added, which looks like an outage with no cause.
RANGES="$(mktemp)"
trap 'rm -f "$RANGES"' EXIT
for url in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
  curl -fsS --max-time 20 "$url" >> "$RANGES" || {
    echo "cloudflare-origin: could not fetch $url; leaving the firewall alone" >&2
    exit 1
  }
done

# A truncated or error-page response must not become the allow-list: that is
# how a firewall ends up letting nothing in, or everything.
COUNT="$(grep -c '/' "$RANGES" || true)"
if [ "$COUNT" -lt 10 ]; then
  echo "cloudflare-origin: only $COUNT ranges returned, which is not a credible list" >&2
  exit 1
fi

if [ -n "$DRY_RUN" ]; then
  echo "cloudflare-origin: would allow $COUNT ranges on 80,443 and deny the rest"
  cat "$RANGES"
  exit 0
fi

# Drop the rules this script wrote last time, by their comment, so repeated
# runs converge rather than piling up. Deleted by number, highest first, so
# that removing one does not renumber the next.
ufw status numbered | grep -F 'klavyn-cloudflare' | grep -oE '^\[[ 0-9]+\]' | tr -d '[] ' | sort -rn | while read -r n; do
  ufw --force delete "$n" >/dev/null
done

while read -r range; do
  [ -z "$range" ] && continue
  ufw allow proto tcp from "$range" to any port 80,443 comment 'klavyn-cloudflare'
done < "$RANGES"

# Anything not from Cloudflare must be refused, or the ranges above are just
# decoration. SSH is deliberately untouched: locking yourself out of the box
# is the one failure here with no remote fix.
ufw --force delete allow 80,443/tcp >/dev/null 2>&1 || true
ufw deny proto tcp to any port 80,443 comment 'klavyn-cloudflare' >/dev/null

echo "cloudflare-origin: allowed $COUNT Cloudflare ranges on 80/443, denied the rest"
echo "cloudflare-origin: confirm SSH is still allowed — ufw status"
