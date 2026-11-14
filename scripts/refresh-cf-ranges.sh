#!/usr/bin/env bash
# Print Cloudflare's current ranges, validated, in the form two static files
# need them.
#
# The ranges live in three places: deploy/nginx/cloudflare-realip.conf,
# deploy/Caddyfile's trusted_proxies, and the list cloudflare-origin.sh
# fetches at run time. Only the last refreshes itself. When Cloudflare adds a
# range the firewall opens to the new edge while Caddy and nginx do not trust
# it, so everyone behind that edge collapses into one rate-limit bucket -- a
# silent degradation nobody attributes to a stale list. This keeps the two
# static copies current.
#
#   scripts/refresh-cf-ranges.sh --nginx   # the whole realip.conf, to stdout
#   scripts/refresh-cf-ranges.sh --caddy   # the trusted_proxies block
#
# **This writes nothing.** It prints, and you redirect. An earlier version
# edited files in place with an `nginx -t` rollback, and the rollback was the
# bug: when the target did not exist yet the "backup" was an empty temp file,
# so an `nginx -t` failure for an unrelated reason elsewhere in the config
# installed a zero-byte realip.conf. An empty include is valid nginx, so it
# reloaded cleanly with no set_real_ip_from at all and $remote_addr quietly
# went back to being the Cloudflare edge -- the exact failure the file exists
# to prevent, made silent. Printing cannot do that.
#
#   scripts/refresh-cf-ranges.sh --nginx > /tmp/realip.conf \
#     && sudo install -m 644 /tmp/realip.conf /etc/nginx/snippets/cloudflare-realip.conf \
#     && sudo nginx -t && sudo systemctl reload nginx
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
readonly HERE REPO
readonly REALIP_CONF="$REPO/deploy/nginx/cloudflare-realip.conf"

# CIDR_PATTERN, MIN_V4_PREFIX and MIN_V6_PREFIX come from the firewall script
# rather than being copied. They were copied once, and the copy was the
# pre-hardening version within the same commit: it still accepted `:/64` and
# `::::::::/64` after the original had been fixed. Sourcing stops at that
# file's own guard, before anything touches the firewall.
# shellcheck source=../deploy/cloudflare-origin.sh
MODE="${1:-}"
# The sourced file parses "$@", so clear it first or our own --nginx reaches
# its argument loop and it exits 2 with "unknown argument".
set --
. "$REPO/deploy/cloudflare-origin.sh"

readonly V4_URL='https://www.cloudflare.com/ips-v4'
readonly V6_URL='https://www.cloudflare.com/ips-v6'
# MIN_CREDIBLE_RANGES, CIDR_PATTERN, MIN_V4_PREFIX and MIN_V6_PREFIX all come
# from the sourced firewall script. Redeclaring any of them here is an error
# now that they are readonly there, which is the point: the two files cannot
# drift apart again without failing loudly.

fetch_ranges() {
  local url
  for url in "$V4_URL" "$V6_URL"; do
    # Neither response ends in a newline, so without the echo the last v4
    # range and the first v6 range fuse into one unusable line.
    { curl -fsS --max-time 20 "$url" && echo; } || {
      echo "refresh-cf-ranges: could not fetch $url; printing nothing" >&2
      return 1
    }
  done
}

# Read ranges on stdin, write the validated ones to stdout, or fail loudly.
validate_ranges() {
  local ranges range prefix bad="" count
  ranges="$(grep -vE '^[[:space:]]*$' || true)"
  [ -n "$ranges" ] || { echo "refresh-cf-ranges: empty range list" >&2; return 1; }

  while read -r range; do
    [ -n "$range" ] || continue
    if ! printf '%s\n' "$range" | grep -qE "$CIDR_PATTERN"; then
      bad="$bad  not a CIDR: $range"$'\n'
      continue
    fi
    prefix="${range##*/}"
    case "$range" in
      *:*) [ "$prefix" -lt "$MIN_V6_PREFIX" ] && bad="$bad  wider than any Cloudflare range: $range"$'\n' ;;
      *)   [ "$prefix" -lt "$MIN_V4_PREFIX" ] && bad="$bad  wider than any Cloudflare range: $range"$'\n' ;;
    esac
  done <<< "$ranges"

  if [ -n "$bad" ]; then
    echo "refresh-cf-ranges: refusing to print a list containing:" >&2
    printf '%s' "$bad" | head -5 >&2
    return 1
  fi

  count="$(printf '%s\n' "$ranges" | grep -c '/' || true)"
  if [ "$count" -lt "$MIN_CREDIBLE_RANGES" ]; then
    echo "refresh-cf-ranges: only $count ranges returned, which is not a credible list" >&2
    return 1
  fi
  printf '%s\n' "$ranges"
}

# The whole file: the committed header verbatim, then the directives. Printed
# as one unit so the two directives at the bottom cannot be left behind --
# dropping them is the failure that reloads cleanly and silently reverts
# $remote_addr to the edge.
emit_nginx() {
  local ranges="$1"
  [ -f "$REALIP_CONF" ] || { echo "refresh-cf-ranges: cannot find $REALIP_CONF" >&2; return 1; }
  # The header is everything before the first directive. Keyed on the
  # directive rather than on a blank line: a header that lost its blank line
  # would otherwise copy the whole file, directives included, and the output
  # would carry a duplicate real_ip_header that nginx refuses.
  sed -n '/^set_real_ip_from/q;p' "$REALIP_CONF"
  printf '%s\n' "$ranges" | sed 's|^|set_real_ip_from |; s|$|;|'
  echo
  echo "real_ip_header    CF-Connecting-IP;"
  echo "real_ip_recursive off;"
}

emit_caddy() {
  local ranges="$1" tab
  # Literal tabs via a variable: `\t` in a sed replacement is GNU-only, and
  # BSD sed (this repo is developed on darwin) emits a literal backslash-t,
  # which pasted into a Caddyfile makes `\t\ttrusted_proxies` the directive
  # name.
  tab="$(printf '\t')"
  echo "# Replace the trusted_proxies line in deploy/Caddyfile's servers block:"
  printf '%s\n' "$ranges" | tr '\n' ' ' | fold -s -w 66 \
    | sed -e "s|[[:space:]]*\$| \\\\|" \
          -e "1s|^|${tab}${tab}trusted_proxies static |" \
          -e "2,\$s|^|${tab}${tab}${tab}|" \
          -e "\$s| \\\\\$||"
}

main() {
  local mode="$MODE" ranges
  case "$mode" in
    --nginx|--caddy) ;;
    *) echo "usage: refresh-cf-ranges.sh --nginx | --caddy" >&2; return 2 ;;
  esac
  ranges="$(fetch_ranges | validate_ranges)"
  case "$mode" in
    --nginx) emit_nginx "$ranges" ;;
    --caddy) emit_caddy "$ranges" ;;
  esac
}

main
