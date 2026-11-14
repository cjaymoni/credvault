#!/usr/bin/env bash
# Tests for the pure string functions in deploy/cloudflare-origin.sh.
#
# Those functions decide whether the origin is open, and three review passes
# in a row found a bug in this script -- an application profile the guard
# could not see, an interface-scoped rule, a numeric IPv6 destination read as
# a port range, a destination strip that broke profile resolution for every
# multi-word name, a first-run `pipefail` abort, and a --no-ipv6 path that
# aborted mid-apply. The first four are string cases and are covered below
# directly; the last two live in the acting half of the script, and the
# "apply path" section at the bottom pins their shapes against a stubbed ufw.
# All six were cheap to catch once someone wrote them down.
#
# The script is sourced rather than run: it is guarded so that sourcing stops
# before anything touches the firewall. `ufw` is a shell function here, so no
# test reaches the real one.
#
#   bash deploy/tests/cloudflare-origin.test.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/cloudflare-origin.sh"
[ -f "$SCRIPT" ] || { echo "cannot find $SCRIPT" >&2; exit 1; }

PASSED=0
FAILED=0

# Both must return 0. Every case below is `( ... ) && ok ... || fail ...`, so
# an `ok` that returned nonzero -- `((PASSED++))` is the obvious way to write
# this and returns 1 when PASSED is 0 -- would fire the || arm as well and
# count the first case twice.
ok()   { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "$1"; return 0; }
fail() { FAILED=$((FAILED + 1)); printf '  FAIL %s\n     %s\n' "$1" "$2"; }

# ----- the stub ufw ---------------------------------------------------------

FAKE_STATUS=""

ufw() {
  case "${1:-}${2:-}" in
    statusnumbered) printf '%s\n' "$FAKE_STATUS"; return 0 ;;
    status)         printf '%s\n' "$FAKE_STATUS"; return 0 ;;
  esac
  if [ "${1:-}" = "app" ] && [ "${2:-}" = "info" ]; then
    case "$3" in
      "Nginx Full")        printf 'Profile: Nginx Full\n\nPorts:\n  80,443/tcp\n' ;;
      "Nginx HTTP")        printf 'Profile: Nginx HTTP\n\nPorts:\n  80/tcp\n' ;;
      "WWW Full")          printf 'Profile: WWW Full\n\nPorts:\n  80,443/tcp\n' ;;
      "Dovecot IMAP")      printf 'Profile: Dovecot IMAP\n\nPorts:\n  143/tcp\n' ;;
      "OpenSSH")           printf 'Profile: OpenSSH\n\nPorts:\n  22/tcp\n' ;;
      "Samba")             printf 'Profile: Samba\n\nPorts:\n  137,138/udp\n  139,445/tcp\n' ;;
      *) return 1 ;;
    esac
    return 0
  fi
  return 0
}

# Load the functions under test. The script returns early when sourced, before
# anything touches the firewall.
#
# `set --` first: the sourced file parses "$@", so without this the runner's
# own arguments reach its argument loop and `--verbose` aborts the suite with
# "unknown argument" before a single test runs.
set --
# shellcheck disable=SC1090
. "$SCRIPT"

# ----- to_covers_web --------------------------------------------------------

covers() {
  local label="$1" to="$2" want="$3"
  if to_covers_web "$to"; then got="yes"; else got="no"; fi
  if [ "$got" = "$want" ]; then
    ok "$label"
  else
    fail "$label" "to_covers_web '$to' said $got, wanted $want"
  fi
}

echo "to_covers_web:"
covers "a bare web port"                       "80/tcp"                  yes
covers "both web ports"                        "80,443/tcp"              yes
covers "the v6 row of the same rule"           "80,443/tcp (v6)"         yes
covers "an unrelated port"                     "3000/tcp"                no
covers "udp only"                              "53/udp"                  no
covers "a range spanning 443"                  "400:500/tcp"             yes
covers "a range below the web ports"           "8000:8100/tcp"           no
covers "Anywhere means every port"             "Anywhere"                yes
# Profiles: the reason ufw app info is consulted at all.
covers "a multi-word profile opening the web"  "Nginx Full"              yes
covers "the v6 row of a profile"               "Nginx Full (v6)"         yes
covers "a single-word profile that does not"   "OpenSSH"                 no
covers "a multi-word profile that does not"    "Dovecot IMAP"            no
covers "a profile with mixed udp and tcp"      "Samba"                   no
covers "a profile that no longer resolves"     "Deleted Profile"         yes
# Interface scoping and destination addresses: both put a space in the column.
covers "interface-scoped, bare port"           "80 on eth0"              yes
covers "interface-scoped, comma form"          "80,443/tcp on eth0"      yes
covers "interface-scoped, unrelated port"      "3000/tcp on eth0"        no
covers "a numeric v6 destination"              "2606:4700::1 443/tcp"    yes
covers "a v6 prefix destination"               "2001:4860::/32 80/tcp"   yes
covers "a v4 destination"                      "10.0.0.1 443/tcp"        yes
covers "a destination on an unrelated port"    "2606:4700::1 9000/tcp"   no
covers "a profile behind a destination"        "10.0.0.1 Nginx Full"     yes
covers "an unparseable spec errs to covering"  "80-ish/tcp"              yes

# ----- foreign_web_allows ---------------------------------------------------

flags() {
  local label="$1" want="$2" table="$3"
  FAKE_STATUS="$table"
  local got
  got="$(foreign_web_allows 2>/dev/null | awk -F'\t' '{print $1}' | tr '\n' ',' | sed 's/,$//')"
  if [ "$got" = "$want" ]; then
    ok "$label"
  else
    fail "$label" "flagged [$got], wanted [$want]"
  fi
}

TABLE_HEADER='Status: active

     To                         Action      From
     --                         ------      ----'

echo
echo "foreign_web_allows:"

flags "an nginx host is refused" "2" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] Nginx Full                 ALLOW IN    Anywhere"

flags "the README's bootstrap rule is exempt" "" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] 80,443/tcp (v6)            ALLOW IN    Anywhere (v6)"

flags "our own rules are not foreign" "" "$TABLE_HEADER
[ 1] 80,443/tcp                 ALLOW IN    173.245.48.0/20            # klavyn-cloudflare
[ 2] 80,443/tcp                 DENY IN     Anywhere                   # klavyn-cloudflare
[ 3] OpenSSH                    ALLOW IN    Anywhere"

flags "a commented bootstrap rule is not exempt" "2" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 80,443/tcp                 ALLOW IN    Anywhere                   # someone else"

flags "outbound rules are ignored" "" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] Anywhere                   ALLOW OUT   53
[ 3] Anywhere                   ALLOW OUT   Anywhere"

flags "forwarded rules are ignored" "" "$TABLE_HEADER
[ 1] 8080/tcp                   ALLOW FWD   Anywhere"

flags "LIMIT counts as allowing" "1" "$TABLE_HEADER
[ 1] 443/tcp                    LIMIT IN    Anywhere"

flags "a mail profile is not a web rule" "" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] Dovecot IMAP               ALLOW IN    Anywhere"

flags "a v6 destination rule is seen" "2" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 2606:4700::1 443/tcp       ALLOW IN    Anywhere (v6)"

flags "an interface-scoped rule is seen" "4" "$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 4] 80 on eth0                 ALLOW IN    Anywhere"

# ----- deny_position --------------------------------------------------------

echo
echo "deny_position:"
FAKE_STATUS="$TABLE_HEADER
[ 1] 80,443/tcp                 ALLOW IN    173.245.48.0/20            # klavyn-cloudflare
[ 2] 80,443/tcp                 DENY IN     Anywhere                   # klavyn-cloudflare
[ 3] OpenSSH                    ALLOW IN    Anywhere
[ 4] 80,443/tcp (v6)            ALLOW IN    2400:cb00::/32             # klavyn-cloudflare
[ 5] 80,443/tcp (v6)            DENY IN     Anywhere (v6)              # klavyn-cloudflare"

for family_want in "v4 2" "v6 5"; do
  set -- $family_want
  got="$(deny_position "$1")"
  if [ "$got" = "$2" ]; then ok "finds the $1 deny"; else fail "finds the $1 deny" "got [$got], wanted [$2]"; fi
done

FAKE_STATUS="$TABLE_HEADER
[ 1] 80,443/tcp                 DENY IN     Anywhere                   # klavyn-cloudflare"
got="$(deny_position v6)"
if [ -z "$got" ]; then ok "reports no v6 deny when only v4 landed"; else fail "reports no v6 deny when only v4 landed" "got [$got]"; fi

# ----- the CIDR pattern -----------------------------------------------------

echo
echo "CIDR_PATTERN:"
cidr() {
  local label="$1" value="$2" want="$3" got
  if printf '%s\n' "$value" | grep -qE "$CIDR_PATTERN"; then got="accept"; else got="reject"; fi
  if [ "$got" = "$want" ]; then ok "$label"; else fail "$label" "'$value' was $got, wanted $want"; fi
}
cidr "a real v4 range"            "173.245.48.0/20"      accept
cidr "a real v6 range"            "2400:cb00::/32"       accept
cidr "Cloudflare's widest v6"     "2a06:98c0::/29"       accept
cidr "a single v4 host"           "1.2.3.4/32"           accept
cidr "an octet over 255"          "999.999.999.999/8"    reject
cidr "a v4 prefix over 32"        "1.2.3.4/99"           reject
cidr "hex with no colon"          "deadbeef/24"          reject
cidr "digits with no dots"        "12345678/9"           reject
cidr "a v6 prefix over 128"       "::1/129"              reject
cidr "a bare word"                "not-an-ip"            reject
# Colon-shaped non-addresses: these cleared the earlier pattern and the
# prefix floor, and reached `ufw allow`, which errors after the deny is in.
cidr "a lone leading colon"       ":/64"                 reject
cidr "nothing but colons"         "::::::::/64"          reject
cidr "too many groups"            "1:2:3:4:5:6:7:8:9/64" reject
cidr "a five-digit group"         "12345::/32"           reject
cidr "the unspecified address"    "::/0"                 accept
cidr "a full v6 address"          "2606:4700:1:2:3:4:5:6/128" accept

# ----- the apply path -------------------------------------------------------
#
# Everything above is below-the-guard-free. Two of the three bugs found by
# review were down here instead -- the first-run `pipefail` abort and the
# --no-ipv6 mid-apply abort -- so the stub below models a mutating ufw and
# the loops are replayed against it. These are copies of the script's logic,
# which is weaker than exercising the original, but it pins the shapes that
# actually broke.

echo
echo "apply path:"

# Reproduces the first-run abort: a `grep` that matches nothing fails, and
# under `set -o pipefail` that killed the script before it printed anything.
(
  set -Eeuo pipefail
  FAKE_STATUS="$TABLE_HEADER
[ 1] OpenSSH                    ALLOW IN    Anywhere"
  OLD_POSITIONS=()
  while IFS=$'\t' read -r position _act _to rest; do
    case "$rest" in
      *"# $RULE_COMMENT"*) OLD_POSITIONS+=("$position") ;;
    esac
  done < <(ufw_rules)
  [ ${#OLD_POSITIONS[@]} -eq 0 ] || exit 1
) && ok "a first run with no rules of ours reaches the next statement" \
  || fail "a first run with no rules of ours reaches the next statement" "the collect loop aborted"

# The same loop on a converged table finds exactly our own rules.
(
  set -Eeuo pipefail
  FAKE_STATUS="$TABLE_HEADER
[ 1] 80,443/tcp                 ALLOW IN    173.245.48.0/20            # klavyn-cloudflare
[ 2] 80,443/tcp                 DENY IN     Anywhere                   # klavyn-cloudflare
[ 3] OpenSSH                    ALLOW IN    Anywhere"
  OLD_POSITIONS=()
  while IFS=$'\t' read -r position _act _to rest; do
    case "$rest" in
      *"# $RULE_COMMENT"*) OLD_POSITIONS+=("$position") ;;
    esac
  done < <(ufw_rules)
  [ "${OLD_POSITIONS[*]}" = "1 2" ] || exit 1
) && ok "a repeat run finds its own rules to delete" \
  || fail "a repeat run finds its own rules to delete" "wrong positions collected"

# The --no-ipv6 filter: v6 ranges must be gone before anything is applied,
# because handing them to a ufw with IPV6=no is what aborted mid-apply.
(
  set -Eeuo pipefail
  RANGES="$(mktemp)"
  printf '173.245.48.0/20\n2400:cb00::/32\n131.0.72.0/22\n' > "$RANGES"
  grep -v ':' "$RANGES" > "$RANGES.v4" || true
  mv "$RANGES.v4" "$RANGES"
  [ -s "$RANGES" ] || exit 1
  grep -q ':' "$RANGES" && exit 1
  [ "$(grep -c . "$RANGES")" = "2" ] || exit 1
  rm -f "$RANGES"
) && ok "--no-ipv6 removes every v6 range before applying" \
  || fail "--no-ipv6 removes every v6 range before applying" "v6 ranges survived the filter"

# The ABOVE/BELOW split: ufw is first-match, so only a foreign allow above
# the deny defeats it. One below is the normal state on an nginx host run
# with --force, and treating it as a failure mailed an error every Monday.
classify() {
  local deny="$1" position="$2"
  if [ "$position" -lt "$deny" ]; then echo above; else echo below; fi
}
[ "$(classify 3 1)" = "above" ] && ok "a rule before the deny is above it" \
  || fail "a rule before the deny is above it" "classified wrongly"
[ "$(classify 3 7)" = "below" ] && ok "a rule after the deny is below it" \
  || fail "a rule after the deny is below it" "classified wrongly"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "cloudflare-origin: $PASSED passed"
  exit 0
fi
echo "cloudflare-origin: $FAILED failed, $PASSED passed"
exit 1
