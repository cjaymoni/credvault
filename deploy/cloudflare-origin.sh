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
# EVERY RUN IS A BRIEF OUTAGE, including a successful one. The bootstrap rule
# is removed and the deny goes in before the allows, so from that moment
# until the last allow lands 80/443 is refused -- roughly 15-45 seconds, one
# `ufw insert` per range on a loaded box. That ordering is deliberate: a
# failure part-way leaves the origin closed rather than open, which is the
# right direction for a firewall whose whole job is to be shut. But it means
# the weekly cron above is a weekly blip, so schedule it when that is
# acceptable and do not go looking for a cause on Monday mornings. Reversing
# it (all allows first, then the deny) would shrink the window to the gap
# before the deny lands -- a window in which the origin is *open*, which is
# the worse trade.
#
# NOT NEEDED where nginx is already the edge with Cloudflare real-IP
# restoration (deploy/nginx/cloudflare-realip.conf): nginx resolves the caller
# itself, and such a host has usually narrowed the firewall already. Running
# this there adds a second, redundant rule set, so it stops when it finds a
# web-port ALLOW rule it did not write -- including one spelled as an
# application profile such as `Nginx Full`, which is how such a host normally
# spells it. --force says you meant it.
#
# Usage: ./cloudflare-origin.sh [--dry-run] [--force] [--no-ipv6]
#
# -E so that the ERR trap set before the firewall is edited is inherited by
# the functions that do the editing. Without it a failure inside one of them
# exits silently, which is the single worst outcome here: the operator is
# left with a half-applied firewall and no message saying so.
set -Eeuo pipefail

DRY_RUN=""
DRY_RUN_OBJECTED=""
FORCE=""
NO_IPV6=""
# Set only when ufw is genuinely not managing v6 on this host, so the
# post-apply check knows not to look for a v6 deny that cannot exist.
V6_UNMANAGED=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN="yes" ;;
    --force)   FORCE="yes" ;;
    # Deliberately not folded into --force. The README tells the nginx-host
    # operator to pass --force to get past the `Nginx Full` rule they are
    # expected to have; if that same flag also waived the IPv6 check, they
    # would silently accept an origin reachable over v6 while the script
    # printed that it had denied everything. One waiver, one flag, one
    # decision each.
    --no-ipv6) NO_IPV6="yes" ;;
    *)         echo "cloudflare-origin: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

# The rule this script writes, and the one the README's Firewall section tells
# a fresh VPS to open before Cloudflare is in front of it. The second is
# expected rather than foreign: it is removed further down, deliberately.
readonly RULE_COMMENT='klavyn-cloudflare'
readonly BOOTSTRAP_SPEC='80,443/tcp'

# --- reading ufw's table ---------------------------------------------------
#
# Ownership cannot be inferred from the port column. `ufw allow 'Nginx Full'`
# prints as `Nginx Full  ALLOW IN  Anywhere` -- no port, no digits -- so a
# guard that matches on `^(80|443)` sees nothing on exactly the host this
# script is meant to decline to touch. Profile names are resolved to their
# ports instead.

# Does a ufw port spec (80, 80/tcp, 80,443/tcp, 8000:8100/tcp) cover tcp 80 or
# 443? A bare spec with no protocol covers both protocols, so it counts.
spec_covers_web() {
  local spec="${1// /}" ports item lo hi port
  [ -n "$spec" ] || return 1
  case "$spec" in
    */udp) return 1 ;;
  esac
  ports="${spec%%/*}"
  # A spec this cannot read is treated as covering the web ports, matching
  # what `to_covers_web` does with an application profile that no longer
  # resolves: a rule we cannot parse is one we cannot say is harmless, and
  # the safe direction is to make the operator look at it.
  case "$ports" in
    ''|*[!0-9,:]*) return 0 ;;
  esac
  local IFS=','
  for item in $ports; do
    case "$item" in
      *:*) lo="${item%%:*}"; hi="${item##*:}" ;;
      *)   lo="$item"; hi="$item" ;;
    esac
    case "$lo$hi" in ''|*[!0-9]*) continue ;; esac
    for port in 80 443; do
      if [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ]; then
        return 0
      fi
    done
  done
  return 1
}

# Does a ufw "To" column cover tcp 80 or 443? Anything not starting with a
# digit is an application profile, looked up for its ports. A profile that no
# longer exists is treated as covering the web ports: refusing to act on a
# rule we cannot read is the safe direction.
to_covers_web() {
  # ` (v6)` marks the address family and ` on <iface>` scopes the rule to an
  # interface; neither changes which ports the rule opens. Stripped before
  # anything else, because `spec_covers_web "80 on eth0"` collapses to
  # `80oneth0`, finds a non-digit, and reports that the rule covers nothing --
  # so `ufw allow in on eth0 to any port 80`, which is ordinary on a
  # multi-homed VPS, passed the guard and then sat above the deny keeping the
  # origin open.
  local to="${1% (v6)}"
  to="${to%% on *}"
  # A destination address in front of the port spec: `ufw allow to <addr> port
  # 443` prints `2606:4700::1 443/tcp`. The port spec is always last, so take
  # it. Without this, space-stripping glues the two together --
  # `2606:4700::1443/tcp` -- and because every character of a numeric IPv6
  # address is already in the set spec_covers_web accepts, it is read as the
  # port range 2606:1 and reported as covering nothing. A v4 address or one
  # with hex letters only escapes that by accident.
  #
  # Only when the trailing word actually looks like a port spec. Stripping
  # unconditionally turned `Nginx Full` into `Full` and `Dovecot IMAP` into
  # `IMAP`, neither of which resolves -- so `ufw app info` stopped being
  # consulted for every profile name containing a space, which is nearly all
  # of them, and a port-143 mail rule was reported as opening 80/443.
  # `Nginx Full` was still flagged, but by the parse-failure fallback rather
  # than by its ports, and the false positives pushed the operator towards
  # `--force`, which waives the guard entirely.
  case "$to" in
    *' '*)
      local trailing="${to##* }"
      case "$trailing" in
        [0-9]*) to="$trailing" ;;
      esac
      ;;
  esac
  local spec
  case "$to" in
    Anywhere*) return 0 ;;
    [0-9]*)    spec_covers_web "$to"; return $? ;;
  esac
  local info
  info="$(ufw app info "$to" 2>/dev/null)" || return 0
  local specs
  # Split on `|` and whitespace only. Commas stay: spec_covers_web reads a
  # comma list itself, and splitting `80,443/tcp` here would strip the
  # protocol off everything but the last port.
  specs="$(printf '%s\n' "$info" | sed -n '/^Ports:/,$p' | tail -n +2 \
    | tr '|' '\n' | tr -s ' \t' '\n')"
  [ -n "${specs//[[:space:]]/}" ] || return 0
  while read -r spec; do
    [ -n "$spec" ] || continue
    if spec_covers_web "$spec"; then return 0; fi
  done <<< "$specs"
  return 1
}

# Emit `position<TAB>action<TAB>to<TAB>rest` for every numbered rule. `rest`
# holds the From column and the trailing `# comment`, which is where ufw puts
# a rule's comment in status output.
ufw_rules() {
  ufw status numbered 2>/dev/null | awk '
    match($0, /^\[[ ]*[0-9]+\]/) {
      pos = substr($0, RSTART + 1, RLENGTH - 2); gsub(/ /, "", pos)
      rest = substr($0, RSTART + RLENGTH)
      if (match(rest, /[ \t]+(ALLOW|DENY|REJECT|LIMIT)([ \t]+(IN|OUT|FWD))?([ \t]|$)/)) {
        to   = substr(rest, 1, RSTART - 1)
        act  = substr(rest, RSTART, RLENGTH)
        from = substr(rest, RSTART + RLENGTH)
        gsub(/^[ \t]+|[ \t]+$/, "", to)
        gsub(/^[ \t]+|[ \t]+$/, "", act)
        gsub(/^[ \t]+|[ \t]+$/, "", from)
        print pos "\t" act "\t" to "\t" from
      }
    }
  ' || true
}

# Positions of ALLOW/LIMIT rules on tcp 80/443 that this script did not write
# and that are not the README's bootstrap rule. One position per line.
foreign_web_allows() {
  local pos act to rest
  while IFS=$'\t' read -r pos act to rest; do
    [ -n "$pos" ] || continue
    # Inbound only. An `ALLOW OUT` rule does not expose this host, and
    # `ufw allow out 53` is common enough that treating it as a web-port
    # allow would make the guard fire on almost every box.
    case "$act" in
      ALLOW|'ALLOW IN'|LIMIT|'LIMIT IN') ;;
      *) continue ;;
    esac
    case "$rest" in
      *"# $RULE_COMMENT"*) continue ;;
    esac
    if [ "${to% (v6)}" = "$BOOTSTRAP_SPEC" ] && [ "${rest%% *}" = "Anywhere" ] \
       && [[ "$rest" != *"#"* ]]; then
      continue
    fi
    if to_covers_web "$to"; then
      printf '%s\t%s\t%s\n' "$pos" "$to" "$rest"
    fi
  done < <(ufw_rules)
}

# What a Cloudflare range may look like. Shape alone was not enough: the
# earlier pattern accepted `12345678/9` and `deadbeef/24` (no colon required
# on the v6 branch, so they were then measured against the *v4* prefix floor
# and passed), `999.999.999.999/8` (octets unbounded) and `1.2.3.4/99`. Each
# reached `ufw allow`, which errors -- after the deny is already in, so the
# host ends up refusing real traffic on 80/443.
#
# Octets are bounded to 0-255 and prefixes to 0-32 / 0-128. The v6 branch
# requires at least one colon and allows the `::` compression every
# Cloudflare range uses.
readonly OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
readonly V4_CIDR="^${OCTET}(\\.${OCTET}){3}/(3[0-2]|[12]?[0-9])$"
# Groups of 1-4 hex digits separated by colons, with at most one `::`.
# A looser `[0-9a-fA-F:]*:[0-9a-fA-F:]*` accepted `:/64`, `::::::::/64` and
# twelve-group addresses, all of which cleared the prefix floor too and
# reached `ufw allow`, which errors after the deny is already in.
readonly V6_GROUP='[0-9a-fA-F]{1,4}'
readonly V6_ADDR="(($V6_GROUP:){1,7}$V6_GROUP|($V6_GROUP:){1,7}:|($V6_GROUP:){1,6}:$V6_GROUP|($V6_GROUP:){1,5}(:$V6_GROUP){1,2}|($V6_GROUP:){1,4}(:$V6_GROUP){1,3}|($V6_GROUP:){1,3}(:$V6_GROUP){1,4}|($V6_GROUP:){1,2}(:$V6_GROUP){1,5}|$V6_GROUP:(:$V6_GROUP){1,6}|:((:$V6_GROUP){1,7}|:))"
readonly V6_CIDR="^$V6_ADDR/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$"
readonly CIDR_PATTERN="$V4_CIDR|$V6_CIDR"

readonly MIN_CREDIBLE_RANGES=10
readonly MIN_V4_PREFIX=8
# Cloudflare's widest published ranges are a /13 and a /29, so these leave
# several bits of headroom -- enough that adding a range will not trip this,
# tight enough that `::/16` (2^112 addresses) does not read as credible. A
# floor only has to reject the implausible; the CIDR pattern above rejects
# the malformed.
readonly MIN_V6_PREFIX=24

deny_position() {
  # $1: "v4" or "v6"
  ufw_rules | awk -F'\t' -v tag="# $RULE_COMMENT" -v want="$1" '
    $2 ~ /^DENY/ && index($4, tag) {
      family = ($3 ~ /\(v6\)$/ || $4 ~ /\(v6\)/) ? "v6" : "v4"
      if (family == want) { print $1; exit }
    }'
}

# Everything above is definitions; everything below talks to the real
# firewall. Sourcing the file therefore stops here, which is what lets
# deploy/tests/cloudflare-origin.test.sh and scripts/refresh-cf-ranges.sh
# reuse the parsing and the CIDR constants without reimplementing them.
#
# Asked of the shell rather than read from a variable. An earlier version
# tested ${SOURCED_FOR_TESTS:-}, which is inherited from the environment: one
# stray export in root's cron environment and the weekly run exits 0 having
# done nothing, logging nothing and mailing nothing while the range list goes
# stale. A security control that reports success while disabled is the one
# failure mode worth engineering against, and the shell already knows the
# answer.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
  return 0
fi

if [ -z "$DRY_RUN" ] && [ "$(id -u)" -ne 0 ]; then
  echo "cloudflare-origin: run as root — this edits the firewall" >&2
  exit 1
fi

# An inactive ufw stores rules without enforcing any of them, and reports no
# rules at all in `ufw status numbered` -- so the checks further down cannot
# see their own work, and more to the point the origin is wide open whatever
# this script writes.
#
# A dry run reports it rather than exiting: the README offers --dry-run as the
# way to find out what this script objects to, so a dry run that stays silent
# about a firewall that is not running would be telling the operator the
# opposite of the truth.
if ! ufw status 2>/dev/null | grep -q '^Status: active'; then
  echo "cloudflare-origin: ufw is not active. Rules are stored and not enforced," >&2
  echo "  leaving the origin reachable directly and CF-Connecting-IP forgeable." >&2
  echo "  Enable it first (see \"Firewall\" in README.md): ufw enable" >&2
  [ -n "$DRY_RUN" ] || exit 1
fi

# --- the guard -------------------------------------------------------------
#
# Someone else's rules on these ports mean another thing is already managing
# this, and two overlapping allow-lists are worse than either: whichever is
# stale silently refuses real traffic, and neither owner knows which. Said
# before anything is fetched or changed.
#
# Run under --dry-run too, and before the fetch, because the README sends the
# operator here to decide whether the script is needed at all: "reads the same
# table and names anything it would object to". It did not -- a dry run
# skipped this entirely and printed a clean list of ranges, which reads as
# "nothing to object to" on exactly the host that has an `Nginx Full` rule.
# Reporting without exiting is what makes that sentence true, and running it
# before the fetch means the guard's verdict is printed first, so it is still
# the last thing you see when the fetch then fails.
if [ -z "$FORCE" ]; then
  FOREIGN="$(foreign_web_allows || true)"
  if [ -n "$FOREIGN" ]; then
    echo "cloudflare-origin: these 80/443 rules were not written by this script:" >&2
    printf '%s\n' "$FOREIGN" | sed 's|^|  |' >&2
    echo "  If nginx already restores real client addresses, this script is unnecessary -- see" >&2
    echo "  \"Restricting the origin to Cloudflare\" in README.md. Re-run with --force to proceed." >&2
    [ -n "$DRY_RUN" ] || exit 1
    DRY_RUN_OBJECTED="yes"
  elif [ -n "$DRY_RUN" ]; then
    echo "cloudflare-origin: no 80/443 rules on this host were written by anything else"
  fi
fi

# Fetched rather than pinned: a stale list silently refuses real traffic from
# a range Cloudflare has added, which looks like an outage with no cause.
RANGES="$(mktemp)"
trap 'rm -f "$RANGES" "$RANGES.v4"' EXIT
for url in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
  # The responses do not end in a newline, so the last v4 range and the first
  # v6 range would otherwise be concatenated into one unusable line.
  { curl -fsS --max-time 20 "$url" && echo; } >> "$RANGES" || {
    echo "cloudflare-origin: could not fetch $url; leaving the firewall alone" >&2
    exit 1
  }
done

# A truncated or error-page response must not become the allow-list: that is
# how a firewall ends up letting nothing in, or everything. Counting lines
# that merely contain a slash is not enough on its own -- an HTML error page
# or a captive portal clears a count like that easily, since markup is full of
# slashes -- so every line has to look like a CIDR before any of it is used.
NOT_CIDR="$(grep -vE '^[[:space:]]*$' "$RANGES" \
  | grep -vE "$CIDR_PATTERN" || true)"
if [ -n "$NOT_CIDR" ]; then
  echo "cloudflare-origin: the fetched list contains lines that are not CIDRs;" >&2
  echo "  leaving the firewall alone. First few:" >&2
  printf '%s\n' "$NOT_CIDR" | head -5 | sed 's|^|    |' >&2
  exit 1
fi

# Shape is not enough: `0.0.0.0/0` and `::/0` are well-formed CIDRs, and
# allowing either opens 80/443 to the whole internet while the script prints
# that it restricted them -- the one outcome this exists to prevent, reached
# silently. Cloudflare has never published anything close to these floors
# (its widest are a /13 and a /29), so a prefix shorter than this is a
# changed endpoint, a middlebox, or a mistake, and none of those may become
# an allow rule.
TOO_WIDE=""
while read -r range; do
  [ -n "$range" ] || continue
  prefix="${range##*/}"
  case "$range" in
    *:*) [ "$prefix" -lt "$MIN_V6_PREFIX" ] && TOO_WIDE="$TOO_WIDE$range\n" ;;
    *)   [ "$prefix" -lt "$MIN_V4_PREFIX" ] && TOO_WIDE="$TOO_WIDE$range\n" ;;
  esac
done < "$RANGES"
if [ -n "$TOO_WIDE" ]; then
  echo "cloudflare-origin: the fetched list contains ranges far wider than any Cloudflare" >&2
  echo "  has published, so it is not their list; leaving the firewall alone:" >&2
  printf '%b' "$TOO_WIDE" | head -5 | sed 's|^|    |' >&2
  exit 1
fi

COUNT="$(grep -cE '^[[:space:]]*[^[:space:]]' "$RANGES" || true)"
if [ "$COUNT" -lt "$MIN_CREDIBLE_RANGES" ]; then
  echo "cloudflare-origin: only $COUNT ranges returned, which is not a credible list" >&2
  exit 1
fi

# ufw silently ignores IPv6 rules when IPV6=no, so the v6 ranges below would
# not be allowed while v6 traffic stays unfiltered entirely -- the origin
# remains directly reachable over v6, which is the whole thing this script
# exists to prevent. Said before anything is changed.
if grep -q ':' "$RANGES" && grep -qiE '^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*"?no"?' /etc/default/ufw 2>/dev/null; then
  # The refusal is printed only when refusing. Printing it first meant the
  # intended --no-ipv6 path emitted four lines of "Set IPV6=yes ... and
  # restart ufw" before saying it was proceeding, so every successful weekly
  # cron run mailed what reads as an error -- the habit this script's own
  # comments warn about.
  if [ -z "$NO_IPV6" ]; then
    echo "cloudflare-origin: ufw has IPV6=no, so it would not filter v6 at all while the" >&2
    echo "  v6 ranges below went unapplied -- the origin would stay reachable directly over" >&2
    echo "  v6 and CF-Connecting-IP would stay forgeable. Set IPV6=yes in /etc/default/ufw" >&2
    echo "  and restart ufw, or confirm this host has no v6 address and re-run with --no-ipv6." >&2
    exit 1
  fi
  # Drop the v6 ranges rather than handing them to a ufw that will refuse
  # them. Waiving the refusal alone left every v6 `ufw allow` failing with
  # "IPv6 support not enabled" part-way through the apply -- after the deny
  # was already in, so the ERR trap fired, told the operator the firewall was
  # over-restrictive, and offered `ufw allow 80,443/tcp` as the way out. The
  # firewall was correct at that moment; following that advice is what
  # reopens the origin.
  #
  # Two statements, not `a && b`: a non-final command in an && list is exempt
  # from `set -e`, so a grep that selected nothing would leave the list
  # unfiltered and the run would continue as if it had worked.
  V6_UNMANAGED="yes"
  grep -v ':' "$RANGES" > "$RANGES.v4" || true
  mv "$RANGES.v4" "$RANGES"
  [ -s "$RANGES" ] || {
    echo "cloudflare-origin: nothing left after removing the v6 ranges" >&2
    exit 1
  }
  COUNT="$(grep -cE '^[[:space:]]*[^[:space:]]' "$RANGES" || true)"
  # The credibility floor applies to what is actually being applied, not only
  # to what was fetched.
  if [ "$COUNT" -lt "$MIN_CREDIBLE_RANGES" ]; then
    echo "cloudflare-origin: only $COUNT v4 ranges, which is not a credible list" >&2
    exit 1
  fi
  echo "cloudflare-origin: --no-ipv6 given; applying the $COUNT v4 ranges only. ufw is not"
  echo "  filtering v6 at all, so this is correct only if this host has no v6 address."
fi

if [ -n "$DRY_RUN" ]; then
  # To stderr, with the guard's objection, so that redirecting one captures
  # the other. An operator checking whether this script is needed with
  # `--dry-run > check.log` otherwise gets a log containing only "would allow
  # 22 ranges", while the `Nginx Full` finding went to the terminal.
  echo "cloudflare-origin: would allow $COUNT ranges on 80,443 and deny the rest" >&2
  cat "$RANGES"
  # 2, not 0, when the guard objected: the README offers --dry-run as the way
  # to find out what this script objects to, so the status has to carry that
  # answer. Distinct from the 1 that means "refused to act".
  if [ -n "${DRY_RUN_OBJECTED:-}" ]; then
    echo "cloudflare-origin: the rules named above would stop a real run; --force overrides" >&2
    exit 2
  fi
  exit 0
fi

# --- applying --------------------------------------------------------------
#
# From here on the firewall is being edited, and there is no transaction to
# roll back. A failure part-way leaves it in a state the operator has to be
# told about by name, because the summary at the end will never print and
# `set -e` would otherwise exit in silence.
on_apply_failure() {
  echo "cloudflare-origin: FAILED part-way through editing the firewall." >&2
  echo "  80/443 may now be denied with only some of the Cloudflare ranges allowed," >&2
  echo "  which refuses real traffic. The deny is added before the allows, so this" >&2
  echo "  fails closed rather than open -- an outage, not an exposure." >&2
  echo "  Inspect: ufw status numbered" >&2
  echo "  Re-running this script is safe: it deletes its own rules first and converges." >&2
  echo "  To reopen while you work: ufw allow 80,443/tcp" >&2
}
trap on_apply_failure ERR

# Drop the rules this script wrote last time, by their comment, so repeated
# runs converge rather than piling up. Deleted by number, highest first, so
# that removing one does not renumber the next.
#
# Collected into an array rather than piped into a loop: under `set -o
# pipefail` a pipeline whose grep matches nothing fails, and on a first run
# nothing matches, which aborted this script here before it had printed or
# changed anything at all.
OLD_POSITIONS=()
while IFS=$'\t' read -r pos _act _to rest; do
  case "$rest" in
    *"# $RULE_COMMENT"*) OLD_POSITIONS+=("$pos") ;;
  esac
done < <(ufw_rules)

if [ ${#OLD_POSITIONS[@]} -gt 0 ]; then
  while read -r n; do
    [ -n "$n" ] || continue
    ufw --force delete "$n" >/dev/null
  done < <(printf '%s\n' "${OLD_POSITIONS[@]}" | sort -rn)
fi

# Remove the README's bootstrap rule now that a narrower one replaces it.
ufw --force delete allow 80,443/tcp >/dev/null 2>&1 || true

# Inserted at the top rather than appended. ufw is first-match, so a deny
# appended below a pre-existing `Nginx Full ALLOW` -- which is what --force
# means you are doing -- would never be reached, and the summary below would
# report a restriction that is pure decoration. SSH is deliberately untouched
# and stays below: a deny scoped to 80,443 cannot match port 22, and locking
# yourself out of the box is the one failure here with no remote fix.
insert_or_append() {
  if [ "$(ufw_rules | grep -c '' || true)" -gt 0 ]; then
    ufw insert 1 "$@" >/dev/null
  else
    ufw "$@" >/dev/null
  fi
}

insert_or_append deny proto tcp to any port 80,443 comment "$RULE_COMMENT"
while read -r range; do
  [ -z "$range" ] && continue
  insert_or_append allow proto tcp from "$range" to any port 80,443 comment "$RULE_COMMENT"
done < "$RANGES"

trap - ERR

# The deny is what makes the allow-list mean anything, so confirm it landed
# rather than inferring it from the absence of an error.
#
# ufw keeps a v4 table and a v6 table, and prints the v6 rows with a `(v6)`
# suffix. Taking the first DENY with our tag would find the v4 one and say
# nothing about v6 -- so on a host where the v6 rules never landed, the check
# passed and the script printed "denied the rest" while the origin was
# directly reachable over IPv6.
DENY_POSITION="$(deny_position v4)"
if [ -z "$DENY_POSITION" ]; then
  echo "cloudflare-origin: the deny rule is not in the table after applying it." >&2
  echo "  80/443 is open to everything the rules above it permit. Check: ufw status numbered" >&2
  exit 1
fi

# Only when there were v6 ranges to apply. With --no-ipv6 the operator has
# said this host has no v6 address, and ufw is not managing v6 at all.
if [ -z "$V6_UNMANAGED" ] && grep -q ':' "$RANGES" && [ -z "$(deny_position v6)" ]; then
  echo "cloudflare-origin: the v4 deny landed but the v6 one did not." >&2
  echo "  The origin is still reachable directly over IPv6, where CF-Connecting-IP is" >&2
  echo "  forgeable -- which is the whole thing this script exists to stop. Check:" >&2
  echo "  Check why: ufw status numbered | grep v6, and IPV6= in /etc/default/ufw." >&2
  echo "  (--no-ipv6 only applies when ufw itself has IPV6=no; it will not skip this.)" >&2
  exit 1
fi

# ufw is first-match, so only a foreign allow *above* the deny defeats it.
# One below is unreachable for 80/443 and harmless -- and that is the normal
# state on the nginx host this script supports with --force, where
# `Nginx Full` is expected to still be there. Treating every leftover as a
# failure made a correct weekly cron run mail an error every Monday, which is
# how an operator learns to ignore it.
ABOVE=""
BELOW=""
while IFS=$'\t' read -r position rest; do
  [ -n "$position" ] || continue
  if [ "$position" -lt "$DENY_POSITION" ]; then
    ABOVE="$ABOVE  [$position] $rest"$'\n'
  else
    BELOW="$BELOW  [$position] $rest"$'\n'
  fi
done < <(foreign_web_allows || true)

if [ -n "$ABOVE" ]; then
  echo "cloudflare-origin: FAILED — these rules sit above the deny and allow 80/443, or" >&2
  echo "  could not be confirmed not to (an application profile that no longer resolves" >&2
  echo "  is counted as allowing):" >&2
  printf '%s' "$ABOVE" >&2
  echo "  The origin is still reachable directly and CF-Connecting-IP still forgeable." >&2
  echo "  Remove them (ufw delete <n>) or confirm by hand that they do not reach 80/443." >&2
  exit 1
fi

echo "cloudflare-origin: allowed $COUNT Cloudflare ranges on 80/443, denied the rest"
if [ -n "$BELOW" ]; then
  echo "cloudflare-origin: these rules also match 80/443 but sit below the deny, so they"
  echo "  never take effect for those ports. Not a problem; listed so the table holds no"
  echo "  surprises:"
  printf '%s' "$BELOW"
fi
echo "cloudflare-origin: confirm SSH is still allowed — ufw status"
