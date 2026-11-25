#!/usr/bin/env bash
#
# node-security-check.sh
#
# A security check for any Node.js app, in three parts:
#
#   1. Packages  - known-malicious and vulnerable packages, what is really
#                  installed in node_modules, and install settings.
#   2. Code      - committed secrets (now and in git history), risky code
#                  patterns, framework settings, Docker, Kubernetes and CI.
#   3. Server    - the machine the app runs on: signs of a break-in, accounts,
#                  ports, firewall, SSH, databases, updates, the reverse
#                  proxy, and the live site's HTTPS, headers and DNS.
#
# It works with npm, pnpm, Yarn and Bun. Run it with no options and it asks
# what kind of setup you have before it starts. It only READS: it never
# installs, updates or deletes anything. The only files it writes are the
# ones you ask for (reports, and your saved answers).
#
# Usage:
#   ./node-security-check.sh [options] [project-dir]
#   ./node-security-check.sh --help
#
# Exit codes:
#   0  no problems at the "high" level (warnings may remain)
#   1  possible supply-chain COMPROMISE - do not build or deploy
#   2  high-level problems found
#   3  the check could not complete (bad option, no project, cancelled, or
#      with --strict, a check that could not run)
#
# Limits, stated plainly: this is a first look, not a penetration test. The
# code checks are pattern matches: they raise questions for a person to
# answer, they give false alarms, and they miss things. A clean result does
# not prove the app is safe.
#
# Built-in compromise data, checked on 2026-11-25:
#   TanStack, 2026-05-11   https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
#                          https://snyk.io/blog/tanstack-npm-packages-compromised
#   axios, 2026-03-31      versions 1.14.1 and 0.30.4, and plain-crypto-js 4.2.1
#   chalk/debug, 2025-09-08  https://www.theregister.com/2025/09/08/dev_falls_for_phishing_email
#   Nx, 2025-08-26         https://nx.dev/blog/s1ngularity-postmortem
#   Shai-Hulud worm files  https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
# Everything else known to be malicious is looked up live in the OSV database
# (https://osv.dev), which includes the OpenSSF malicious-packages feed.
#
set -uo pipefail
export LC_ALL=C

VERSION="2.0.0"
DATA_DATE="2026-11-25"

TAB="$(printf '\t')"
US="$(printf '\037')"      # field separator that is never in normal text
NL='
'

# ---------------------------------------------------------------- options --
CLI_PM=""; CLI_SERVER=""; CLI_PROXY=""; CLI_RUNNER=""; CLI_SERVICE=""; CLI_CONTAINER=""
CLI_URL=""; CLI_FAIL_ON=""; CLI_LEVEL=""
PROJECT_DIR="."
STRICT="${STRICT:-0}"
FAIL_ON_WARN=0
ONLY=""; SKIP=""
IOC_FILES=""
PROD_ONLY=0
NO_NETWORK=0; NO_OSV=0; NO_TOOLS=0
FORCE_HISTORY=0
INTERACTIVE="auto"
USE_COLOUR=1
REPORT=""; JSON_OUT=""; MD_OUT=""; HTML_OUT=""; COMPARE=""
CONFIG_FILE=""; SAVE_CONFIG=0; ASK_AGAIN=0
IGNORE_FILE=""
AUDIT_TIMEOUT="${AUDIT_TIMEOUT:-180}"
SYSROOT="${NSC_SYSROOT:-}"                                        # test hook: prefix for /etc, /var, /proc...
OSV_URL="${NSC_OSV_URL:-https://api.osv.dev/v1/querybatch}"       # test hook
NODE_DIST_URL="${NSC_NODE_DIST_URL:-https://nodejs.org/dist/index.json}"

usage() {
  cat <<EOF
node-security-check.sh ${VERSION} - a security check for Node.js apps

Usage: ./node-security-check.sh [options] [project-dir]

With no options, and when run in a terminal, it asks about your setup first.
Every question has an option below, so it can also run unattended.

Setup
  --pm NAME          Package manager: npm, pnpm, yarn or bun (default: detect)
  --server TYPE      Where the app runs:
                       vps      this machine is the Linux server
                       docker   Docker containers on this machine
                       managed  a hosting platform (Vercel, Netlify, Render...)
                       dev      this is a development machine
  --proxy NAME       What sits in front of Node: nginx, apache, caddy or none
  --runner NAME      What keeps the app running: systemd, pm2 or other
  --service NAME     systemd service name of the app
  --container NAME   Docker container name of the app
  --url URL          Live address of the site, for HTTPS, header and DNS checks.
                     Only use an address you own or are allowed to test.
  --config FILE      Saved answers (default: .nsc.conf in the project)
  --save-config      Save this run's setup answers to that file
  --ask              Ask the setup questions again, ignoring saved answers

How much to run
  --quick            The fast checks only (a few seconds)
  --deep             Everything, including the slow checks: git history,
                     package signatures and age, TLS probing, set-uid files,
                     and specialist tools if installed (gitleaks, trufflehog,
                     semgrep, trivy, lynis, testssl.sh)
  --only LIST        Run only these parts: packages,code,server
  --skip LIST        Skip these parts: packages,code,server
  --history          Scan git history for secrets (part of --deep)
  --prod-only        Audit production dependencies only
  --ioc-file FILE    Extra known-bad versions (may be given more than once).
                     One package per line:  name version [version...]
  --no-network       Skip everything that needs the network
  --no-osv           Skip the OSV malicious-package lookup
  --no-tools         Never run the specialist tools, even with --deep

Accepted findings
  --ignore-file FILE Findings you have accepted (default: .nsc-ignore in the
                     project). One per line, each with a reason:
                       FINDING-ID                 # why this is acceptable
                       FINDING-ID path/glob/*     # only for these files
                     Compromise alerts can't be ignored.

Result and reports
  --fail-on LEVEL    Audit severity that counts as a problem: critical
                     (default), high, moderate or low. FAIL_ON=... also works.
  --strict           Exit 3 if any check could not run. STRICT=1 also works.
  --fail-on-warn     Treat warnings as problems (exit 2)
  --report FILE      Save the output as plain text
  --json FILE        Save the findings as JSON
  --markdown FILE    Save the findings as Markdown
  --html FILE        Save the findings as a web page
  --compare FILE     Compare with an earlier --json report: what is new,
                     what was fixed

Other
  -y, --yes          Don't ask questions; use saved answers and detection
  --interactive      Ask the questions even when not run in a terminal
  --no-colour        Plain output
  -h, --help         Show this help
  --version          Show the version

Exit codes: 0 no high-level problems, 1 possible compromise,
            2 high-level problems, 3 could not complete.
EOF
}

die_usage() {
  echo "ERROR: $1" >&2
  echo "Run with --help to see the options." >&2
  exit 3
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --*=*) _opt="${1%%=*}"; _val="${1#*=}"; shift; set -- "$_opt" "$_val" "$@" ;;
  esac
  case "$1" in
    --pm|--server|--proxy|--runner|--service|--container|--url|--only|--skip|--ioc-file|--fail-on|--report|--json|--markdown|--md|--html|--compare|--config|--ignore-file)
      [[ $# -ge 2 ]] || die_usage "$1 needs a value." ;;
  esac
  case "$1" in
    --pm)         CLI_PM="$2"; shift 2 ;;
    --server)     CLI_SERVER="$2"; shift 2 ;;
    --proxy)      CLI_PROXY="$2"; shift 2 ;;
    --runner)     CLI_RUNNER="$2"; shift 2 ;;
    --service)    CLI_SERVICE="$2"; shift 2 ;;
    --container)  CLI_CONTAINER="$2"; shift 2 ;;
    --url)        CLI_URL="$2"; shift 2 ;;
    --only)       ONLY="$2"; shift 2 ;;
    --skip)       SKIP="$2"; shift 2 ;;
    --ioc-file)   [[ -f "$2" ]] || die_usage "--ioc-file '$2' not found."
                  IOC_FILES="${IOC_FILES}$2${NL}"; shift 2 ;;
    --fail-on)    CLI_FAIL_ON="$2"; shift 2 ;;
    --report)     REPORT="$2"; shift 2 ;;
    --json)       JSON_OUT="$2"; shift 2 ;;
    --markdown|--md) MD_OUT="$2"; shift 2 ;;
    --html)       HTML_OUT="$2"; shift 2 ;;
    --compare)    COMPARE="$2"; shift 2 ;;
    --config)     CONFIG_FILE="$2"; shift 2 ;;
    --ignore-file) IGNORE_FILE="$2"; shift 2 ;;
    --save-config) SAVE_CONFIG=1; shift ;;
    --ask)        ASK_AGAIN=1; shift ;;
    --quick)      CLI_LEVEL="quick"; shift ;;
    --deep)       CLI_LEVEL="deep"; shift ;;
    --history)    FORCE_HISTORY=1; shift ;;
    --prod-only)  PROD_ONLY=1; shift ;;
    --no-network) NO_NETWORK=1; shift ;;
    --no-osv)     NO_OSV=1; shift ;;
    --no-tools)   NO_TOOLS=1; shift ;;
    --strict)     STRICT=1; shift ;;
    --fail-on-warn) FAIL_ON_WARN=1; shift ;;
    -y|--yes)     INTERACTIVE=0; shift ;;
    --interactive) INTERACTIVE=1; shift ;;
    --no-colour|--no-color) USE_COLOUR=0; shift ;;
    -h|--help)    usage; exit 0 ;;
    --version)    echo "node-security-check.sh ${VERSION} (compromise data checked ${DATA_DATE})"; exit 0 ;;
    --)           shift; [[ $# -gt 0 ]] && PROJECT_DIR="$1"; break ;;
    -*)           die_usage "unknown option '$1'." ;;
    *)            PROJECT_DIR="$1"; shift ;;
  esac
done

if ! PROJECT_DIR="$(cd "${PROJECT_DIR}" 2>/dev/null && pwd)"; then
  echo "ERROR: project folder not found." >&2
  exit 3
fi
PJ="${PROJECT_DIR}/package.json"
SELF_NAME="$(basename "$0")"
TODAY="$(date +%Y-%m-%d)"

# ---- saved answers (.nsc.conf): read as data, never run as code ------------
CFG_PM=""; CFG_SERVER=""; CFG_PROXY=""; CFG_RUNNER=""; CFG_SERVICE=""; CFG_CONTAINER=""
CFG_URL=""; CFG_FAIL_ON=""; CFG_LEVEL=""
CONFIG_USED=""
[[ -z "${CONFIG_FILE}" ]] && CONFIG_FILE="${PROJECT_DIR}/.nsc.conf"
if [[ "${ASK_AGAIN}" -eq 0 && -f "${CONFIG_FILE}" ]]; then
  while IFS= read -r _line || [[ -n "${_line}" ]]; do
    case "${_line}" in ""|"#"*) continue ;; esac
    case "${_line}" in *=*) ;; *) continue ;; esac
    _key="$(printf '%s' "${_line%%=*}" | tr -d '[:space:]')"
    _val="${_line#*=}"
    _val="${_val#"${_val%%[![:space:]]*}"}"; _val="${_val%"${_val##*[![:space:]]}"}"
    case "${_key}" in
      pm) CFG_PM="${_val}" ;; server) CFG_SERVER="${_val}" ;; proxy) CFG_PROXY="${_val}" ;;
      runner) CFG_RUNNER="${_val}" ;; service) CFG_SERVICE="${_val}" ;; container) CFG_CONTAINER="${_val}" ;;
      url) CFG_URL="${_val}" ;; fail_on) CFG_FAIL_ON="${_val}" ;; level) CFG_LEVEL="${_val}" ;;
    esac
  done < "${CONFIG_FILE}"
  CONFIG_USED="${CONFIG_FILE}"
fi

PM="${CLI_PM:-${CFG_PM:-auto}}"
SERVER="${CLI_SERVER:-${CFG_SERVER:-auto}}"
PROXY="${CLI_PROXY:-${CFG_PROXY:-auto}}"
RUNNER="${CLI_RUNNER:-${CFG_RUNNER:-auto}}"
SERVICE="${CLI_SERVICE:-${CFG_SERVICE}}"
CONTAINER="${CLI_CONTAINER:-${CFG_CONTAINER}}"
URL="${CLI_URL:-${CFG_URL}}"
FAIL_ON="${CLI_FAIL_ON:-${FAIL_ON:-${CFG_FAIL_ON:-critical}}}"
LEVEL="${CLI_LEVEL:-${CFG_LEVEL:-auto}}"
# Which answers came from the command line or the saved file (so they are not asked again).
URL_GIVEN=0; [[ -n "${URL}" || "${CFG_URL}" == "none" ]] && URL_GIVEN=1
[[ "${URL}" == "none" ]] && URL=""
SERVICE_GIVEN=0; [[ -n "${SERVICE}" || "${CFG_SERVICE}" == "none" ]] && SERVICE_GIVEN=1
[[ "${SERVICE}" == "none" ]] && SERVICE=""
CONTAINER_GIVEN=0; [[ -n "${CONTAINER}" || "${CFG_CONTAINER}" == "none" ]] && CONTAINER_GIVEN=1
[[ "${CONTAINER}" == "none" ]] && CONTAINER=""

check_values() {
  case "${PM}" in auto|npm|pnpm|yarn|bun) ;; *) die_usage "--pm must be npm, pnpm, yarn or bun (got '${PM}')." ;; esac
  case "${SERVER}" in auto|vps|docker|managed|dev) ;; *) die_usage "--server must be vps, docker, managed or dev (got '${SERVER}')." ;; esac
  case "${PROXY}" in auto|nginx|apache|caddy|none) ;; *) die_usage "--proxy must be nginx, apache, caddy or none (got '${PROXY}')." ;; esac
  case "${RUNNER}" in auto|systemd|pm2|other) ;; *) die_usage "--runner must be systemd, pm2 or other (got '${RUNNER}')." ;; esac
  case "${FAIL_ON}" in critical|high|moderate|low) ;; *) die_usage "FAIL_ON must be critical, high, moderate or low (got '${FAIL_ON}')." ;; esac
  case "${LEVEL}" in auto|quick|standard|deep) ;; *) die_usage "level must be quick, standard or deep (got '${LEVEL}')." ;; esac
  case "${URL}" in ""|http://*|https://*) ;; *) die_usage "the site address (--url) must start with http:// or https://." ;; esac
  case "${URL}" in *[[:space:]\"\'\\\`\$\<\>\;\|\&\(\)\{\}]*) die_usage "the site address (--url) contains characters that are not allowed." ;; esac
  case "${SERVICE}${CONTAINER}" in *[!A-Za-z0-9_.@:-]*) die_usage "service and container names may only contain letters, numbers and _ . @ : -" ;; esac
}
check_values

DO_PKG=1; DO_CODE=1; DO_SERVER=1
parts_ok() {
  local p
  for p in $(printf '%s' "$1" | tr ',' ' '); do
    case "$p" in packages|code|server) ;; *) die_usage "unknown part '$p' (use packages, code, server)." ;; esac
  done
}
has_part() { case ",$1," in *",$2,"*) return 0 ;; esac; return 1; }
if [[ -n "${ONLY}" ]]; then
  parts_ok "${ONLY}"
  has_part "${ONLY}" packages || DO_PKG=0
  has_part "${ONLY}" code     || DO_CODE=0
  has_part "${ONLY}" server   || DO_SERVER=0
fi
if [[ -n "${SKIP}" ]]; then
  parts_ok "${SKIP}"
  has_part "${SKIP}" packages && DO_PKG=0
  has_part "${SKIP}" code     && DO_CODE=0
  has_part "${SKIP}" server   && DO_SERVER=0
fi

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t nsc)"
trap 'rm -rf "${TMP}"' EXIT

# Read the earlier report now, in case --json writes to the same file later.
if [[ -n "${COMPARE}" ]]; then
  [[ -f "${COMPARE}" ]] || die_usage "--compare file '${COMPARE}' not found."
  cp "${COMPARE}" "${TMP}/previous.json" || die_usage "can't read '${COMPARE}'."
fi
for _out in "${REPORT}" "${JSON_OUT}" "${MD_OUT}" "${HTML_OUT}"; do
  [[ -z "${_out}" ]] && continue
  if ! : >> "${_out}" 2>/dev/null; then die_usage "can't write the report file '${_out}'."; fi
done
[[ -n "${REPORT}" ]] && : > "${REPORT}"

# ----------------------------------------------------------------- output --
ESC="$(printf '\033')"
C_RESET=""; C_RED=""; C_YELLOW=""; C_GREEN=""; C_BLUE=""; C_BOLD=""; C_DIM=""
if [[ "${USE_COLOUR}" -eq 1 && -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET="${ESC}[0m"; C_RED="${ESC}[31m"; C_YELLOW="${ESC}[33m"; C_GREEN="${ESC}[32m"
  C_BLUE="${ESC}[36m"; C_BOLD="${ESC}[1m"; C_DIM="${ESC}[2m"
fi

N_OK=0; N_NOTE=0; N_WARN=0; N_HIGH=0; N_ALERT=0; N_INCOMPLETE=0; N_ACCEPTED=0
LIST_ALERT=""; LIST_HIGH=""; LIST_INCOMPLETE=""
FINDINGS="${TMP}/findings.tsv"; : > "${FINDINGS}"
CUR_PART="setup"; CUR_SECTION=""
MUTED=0            # 1 while the current finding is an accepted one (its hints are hidden)
LOCS_HIDDEN=0

say() {
  printf '%s\n' "$*"
  if [[ -n "${REPORT}" ]]; then
    printf '%s\n' "$*" | sed "s/${ESC}\[[0-9;]*m//g" >> "${REPORT}"
  fi
}
# Strip control characters from text that came out of a file or the network,
# so it can't play tricks with the terminal.
clean() { printf '%s' "$1" | tr -d '\000-\010\013-\037\177'; }
have() { command -v "$1" >/dev/null 2>&1; }
count_lines() { if [[ -s "$1" ]]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
plural() { if [[ "$1" -eq 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi; }
pj_has() { [[ -f "${PJ}" ]] && grep -qE "\"$1\"[[:space:]]*:" "${PJ}"; }
is_deep()  { [[ "${LEVEL}" == "deep" ]]; }
is_quick() { [[ "${LEVEL}" == "quick" ]]; }
with_timeout() {   # with_timeout SECONDS command...
  local secs="$1"; shift
  if have timeout; then timeout "${secs}" "$@"; else "$@"; fi
}

# ---- accepted findings (.nsc-ignore) ---------------------------------------
IGNORE_TSV="${TMP}/ignore.tsv"; : > "${IGNORE_TSV}"
HAVE_IGNORE=0; HAVE_IGNORE_LOCS=0; IGNORE_NOTES=""
[[ -z "${IGNORE_FILE}" ]] && IGNORE_FILE="${PROJECT_DIR}/.nsc-ignore"
if [[ -f "${IGNORE_FILE}" ]]; then
  while IFS= read -r _line || [[ -n "${_line}" ]]; do
    case "${_line}" in ""|"#"*) continue ;; esac
    _reason=""
    case "${_line}" in *"#"*) _reason="${_line#*#}"; _line="${_line%%#*}" ;; esac
    _reason="${_reason#"${_reason%%[![:space:]]*}"}"; _reason="${_reason%"${_reason##*[![:space:]]}"}"
    # shellcheck disable=SC2086  # deliberate word splitting into ID and glob
    set -- ${_line}
    [[ $# -eq 0 ]] && continue
    _id="$1"; _glob="${2:-}"
    case "${_id}" in *[!A-Z0-9*-]*|[!A-Z*]*) IGNORE_NOTES="${IGNORE_NOTES}  '$(clean "${_id}")' is not a finding ID, so that line was skipped.${NL}"; continue ;; esac
    if [[ -z "${_reason}" ]]; then
      IGNORE_NOTES="${IGNORE_NOTES}  ${_id} has no reason after a '#', so it is NOT accepted.${NL}"
      continue
    fi
    printf '%s%s%s%s%s\n' "${_id}" "${US}" "${_glob}" "${US}" "$(clean "${_reason}")" >> "${IGNORE_TSV}"
    HAVE_IGNORE=1
    [[ -n "${_glob}" ]] && HAVE_IGNORE_LOCS=1
  done < "${IGNORE_FILE}"
  set --
fi

# ignore_reason ID: print the reason if the whole finding is accepted.
ignore_reason() {
  local id="$1" pat glob reason
  while IFS="${US}" read -r pat glob reason; do
    [[ -n "${glob}" ]] && continue
    # shellcheck disable=SC2254  # the pattern is meant to be a glob
    case "${id}" in ${pat}) printf '%s' "${reason}"; return 0 ;; esac
  done < "${IGNORE_TSV}"
  return 1
}

# filter_locs ID FILE: drop accepted locations ("path:line" lines) from FILE.
filter_locs() {
  LOCS_HIDDEN=0
  [[ "${HAVE_IGNORE_LOCS}" -eq 1 && -s "$2" ]] || return 0
  local id="$1" file="$2" line path pat glob reason hit
  : > "${file}.keep"
  while IFS= read -r line; do
    path="${line%%:*}"; hit=0
    while IFS="${US}" read -r pat glob reason; do
      [[ -z "${glob}" ]] && continue
      # shellcheck disable=SC2254
      case "${id}" in ${pat}) case "${path}" in ${glob}) hit=1; break ;; esac ;; esac
    done < "${IGNORE_TSV}"
    if [[ "${hit}" -eq 1 ]]; then LOCS_HIDDEN=$((LOCS_HIDDEN + 1)); else printf '%s\n' "${line}" >> "${file}.keep"; fi
  done < "${file}"
  mv "${file}.keep" "${file}"
  N_ACCEPTED=$((N_ACCEPTED + LOCS_HIDDEN))
}

# ---- findings ---------------------------------------------------------------
_record() {   # level id message
  local m="$3"
  m="${m//${TAB}/ }"; m="${m//${NL}/ }"
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "${CUR_PART}" "${CUR_SECTION}" "${m}" >> "${FINDINGS}"
}
_find() {     # level id message
  local level="$1" id="$2" msg="$3" reason=""
  if [[ "${HAVE_IGNORE}" -eq 1 && "${level}" != "ok" && "${level}" != "alert" ]] && reason="$(ignore_reason "${id}")"; then
    N_ACCEPTED=$((N_ACCEPTED + 1)); MUTED=1
    say "  ${C_DIM}[SKIP] ${msg}  (${id}; accepted: ${reason})${C_RESET}"
    _record accepted "${id}" "${msg}"
    return 0
  fi
  MUTED=0
  case "${level}" in
    ok)         N_OK=$((N_OK + 1));       say "  ${C_GREEN}[ OK ]${C_RESET} ${msg}" ;;
    note)       N_NOTE=$((N_NOTE + 1));   say "  ${C_BLUE}[NOTE]${C_RESET} ${msg}  ${C_DIM}(${id})${C_RESET}" ;;
    warn)       N_WARN=$((N_WARN + 1));   say "  ${C_YELLOW}[WARN]${C_RESET} ${msg}  ${C_DIM}(${id})${C_RESET}" ;;
    high)       N_HIGH=$((N_HIGH + 1));   say "  ${C_RED}[HIGH]${C_RESET} ${msg}  ${C_DIM}(${id})${C_RESET}"
                LIST_HIGH="${LIST_HIGH}   - ${msg}${NL}" ;;
    alert)      N_ALERT=$((N_ALERT + 1)); say "  ${C_RED}${C_BOLD}[ALERT]${C_RESET} ${msg}  ${C_DIM}(${id})${C_RESET}"
                LIST_ALERT="${LIST_ALERT}   - ${msg}${NL}" ;;
    incomplete) N_INCOMPLETE=$((N_INCOMPLETE + 1)); say "  ${C_YELLOW}[ ?? ]${C_RESET} ${msg}  ${C_DIM}(${id})${C_RESET}"
                LIST_INCOMPLETE="${LIST_INCOMPLETE}   - ${msg}${NL}" ;;
  esac
  _record "${level}" "${id}" "${msg}"
}
ok()         { _find ok "$1" "$2"; }
note()       { _find note "$1" "$2"; }
warn()       { _find warn "$1" "$2"; }
high()       { _find high "$1" "$2"; }
alert()      { _find alert "$1" "$2"; }
incomplete() { _find incomplete "$1" "$2"; }
na()         { MUTED=0; say "  ${C_DIM}[ -- ] $*${C_RESET}"; }
hint()       { [[ "${MUTED}" -eq 1 ]] && return 0; say "         $*"; _record hint "" "$*"; }
section()    { CUR_PART="$1"; CUR_SECTION=""; MUTED=0; say ""; say "${C_BOLD}== $2 ==${C_RESET}"; }
subsection() { CUR_SECTION="$*"; MUTED=0; say ""; say "${C_BOLD}-- $* --${C_RESET}"; }

# show_locs FILE [MAX]: print up to MAX lines from FILE, indented.
show_locs() {
  [[ "${MUTED}" -eq 1 ]] && return 0
  local file="$1" max="${2:-5}" total line shown=0
  total="$(count_lines "${file}")"
  while IFS= read -r line; do
    [[ "${shown}" -ge "${max}" ]] && break
    line="$(clean "${line}")"
    say "           ${line}"
    _record loc "" "${line}"
    shown=$((shown + 1))
  done < "${file}"
  if [[ "${total}" -gt "${max}" ]]; then say "           ...and $((total - max)) more"; fi
}

IS_ROOT=0
if [[ "$(id -u 2>/dev/null || echo 1)" == "0" ]]; then IS_ROOT=1; fi
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
ME="$(id -un 2>/dev/null || echo unknown)"

# One snapshot of the running processes, used by detection and by part 3.
PS_FILE="${TMP}/ps.txt"
ps -e -o user= -o pid= -o args= > "${PS_FILE}" 2>/dev/null || : > "${PS_FILE}"

# A JavaScript runtime, used only to read JSON (audit results, OSV answers).
JS=""
if have node; then JS="node"; elif have bun; then JS="bun"; fi

# -------------------------------------------------------------- detection --
LOCKFILES=""
for _lf in package-lock.json npm-shrinkwrap.json pnpm-lock.yaml yarn.lock bun.lock bun.lockb; do
  [[ -f "${PROJECT_DIR}/${_lf}" ]] && LOCKFILES="${LOCKFILES} ${_lf}"
done
LOCKFILES="${LOCKFILES# }"

detect_pm() {
  local declared=""
  if [[ -f "${PJ}" ]]; then
    declared="$(grep -oE '"packageManager"[[:space:]]*:[[:space:]]*"[a-z]+' "${PJ}" 2>/dev/null | grep -oE '[a-z]+$' | head -n 1)"
  fi
  case "${declared}" in npm|pnpm|yarn|bun) echo "${declared}"; return ;; esac
  case " ${LOCKFILES} " in
    *" bun.lock "*|*" bun.lockb "*) echo bun ;;
    *" pnpm-lock.yaml "*)           echo pnpm ;;
    *" yarn.lock "*)                echo yarn ;;
    *)                              echo npm ;;
  esac
}

detect_server() {
  local f
  for f in vercel.json netlify.toml fly.toml render.yaml railway.json railway.toml wrangler.toml wrangler.jsonc app.yaml Procfile; do
    if [[ -f "${PROJECT_DIR}/${f}" ]]; then echo managed; return; fi
  done
  if [[ "${OS_NAME}" != "Linux" ]]; then echo dev; return; fi
  if have docker && { [[ -f "${PROJECT_DIR}/Dockerfile" ]] || [[ -f "${PROJECT_DIR}/docker-compose.yml" ]] || [[ -f "${PROJECT_DIR}/compose.yaml" ]] || [[ -f "${PROJECT_DIR}/compose.yml" ]]; }; then
    echo docker; return
  fi
  if [[ -n "${SSH_CONNECTION:-}" ]] || have nginx || have caddy || have apache2 || have httpd || have pm2; then
    echo vps; return
  fi
  echo dev
}

detect_proxy() {
  if grep -qE '(^|[/ ])nginx(:| |$)' "${PS_FILE}"; then echo nginx; return; fi
  if grep -qE '(^|[/ ])(apache2|httpd)( |$)' "${PS_FILE}"; then echo apache; return; fi
  if grep -qE '(^|[/ ])caddy( |$)' "${PS_FILE}"; then echo caddy; return; fi
  if have nginx; then echo nginx; return; fi
  if have apache2 || have httpd; then echo apache; return; fi
  if have caddy; then echo caddy; return; fi
  echo none
}

detect_runner() {
  if grep -qE 'PM2 v[0-9]' "${PS_FILE}" || have pm2; then echo pm2; return; fi
  if have systemctl; then echo systemd; return; fi
  echo other
}

DETECTED_PM="$(detect_pm)"
DETECTED_SERVER="$(detect_server)"
DETECTED_PROXY="$(detect_proxy)"
DETECTED_RUNNER="$(detect_runner)"

# ------------------------------------------------------------ setup menu --
REPLY_KEY=""; REPLY_TEXT=""; ASKED=0

# choose "Question" suggested-key "key|Label" ...   -> REPLY_KEY
choose() {
  local question="$1" suggested="$2"; shift 2
  local i=1 opt key label defnum=1 ans
  ASKED=1
  printf '\n%s\n' "${question}"
  for opt in "$@"; do
    key="${opt%%|*}"; label="${opt#*|}"
    if [[ "${key}" == "${suggested}" ]]; then
      defnum="${i}"; printf '  %d) %s  <- suggested\n' "${i}" "${label}"
    else
      printf '  %d) %s\n' "${i}" "${label}"
    fi
    i=$((i + 1))
  done
  while :; do
    printf 'Type a number and press Enter [%d]: ' "${defnum}"
    IFS= read -r ans || ans=""
    [[ -z "${ans}" ]] && ans="${defnum}"
    case "${ans}" in
      *[!0-9]*|0*) ;;
      *) if [[ "${#ans}" -le 3 && "${ans}" -ge 1 && "${ans}" -le $# ]]; then break; fi ;;
    esac
    printf '  Please type a number from 1 to %d.\n' "$#"
  done
  i=1
  for opt in "$@"; do
    [[ "${i}" -eq "${ans}" ]] && REPLY_KEY="${opt%%|*}"
    i=$((i + 1))
  done
}

# ask "Question" -> REPLY_TEXT
ask() {
  local ans=""
  ASKED=1
  printf '\n%s: ' "$1"
  IFS= read -r ans || ans=""
  REPLY_TEXT="${ans}"
}

# confirm "Question" -> returns 0 for yes (the default), 1 for no
confirm() {
  local ans=""
  printf '\n%s [Y/n]: ' "$1"
  IFS= read -r ans || ans=""
  case "${ans}" in n|N|no|No|NO) return 1 ;; esac
  return 0
}

if [[ "${INTERACTIVE}" == "auto" ]]; then
  if [[ -t 0 && -t 1 ]]; then INTERACTIVE=1; else INTERACTIVE=0; fi
fi

say "${C_BOLD}node-security-check.sh ${VERSION}${C_RESET}  (read-only: it writes nothing except the reports and settings you ask for)"
say "Project: ${PROJECT_DIR}"
[[ -n "${CONFIG_USED}" ]] && say "Using saved answers from ${CONFIG_USED}  (--ask to be asked again)"
if [[ -n "${IGNORE_NOTES}" ]]; then
  say "${C_YELLOW}Problems in ${IGNORE_FILE}:${C_RESET}"
  printf '%s' "${IGNORE_NOTES}" | while IFS= read -r _l; do say "${_l}"; done
fi

if [[ "${INTERACTIVE}" -eq 1 ]]; then
  printf '\nA few questions about your setup. Press Enter to accept a suggestion.\n'

  if [[ -z "${ONLY}" && -z "${SKIP}" ]]; then
    choose "What do you want to check?" all \
      "all|Everything: packages, code and server" \
      "pkgcode|Packages and code only" \
      "packages|Packages only" \
      "code|Code only" \
      "server|Server only"
    case "${REPLY_KEY}" in
      pkgcode)  DO_SERVER=0 ;;
      packages) DO_CODE=0; DO_SERVER=0 ;;
      code)     DO_PKG=0; DO_SERVER=0 ;;
      server)   DO_PKG=0; DO_CODE=0 ;;
    esac
  fi

  if [[ "${LEVEL}" == "auto" ]]; then
    choose "How thorough should it be?" standard \
      "quick|Quick: the fast checks only (a few seconds)" \
      "standard|Standard: everything except the slow checks" \
      "deep|Deep: everything, including git history, TLS probing and specialist tools (minutes)"
    LEVEL="${REPLY_KEY}"
  fi

  if [[ "${DO_PKG}" -eq 1 && "${PM}" == "auto" ]]; then
    choose "Which package manager does this project use?" "${DETECTED_PM}" \
      "npm|npm" "pnpm|pnpm" "yarn|Yarn" "bun|Bun"
    PM="${REPLY_KEY}"
  fi

  if [[ "${DO_SERVER}" -eq 1 ]]; then
    if [[ "${SERVER}" == "auto" ]]; then
      choose "Where does the app run?" "${DETECTED_SERVER}" \
        "vps|On this machine: a Linux server or VPS" \
        "docker|In Docker containers on this machine" \
        "managed|On a hosting platform (Vercel, Netlify, Render, Railway, Fly.io...)" \
        "dev|Somewhere else: this is my development machine"
      SERVER="${REPLY_KEY}"
    fi
    if [[ "${SERVER}" == "vps" || "${SERVER}" == "docker" ]]; then
      if [[ "${PROXY}" == "auto" ]]; then
        choose "What sits in front of Node and receives the web traffic?" "${DETECTED_PROXY}" \
          "nginx|nginx" "apache|Apache" "caddy|Caddy" "none|Nothing: Node answers directly (or I don't know)"
        PROXY="${REPLY_KEY}"
      fi
    fi
    if [[ "${SERVER}" == "vps" ]]; then
      if [[ "${RUNNER}" == "auto" ]]; then
        choose "What keeps the app running?" "${DETECTED_RUNNER}" \
          "systemd|A systemd service" "pm2|PM2" "other|Something else (or I don't know)"
        RUNNER="${REPLY_KEY}"
      fi
      if [[ "${RUNNER}" == "systemd" && "${SERVICE_GIVEN}" -eq 0 ]]; then
        ask "Name of the systemd service (leave empty to skip that check)"
        SERVICE="${REPLY_TEXT}"
      fi
    fi
    if [[ "${SERVER}" == "docker" && "${CONTAINER_GIVEN}" -eq 0 ]]; then
      ask "Name of the app's container (leave empty to check every Node container)"
      CONTAINER="${REPLY_TEXT}"
    fi
    if [[ "${URL_GIVEN}" -eq 0 && "${NO_NETWORK}" -eq 0 ]]; then
      ask "Live address of the site, for HTTPS, header and DNS checks, e.g. https://example.com (leave empty to skip)"
      URL="${REPLY_TEXT}"
    fi
  fi
fi

[[ "${PM}" == "auto" ]]     && PM="${DETECTED_PM}"
[[ "${SERVER}" == "auto" ]] && SERVER="${DETECTED_SERVER}"
[[ "${PROXY}" == "auto" ]]  && PROXY="${DETECTED_PROXY}"
[[ "${RUNNER}" == "auto" ]] && RUNNER="${DETECTED_RUNNER}"
[[ "${LEVEL}" == "auto" ]]  && LEVEL="standard"
check_values

if [[ ("${DO_PKG}" -eq 1 || "${DO_CODE}" -eq 1) && ! -f "${PJ}" ]]; then
  echo "ERROR: ${PJ} not found. Point the script at a Node.js project folder," >&2
  echo "       or use --only server to check just the machine." >&2
  exit 3
fi
if [[ $((DO_PKG + DO_CODE + DO_SERVER)) -eq 0 ]]; then die_usage "every part was skipped; nothing to check."; fi

server_label() {
  case "$1" in
    vps) echo "this machine is the Linux server" ;;
    docker) echo "Docker containers on this machine" ;;
    managed) echo "a hosting platform" ;;
    dev) echo "development machine (server is elsewhere)" ;;
  esac
}
_parts=""
[[ "${DO_PKG}" -eq 1 ]]    && _parts="${_parts}packages, "
[[ "${DO_CODE}" -eq 1 ]]   && _parts="${_parts}code, "
[[ "${DO_SERVER}" -eq 1 ]] && _parts="${_parts}server, "
say ""
say "Setup"
say "  Checking         : ${_parts%, }"
say "  Thoroughness     : ${LEVEL}"
[[ "${DO_PKG}" -eq 1 ]] && say "  Package manager  : ${PM}   (audit fails at: ${FAIL_ON} and above)"
if [[ "${DO_SERVER}" -eq 1 ]]; then
  say "  App runs on      : $(server_label "${SERVER}")"
  if [[ "${SERVER}" == "vps" || "${SERVER}" == "docker" ]]; then say "  In front of Node : ${PROXY}"; fi
  if [[ "${SERVER}" == "vps" ]]; then say "  Kept running by  : ${RUNNER}${SERVICE:+ (service: ${SERVICE})}"; fi
  if [[ "${SERVER}" == "docker" ]]; then say "  Container        : ${CONTAINER:-every Node container}"; fi
  say "  Live address     : ${URL:-not given}"
fi
[[ "${HAVE_IGNORE}" -eq 1 ]] && say "  Accepted findings: $(count_lines "${IGNORE_TSV}") from ${IGNORE_FILE}"

save_config() {
  {
    echo "# Saved answers for node-security-check.sh. Delete this file, or run"
    echo "# with --ask, to be asked again. Command-line options override it."
    echo "pm = ${PM}"
    echo "level = ${LEVEL}"
    echo "server = ${SERVER}"
    echo "proxy = ${PROXY}"
    echo "runner = ${RUNNER}"
    echo "service = ${SERVICE:-none}"
    echo "container = ${CONTAINER:-none}"
    echo "url = ${URL:-none}"
    echo "fail_on = ${FAIL_ON}"
  } > "${CONFIG_FILE}" 2>/dev/null
}

if [[ "${INTERACTIVE}" -eq 1 ]]; then
  if [[ "${SAVE_CONFIG}" -eq 0 && "${ASKED}" -eq 1 ]]; then
    if confirm "Save these answers to ${CONFIG_FILE} so you aren't asked next time?"; then SAVE_CONFIG=1; fi
  fi
  if ! confirm "Start the check?"; then
    echo "Cancelled. Nothing was checked."
    exit 3
  fi
fi
if [[ "${SAVE_CONFIG}" -eq 1 ]]; then
  if save_config; then say "  Answers saved to ${CONFIG_FILE}"; else say "  ${C_YELLOW}Couldn't write ${CONFIG_FILE}; answers not saved.${C_RESET}"; fi
fi

# Is the project a usable git repository with committed files?
GIT_OK=0
if have git && git -C "${PROJECT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -n "$(git -C "${PROJECT_DIR}" ls-files -- . 2>/dev/null | head -n 1)" ]]; then GIT_OK=1; fi
fi
SCAN_SCOPE="the project files"

# ============================================================ PART 1 ======
# Known-compromised versions. "@@ label" starts an incident; then one package
# per line: name version [version...]
builtin_iocs() {
  cat <<'EOF'
@@ TanStack 2026-05 (GHSA-g7cv-rxg3-hmpx)
@tanstack/arktype-adapter 1.166.12 1.166.15
@tanstack/eslint-plugin-router 1.161.9 1.161.12
@tanstack/eslint-plugin-start 0.0.4 0.0.7
@tanstack/history 1.161.9 1.161.12
@tanstack/nitro-v2-vite-plugin 1.154.12 1.154.15
@tanstack/react-router 1.169.5 1.169.8
@tanstack/react-router-devtools 1.166.16 1.166.19
@tanstack/react-router-ssr-query 1.166.15 1.166.18
@tanstack/react-start 1.167.68 1.167.71
@tanstack/react-start-client 1.166.51 1.166.54
@tanstack/react-start-rsc 0.0.47 0.0.50
@tanstack/react-start-server 1.166.55 1.166.58
@tanstack/router-cli 1.166.46 1.166.49
@tanstack/router-core 1.169.5 1.169.8
@tanstack/router-devtools 1.166.16 1.166.19
@tanstack/router-devtools-core 1.167.6 1.167.9
@tanstack/router-generator 1.166.45 1.166.48
@tanstack/router-plugin 1.167.38 1.167.41
@tanstack/router-ssr-query-core 1.168.3 1.168.6
@tanstack/router-utils 1.161.11 1.161.14
@tanstack/router-vite-plugin 1.166.53 1.166.56
@tanstack/solid-router 1.169.5 1.169.8
@tanstack/solid-router-devtools 1.166.16 1.166.19
@tanstack/solid-router-ssr-query 1.166.15 1.166.18
@tanstack/solid-start 1.167.65 1.167.68
@tanstack/solid-start-client 1.166.50 1.166.53
@tanstack/solid-start-server 1.166.54 1.166.57
@tanstack/start-client-core 1.168.5 1.168.8
@tanstack/start-fn-stubs 1.161.9 1.161.12
@tanstack/start-plugin-core 1.169.23 1.169.26
@tanstack/start-server-core 1.167.33 1.167.36
@tanstack/start-static-server-functions 1.166.44 1.166.47
@tanstack/start-storage-context 1.166.38 1.166.41
@tanstack/valibot-adapter 1.166.12 1.166.15
@tanstack/virtual-file-routes 1.161.10 1.161.13
@tanstack/vue-router 1.169.5 1.169.8
@tanstack/vue-router-devtools 1.166.16 1.166.19
@tanstack/vue-router-ssr-query 1.166.15 1.166.18
@tanstack/vue-start 1.167.61 1.167.64
@tanstack/vue-start-client 1.166.46 1.166.49
@tanstack/vue-start-server 1.166.50 1.166.53
@tanstack/zod-adapter 1.166.12 1.166.15
@@ axios 2026-03
axios 1.14.1 0.30.4
plain-crypto-js 4.2.1
@@ chalk/debug 2025-09
ansi-regex 6.2.1
ansi-styles 6.2.2
backslash 0.2.1
chalk 5.6.1
chalk-template 1.1.1
color 5.0.1
color-convert 3.1.1
color-name 2.0.1
color-string 2.1.1
debug 4.4.2
error-ex 1.3.3
has-ansi 6.0.1
is-arrayish 0.3.3
simple-swizzle 0.2.3
slice-ansi 7.1.1
strip-ansi 7.1.1
supports-color 10.2.1
supports-hyperlinks 4.1.1
wrap-ansi 9.0.1
@duckdb/node-api 1.3.3
@duckdb/node-bindings 1.3.3
@@ Nx 2025-08 (GHSA-cxm3-wv7p-598c)
nx 20.9.0 20.10.0 20.11.0 20.12.0 21.5.0 21.6.0 21.7.0 21.8.0
@nx/devkit 20.9.0 21.5.0
@nx/js 20.9.0 21.5.0
@nx/workspace 20.9.0 21.5.0
@nx/node 20.9.0 21.5.0
@nx/eslint 21.5.0
@nx/key 3.2.0
@nx/enterprise-cloud 3.2.0
EOF
}

# Strings that should never appear in a lockfile or package.json.
MARKERS="@tanstack/setup
tanstack/router#79ac49e
79ac49eedf774dd4b0cfa308722bc463cfe5885c
router_init.js
router_runtime.js
tanstack_runner.js
gh-token-monitor
git-tanstack.com
getsession.org
litter.catbox.moe
api.masscan.cloud
setup_bun.js
bun_environment.js
plain-crypto-js"

# lock_inventory FILE: print "name<TAB>version" for every package in a lockfile.
lock_inventory() {
  case "$(basename "$1")" in
    package-lock.json|npm-shrinkwrap.json)
      awk '
        /^[[:space:]]*"[^"]*":[[:space:]]*\{[[:space:]]*$/ {
          key = $0
          sub(/^[[:space:]]*"/, "", key)
          sub(/":[[:space:]]*\{[[:space:]]*$/, "", key)
          while ((i = index(key, "node_modules/")) > 0) key = substr(key, i + 13)
          name = key; since = 0
          next
        }
        { since++ }
        since <= 2 && /^[[:space:]]*"name":[[:space:]]*"/ {
          v = $0; sub(/^[[:space:]]*"name":[[:space:]]*"/, "", v); sub(/".*$/, "", v); name = v; next
        }
        since <= 2 && name != "" && /^[[:space:]]*"version":[[:space:]]*"/ {
          v = $0; sub(/^[[:space:]]*"version":[[:space:]]*"/, "", v); sub(/".*$/, "", v)
          print name "\t" v; name = ""
        }
      ' "$1" ;;
    pnpm-lock.yaml)
      awk '
        /^[^[:space:]#]/ { sec = $0; sub(/:.*$/, "", sec); next }
        (sec == "packages" || sec == "snapshots") && /^  [^[:space:]]/ {
          k = $0
          sub(/^  /, "", k)
          sub(/:[[:space:]]*(\{\})?[[:space:]]*$/, "", k)
          gsub(/^[\047"]|[\047"]$/, "", k)
          if (k ~ "^/(@[^/]+/)?[^/@]+/[0-9]") {
            # pnpm 7 and older: /name/1.2.3_peers
            sub("^/", "", k)
            n = split(k, p, "/")
            if (substr(k, 1, 1) == "@") { name = p[1] "/" p[2]; ver = p[3] } else { name = p[1]; ver = p[2] }
            sub(/_.*$/, "", ver)
          } else {
            sub("^/", "", k)
            sub(/\(.*$/, "", k)
            at = 0
            for (i = length(k); i > 1; i--) if (substr(k, i, 1) == "@") { at = i; break }
            if (at == 0) next
            name = substr(k, 1, at - 1); ver = substr(k, at + 1)
          }
          if (name != "" && ver != "") print name "\t" ver
        }
      ' "$1" ;;
    yarn.lock)
      awk '
        /^[^[:space:]#].*:[[:space:]]*$/ {
          k = $0
          sub(/:[[:space:]]*$/, "", k)
          sub(/,.*$/, "", k)
          gsub(/"/, "", k)
          at = index(substr(k, 2), "@")
          name = (at > 0) ? substr(k, 1, at) : k
          if (name == "__metadata") name = ""
          next
        }
        /^  version:?[[:space:]]/ && name != "" {
          v = $0; sub(/^  version:?[[:space:]]*/, "", v); gsub(/"/, "", v)
          print name "\t" v
          next
        }
        /^  resolution:[[:space:]]/ {
          # Yarn 2+: the real package behind an alias, e.g. "real@npm:1.2.3"
          r = $0; sub(/^  resolution:[[:space:]]*/, "", r); gsub(/"/, "", r)
          at = index(substr(r, 2), "@")
          if (at > 0) {
            rn = substr(r, 1, at); rv = substr(r, at + 2); sub(/^npm:/, "", rv)
            print rn "\t" rv
          }
        }
      ' "$1" ;;
    bun.lock)
      grep -oE '\["[^"]+@[^"]+"' "$1" 2>/dev/null | sed -e 's/^\["//' -e 's/"$//' | awk '
        { at = index(substr($0, 2), "@"); if (at > 0) print substr($0, 1, at) "\t" substr($0, at + 2) }
      ' ;;
  esac
}

# Counts the findings in the JSON that each package manager's audit prints.
read -r -d '' AUDIT_JS <<'EOF' || true
const fs = require("fs");
const text = fs.readFileSync(process.env.NSC_AUDIT_FILE, "utf8");
const c = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };
const details = [];
const tidy = (s) => String(s == null ? "" : s).replace(/[^\x20-\x7e]/g, "").slice(0, 90);
const sev = (s) => { s = String(s || "").toLowerCase(); return s in c ? s : null; };
const detail = (s, pkg, title) => { if (sev(s)) details.push([sev(s), tidy(pkg), tidy(title)]); };
const addCounts = (v) => { for (const k in c) if (typeof v[k] === "number") c[k] += v[k]; };
function whole(o) {
  if (!o || typeof o !== "object" || Array.isArray(o) || o.error) return false;
  if (o.metadata && o.metadata.vulnerabilities && typeof o.metadata.vulnerabilities === "object") {
    addCounts(o.metadata.vulnerabilities);
    if (o.vulnerabilities && typeof o.vulnerabilities === "object") {           // npm 7+
      for (const name in o.vulnerabilities) {
        const v = o.vulnerabilities[name] || {};
        const via = (Array.isArray(v.via) ? v.via : []).find((x) => x && typeof x === "object");
        detail(v.severity, name, via ? via.title : "via a dependency");
      }
    }
    if (o.advisories && typeof o.advisories === "object") {                     // npm 6, pnpm, Yarn 2-3
      for (const id in o.advisories) { const a = o.advisories[id] || {}; detail(a.severity, a.module_name, a.title); }
    }
    return true;
  }
  const vals = Object.values(o);                                                // Bun: { pkg: [advisory...] }
  if (vals.every(Array.isArray)) {
    for (const name in o) for (const a of o[name]) {
      if (a && sev(a.severity)) { c[sev(a.severity)]++; detail(a.severity, name, a.title); }
    }
    return true;
  }
  return false;
}
function lines(t) {                                                             // Yarn prints one JSON object per line
  let seen = false;
  for (const line of t.split("\n")) {
    const s = line.trim();
    if (!s.startsWith("{")) continue;
    let o; try { o = JSON.parse(s); } catch (e) { continue; }
    if (o.type === "auditSummary" && o.data && o.data.vulnerabilities) { addCounts(o.data.vulnerabilities); seen = true; }
    else if (o.type === "auditAdvisory" && o.data && o.data.advisory) { const a = o.data.advisory; detail(a.severity, a.module_name, a.title); }
    else if (o.children && sev(o.children.Severity)) { c[sev(o.children.Severity)]++; detail(o.children.Severity, o.value, o.children.Issue); seen = true; }
  }
  return seen;
}
let done = false;
const t = text.trim();
if (t === "" && process.env.NSC_EMPTY_OK === "1") done = true;
if (!done) { try { done = whole(JSON.parse(t)); } catch (e) { done = false; } }
if (!done) {
  const a = t.indexOf("{"), b = t.lastIndexOf("}");
  if (a >= 0 && b > a) { try { done = whole(JSON.parse(t.slice(a, b + 1))); } catch (e) { done = false; } }
}
if (!done) done = lines(t);
if (!done) process.exit(1);
console.log([c.critical, c.high, c.moderate, c.low].join(" "));
const order = { critical: 0, high: 1, moderate: 2, low: 3, info: 4 };
const seenKey = new Set();
details.sort((x, y) => order[x[0]] - order[y[0]]);
for (const d of details) { const k = d.join("|"); if (seenKey.has(k)) continue; seenKey.add(k); console.log("D\t" + d.join("\t")); }
EOF

# Reads an OSV /v1/querybatch answer. Results come back in the order asked.
read -r -d '' OSV_JS <<'EOF' || true
const fs = require("fs");
const resp = JSON.parse(fs.readFileSync(process.env.NSC_OSV_RESP, "utf8"));
const keys = fs.readFileSync(process.env.NSC_OSV_KEYS, "utf8").split("\n").filter(Boolean);
if (!resp || !Array.isArray(resp.results) || resp.results.length !== keys.length) process.exit(1);
let other = 0;
resp.results.forEach((r, i) => {
  for (const v of (r && r.vulns) || []) {
    const id = String(v.id || "").replace(/[^A-Za-z0-9-]/g, "");
    if (id.startsWith("MAL-")) console.log("MAL\t" + keys[i] + "\t" + id); else other++;
  }
});
console.log("OTHER\t" + other);
EOF

# Reads "npm view name@version name version deprecated time --json".
read -r -d '' AGE_JS <<'EOF' || true
const fs = require("fs");
let o; try { o = JSON.parse(fs.readFileSync(process.env.NSC_VIEW_FILE, "utf8")); } catch (e) { process.exit(1); }
if (Array.isArray(o)) o = o[0];
if (!o || typeof o !== "object" || o.error) process.exit(1);
const tidy = (s) => String(s == null ? "" : s).replace(/[^\x20-\x7e]/g, "").slice(0, 100);
const now = Date.parse(process.env.NSC_TODAY + "T12:00:00Z");
if (o.deprecated) console.log("DEPRECATED\t" + tidy(o.deprecated));
const t = o.time || {};
const mine = Date.parse(t[o.version] || "");
if (!isNaN(mine)) { const days = Math.floor((now - mine) / 86400000); if (days < 7) console.log("NEW\t" + Math.max(days, 0)); }
let newest = 0;
for (const k in t) { if (k === "created" || k === "modified") continue; const d = Date.parse(t[k]); if (!isNaN(d) && d > newest) newest = d; }
if (newest > 0) { const years = (now - newest) / (365.25 * 86400000); if (years >= 3) console.log("STALE\t" + Math.floor(years)); }
console.log("OK");
EOF

node_eol_date() {
  case "$1" in
    26) echo 2029-04-30 ;;
    24) echo 2028-04-30 ;;
    22) echo 2027-04-30 ;;
    20) echo 2026-04-30 ;;
    18) echo 2025-04-30 ;;
    16) echo 2023-09-11 ;;
    25) echo 2026-06-01 ;;
    23) echo 2025-06-01 ;;
    21) echo 2024-06-01 ;;
    *)  if [[ "$1" -lt 26 ]]; then echo 2000-01-01; else echo unknown; fi ;;
  esac
}
NODE_MAJORS_SEEN=" "
check_node_major() {   # $1 major version, $2 where it came from
  local major="$1" where="$2" eol
  case "${major}" in ""|*[!0-9]*) return ;; esac
  [[ "${#major}" -gt 3 ]] && return
  # The same version found in two places (installed, running) is reported once.
  case "${NODE_MAJORS_SEEN}" in *" ${major} "*) return ;; esac
  NODE_MAJORS_SEEN="${NODE_MAJORS_SEEN}${major} "
  eol="$(node_eol_date "${major}")"
  if [[ "${eol}" == "unknown" ]]; then
    ok PKG-NODE-EOL "Node.js ${major} (${where}) is newer than this script's end-of-life table."
  elif [[ "${eol}" == "2000-01-01" ]]; then
    warn PKG-NODE-EOL "Node.js ${major} (${where}) reached end of life long ago and gets no security fixes."
    hint "Move to a supported LTS release: https://nodejs.org/en/about/previous-releases"
  elif [[ "${TODAY}" > "${eol}" ]]; then
    warn PKG-NODE-EOL "Node.js ${major} (${where}) reached end of life on ${eol} and gets no security fixes."
    hint "Move to a supported LTS release: https://nodejs.org/en/about/previous-releases"
  else
    ok PKG-NODE-EOL "Node.js ${major} (${where}) is supported until ${eol}."
  fi
}

INV="${TMP}/inventory.tsv"          # name<TAB>version from the lockfile(s)
INV_NM="${TMP}/inventory-nm.tsv"    # name<TAB>version from node_modules
IOCS="${TMP}/iocs.tsv"              # name<TAB>version<TAB>incident
DEPS="${TMP}/deps.txt"              # the dependency sections of package.json

build_iocs() {
  {
    builtin_iocs | awk '/^@@ / { label = substr($0, 4); next } NF >= 2 { for (i = 2; i <= NF; i++) print $1 "\t" $i "\t" label }'
    if [[ -n "${IOC_FILES}" ]]; then
      printf '%s' "${IOC_FILES}" | while IFS= read -r f; do
        [[ -n "${f}" ]] && sed -e 's/#.*$//' "${f}" | awk 'NF >= 2 { for (i = 2; i <= NF; i++) print $1 "\t" $i "\tyour list" }'
      done
    fi
  } > "${IOCS}"
}

# The dependency sections of package.json only (so "homepage" and
# "repository" addresses are not mistaken for dependencies).
build_deps() {
  awk '
    /"(dependencies|devDependencies|optionalDependencies|peerDependencies)"[[:space:]]*:[[:space:]]*\{/ {
      rest = $0; sub(/^.*ependencies"[[:space:]]*:[[:space:]]*\{/, "", rest)
      if (rest ~ /\}/) { sub(/\}.*$/, "", rest); print rest } else { if (rest != "") print rest; inside = 1 }
      next
    }
    inside && /\}/ { inside = 0; next }
    inside { print }
  ' "${PJ}" > "${DEPS}" 2>/dev/null
}

part_packages() {
  section packages "Part 1 of 3: packages and dependencies"
  build_deps

  # ---- lockfile ----------------------------------------------------------
  subsection "Lockfile"
  local lf count=0 pm_lock=""
  for lf in ${LOCKFILES}; do count=$((count + 1)); done
  case "${PM}" in
    npm)  for lf in package-lock.json npm-shrinkwrap.json; do [[ -f "${PROJECT_DIR}/${lf}" ]] && pm_lock="${lf}"; done ;;
    pnpm) [[ -f "${PROJECT_DIR}/pnpm-lock.yaml" ]] && pm_lock="pnpm-lock.yaml" ;;
    yarn) [[ -f "${PROJECT_DIR}/yarn.lock" ]] && pm_lock="yarn.lock" ;;
    bun)  [[ -f "${PROJECT_DIR}/bun.lock" ]] && pm_lock="bun.lock" ;;
  esac
  if [[ "${count}" -eq 0 ]]; then
    warn PKG-NO-LOCKFILE "No lockfile found. Without one, every install can pull in different versions."
    hint "Run your package manager's install once and commit the lockfile it writes."
  else
    ok PKG-LOCKFILE "Lockfile(s) found: ${LOCKFILES}"
    if [[ -z "${pm_lock}" ]]; then
      warn PKG-LOCKFILE-MISMATCH "None of them belongs to ${PM}. Check the package manager choice."
    fi
    if [[ "${count}" -gt 1 ]]; then
      warn PKG-LOCKFILE-MANY "More than one lockfile. Keep the one your package manager uses and delete the others."
    fi
  fi
  if [[ -f "${PROJECT_DIR}/bun.lockb" ]]; then
    if [[ -f "${PROJECT_DIR}/bun.lock" ]]; then
      note PKG-LOCKB "bun.lockb (the old binary format) is ignored; bun.lock is read instead."
    else
      incomplete PKG-LOCKB "bun.lockb is Bun's old binary lockfile and can't be read by this script."
      hint "Convert it with: bun install --save-text-lockfile   (Bun 1.2 or newer)"
    fi
  fi
  if [[ -n "${pm_lock}" && "${GIT_OK}" -eq 1 ]]; then
    if git -C "${PROJECT_DIR}" ls-files --error-unmatch "${pm_lock}" >/dev/null 2>&1; then
      ok PKG-LOCKFILE-GIT "${pm_lock} is committed to git."
    else
      warn PKG-LOCKFILE-GIT "${pm_lock} is not committed to git, so other machines may install different versions."
    fi
  fi

  # ---- known-compromised versions ---------------------------------------
  subsection "Known-compromised package versions"
  local hits="${TMP}/ioc-hits.txt"
  : > "${INV}"; : > "${INV_NM}"
  for lf in ${LOCKFILES}; do
    [[ "${lf}" == "bun.lockb" ]] && continue
    lock_inventory "${PROJECT_DIR}/${lf}" >> "${INV}" 2>/dev/null
  done
  sort -u "${INV}" -o "${INV}"
  build_iocs
  local n_inv n_ioc
  n_inv="$(count_lines "${INV}")"
  n_ioc="$(count_lines "${IOCS}")"
  if [[ "${n_inv}" -eq 0 ]]; then
    if [[ "${count}" -gt 0 ]]; then
      incomplete PKG-IOC "Couldn't read any package versions from the lockfile(s), so this check did not run."
    else
      na "No lockfile to check."
    fi
  else
    awk -F '\t' 'NR == FNR { bad[$1 FS $2] = $3; next } ($1 FS $2) in bad { print $1 "@" $2 "\t" bad[$1 FS $2] }' \
      "${IOCS}" "${INV}" > "${hits}"
    if [[ -s "${hits}" ]]; then
      local h_pkg h_src
      while IFS="${TAB}" read -r h_pkg h_src; do
        alert PKG-IOC "Known-malicious version in the lockfile: $(clean "${h_pkg}")  (source: $(clean "${h_src}"))"
      done < "${hits}"
    else
      ok PKG-IOC "None of the ${n_inv} package versions in the lockfile(s) is on the known-bad list (${n_ioc} entries)."
    fi
  fi

  # ---- malware markers ---------------------------------------------------
  subsection "Malware markers"
  local marker found_marker=0 f
  while IFS= read -r marker; do
    [[ -z "${marker}" ]] && continue
    for f in package.json ${LOCKFILES}; do
      [[ "${f}" == "bun.lockb" ]] && continue
      if grep -qF -- "${marker}" "${PROJECT_DIR}/${f}" 2>/dev/null; then
        alert PKG-MARKER "Malware marker '${marker}' found in ${f}"
        found_marker=1
      fi
    done
  done <<EOF
${MARKERS}
EOF
  [[ "${found_marker}" -eq 0 ]] && ok PKG-MARKER "No known malware markers in package.json or the lockfile(s)."

  local found_file=0 p
  for p in \
    "${HOME:-/nonexistent}/.config/systemd/user/gh-token-monitor.service" \
    "/root/.config/systemd/user/gh-token-monitor.service" \
    "${HOME:-/nonexistent}/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
    "${HOME:-/nonexistent}/.local/bin/gh-token-monitor.sh" \
    "${PROJECT_DIR}/.claude/router_runtime.js" \
    "${PROJECT_DIR}/.claude/setup.mjs" \
    "${PROJECT_DIR}/.vscode/setup.mjs" \
    "${PROJECT_DIR}/setup_bun.js" \
    "${PROJECT_DIR}/bun_environment.js" \
    "${PROJECT_DIR}/.github/workflows/shai-hulud-workflow.yml"
  do
    if [[ -e "${p}" ]]; then
      alert PKG-LEFTOVER "File left behind by a known npm malware payload: ${p}"
      found_file=1
    fi
  done
  for p in "${PROJECT_DIR}/.claude/settings.json" "${PROJECT_DIR}/.vscode/tasks.json"; do
    if [[ -f "${p}" ]] && grep -qE 'setup\.mjs|router_runtime\.js' "${p}" 2>/dev/null; then
      alert PKG-LEFTOVER "${p} runs setup.mjs or router_runtime.js, as the TanStack payload does"
      found_file=1
    fi
  done
  [[ "${found_file}" -eq 0 ]] && ok PKG-LEFTOVER "No files left behind by known payloads in the home folder or the project."
  if [[ -f "${PROJECT_DIR}/.github/workflows/codeql_analysis.yml" ]]; then
    warn PKG-WORKFLOW-NAME ".github/workflows/codeql_analysis.yml exists. The TanStack payload adds a workflow with this name."
    hint "GitHub's own template is codeql-analysis.yml (hyphen). Check that you wrote this file."
  fi
  if [[ -f "${PROJECT_DIR}/.github/workflows/discussion.yaml" ]]; then
    warn PKG-WORKFLOW-NAME ".github/workflows/discussion.yaml exists. The Shai-Hulud worm adds a workflow with this name."
    hint "Check that you wrote this file, and that it doesn't run on a self-hosted runner you don't know."
  fi

  # ---- what is really installed -------------------------------------------
  if ! is_quick; then
    subsection "Installed packages (node_modules)"
    scan_node_modules
  fi

  # ---- OSV: every known malicious package ---------------------------------
  if ! is_quick; then
    subsection "Known malicious packages (OSV database)"
    osv_lookup
  fi

  # ---- audit -------------------------------------------------------------
  subsection "Known vulnerabilities (${PM} audit)"
  run_audit

  # ---- registry: signatures, deprecated and very new packages -------------
  if is_deep; then
    subsection "Registry checks (signatures, deprecated and very new packages)"
    registry_checks
  fi

  # ---- install settings --------------------------------------------------
  subsection "Install settings"
  install_settings

  # ---- Node.js version ---------------------------------------------------
  subsection "Node.js version"
  local nv="" pinned=""
  if have node; then
    nv="$(node --version 2>/dev/null | sed -e 's/^v//' -e 's/\..*$//')"
    check_node_major "${nv}" "installed on this machine"
  else
    na "node is not installed on this machine."
  fi
  for f in .nvmrc .node-version; do
    if [[ -f "${PROJECT_DIR}/${f}" ]]; then
      pinned="$(head -n 1 "${PROJECT_DIR}/${f}" | sed -e 's/^v//' -e 's/\..*$//' | tr -d '[:space:]')"
      [[ "${pinned}" != "${nv}" ]] && check_node_major "${pinned}" "set in ${f}"
    fi
  done
}

scan_node_modules() {
  local nm="${PROJECT_DIR}/node_modules" all="${TMP}/nm-all.txt" pj="${TMP}/nm-pj.txt"
  if [[ ! -d "${nm}" ]]; then
    na "No node_modules folder here, so only the lockfile was checked."
    return
  fi
  find "${nm}" -type f \( -name package.json -o -name setup_bun.js -o -name bun_environment.js \
    -o -name router_init.js -o -name router_runtime.js -o -name tanstack_runner.js \) 2>/dev/null | head -n 60000 > "${all}"
  grep -E '/node_modules/(@[^/]+/)?[^/]+/package\.json$' "${all}" > "${pj}" || true

  # Payload files.
  grep -E '/(setup_bun|bun_environment)\.js$|/@tanstack/.*/(router_init|router_runtime|tanstack_runner)\.js$' "${all}" \
    | sed "s|^${PROJECT_DIR}/||" > "${TMP}/nm-payload.txt" || true
  if [[ -s "${TMP}/nm-payload.txt" ]]; then
    alert PKG-NM-PAYLOAD "Malware payload file(s) inside node_modules:"
    show_locs "${TMP}/nm-payload.txt" 5
  else
    ok PKG-NM-PAYLOAD "No known payload files inside node_modules."
  fi

  # Installed versions against the known-bad list (catches what a lockfile doesn't show).
  if [[ -s "${pj}" ]]; then
    tr '\n' '\0' < "${pj}" | xargs -0 awk '
      function flush() { if (n != "" && v != "") print n "\t" v }
      FNR == 1 { flush(); n = ""; v = "" }
      n == "" && match($0, /"name"[[:space:]]*:[[:space:]]*"[^"]*"/) {
        s = substr($0, RSTART, RLENGTH); sub(/^"name"[[:space:]]*:[[:space:]]*"/, "", s); sub(/"$/, "", s); n = s
      }
      v == "" && match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]*"/) {
        s = substr($0, RSTART, RLENGTH); sub(/^"version"[[:space:]]*:[[:space:]]*"/, "", s); sub(/"$/, "", s); v = s
      }
      END { flush() }
    ' 2>/dev/null | sort -u > "${INV_NM}"
  fi
  local n_nm
  n_nm="$(count_lines "${INV_NM}")"
  if [[ "${n_nm}" -gt 0 ]]; then
    awk -F '\t' 'NR == FNR { bad[$1 FS $2] = $3; next } ($1 FS $2) in bad { print $1 "@" $2 "\t" bad[$1 FS $2] }' \
      "${IOCS}" "${INV_NM}" > "${TMP}/nm-hits.txt"
    if [[ -s "${TMP}/nm-hits.txt" ]]; then
      local h_pkg h_src
      while IFS="${TAB}" read -r h_pkg h_src; do
        alert PKG-NM-IOC "Known-malicious version INSTALLED in node_modules: $(clean "${h_pkg}")  (source: $(clean "${h_src}"))"
      done < "${TMP}/nm-hits.txt"
    else
      ok PKG-NM-IOC "None of the ${n_nm} installed package versions is on the known-bad list."
    fi
  fi

  # Packages that run code when installed.
  if [[ -s "${pj}" ]]; then
    tr '\n' '\0' < "${pj}" | xargs -0 grep -lE '"(preinstall|install|postinstall)"[[:space:]]*:' 2>/dev/null > "${TMP}/nm-scripts.txt" || true
    local n_scripts
    n_scripts="$(count_lines "${TMP}/nm-scripts.txt")"
    if [[ "${n_scripts}" -gt 0 ]]; then
      tr '\n' '\0' < "${TMP}/nm-scripts.txt" | xargs -0 grep -HE '"(preinstall|install|postinstall)"[[:space:]]*:[[:space:]]*"[^"]*(curl[[:space:]]|wget[[:space:]]|\|[[:space:]]*(ba)?sh|base64|eval[[:space:]]*\(|powershell|/dev/tcp|\.onion|pastebin\.|webhook|bun\.sh/install)' 2>/dev/null \
        | cut -d: -f1 | sed -e "s|^${PROJECT_DIR}/||" -e 's|/package\.json$||' | sort -u > "${TMP}/nm-sus.txt" || true
      sed -e "s|^${PROJECT_DIR}/node_modules/||" -e 's|^.*/node_modules/||' -e 's|/package\.json$||' "${TMP}/nm-scripts.txt" | sort -u > "${TMP}/nm-script-names.txt"
      if [[ -s "${TMP}/nm-sus.txt" ]]; then
        warn PKG-NM-SCRIPT "Installed package(s) whose install script downloads or decodes something:"
        show_locs "${TMP}/nm-sus.txt" 8
        hint "Read the script in each package.json. Legitimate packages sometimes do this to fetch a binary; malware always does."
      fi
      note PKG-NM-SCRIPTS "$(count_lines "${TMP}/nm-script-names.txt") installed package(s) run a script when installed:"
      show_locs "${TMP}/nm-script-names.txt" 8
      hint "Install scripts are how most npm malware runs. 'ignore-scripts=true' in .npmrc turns them off;"
      hint "pnpm and Bun already block them unless you allow a package."
    else
      ok PKG-NM-SCRIPTS "No installed package runs a script when installed."
    fi
  fi
}

osv_lookup() {
  if [[ "${NO_NETWORK}" -eq 1 || "${NO_OSV}" -eq 1 ]]; then na "Skipped (--no-network or --no-osv)."; return; fi
  if ! have curl; then incomplete PKG-OSV "curl is not installed, so the OSV lookup did not run."; return; fi
  if [[ -z "${JS}" ]]; then incomplete PKG-OSV "Neither node nor bun is available to read the OSV answer, so the lookup did not run."; return; fi
  local q="${TMP}/osv-all.tsv" chunks i resp="${TMP}/osv-resp.json" out="${TMP}/osv-out.txt"
  cat "${INV}" "${INV_NM}" 2>/dev/null | sort -u \
    | grep -E "^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+${TAB}[0-9][A-Za-z0-9.+-]*\$" > "${q}" || true
  if [[ ! -s "${q}" ]]; then na "No package versions to look up."; return; fi
  chunks="$(awk -F '\t' -v dir="${TMP}" '
    { if (n % 500 == 0) {
        if (n > 0) { print "]}" > qf; close(qf); close(kf) }
        c++; qf = dir "/osv-q-" c ".json"; kf = dir "/osv-k-" c ".txt"; printf "{\"queries\":[" > qf; sep = ""
      }
      printf "%s{\"package\":{\"name\":\"%s\",\"ecosystem\":\"npm\"},\"version\":\"%s\"}", sep, $1, $2 > qf
      sep = ","; print $1 "@" $2 > kf; n++
    }
    END { if (n > 0) print "]}" > qf; print c + 0 }' "${q}")"
  : > "${out}"
  i=1
  while [[ "${i}" -le "${chunks}" ]]; do
    if ! curl -sS --max-time 60 -H 'Content-Type: application/json' --data-binary "@${TMP}/osv-q-${i}.json" -o "${resp}" "${OSV_URL}" 2>/dev/null \
       || ! NSC_OSV_RESP="${resp}" NSC_OSV_KEYS="${TMP}/osv-k-${i}.txt" "${JS}" -e "${OSV_JS}" >> "${out}" 2>/dev/null; then
      incomplete PKG-OSV "Couldn't get an answer from the OSV database, so the malicious-package lookup did not complete."
      hint "Check the network connection. The built-in list above was still checked."
      return
    fi
    i=$((i + 1))
  done
  local n_q tag pkg id other=0 mal=0
  n_q="$(count_lines "${q}")"
  while IFS="${TAB}" read -r tag pkg id; do
    case "${tag}" in
      MAL) mal=$((mal + 1)); alert PKG-OSV-MALWARE "OSV lists this package version as MALICIOUS: $(clean "${pkg}")  (https://osv.dev/vulnerability/${id})" ;;
      OTHER) case "${pkg}" in ""|*[!0-9]*) ;; *) other=$((other + pkg)) ;; esac ;;
    esac
  done < "${out}"
  if [[ "${mal}" -eq 0 ]]; then
    ok PKG-OSV-MALWARE "OSV lists none of the ${n_q} package versions as malicious."
  fi
  [[ "${other}" -gt 0 ]] && say "         (OSV also lists ${other} ordinary vulnerability record(s) for these versions; the audit below covers those.)"
}

run_audit() {
  if [[ "${NO_NETWORK}" -eq 1 ]]; then
    na "Skipped (--no-network)."
    return
  fi
  if ! have "${PM}"; then
    incomplete PKG-AUDIT "${PM} is not installed here, so the vulnerability audit did not run."
    return
  fi
  if [[ -z "${JS}" ]]; then
    incomplete PKG-AUDIT "Neither node nor bun is available to read the audit result, so the audit did not run."
    return
  fi
  local out="${TMP}/audit.out" err="${TMP}/audit.err" rc=0 berry=0 tmo=""
  have timeout && tmo="timeout ${AUDIT_TIMEOUT}"
  if [[ "${PM}" == "yarn" ]] && grep -q '^__metadata:' "${PROJECT_DIR}/yarn.lock" 2>/dev/null; then berry=1; fi
  # shellcheck disable=SC2086  # ${tmo} is either empty or "timeout N"
  (
    cd "${PROJECT_DIR}" || exit 99
    case "${PM}" in
      npm)  if [[ "${PROD_ONLY}" -eq 1 ]]; then ${tmo} npm audit --json --omit=dev; else ${tmo} npm audit --json; fi ;;
      pnpm) if [[ "${PROD_ONLY}" -eq 1 ]]; then ${tmo} pnpm audit --json --prod; else ${tmo} pnpm audit --json; fi ;;
      bun)  if [[ "${PROD_ONLY}" -eq 1 ]]; then ${tmo} bun audit --json --production; else ${tmo} bun audit --json; fi ;;
      yarn)
        if [[ "${berry}" -eq 1 ]]; then
          if [[ "${PROD_ONLY}" -eq 1 ]]; then ${tmo} yarn npm audit --all --recursive --json --environment production
          else ${tmo} yarn npm audit --all --recursive --json; fi
        else
          if [[ "${PROD_ONLY}" -eq 1 ]]; then ${tmo} yarn audit --json --groups dependencies; else ${tmo} yarn audit --json; fi
        fi ;;
    esac
  ) > "${out}" 2> "${err}"
  rc=$?
  if [[ "${rc}" -eq 124 ]]; then
    incomplete PKG-AUDIT "The ${PM} audit timed out after ${AUDIT_TIMEOUT} seconds, so it did not complete."
    return
  fi
  local empty_ok=0 parsed="${TMP}/audit.parsed"
  [[ "${berry}" -eq 1 && "${rc}" -eq 0 ]] && empty_ok=1
  if ! NSC_AUDIT_FILE="${out}" NSC_EMPTY_OK="${empty_ok}" "${JS}" -e "${AUDIT_JS}" > "${parsed}" 2>/dev/null; then
    incomplete PKG-AUDIT "Couldn't read the ${PM} audit result (exit code ${rc}), so the audit did not complete."
    hint "Check the network connection, then run '${PM} audit' yourself to see the error."
    return
  fi
  local crit high_n mod low
  read -r crit high_n mod low < "${parsed}"
  case "${crit}${high_n}${mod}${low}" in
    ""|*[!0-9]*) incomplete PKG-AUDIT "Couldn't read the ${PM} audit counts, so the audit did not complete."; return ;;
  esac
  local at_or_above=0 below=0 total=$((crit + high_n + mod + low))
  case "${FAIL_ON}" in
    critical) at_or_above="${crit}" ;;
    high)     at_or_above=$((crit + high_n)) ;;
    moderate) at_or_above=$((crit + high_n + mod)) ;;
    low)      at_or_above="${total}" ;;
  esac
  below=$((total - at_or_above))
  local scope="all dependencies"
  [[ "${PROD_ONLY}" -eq 1 ]] && scope="production dependencies only"
  if [[ "${at_or_above}" -gt 0 ]]; then
    high PKG-AUDIT "${PM} audit: ${at_or_above} known $(plural "${at_or_above}" vulnerability vulnerabilities) at or above '${FAIL_ON}' (critical=${crit} high=${high_n} moderate=${mod} low=${low}; ${scope})."
  elif [[ "${total}" -gt 0 ]]; then
    warn PKG-AUDIT "${PM} audit: ${below} known $(plural "${below}" vulnerability vulnerabilities) below the '${FAIL_ON}' level (critical=${crit} high=${high_n} moderate=${mod} low=${low}; ${scope})."
  else
    ok PKG-AUDIT "${PM} audit: no known vulnerabilities (${scope})."
  fi
  if [[ "${total}" -gt 0 ]]; then
    local d_tag d_sev d_pkg d_title shown=0 more=0
    while IFS="${TAB}" read -r d_tag d_sev d_pkg d_title; do
      [[ "${d_tag}" == "D" ]] || continue
      if [[ "${shown}" -lt 10 ]]; then
        hint "$(printf '%-9s %s: %s' "${d_sev}" "${d_pkg}" "${d_title}")"
        shown=$((shown + 1))
      else
        more=$((more + 1))
      fi
    done < "${parsed}"
    [[ "${more}" -gt 0 ]] && hint "...and ${more} more. Run '${PM} audit' for the full list."
    case "${PM}" in
      npm)  hint "To fix: 'npm audit fix', then re-run this check. For a copy that stays, add an \"overrides\" entry in package.json." ;;
      pnpm) hint "To fix: 'pnpm update', or 'pnpm audit --fix' to add overrides, then re-run this check." ;;
      yarn) hint "To fix: upgrade the affected packages, or pin a fixed version under \"resolutions\" in package.json, then re-run this check." ;;
      bun)  hint "To fix: 'bun update' or 'bun audit fix', then re-run this check. For a copy that stays, add an \"overrides\" entry in package.json." ;;
    esac
    hint "(npm counts affected packages; the others count advisories, so totals differ between tools.)"
  fi
}

registry_checks() {
  if [[ "${NO_NETWORK}" -eq 1 ]]; then na "Skipped (--no-network)."; return; fi
  if ! have npm || [[ -z "${JS}" ]]; then
    incomplete PKG-REGISTRY "These checks use the npm command, which is not installed here, so they did not run."
    return
  fi

  # Signatures: does what is installed match what the registry signed?
  if [[ "${PM}" == "npm" && -d "${PROJECT_DIR}/node_modules" ]]; then
    local sig="${TMP}/sig.json" res
    (cd "${PROJECT_DIR}" && with_timeout 120 npm audit signatures --json) > "${sig}" 2>/dev/null
    res="$(NSC_F="${sig}" "${JS}" -e 'const fs=require("fs");let o;try{const t=fs.readFileSync(process.env.NSC_F,"utf8");o=JSON.parse(t.slice(t.indexOf("{")))}catch(e){process.exit(1)}if(!o||o.error||!Array.isArray(o.invalid)||!Array.isArray(o.missing))process.exit(1);console.log(o.invalid.length+" "+o.missing.length)' 2>/dev/null)" || res=""
    case "${res}" in
      "") incomplete PKG-SIGNATURES "Couldn't run 'npm audit signatures', so package signatures were not checked." ;;
      "0 0") ok PKG-SIGNATURES "Every installed package has a valid registry signature." ;;
      "0 "*) note PKG-SIGNATURES "${res#0 } installed package(s) have no registry signature (older or third-party registries don't sign)." ;;
      *) high PKG-SIGNATURES "${res%% *} installed package(s) have an INVALID registry signature: what is on disk is not what the registry published."
         hint "Run 'npm audit signatures' to see which. Delete node_modules and reinstall from a clean cache." ;;
    esac
  else
    na "Signature check skipped (it needs npm and an installed node_modules folder)."
  fi

  # Direct dependencies: deprecated, published in the last week, or long abandoned.
  local names="${TMP}/direct.txt" name ver n=0 view="${TMP}/view.json" line detail
  : > "${TMP}/dep-deprecated.txt"; : > "${TMP}/dep-new.txt"; : > "${TMP}/dep-stale.txt"
  grep -oE '"(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+"[[:space:]]*:' "${DEPS}" 2>/dev/null | sed -e 's/^"//' -e 's/"[[:space:]]*:$//' | sort -u > "${names}" || true
  if [[ ! -s "${names}" ]]; then na "No direct dependencies found in package.json."; return; fi
  local failed=0 total
  total="$(count_lines "${names}")"
  while IFS= read -r name; do
    [[ "${n}" -ge 40 ]] && break
    n=$((n + 1))
    ver="$(awk -F '\t' -v n="${name}" '$1 == n { print $2; exit }' "${INV}" 2>/dev/null)"
    case "${ver}" in ""|*[!0-9A-Za-z.+-]*) ver="" ;; esac
    (cd "${PROJECT_DIR}" && with_timeout 20 npm view "${name}${ver:+@${ver}}" name version deprecated time --json) > "${view}" 2>/dev/null
    if ! NSC_VIEW_FILE="${view}" NSC_TODAY="${TODAY}" "${JS}" -e "${AGE_JS}" > "${TMP}/view.out" 2>/dev/null; then
      failed=$((failed + 1)); continue
    fi
    while IFS="${TAB}" read -r line detail; do
      case "${line}" in
        DEPRECATED) printf '%s: %s\n' "${name}" "${detail}" >> "${TMP}/dep-deprecated.txt" ;;
        NEW) printf '%s@%s was published %s day(s) ago\n' "${name}" "${ver}" "${detail}" >> "${TMP}/dep-new.txt" ;;
        STALE) printf '%s: no release for %s years\n' "${name}" "${detail}" >> "${TMP}/dep-stale.txt" ;;
      esac
    done < "${TMP}/view.out"
  done < "${names}"
  if [[ "${failed}" -ge "${n}" ]]; then
    incomplete PKG-REGISTRY "Couldn't read package details from the registry, so deprecated and very new packages were not checked."
    return
  fi
  if [[ -s "${TMP}/dep-new.txt" ]]; then
    warn PKG-VERY-NEW "Direct dependencies published within the last 7 days. Most hijacked versions are caught within days:"
    show_locs "${TMP}/dep-new.txt" 8
  fi
  if [[ -s "${TMP}/dep-deprecated.txt" ]]; then
    warn PKG-DEPRECATED "Deprecated direct dependencies (their maintainers say not to use them):"
    show_locs "${TMP}/dep-deprecated.txt" 8
  fi
  if [[ -s "${TMP}/dep-stale.txt" ]]; then
    note PKG-ABANDONED "Direct dependencies with no release for 3 years or more (security fixes are unlikely):"
    show_locs "${TMP}/dep-stale.txt" 8
  fi
  if [[ ! -s "${TMP}/dep-new.txt" && ! -s "${TMP}/dep-deprecated.txt" && ! -s "${TMP}/dep-stale.txt" ]]; then
    ok PKG-REGISTRY "None of the ${n} direct dependencies checked is deprecated, brand new or long abandoned."
  fi
  [[ "${total}" -gt 40 ]] && say "         (Only the first 40 of ${total} direct dependencies were looked up.)"
}

install_settings() {
  local lf f
  if grep -qE '"(preinstall|install|postinstall)"[[:space:]]*:' "${PJ}" 2>/dev/null; then
    note PKG-OWN-SCRIPTS "package.json has install scripts (preinstall/install/postinstall). They run on every install; check they do what you expect."
  fi
  if grep -E '"[^"]+"[[:space:]]*:[[:space:]]*"[^"]*(curl|wget)[^"]*\|[[:space:]]*(ba)?sh' "${PJ}" >/dev/null 2>&1; then
    warn PKG-CURL-PIPE "A script in package.json downloads something and pipes it straight into a shell (curl | sh)."
    hint "Whoever controls that address controls your machine. Download, check, then run."
  fi
  if grep -qE '"[^"]+"[[:space:]]*:[[:space:]]*"(\*|latest|x)"' "${DEPS}" 2>/dev/null; then
    warn PKG-LOOSE-RANGE "package.json has a dependency set to \"*\" or \"latest\", which accepts any future version."
    hint "Use a version range such as \"^1.2.3\"."
  fi
  if grep -qE ':[[:space:]]*"(git\+|git://|github:|gitlab:|bitbucket:|https?://|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#[^"]*)?")' "${DEPS}" 2>/dev/null; then
    note PKG-GIT-DEP "package.json has a dependency loaded from git or a URL. The audit doesn't cover those; pin them to a full commit hash."
  fi
  local lf_http=0
  for lf in ${LOCKFILES}; do
    [[ "${lf}" == "bun.lockb" ]] && continue
    if grep -qE '(resolved|tarball)[": ]+"?http://' "${PROJECT_DIR}/${lf}" 2>/dev/null; then lf_http=1; fi
  done
  [[ "${lf_http}" -eq 1 ]] && warn PKG-HTTP-SOURCE "A lockfile downloads at least one package over plain http://, which can be tampered with in transit."

  local npmrc="${PROJECT_DIR}/.npmrc"
  if [[ -f "${npmrc}" ]]; then
    if grep -E '(_authToken|_auth|_password)[[:space:]]*=' "${npmrc}" 2>/dev/null | grep -vqF '${'; then
      if [[ "${GIT_OK}" -eq 1 ]] && git -C "${PROJECT_DIR}" ls-files --error-unmatch .npmrc >/dev/null 2>&1; then
        high PKG-NPMRC-TOKEN ".npmrc holds a registry token or password and is committed to git."
        hint "Revoke that token, then use an environment variable: //registry.npmjs.org/:_authToken=\${NPM_TOKEN}"
      else
        warn PKG-NPMRC-TOKEN ".npmrc in the project holds a registry token or password in plain text."
        hint "Prefer an environment variable: //registry.npmjs.org/:_authToken=\${NPM_TOKEN}"
      fi
    fi
    if grep -qE '^[[:space:]]*registry[[:space:]]*=[[:space:]]*http://' "${npmrc}" 2>/dev/null; then
      warn PKG-NPMRC-HTTP ".npmrc uses a registry over plain http://."
    fi
    if grep -qiE '^[[:space:]]*strict-ssl[[:space:]]*=[[:space:]]*false' "${npmrc}" 2>/dev/null; then
      warn PKG-NPMRC-SSL ".npmrc turns off certificate checks (strict-ssl=false)."
    fi
  fi

  local age_set=0
  case "${PM}" in
    npm)  grep -qE '^[[:space:]]*min-release-age[[:space:]]*=' "${npmrc}" 2>/dev/null && age_set=1 ;;
    pnpm) grep -qE '^[[:space:]]*minimumReleaseAge[[:space:]]*:' "${PROJECT_DIR}/pnpm-workspace.yaml" 2>/dev/null && age_set=1
          grep -qE '^[[:space:]]*minimum-release-age[[:space:]]*=' "${npmrc}" 2>/dev/null && age_set=1 ;;
    yarn) grep -qE '^[[:space:]]*npmMinimalAgeGate[[:space:]]*:' "${PROJECT_DIR}/.yarnrc.yml" 2>/dev/null && age_set=1 ;;
    bun)  grep -qE '^[[:space:]]*minimumReleaseAge[[:space:]]*=' "${PROJECT_DIR}/bunfig.toml" 2>/dev/null && age_set=1 ;;
  esac
  if [[ "${age_set}" -eq 1 ]]; then
    ok PKG-RELEASE-AGE "A minimum release age is set, so brand-new package versions are not installed straight away."
  else
    note PKG-RELEASE-AGE "No minimum release age is set in this project (it may be set in your user settings)."
    case "${PM}" in
      npm)  hint "It delays brand-new versions, which is when most attacks are caught. npm 11.10+: 'min-release-age=3' (days) in .npmrc" ;;
      pnpm) hint "It delays brand-new versions, which is when most attacks are caught. pnpm 10.16+: 'minimumReleaseAge: 4320' (minutes) in pnpm-workspace.yaml" ;;
      yarn) hint "It delays brand-new versions, which is when most attacks are caught. Yarn 4.10+: 'npmMinimalAgeGate: 4320' (minutes) in .yarnrc.yml" ;;
      bun)  hint "It delays brand-new versions, which is when most attacks are caught. Bun 1.3+: 'minimumReleaseAge = 259200' (seconds) under [install] in bunfig.toml" ;;
    esac
  fi
  if [[ "${GIT_OK}" -eq 1 || -d "${PROJECT_DIR}/.github" ]]; then
    f=""
    for lf in .github/dependabot.yml .github/dependabot.yaml renovate.json renovate.json5 .renovaterc .renovaterc.json .github/renovate.json .github/renovate.json5; do
      [[ -f "${PROJECT_DIR}/${lf}" ]] && f="${lf}"
    done
    if [[ -n "${f}" ]]; then ok PKG-UPDATE-BOT "Automatic dependency updates are configured (${f})."
    else note PKG-UPDATE-BOT "No Dependabot or Renovate settings found. They open a pull request when a dependency gets a security fix."; fi
  fi
}

# ============================================================ PART 2 ======
# scan PATTERN KIND [i]: print "path:line" for matches, never the matching text.
#   KIND is "code" (JS/TS source files) or "all" (every text file).
scan() {
  local pat="$1" kind="$2" flags="-nIE"
  [[ "${3:-}" == "i" ]] && flags="-nIiE"
  if [[ "${GIT_OK}" -eq 1 ]]; then
    if [[ "${kind}" == "code" ]]; then
      git -C "${PROJECT_DIR}" grep "${flags}" -e "${pat}" -- \
        '*.js' '*.mjs' '*.cjs' '*.jsx' '*.ts' '*.mts' '*.cts' '*.tsx' '*.vue' '*.svelte' '*.astro' \
        ':(exclude)*.min.js' ':(exclude)*.d.ts' ':(exclude)dist/*' ':(exclude)build/*' 2>/dev/null
    else
      git -C "${PROJECT_DIR}" grep "${flags}" -e "${pat}" -- . \
        ':(exclude)package-lock.json' ':(exclude)npm-shrinkwrap.json' ':(exclude)pnpm-lock.yaml' \
        ':(exclude)yarn.lock' ':(exclude)bun.lock' ':(exclude)*.min.js' ':(exclude)*.map' \
        ":(exclude)${SELF_NAME}" ':(exclude).nsc-ignore' 2>/dev/null
    fi
  else
    (
      cd "${PROJECT_DIR}" || exit 0
      if [[ "${kind}" == "code" ]]; then
        grep -r "${flags}" \
          --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build \
          --exclude-dir=.next --exclude-dir=.nuxt --exclude-dir=.output --exclude-dir=.svelte-kit \
          --exclude-dir=coverage --exclude-dir=out --exclude-dir=vendor --exclude-dir=.turbo \
          --exclude-dir=.cache --exclude-dir=.vercel --exclude-dir=.yarn \
          --include='*.js' --include='*.mjs' --include='*.cjs' --include='*.jsx' --include='*.ts' \
          --include='*.mts' --include='*.cts' --include='*.tsx' --include='*.vue' --include='*.svelte' \
          --include='*.astro' --exclude='*.min.js' --exclude='*.d.ts' \
          -e "${pat}" . 2>/dev/null
      else
        grep -r "${flags}" \
          --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build \
          --exclude-dir=.next --exclude-dir=.nuxt --exclude-dir=.output --exclude-dir=.svelte-kit \
          --exclude-dir=coverage --exclude-dir=out --exclude-dir=vendor --exclude-dir=.turbo \
          --exclude-dir=.cache --exclude-dir=.vercel --exclude-dir=.yarn \
          --exclude=package-lock.json --exclude=npm-shrinkwrap.json --exclude=pnpm-lock.yaml \
          --exclude=yarn.lock --exclude=bun.lock --exclude='*.min.js' --exclude='*.map' \
          --exclude='.env' --exclude='.env.*' --exclude="${SELF_NAME}" --exclude='.nsc-ignore' \
          -e "${pat}" . 2>/dev/null
      fi
    )
  fi | cut -d: -f1,2 | sed 's|^\./||' | head -n 500
}

accepted_suffix() { if [[ "${LOCS_HIDDEN}" -gt 0 ]]; then printf ' (%s more accepted in .nsc-ignore)' "${LOCS_HIDDEN}"; fi; }

# secret_check ID LEVEL "what it is" PATTERN [i]
secret_check() {
  local id="$1" level="$2" what="$3" pat="$4" icase="${5:-}" out="${TMP}/scan.txt" n
  scan "${pat}" all "${icase}" > "${out}"
  filter_locs "${id}" "${out}"
  n="$(count_lines "${out}")"
  [[ "${n}" -eq 0 ]] && return 1
  "${level}" "${id}" "${what}: ${n} $(plural "${n}" line lines) in ${SCAN_SCOPE}$(accepted_suffix)"
  show_locs "${out}" 5
  return 0
}

# code_check ID "what was found" "why it matters / what to do" PATTERN [i]
code_check() {
  local id="$1" what="$2" advice="$3" pat="$4" icase="${5:-}" out="${TMP}/scan.txt" n
  scan "${pat}" code "${icase}" > "${out}"
  filter_locs "${id}" "${out}"
  n="$(count_lines "${out}")"
  [[ "${n}" -eq 0 ]] && return 1
  warn "${id}" "${what}: ${n} $(plural "${n}" line lines)$(accepted_suffix)"
  hint "${advice}"
  show_locs "${out}" 3
  return 0
}
code_has() { [[ -n "$(scan "$1" code "${2:-}" | head -n 1)" ]]; }

# Secret formats that are specific enough to trust without a person looking.
# Used for the git history and build-output scans.
STRONG_SECRETS='-----BEGIN [A-Z ]*PRIVATE KEY-----|(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{20,}|(sk|rk)_live_[A-Za-z0-9]{20,}|whsec_[A-Za-z0-9]{24,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|sk-(ant|proj)-[A-Za-z0-9_-]{20,}|dckr_pat_[A-Za-z0-9_-]{20,}|dop_v1_[a-f0-9]{64}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}'

part_code() {
  section code "Part 2 of 3: code and project files"

  # ---- secrets -----------------------------------------------------------
  subsection "Secrets"
  if [[ "${GIT_OK}" -eq 1 ]]; then
    SCAN_SCOPE="files committed to git"
    git -C "${PROJECT_DIR}" ls-files -- . 2>/dev/null \
      | grep -E '(^|/)\.env($|\.)' \
      | grep -vE '\.(example|sample|template|dist|defaults?|schema)$' > "${TMP}/env-tracked.txt"
    filter_locs CODE-ENV-COMMITTED "${TMP}/env-tracked.txt"
    if [[ -s "${TMP}/env-tracked.txt" ]]; then
      high CODE-ENV-COMMITTED ".env file(s) committed to git. Anyone with the repository has those values."
      show_locs "${TMP}/env-tracked.txt" 5
      hint "Change every secret in them, run 'git rm --cached <file>', and add .env to .gitignore."
      hint "The old values stay in the git history, which is why they must be changed."
    else
      ok CODE-ENV-COMMITTED "No .env file is committed to git."
    fi
    if [[ -f "${PROJECT_DIR}/.env" ]] && ! git -C "${PROJECT_DIR}" check-ignore -q .env 2>/dev/null \
       && ! grep -qxF ".env" "${TMP}/env-tracked.txt"; then
      warn CODE-ENV-GITIGNORE ".env exists but .gitignore doesn't cover it, so it could be committed by accident."
    fi
    git -C "${PROJECT_DIR}" ls-files -- . 2>/dev/null \
      | grep -E '(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|p12|pfx|keystore|jks)$' > "${TMP}/key-files.txt"
    filter_locs CODE-KEY-FILES "${TMP}/key-files.txt"
    if [[ -s "${TMP}/key-files.txt" ]]; then
      warn CODE-KEY-FILES "Key or certificate file(s) committed to git. Check that none is a private key."
      show_locs "${TMP}/key-files.txt" 5
    fi
  else
    SCAN_SCOPE="the project files"
    if [[ -e "${PROJECT_DIR}/.git" ]]; then
      note CODE-NO-GIT "This is a git repository but git couldn't read it here, so every file is scanned instead of the committed ones."
    else
      note CODE-NO-GIT "Not a git repository: every file is scanned (except .env files, node_modules and build folders)."
    fi
  fi

  local any=0
  secret_check CODE-SECRET-PRIVATE-KEY high "Private key" '-----BEGIN [A-Z ]*PRIVATE KEY-----' && any=1
  secret_check CODE-SECRET-AWS high "AWS access key ID" '(AKIA|ASIA)[0-9A-Z]{16}' && any=1
  secret_check CODE-SECRET-GITHUB high "GitHub token" '(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})' && any=1
  secret_check CODE-SECRET-NPM high "npm token" 'npm_[A-Za-z0-9]{36}' && any=1
  secret_check CODE-SECRET-SLACK high "Slack token" 'xox[baprs]-[A-Za-z0-9-]{20,}' && any=1
  secret_check CODE-SECRET-STRIPE high "Stripe or Clerk live key" '(sk|rk)_live_[A-Za-z0-9]{20,}' && any=1
  secret_check CODE-SECRET-SENDGRID high "SendGrid key" 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}' && any=1
  secret_check CODE-SECRET-AI high "AI provider key (Anthropic, OpenAI, Hugging Face, Groq, xAI, Replicate, Perplexity)" \
    '(^|[^A-Za-z0-9_])(sk-(ant|proj)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|hf_[A-Za-z0-9]{34,}|gsk_[A-Za-z0-9]{50,}|xai-[A-Za-z0-9]{70,}|r8_[A-Za-z0-9]{37,}|pplx-[A-Za-z0-9]{40,})' && any=1
  secret_check CODE-SECRET-CLOUD high "Cloud key (Google OAuth secret, Google service account, Azure storage, DigitalOcean)" \
    'GOCSPX-[A-Za-z0-9_-]{28}|"type"[[:space:]]*:[[:space:]]*"service_account"|AccountKey=[A-Za-z0-9+/=]{60,}|dop_v1_[a-f0-9]{64}' && any=1
  secret_check CODE-SECRET-DEVTOOL high "Developer platform token (GitLab, PyPI, Docker Hub, Netlify, Doppler, PlanetScale, Databricks, Postman, Figma, Grafana, Sentry, New Relic, Linear, Notion, age)" \
    '(^|[^A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{20,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}|dckr_pat_[A-Za-z0-9_-]{20,}|nfp_[A-Za-z0-9]{36,}|dp\.pt\.[A-Za-z0-9]{40,}|pscale_(tkn|pw|oauth)_[A-Za-z0-9_.=-]{30,}|dapi[a-f0-9]{32}|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|figd_[A-Za-z0-9_-]{40,}|glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|sntrys_[A-Za-z0-9_=+/-]{40,}|NRAK-[A-Z0-9]{27}|lin_api_[A-Za-z0-9]{40}|ntn_[A-Za-z0-9]{40,}|AGE-SECRET-KEY-1[A-Z0-9]{58})' && any=1
  secret_check CODE-SECRET-PAYMENT high "Payment key (Stripe webhook secret, Square, Shopify)" \
    'whsec_[A-Za-z0-9]{24,}|sq0(atp|csp)-[A-Za-z0-9_-]{22,}|shp(at|ca|pa|ss)_[a-fA-F0-9]{32}' && any=1
  secret_check CODE-SECRET-CHAT high "Chat or bot secret (Slack webhook, Discord webhook, Telegram bot)" \
    'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+|https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+|(^|[^0-9])[0-9]{8,10}:AA[A-Za-z0-9_-]{33}' && any=1
  if ! is_quick; then
    secret_check CODE-SECRET-EMAIL warn "Possible email or SMS service key (Mailgun, Mailchimp, Twilio)" \
      '(^|[^A-Za-z0-9_-])(key-[0-9a-f]{32}|[0-9a-f]{32}-us[0-9]{1,2}|SK[0-9a-f]{32})([^A-Za-z0-9]|$)' && any=1
    secret_check CODE-SECRET-GOOGLE-API warn "Google API key (Firebase web keys are public by design; others are not)" 'AIza[0-9A-Za-z_-]{35}' && any=1
    secret_check CODE-SECRET-JWT warn "A signed token (JWT) written into a file" \
      'eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}' && any=1
    secret_check CODE-SECRET-DB-URL warn "Database or service address with a password in it" \
      '(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|rediss|amqps?)://[^:/@[:space:]"]+:[^@/[:space:]"$<{]{3,}@' && any=1
    secret_check CODE-SECRET-GENERIC warn "Possible hard-coded password, secret or key" \
      "(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"'[:space:]\$<{]{12,}[\"']" i && any=1
  fi
  if [[ "${any}" -eq 0 ]]; then
    ok CODE-SECRETS "No secrets matched the known patterns in ${SCAN_SCOPE}."
  else
    hint "The matching text is not shown, on purpose. Open the lines listed to see it."
    hint "A real secret that was ever committed must be changed, not just deleted."
  fi

  local pub
  for pub in public static www dist build; do
    if [[ -e "${PROJECT_DIR}/${pub}/.env" || -e "${PROJECT_DIR}/${pub}/.git" ]]; then
      high CODE-PUBLIC-DOTFILE "${pub}/ contains a .env file or a .git folder. That folder is usually served to visitors."
    fi
  done

  if ! is_quick; then
    # Secrets that ended up in what gets sent to browsers.
    local bdir found_build=0
    : > "${TMP}/build-secrets.txt"; : > "${TMP}/build-maps.txt"
    for bdir in dist build out public .next/static .output/public .svelte-kit/output/client www; do
      [[ -d "${PROJECT_DIR}/${bdir}" ]] || continue
      found_build=1
      (cd "${PROJECT_DIR}" && grep -rIlE --exclude-dir=node_modules -e "${STRONG_SECRETS}" "${bdir}" 2>/dev/null | head -n 20) >> "${TMP}/build-secrets.txt"
      (cd "${PROJECT_DIR}" && find "${bdir}" -name '*.js.map' -type f 2>/dev/null | head -n 20) >> "${TMP}/build-maps.txt"
    done
    filter_locs CODE-BUILD-SECRET "${TMP}/build-secrets.txt"
    if [[ -s "${TMP}/build-secrets.txt" ]]; then
      high CODE-BUILD-SECRET "Secret-looking text inside build output or public files, which are sent to every visitor:"
      show_locs "${TMP}/build-secrets.txt" 5
      hint "Something server-only is being bundled for the browser. Change the secret, then find the import that pulls it in."
    elif [[ "${found_build}" -eq 1 ]]; then
      ok CODE-BUILD-SECRET "No secrets in the build output or public folders."
    fi
    if [[ -s "${TMP}/build-maps.txt" ]]; then
      note CODE-SOURCE-MAPS "$(count_lines "${TMP}/build-maps.txt") source map file(s) in the build output. If they are deployed, visitors can read your original source."
    fi
    # Variables with these prefixes are copied into the browser bundle.
    local pubre='(NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]*(SECRET|PRIVATE|PASSWORD|PASSWD)[A-Z0-9_]*'
    scan "${pubre}" all > "${TMP}/pubenv.txt"
    # .env files are usually not committed, so they are searched separately;
    # one already listed with a line number is not listed again.
    grep -lE "${pubre}" "${PROJECT_DIR}"/.env* 2>/dev/null | sed "s|^${PROJECT_DIR}/||" \
      | awk 'NR == FNR { i = index($0, ":"); if (i > 0) seen[substr($0, 1, i - 1)] = 1; next } !($0 in seen)' "${TMP}/pubenv.txt" - \
      > "${TMP}/pubenv-extra.txt" || true
    cat "${TMP}/pubenv-extra.txt" >> "${TMP}/pubenv.txt"
    filter_locs CODE-PUBLIC-ENV "${TMP}/pubenv.txt"
    if [[ -s "${TMP}/pubenv.txt" ]]; then
      warn CODE-PUBLIC-ENV "A variable named like a secret has a prefix that sends it to the browser (NEXT_PUBLIC_, VITE_, REACT_APP_...):"
      show_locs "${TMP}/pubenv.txt" 5
      hint "Everything with those prefixes is public. Rename it without the prefix and use it on the server only."
    fi
  fi

  if is_deep || [[ "${FORCE_HISTORY}" -eq 1 ]]; then
    subsection "Secrets in git history"
    history_scan
  fi

  # ---- risky code --------------------------------------------------------
  subsection "Risky code patterns (pattern matches: each one needs a person to look)"
  any=0
  code_check CODE-EVAL "eval() or new Function()" \
    "These run text as code. If any part of that text comes from a visitor, they can run their own code." \
    '(^|[^A-Za-z0-9_.$])eval[[:space:]]*\(|new[[:space:]]+Function[[:space:]]*\(' && any=1
  code_check CODE-SHELL "Shell command built from variables" \
    "If a visitor controls part of the command they can run their own. Use execFile/spawn with an argument list." \
    '(^|[^A-Za-z0-9_.$])(child_process\.)?exec(Sync)?[[:space:]]*\(.*(\$\{|["'"'"'`][[:space:]]*\+|\+[[:space:]]*["'"'"'`])|shell:[[:space:]]*true' && any=1
  code_check CODE-TLS-OFF "TLS certificate checks turned off" \
    "The app will accept a forged certificate, so connections can be intercepted. Remove it outside local testing." \
    'rejectUnauthorized[[:space:]]*:[[:space:]]*false|NODE_TLS_REJECT_UNAUTHORIZED[^0-9A-Za-z]{0,12}0' && any=1
  code_check CODE-HTML "HTML inserted without escaping" \
    "dangerouslySetInnerHTML, innerHTML, v-html and {@html} can allow cross-site scripting if the content isn't yours. Sanitise it first." \
    'dangerouslySetInnerHTML|\.(inner|outer)HTML[[:space:]]*\+?=[^=]|v-html=|\{@html[[:space:]]' && any=1
  code_check CODE-SQL "SQL built by joining strings" \
    "Use query parameters (placeholders) so that input can't change the query." \
    '(query|execute|raw|exec)[[:space:]]*\([[:space:]]*["'"'"'`][[:space:]]*(select|insert|update|delete)[^;]*(\$\{|["'"'"'`][[:space:]]*\+)|\$(queryRawUnsafe|executeRawUnsafe)[[:space:]]*\(' i && any=1
  code_check CODE-PATH "File path or redirect taken straight from the request" \
    "A visitor could read other files (../) or send people to another site. Check the value against an allowed list." \
    '(sendFile|readFile(Sync)?|createReadStream|unlink(Sync)?|writeFile(Sync)?|redirect|download)[[:space:]]*\([^)]*req\.(query|params|body)' && any=1
  code_check CODE-RANDOM "Math.random() near a token, password or session value" \
    "Math.random() is predictable. Use crypto.randomBytes() or crypto.randomUUID() for anything secret." \
    '(token|secret|password|session|nonce|otp|salt)[^;]*Math\.random\(|Math\.random\([^;]*(token|secret|password|session|nonce|otp|salt)' i && any=1
  code_check CODE-WEAK-HASH "MD5 or SHA-1 hashing" \
    "Fine for checksums, not for passwords or signatures. Use bcrypt/argon2 for passwords and SHA-256 or better elsewhere." \
    'createHash[[:space:]]*\([[:space:]]*["'"'"'`](md5|sha1)["'"'"'`]' i && any=1
  code_check CODE-CORS "CORS open to every site" \
    "With credentials this lets any website act as the signed-in visitor. List the sites you trust instead." \
    'Access-Control-Allow-Origin["'"'"'`][[:space:]]*,[[:space:]]*["'"'"'`]\*|origin[[:space:]]*:[[:space:]]*(["'"'"'`]\*["'"'"'`]|true)|enableCors[[:space:]]*\([[:space:]]*\)' && any=1
  code_check CODE-JWT "JWT checks weakened" \
    "The 'none' algorithm and ignoreExpiration let forged or expired tokens through." \
    'algorithms?[[:space:]]*:[[:space:]]*\[?[^]]*["'"'"'`]none["'"'"'`]|ignoreExpiration[[:space:]]*:[[:space:]]*true' i && any=1
  if ! is_quick; then
    code_check CODE-SSRF "Outgoing request to an address taken from the incoming request" \
      "A visitor can make your server fetch internal addresses (cloud metadata, databases). Allow only known hosts." \
      '(^|[^A-Za-z0-9_$])(fetch|axios(\.(get|post|put|request))?|got(\.(get|post))?|needle|superagent\.(get|post)|https?\.(get|request))[[:space:]]*\([^)]*req\.(query|params|body)' && any=1
    code_check CODE-NOSQL "Database filter taken straight from the request" \
      "Passing the request body as a filter lets visitors send operators such as \$ne or \$gt. Pick out and type-check each field." \
      '\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|count|countDocuments)[[:space:]]*\([[:space:]]*req\.(body|query)[[:space:]]*[,)]|\$where' && any=1
    code_check CODE-MASS-ASSIGN "Whole request body saved to the database" \
      "A visitor can set fields you didn't intend, such as isAdmin. Copy only the fields you expect." \
      '\.(create|insertOne|insertMany|update|findByIdAndUpdate|save|upsert|build)[[:space:]]*\([[:space:]]*(\{[[:space:]]*(data:[[:space:]]*)?)?(\.\.\.)?req\.body[[:space:]]*[,)}]' && any=1
    code_check CODE-PROTO "Request data merged into an object" \
      "Deep-merging visitor input can overwrite Object.prototype (prototype pollution). Validate the input against a schema first." \
      '(Object\.assign|_\.merge|_\.mergeWith|_\.defaultsDeep|deepmerge|merge|extend)[[:space:]]*\([^)]*req\.(body|query)|__proto__' && any=1
    code_check CODE-DESERIALISE "Code-capable deserialisation or the vm module" \
      "unserialize(), vm.runIn*Context() and similar run code held in data. Never feed them anything a visitor can influence." \
      '\.unserialize[[:space:]]*\(|vm\.run(InNewContext|InThisContext|InContext)[[:space:]]*\(|new[[:space:]]+vm\.Script[[:space:]]*\(' && any=1
    code_check CODE-WEAK-CRYPTO "Weak or outdated encryption" \
      "createCipher() and DES/RC4/ECB modes are broken. Use createCipheriv with aes-256-gcm and a random IV." \
      'createCipher[[:space:]]*\(|createCipheriv[[:space:]]*\([[:space:]]*["'"'"'`](aes-[0-9]+-ecb|des|des-ede3?(-cbc)?|rc4|bf(-cbc)?)["'"'"'`]' i && any=1
    code_check CODE-WEAK-KDF "Password hashing set too low" \
      "bcrypt needs at least 10 rounds and PBKDF2 at least 100,000 iterations, or stolen hashes are quickly cracked." \
      'bcrypt(js)?\.(hash|hashSync|genSalt|genSaltSync)[[:space:]]*\([^)]*,[[:space:]]*[1-9][[:space:]]*[,)]|pbkdf2(Sync)?[[:space:]]*\([^,]+,[^,]+,[[:space:]]*[0-9]{1,4}[[:space:]]*,' && any=1
    code_check CODE-JWT-SECRET "JWT signed or checked with a secret written in the code" \
      "Anyone who can read the code can forge sign-ins. Load the secret from the environment." \
      'jwt\.(sign|verify)[[:space:]]*\([^)]*,[[:space:]]*["'"'"'`][^"'"'"'`]+["'"'"'`]' && any=1
    code_check CODE-SESSION-SECRET "Session secret written in the code, or a placeholder" \
      "Anyone who knows the secret can forge session cookies. Load a long random value from the environment." \
      'session[[:space:]]*\([[:space:]]*\{[^}]*secret[[:space:]]*:[[:space:]]*["'"'"'`]|secret[[:space:]]*:[[:space:]]*["'"'"'`](keyboard cat|secret|changeme|change-me|your[-_ ]?secret[^"'"'"'`]*)["'"'"'`]' i && any=1
    code_check CODE-COOKIE "Cookie protections switched off" \
      "secure: false sends the cookie over plain HTTP; httpOnly: false lets page scripts read it." \
      '(secure|httpOnly)[[:space:]]*:[[:space:]]*false' && any=1
    code_check CODE-ERROR-LEAK "Error details or stack traces sent to the visitor" \
      "Stack traces reveal file paths and library versions. Log the error and send a plain message." \
      'res\.(status\([0-9]+\)\.)?(send|json|end|write)[[:space:]]*\([^)]*(err|error|e)\.(stack|message)' && any=1
    code_check CODE-LOG-SECRET "Passwords, tokens or secrets written to the log" \
      "Logs are read by more people, and kept for longer, than the secrets should be." \
      '(console\.(log|info|debug|warn|error)|logger\.[a-z]+)[[:space:]]*\([^)]*(req\.body\.password|req\.headers\.authorization|process\.env\.[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|PRIVATE)[A-Z0-9_]*)' && any=1
    code_check CODE-TEMPLATE "Template name or template text taken from the request" \
      "Rendering a template that a visitor chose or wrote can run their code on the server." \
      'res\.render[[:space:]]*\([[:space:]]*req\.(query|params|body)|(ejs|pug|handlebars|nunjucks|mustache)\.(render|compile|renderString)[[:space:]]*\([[:space:]]*req\.(query|params|body)' && any=1
    code_check CODE-REGEX "Regular expression built from the request" \
      "A crafted pattern can freeze the server (ReDoS). Escape the input, or use a plain string search." \
      'new[[:space:]]+RegExp[[:space:]]*\([^)]*req\.(query|params|body)' && any=1
    code_check CODE-STATIC-ROOT "The whole project folder served as static files" \
      "Visitors could download your source and settings files. Serve a dedicated folder such as public/." \
      'express\.static[[:space:]]*\([[:space:]]*(__dirname|process\.cwd\(\)|["'"'"'`]\.?/?["'"'"'`])[[:space:]]*[,)]' && any=1
    code_check CODE-GRAPHQL "GraphQL introspection or playground switched on" \
      "In production these hand visitors a full map of your API. Turn them off unless NODE_ENV is development." \
      '(introspection|playground)[[:space:]]*:[[:space:]]*true' && any=1
    if code_has 'multer[[:space:]]*\(' && ! code_has 'limits[[:space:]]*:'; then
      any=1
      warn CODE-UPLOAD-LIMIT "File uploads (multer) with no size limits."
      hint "Without 'limits: { fileSize: ... }' one large upload can fill the disk or memory."
    fi
  fi
  [[ "${any}" -eq 0 ]] && ok CODE-PATTERNS "None of the risky patterns were found in the JavaScript/TypeScript source."

  # ---- framework settings ------------------------------------------------
  subsection "Framework settings"
  framework_checks

  # ---- Docker, Kubernetes, CI --------------------------------------------
  docker_file_checks
  [[ "${LEVEL}" != "quick" ]] && kubernetes_checks
  workflow_checks

  # ---- specialist tools ---------------------------------------------------
  if is_deep && [[ "${NO_TOOLS}" -eq 0 ]]; then
    subsection "Specialist tools (code)"
    tools_code
  fi
}

history_scan() {
  if [[ "${GIT_OK}" -ne 1 ]]; then na "Not a readable git repository, so there is no history to scan."; return; fi
  local out="${TMP}/history.txt" rc=0
  git -C "${PROJECT_DIR}" rev-parse --is-shallow-repository 2>/dev/null | grep -q true \
    && note CODE-HISTORY-SHALLOW "This is a shallow clone, so only part of the history is here to scan."
  # Every added line in every commit; print "path:commit", never the line itself.
  with_timeout 300 git -C "${PROJECT_DIR}" log --all -p --no-color -U0 --format='commit %h' -- . \
      ':(exclude)package-lock.json' ':(exclude)pnpm-lock.yaml' ':(exclude)yarn.lock' ':(exclude)bun.lock' ':(exclude)*.min.js' ':(exclude)*.map' 2>/dev/null \
    | awk '
        /^commit [0-9a-f]+$/ { c = $2; next }
        /^\+\+\+ / { f = substr($0, 7); next }
        /^\+/ { print f ":" c "\t" substr($0, 2) }' \
    | grep -E -e "^[^${TAB}]*${TAB}.*(${STRONG_SECRETS})" \
    | cut -f1 | sort -u | head -n 500 > "${out}"
  rc="${PIPESTATUS[0]}"
  if [[ "${rc}" -eq 124 ]]; then
    incomplete CODE-HISTORY-SECRET "Scanning the git history took more than 5 minutes and was stopped. Try gitleaks for a large repository."
    return
  fi
  filter_locs CODE-HISTORY-SECRET "${out}"
  if [[ -s "${out}" ]]; then
    high CODE-HISTORY-SECRET "Secret-looking text in $(count_lines "${out}") place(s) in the git history (shown as file:commit)$(accepted_suffix):"
    show_locs "${out}" 8
    hint "Deleting a secret in a later commit does not remove it: anyone with the repository can still read it."
    hint "Change each secret. Then accept the finding in .nsc-ignore with the date it was changed."
  else
    ok CODE-HISTORY-SECRET "No secrets matched the high-confidence patterns anywhere in the git history."
  fi
}

framework_checks() {
  local fw=""
  pj_has express && fw="${fw}Express, "
  pj_has fastify && fw="${fw}Fastify, "
  pj_has koa && fw="${fw}Koa, "
  pj_has '@nestjs/core' && fw="${fw}NestJS, "
  pj_has next && fw="${fw}Next.js, "
  pj_has nuxt && fw="${fw}Nuxt, "
  pj_has '@remix-run/node' && fw="${fw}Remix, "
  pj_has '@sveltejs/kit' && fw="${fw}SvelteKit, "
  pj_has astro && fw="${fw}Astro, "
  pj_has '@tanstack/react-start' && fw="${fw}TanStack Start, "
  pj_has hono && fw="${fw}Hono, "
  if [[ -n "${fw}" ]]; then say "  Detected: ${fw%, }"; else say "  No well-known web framework detected in package.json."; fi

  if pj_has express || pj_has '@nestjs/core'; then
    if pj_has helmet; then ok CODE-HELMET "helmet is installed (it sets the common security headers)."
    else
      warn CODE-HELMET "Express/NestJS without helmet: the common security headers are probably not set."
      hint "npm install helmet, then app.use(helmet()). If a proxy already sets the headers, ignore this."
    fi
    if pj_has express-rate-limit || pj_has rate-limiter-flexible || pj_has express-slow-down || pj_has '@nestjs/throttler'; then
      ok CODE-RATE-LIMIT "A rate limiter is installed."
    else
      note CODE-RATE-LIMIT "No rate limiter found. Login and API routes are easier to brute-force without one (a proxy can do this too)."
    fi
  fi
  if is_quick; then return; fi
  if pj_has express; then
    if { pj_has express-session || pj_has cookie-session || pj_has cookie-parser; } \
       && ! { pj_has csurf || pj_has csrf-csrf || pj_has csrf-sync || pj_has lusca || pj_has tiny-csrf; }; then
      note CODE-CSRF "The app uses cookies but no CSRF protection package was found."
      hint "If forms or state-changing requests rely on a cookie, add csrf-csrf or csrf-sync, or set the cookie to SameSite=Strict."
    fi
    if [[ "${PROXY}" != "none" && "${DO_SERVER}" -eq 1 ]] && ! code_has "trust proxy"; then
      note CODE-TRUST-PROXY "Express runs behind ${PROXY} but 'trust proxy' is not set, so it sees the proxy's address, not the visitor's."
      hint "app.set('trust proxy', 1) makes rate limits and secure cookies work properly behind one proxy."
    fi
  fi
  if pj_has '@nestjs/core' && ! code_has 'ValidationPipe'; then
    note CODE-NEST-VALIDATION "NestJS without a ValidationPipe: request bodies are not checked against your DTOs."
    hint "app.useGlobalPipes(new ValidationPipe({ whitelist: true })) drops fields you didn't declare."
  fi
  if pj_has fastify && ! pj_has '@fastify/helmet'; then note CODE-HELMET "Fastify without @fastify/helmet: check that security headers are set somewhere."; fi
  if pj_has koa && ! pj_has koa-helmet; then note CODE-HELMET "Koa without koa-helmet: check that security headers are set somewhere."; fi
  if pj_has next; then
    local nc
    nc="$(ls "${PROJECT_DIR}"/next.config.* 2>/dev/null | head -n 1)"
    if [[ -z "${nc}" ]] || ! grep -qE 'poweredByHeader[[:space:]]*:[[:space:]]*false' "${nc}" 2>/dev/null; then
      note CODE-NEXT-POWERED "Next.js sends an 'X-Powered-By' header unless next.config has poweredByHeader: false."
    fi
    if [[ -n "${nc}" ]]; then
      if ! grep -qE 'headers[[:space:]]*\(|headers[[:space:]]*:' "${nc}" 2>/dev/null && [[ ! -f "${PROJECT_DIR}/middleware.ts" && ! -f "${PROJECT_DIR}/middleware.js" && ! -f "${PROJECT_DIR}/src/middleware.ts" && ! -f "${PROJECT_DIR}/src/middleware.js" ]]; then
        note CODE-NEXT-HEADERS "next.config sets no headers() and there is no middleware, so security headers must come from the host or a proxy."
      fi
      if grep -qE "hostname[[:space:]]*:[[:space:]]*[\"'](\*\*?|\*\*\.\*)[\"']" "${nc}" 2>/dev/null; then
        warn CODE-NEXT-IMAGES "next.config lets the image optimiser fetch from any host (remotePatterns hostname '**')."
        hint "Anyone can use your server to fetch and resize images from anywhere. List the hosts you use."
      fi
      grep -qE 'dangerouslyAllowSVG[[:space:]]*:[[:space:]]*true' "${nc}" 2>/dev/null \
        && warn CODE-NEXT-SVG "next.config has dangerouslyAllowSVG: true. SVG files can carry scripts; add a strict contentSecurityPolicy for images."
      grep -qE 'productionBrowserSourceMaps[[:space:]]*:[[:space:]]*true' "${nc}" 2>/dev/null \
        && note CODE-NEXT-SOURCEMAPS "next.config publishes source maps in production, so visitors can read your original source."
    fi
  fi
  if pj_has graphql || pj_has '@apollo/server' || pj_has apollo-server || pj_has graphql-yoga || pj_has mercurius; then
    if ! { pj_has graphql-depth-limit || pj_has graphql-query-complexity || pj_has '@escape.tech/graphql-armor' || pj_has graphql-armor || pj_has graphql-rate-limit; }; then
      note CODE-GRAPHQL-LIMITS "GraphQL server with no query depth or complexity limit: one deeply nested query can overload it."
      hint "Add graphql-armor, graphql-depth-limit or graphql-query-complexity."
    fi
  fi
  local risky
  for risky in vm2 node-serialize; do
    if pj_has "${risky}"; then
      warn CODE-RISKY-PACKAGE "package.json uses '${risky}', which has known unfixed security problems and is no longer maintained."
    fi
  done
  if pj_has request; then note CODE-RISKY-PACKAGE "package.json uses 'request', which was deprecated in 2020 and gets no fixes. Use fetch, undici or got."; fi
}

docker_file_checks() {
  local df any_df=0 cf
  for df in "${PROJECT_DIR}"/Dockerfile "${PROJECT_DIR}"/Dockerfile.* "${PROJECT_DIR}"/*.Dockerfile; do
    [[ -f "${df}" ]] || continue
    if [[ "${any_df}" -eq 0 ]]; then subsection "Docker files"; any_df=1; fi
    check_dockerfile "${df}"
  done
  for cf in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    [[ -f "${PROJECT_DIR}/${cf}" ]] || continue
    if [[ "${any_df}" -eq 0 ]]; then subsection "Docker files"; any_df=1; fi
    local c="${PROJECT_DIR}/${cf}"
    if grep -qE '^[[:space:]]*privileged:[[:space:]]*true' "${c}"; then
      high CODE-COMPOSE-PRIVILEGED "${cf}: a service runs with 'privileged: true', which gives the container full control of the host."
    fi
    if grep -qF '/var/run/docker.sock' "${c}"; then
      warn CODE-COMPOSE-SOCKET "${cf}: a service mounts the Docker socket, which gives it control of every container and the host."
    fi
    if grep -qE "^[[:space:]]*-[[:space:]]*[\"']?(27017|6379|5432|3306|9200|11211):" "${c}"; then
      warn CODE-COMPOSE-DB-PORT "${cf}: a database port is published on every network interface."
      hint "Write it as \"127.0.0.1:5432:5432\", or drop the port line if only other containers need it."
      hint "Ports published by Docker are NOT blocked by ufw."
    fi
    is_quick && continue
    if grep -qE '^[[:space:]]*(network_mode|pid):[[:space:]]*["'"'"']?host' "${c}"; then
      warn CODE-COMPOSE-HOST "${cf}: a service shares the host's network or process list (network_mode/pid: host)."
    fi
    if grep -A3 -E '^[[:space:]]*cap_add:' "${c}" | grep -qE '(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE)'; then
      warn CODE-COMPOSE-CAPS "${cf}: a service is given extra kernel permissions (cap_add)."
    fi
    if grep -qE "^[[:space:]]*-?[[:space:]]*[A-Za-z0-9_]*(PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*[\"']?[^\"'\$[:space:]{][^[:space:]]{3,}" "${c}"; then
      warn CODE-COMPOSE-SECRET "${cf}: a password or secret is written directly in the file."
      hint "Use \${VARIABLE} with a .env file that is not committed, or Docker secrets."
    fi
    if grep -qE '^[[:space:]]*image:[[:space:]]*[^[:space:]:@]+(:latest)?[[:space:]]*$' "${c}"; then
      note CODE-COMPOSE-LATEST "${cf}: an image has no version tag (or uses 'latest'), so restarts can pull a different version."
    fi
    if ! grep -qE 'no-new-privileges' "${c}"; then
      note CODE-COMPOSE-HARDEN "${cf}: no service sets 'security_opt: [no-new-privileges:true]' (and consider 'read_only: true')."
    fi
  done
}

check_dockerfile() {
  local df="$1" name last_user missing="" img
  name="$(basename "$1")"
  last_user="$(grep -iE '^[[:space:]]*USER[[:space:]]+' "${df}" | tail -n 1 | awk '{ print $2 }')"
  if [[ -z "${last_user}" ]]; then
    warn CODE-DOCKER-USER "${name}: no USER line, so the app runs as root inside the container."
    hint "Add 'USER node' before the CMD line (the official node images include that user)."
  elif [[ "${last_user}" == "root" || "${last_user}" == "0" ]]; then
    warn CODE-DOCKER-USER "${name}: the last USER line is root, so the app runs as root inside the container."
  else
    ok CODE-DOCKER-USER "${name}: runs as a non-root user ($(clean "${last_user}"))."
  fi
  grep -iE '^[[:space:]]*FROM[[:space:]]+' "${df}" | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; break } }' > "${TMP}/from.txt"
  grep -iE '^[[:space:]]*FROM[[:space:]]+.*[[:space:]]+[Aa][Ss][[:space:]]+' "${df}" | awk '{ print $NF }' > "${TMP}/stages.txt"
  while IFS= read -r img; do
    [[ -z "${img}" || "${img}" == "scratch" ]] && continue
    grep -qxF -- "${img}" "${TMP}/stages.txt" && continue
    case "${img}" in
      *'$'*) ;;
      *@sha256:*) ;;
      *:latest) warn CODE-DOCKER-TAG "${name}: base image '$(clean "${img}")' uses the 'latest' tag, so builds change without notice. Pin a version." ;;
      *:*) ;;
      *) warn CODE-DOCKER-TAG "${name}: base image '$(clean "${img}")' has no version tag, so builds change without notice. Pin a version." ;;
    esac
  done < "${TMP}/from.txt"
  if grep -qiE '^[[:space:]]*(COPY|ADD)[[:space:]].*(^|[[:space:]/])\.env([[:space:]]|$)' "${df}"; then
    high CODE-DOCKER-ENV "${name}: copies a .env file into the image. Anyone who can pull the image can read it."
    hint "Pass secrets when the container starts (environment variables or a secrets manager)."
  fi
  if grep -qiE '^[[:space:]]*(ENV|ARG)[[:space:]]+[A-Za-z0-9_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY)' "${df}"; then
    warn CODE-DOCKER-SECRET "${name}: a secret-looking ENV or ARG. Their values are stored in the image history."
    hint "Use build secrets (RUN --mount=type=secret) or pass the value when the container starts."
  fi
  if grep -qiE '^[[:space:]]*ADD[[:space:]]+https?://' "${df}"; then
    warn CODE-DOCKER-ADD "${name}: ADD downloads from a URL with no integrity check."
  fi
  if grep -qiE '^[[:space:]]*(COPY|ADD)[[:space:]]+(--[^[:space:]]+[[:space:]]+)*\.[[:space:]]' "${df}"; then
    if [[ ! -f "${PROJECT_DIR}/.dockerignore" ]]; then
      warn CODE-DOCKERIGNORE "${name} copies the whole folder and there is no .dockerignore, so .env, .git and node_modules can end up in the image."
    else
      grep -qE '^\**/?\.env' "${PROJECT_DIR}/.dockerignore" || missing="${missing} .env"
      grep -qE '^\**/?\.git/?$' "${PROJECT_DIR}/.dockerignore" || missing="${missing} .git"
      if [[ -n "${missing}" ]]; then
        warn CODE-DOCKERIGNORE ".dockerignore doesn't list:${missing}. Those can end up inside the image."
      fi
    fi
  fi
  is_quick && return
  if grep -qiE '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh' "${df}"; then
    warn CODE-DOCKER-CURL-PIPE "${name}: downloads a script and pipes it straight into a shell (curl | sh), with no check of what arrives."
  fi
  if grep -qiE 'chmod[[:space:]]+(-R[[:space:]]+)?(777|a\+rwx)' "${df}"; then
    warn CODE-DOCKER-CHMOD "${name}: chmod 777 makes files writable by every user in the container."
  fi
  if grep -qiE '^[[:space:]]*EXPOSE[[:space:]]+.*(^|[[:space:]])22([[:space:]/]|$)' "${df}"; then
    warn CODE-DOCKER-SSH "${name}: exposes port 22. An SSH server inside an app container is rarely needed; use 'docker exec'."
  fi
  if grep -qiE '^[[:space:]]*RUN[[:space:]].*npm[[:space:]]+(install|i)([[:space:]]|$)' "${df}" && ! grep -qiE 'npm[[:space:]]+ci' "${df}"; then
    note CODE-DOCKER-NPM-CI "${name}: uses 'npm install'. 'npm ci' installs exactly what the lockfile says and fails if they disagree."
  fi
  if ! grep -qiE 'NODE_ENV[[:space:]=]+["'"'"']?production' "${df}"; then
    note CODE-DOCKER-NODE-ENV "${name}: NODE_ENV=production is not set. Many frameworks show detailed errors to visitors without it."
  fi
}

kubernetes_checks() {
  local list="${TMP}/k8s-files.txt" f rel
  if [[ "${GIT_OK}" -eq 1 ]]; then
    git -C "${PROJECT_DIR}" ls-files -- '*.yml' '*.yaml' 2>/dev/null | grep -vE '^\.github/|node_modules/' | head -n 400 > "${TMP}/yaml.txt"
  else
    (cd "${PROJECT_DIR}" && find . -maxdepth 5 \( -name node_modules -o -name .git -o -name .github \) -prune -o -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null | sed 's|^\./||' | head -n 400) > "${TMP}/yaml.txt"
  fi
  : > "${list}"
  while IFS= read -r rel; do
    grep -qE '^kind:[[:space:]]*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)[[:space:]]*$' "${PROJECT_DIR}/${rel}" 2>/dev/null && printf '%s\n' "${rel}" >> "${list}"
  done < "${TMP}/yaml.txt"
  # Secrets committed as Kubernetes Secret objects.
  : > "${TMP}/k8s-secret.txt"
  while IFS= read -r rel; do
    if grep -qE '^kind:[[:space:]]*Secret[[:space:]]*$' "${PROJECT_DIR}/${rel}" 2>/dev/null && grep -qE '^(data|stringData):' "${PROJECT_DIR}/${rel}" 2>/dev/null; then
      printf '%s\n' "${rel}" >> "${TMP}/k8s-secret.txt"
    fi
  done < "${TMP}/yaml.txt"
  [[ -s "${list}" || -s "${TMP}/k8s-secret.txt" ]] || return 0
  subsection "Kubernetes files"
  k8s_issue() {   # ID LEVEL "message" PATTERN [invert]
    local id="$1" level="$2" msg="$3" pat="$4" invert="${5:-}" out="${TMP}/k8s-hit.txt"
    : > "${out}"
    while IFS= read -r f; do
      if [[ -n "${invert}" ]]; then
        grep -qE "${pat}" "${PROJECT_DIR}/${f}" 2>/dev/null || printf '%s\n' "${f}" >> "${out}"
      else
        grep -qE "${pat}" "${PROJECT_DIR}/${f}" 2>/dev/null && printf '%s\n' "${f}" >> "${out}"
      fi
    done < "${list}"
    filter_locs "${id}" "${out}"
    [[ -s "${out}" ]] || return 0
    "${level}" "${id}" "${msg}"
    show_locs "${out}" 5
  }
  if [[ -s "${list}" ]]; then
    k8s_issue CODE-K8S-PRIVILEGED high "Kubernetes: a container runs privileged, with full control of the node:" '^[[:space:]]*privileged:[[:space:]]*true'
    k8s_issue CODE-K8S-HOST warn "Kubernetes: a pod shares the node's network, process list or files (hostNetwork, hostPID, hostPath):" '^[[:space:]]*(hostNetwork|hostPID|hostIPC):[[:space:]]*true|^[[:space:]]*hostPath:'
    k8s_issue CODE-K8S-ROOT warn "Kubernetes: a container is told to run as root (runAsUser: 0 or runAsNonRoot: false):" '^[[:space:]]*runAsUser:[[:space:]]*0[[:space:]]*$|^[[:space:]]*runAsNonRoot:[[:space:]]*false'
    k8s_issue CODE-K8S-ESCALATION warn "Kubernetes: allowPrivilegeEscalation is true:" '^[[:space:]]*allowPrivilegeEscalation:[[:space:]]*true'
    k8s_issue CODE-K8S-LATEST warn "Kubernetes: an image has no version tag or uses 'latest':" '^[[:space:]]*-?[[:space:]]*image:[[:space:]]*["'"'"']?[^[:space:]:@"'"'"']+(:latest)?["'"'"']?[[:space:]]*$'
    # A secret-named variable followed by "value:" (rather than "valueFrom:").
    : > "${TMP}/k8s-env.txt"
    while IFS= read -r f; do
      awk '/name:[[:space:]]*["\047]?[A-Za-z0-9_]*(PASSWORD|SECRET|TOKEN|API_?KEY)[A-Za-z0-9_]*["\047]?[[:space:]]*$/ { armed = 1; next }
           armed && /^[[:space:]]*$/ { next }
           armed { if ($0 ~ /^[[:space:]]*value:[[:space:]]*[^[:space:]]/) found = 1; armed = 0 }
           END { exit found ? 0 : 1 }' "${PROJECT_DIR}/${f}" 2>/dev/null && printf '%s\n' "${f}" >> "${TMP}/k8s-env.txt"
    done < "${list}"
    filter_locs CODE-K8S-ENV-SECRET "${TMP}/k8s-env.txt"
    if [[ -s "${TMP}/k8s-env.txt" ]]; then
      warn CODE-K8S-ENV-SECRET "Kubernetes: a password or secret is written as a plain env value (use secretKeyRef):"
      show_locs "${TMP}/k8s-env.txt" 5
    fi
    k8s_issue CODE-K8S-NONROOT note "Kubernetes: no 'runAsNonRoot: true', so nothing stops the container running as root:" 'runAsNonRoot:[[:space:]]*true' invert
    k8s_issue CODE-K8S-LIMITS note "Kubernetes: no resource limits, so one container can starve the others:" '^[[:space:]]*limits:' invert
  fi
  if [[ -s "${TMP}/k8s-secret.txt" ]]; then
    filter_locs CODE-K8S-SECRET-FILE "${TMP}/k8s-secret.txt"
    if [[ -s "${TMP}/k8s-secret.txt" ]]; then
      warn CODE-K8S-SECRET-FILE "Kubernetes Secret object(s) with values in the project. Base64 is not encryption:"
      show_locs "${TMP}/k8s-secret.txt" 5
      hint "Use Sealed Secrets, SOPS or an external secrets manager, and change any real values that were committed."
    fi
  fi
}

workflow_checks() {
  [[ -d "${PROJECT_DIR}/.github/workflows" ]] || return 0
  subsection "GitHub Actions workflows"
  local wf="${PROJECT_DIR}/.github/workflows"
  grep -hE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^[:space:]]+' "${wf}"/*.yml "${wf}"/*.yaml 2>/dev/null \
    | sed -e 's/^[[:space:]]*-\{0,1\}[[:space:]]*uses:[[:space:]]*//' -e 's/[[:space:]]*#.*$//' -e "s/[\"']//g" \
    | grep -vE '^(\./|docker://)' > "${TMP}/uses.txt"
  local n_uses n_unpinned
  n_uses="$(count_lines "${TMP}/uses.txt")"
  grep -vE '@[0-9a-f]{40}$' "${TMP}/uses.txt" | sort -u > "${TMP}/uses-unpinned.txt"
  n_unpinned="$(count_lines "${TMP}/uses-unpinned.txt")"
  if [[ "${n_uses}" -eq 0 ]]; then
    na "No third-party actions used."
  elif [[ "${n_unpinned}" -eq 0 ]]; then
    ok CODE-ACTIONS-PIN "Every action is pinned to a full commit hash."
  else
    warn CODE-ACTIONS-PIN "${n_unpinned} action reference(s) use a tag or branch instead of a full commit hash."
    hint "A tag can be moved to malicious code later. Pin to the 40-character commit hash."
    show_locs "${TMP}/uses-unpinned.txt" 5
  fi
  grep -lE 'pull_request_target' "${wf}"/*.yml "${wf}"/*.yaml > "${TMP}/prt.txt" 2>/dev/null || true
  if [[ -s "${TMP}/prt.txt" ]]; then
    warn CODE-ACTIONS-PRT "A workflow uses pull_request_target. It runs with your secrets, so it must never check out or run code from the pull request."
  fi
  is_quick && return
  # Text written by outsiders (titles, branch names, comments) used inside a script.
  grep -nE '\$\{\{[[:space:]]*github\.(head_ref|event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)[A-Za-z0-9_.]*\.(title|body|message|name|email|ref|label|head_ref|page_name|display_title))[[:space:]]*\}\}' \
      "${wf}"/*.yml "${wf}"/*.yaml 2>/dev/null \
    | grep -vE ':[0-9]+:[[:space:]]*(-[[:space:]]*)?([A-Z_][A-Z0-9_]*|if|name|group|ref|title|body|concurrency)[[:space:]]*:' \
    | cut -d: -f1,2 | sed "s|^${PROJECT_DIR}/||" > "${TMP}/inject.txt" || true
  filter_locs CODE-ACTIONS-INJECTION "${TMP}/inject.txt"
  if [[ -s "${TMP}/inject.txt" ]]; then
    warn CODE-ACTIONS-INJECTION "A workflow puts text written by outsiders (a title, branch name or comment) straight into a script:"
    show_locs "${TMP}/inject.txt" 5
    hint "Someone can open an issue or pull request whose title is a shell command. Pass the value through 'env:' and use \"\$VAR\" in the script."
    hint "This is how the Nx packages were hijacked in August 2025."
  fi
  grep -LE '^[[:space:]]*permissions:' "${wf}"/*.yml "${wf}"/*.yaml 2>/dev/null | sed "s|^${PROJECT_DIR}/||" > "${TMP}/noperm.txt" || true
  if [[ -s "${TMP}/noperm.txt" ]]; then
    note CODE-ACTIONS-PERMISSIONS "$(count_lines "${TMP}/noperm.txt") workflow(s) set no 'permissions:', so they get the repository's default token rights (often read and write)."
    hint "Start each workflow with 'permissions: { contents: read }' and add only what a job needs."
  fi
  if grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh' "${wf}"/*.yml "${wf}"/*.yaml 2>/dev/null; then
    warn CODE-ACTIONS-CURL-PIPE "A workflow downloads a script and pipes it straight into a shell (curl | sh), next to your secrets."
  fi
  if grep -qE 'runs-on:.*self-hosted' "${wf}"/*.yml "${wf}"/*.yaml 2>/dev/null; then
    note CODE-ACTIONS-SELF-HOSTED "A workflow runs on a self-hosted runner. On a public repository, a pull request can run code on that machine."
  fi
}

# ============================================================ PART 3 ======
PORTS_FILE="${TMP}/ports.txt"; : > "${PORTS_FILE}"
NODE_PS="${TMP}/node-ps.txt"; : > "${NODE_PS}"

# Commands that have no good reason to be in a cron job, service or login script.
BAD_COMMANDS='(curl|wget)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh|base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba)?sh|/dev/tcp/|(^|[[:space:]/])(nc|ncat|netcat)[[:space:]]+[^|;&]*-e[[:space:]]|xmrig|stratum\+(tcp|ssl)://|\.onion([/:[:space:]]|$)|pastebin\.com/raw|python[0-9.]*[[:space:]]+-c[[:space:]]+.?import[[:space:]]+(socket|pty)'
MINER_NAMES='(^|[/[:space:]])(xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|nanominer|lolminer|ethminer|phoenixminer|nbminer|t-rex|sysrv)([[:space:]]|$)|stratum\+(tcp|ssl)://'

# port_public PORT: true if that port listens on a non-loopback address.
port_public() {
  awk -F '\t' -v p="$1" '$2 == p && $1 !~ /^(127\.|\[::1\]|::1$|localhost)/ { found = 1 } END { exit found ? 0 : 1 }' "${PORTS_FILE}"
}

part_server() {
  section server "Part 3 of 3: server"
  case "${SERVER}" in
    dev)
      na "Machine checks skipped: this is a development machine, not the server."
      hint "Run this script on the server itself (with --server vps or --server docker) to check it."
      ;;
    managed)
      na "Machine checks skipped: the hosting platform looks after the machine."
      note SRV-MANAGED "On a hosting platform, your part is: secrets set in the platform's dashboard (not in the repository),"
      hint "who has access to the account (use two-factor sign-in), and the headers your app sends."
      ;;
    vps|docker)
      if [[ "${OS_NAME}" != "Linux" ]]; then
        incomplete SRV-NOT-LINUX "The machine checks need Linux; this machine runs ${OS_NAME}. Run the script on the server."
      else
        if [[ "${IS_ROOT}" -eq 0 ]]; then
          note SRV-NOT-ROOT "Not running as root, so some checks can't see everything. For the full picture: sudo $0 ..."
        fi
        server_processes
        server_ports
        if ! is_quick; then server_breakin; server_accounts; fi
        server_firewall
        server_ssh
        server_updates
        if ! is_quick; then server_os; server_databases; server_app; fi
        server_files
        server_proxy
        if [[ "${SERVER}" == "vps" ]]; then server_runner; else server_docker; fi
        if is_deep && [[ "${NO_TOOLS}" -eq 0 ]]; then
          subsection "Specialist tools (server)"
          tools_server
        fi
      fi
      ;;
  esac
  if [[ -n "${URL}" ]]; then
    server_url
  else
    subsection "Live site"
    na "No address given (use --url https://your-site) so HTTPS, headers and DNS were not checked."
  fi
}

server_processes() {
  subsection "Node processes"
  grep -E '^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+([^[:space:]]*/)?(node|nodejs|bun|next-server)([[:space:]]|$)' "${PS_FILE}" > "${NODE_PS}"
  if [[ ! -s "${NODE_PS}" ]]; then
    note SRV-NO-NODE "No running Node or Bun process found on this machine. Is this the right machine, and is the app running?"
    return
  fi
  local user pid args root_seen=0 inspect_seen=0
  while read -r user pid args; do
    args="$(clean "${args}")"
    if [[ "${user}" == "root" ]]; then
      if [[ "${SERVER}" == "docker" ]]; then
        warn SRV-NODE-ROOT "Node process running as root (PID ${pid}): ${args:0:80}"
      else
        high SRV-NODE-ROOT "Node process running as root (PID ${pid}): ${args:0:80}"
      fi
      if [[ "${root_seen}" -eq 0 ]]; then
        hint "If the app is broken into, the attacker gets the same rights as the app. Run it as its own unprivileged user."
      fi
      root_seen=1
    fi
    case " ${args} " in
      *" --inspect"*)
        inspect_seen=1
        case "${args}" in
          *"--inspect=0.0.0.0"*|*"--inspect-brk=0.0.0.0"*|*"--inspect=[::]"*)
            high SRV-NODE-INSPECT "Node debugger open to the network (PID ${pid}). Anyone who can reach that port can run code as the app." ;;
          *) warn SRV-NODE-INSPECT "Node debugger switched on (PID ${pid}, --inspect). Remove it in production." ;;
        esac ;;
    esac
  done < "${NODE_PS}"
  [[ "${root_seen}" -eq 0 ]] && ok SRV-NODE-ROOT "No Node process runs as root."
  [[ "${inspect_seen}" -eq 0 ]] && ok SRV-NODE-INSPECT "No Node process has the debugger (--inspect) switched on."
}

server_ports() {
  subsection "Listening ports"
  local raw="${TMP}/ports-raw.txt" ports="${PORTS_FILE}"
  if have ss; then
    ss -H -tlnp > "${raw}" 2>/dev/null || : > "${raw}"
    # LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=1,fd=18))
    awk '{
      addr = $4; n = split(addr, a, ":"); port = a[n]
      host = substr(addr, 1, length(addr) - length(port) - 1)
      proc = ""; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
      print host "\t" port "\t" proc
    }' "${raw}" > "${ports}"
  elif have netstat; then
    netstat -tlnp 2>/dev/null | awk '$1 ~ /^tcp/ {
      addr = $4; n = split(addr, a, ":"); port = a[n]
      host = substr(addr, 1, length(addr) - length(port) - 1)
      proc = $NF; sub(/^[0-9]+\//, "", proc); if (proc == "-") proc = ""
      print host "\t" port "\t" proc
    }' > "${ports}"
  else
    incomplete SRV-PORTS "Neither ss nor netstat is installed, so listening ports were not checked."
    return
  fi
  if [[ ! -s "${ports}" ]]; then
    note SRV-PORTS "No listening TCP ports found."
    return
  fi
  local host port proc open_node=0 open_db=0 label
  while IFS="${TAB}" read -r host port proc; do
    case "${host}" in 127.*|"[::1]"|::1|localhost) continue ;; esac
    case "${proc}" in
      node|nodejs|bun|"node "*)
        open_node=1
        if [[ "${PROXY}" != "none" ]]; then
          warn SRV-NODE-PUBLIC "Node listens on every network interface (port ${port}), so visitors can bypass ${PROXY} unless a firewall blocks that port."
          hint "Listen on 127.0.0.1 only, e.g. app.listen(${port}, '127.0.0.1')."
        else
          note SRV-NODE-PUBLIC "Node listens on port ${port} on every network interface and answers visitors directly."
        fi ;;
    esac
    label=""
    case "${port}" in
      27017) label="MongoDB" ;; 6379) label="Redis" ;; 5432) label="PostgreSQL" ;;
      3306) label="MySQL/MariaDB" ;; 9200) label="Elasticsearch" ;; 11211) label="Memcached" ;;
      5984) label="CouchDB" ;; 9229) label="the Node debugger" ;; 2375) label="the Docker API (no encryption or sign-in)" ;;
    esac
    if [[ -n "${label}" ]]; then
      open_db=1
      warn "SRV-PORT-${port}" "Port ${port} (${label}) listens on every network interface (${host})."
      hint "Unless a firewall blocks it, the whole internet can reach it. Bind it to 127.0.0.1."
    fi
  done < "${ports}"
  [[ "${open_db}" -eq 0 ]] && ok SRV-PORTS "No database or debugger port listens on a public interface."
  if [[ "${open_node}" -eq 0 && "${IS_ROOT}" -eq 0 ]]; then
    note SRV-NODE-PUBLIC "Without root, the script can't see which program owns each port, so it couldn't check how Node listens."
  elif [[ "${open_node}" -eq 0 ]]; then
    ok SRV-NODE-PUBLIC "Node doesn't listen on a public interface."
  fi
}

server_breakin() {
  subsection "Signs of a break-in"
  local found=0 f out="${TMP}/breakin.txt"

  # Processes: crypto-miners, and programs started from temporary folders.
  grep -E "${MINER_NAMES}" "${PS_FILE}" | awk '{ print "PID " $2 " (" $1 "): " substr($0, index($0, $3), 70) }' > "${out}" || true
  if [[ -s "${out}" ]]; then
    found=1
    high SRV-MINER "A process looks like a crypto-miner:"
    show_locs "${out}" 5
  fi
  grep -E '^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+(/tmp/|/var/tmp/|/dev/shm/)|^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+([^[:space:]]*/)?(ba|da|z)?sh[[:space:]]+(-c[[:space:]]+)?(/tmp/|/var/tmp/|/dev/shm/)' "${PS_FILE}" \
    | awk '{ print "PID " $2 " (" $1 "): " substr($0, index($0, $3), 70) }' > "${out}" || true
  if [[ -s "${out}" ]]; then
    found=1
    high SRV-TMP-PROCESS "A program is running from a temporary folder (/tmp, /var/tmp or /dev/shm), where malware usually lands:"
    show_locs "${out}" 5
  fi

  # Scheduled jobs.
  : > "${TMP}/cron-all.txt"
  for f in "${SYSROOT}/etc/crontab" "${SYSROOT}"/etc/cron.d/* "${SYSROOT}"/var/spool/cron/crontabs/* "${SYSROOT}"/var/spool/cron/*; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    grep -vE '^[[:space:]]*(#|$)' "${f}" 2>/dev/null | sed "s|^|${f#"${SYSROOT}"}: |" >> "${TMP}/cron-all.txt"
  done
  if have crontab; then crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sed "s|^|crontab of ${ME}: |" >> "${TMP}/cron-all.txt" || true; fi
  grep -E "${BAD_COMMANDS}" "${TMP}/cron-all.txt" | cut -c1-140 > "${out}" || true
  if [[ -s "${out}" ]]; then
    found=1
    high SRV-CRON "A scheduled job downloads and runs something, or opens a remote shell:"
    show_locs "${out}" 5
  fi
  grep -vE "${BAD_COMMANDS}" "${TMP}/cron-all.txt" | grep -E '[[:space:]](/tmp|/var/tmp|/dev/shm)/[^[:space:]]+' | cut -c1-140 > "${out}" || true
  if [[ -s "${out}" ]]; then
    found=1
    warn SRV-CRON-TMP "A scheduled job runs something from a temporary folder. Check that you set it up:"
    show_locs "${out}" 5
  fi

  # Services.
  : > "${TMP}/units.txt"
  for f in "${SYSROOT}"/etc/systemd/system/*.service "${HOME:-/nonexistent}"/.config/systemd/user/*.service; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost)[[:space:]]*=' "${f}" 2>/dev/null | sed "s|^|$(basename "${f}"): |" >> "${TMP}/units.txt"
  done
  grep -E "${BAD_COMMANDS}|=[[:space:]]*[-@+!]*(/tmp|/var/tmp|/dev/shm)/|=[[:space:]]*[-@+!]*/[^[:space:]]*/\.[^/[:space:]]+/[^[:space:]]*" "${TMP}/units.txt" | cut -c1-140 > "${out}" || true
  if [[ -s "${out}" ]]; then
    found=1
    high SRV-UNIT "A systemd service starts something from a temporary or hidden folder, or downloads and runs code:"
    show_locs "${out}" 5
  fi
  if [[ -d "${SYSROOT}/etc/systemd/system" ]]; then
    find "${SYSROOT}/etc/systemd/system" -maxdepth 1 -name '*.service' -type f -mtime -7 2>/dev/null | sed 's|.*/||' > "${out}"
    if [[ -s "${out}" ]]; then
      note SRV-UNIT-NEW "systemd service file(s) created or changed in the last 7 days. Fine if you did it:"
      show_locs "${out}" 5
    fi
  fi

  # Library pre-loading and login scripts.
  if [[ -s "${SYSROOT}/etc/ld.so.preload" ]]; then
    found=1
    high SRV-PRELOAD "/etc/ld.so.preload is not empty. It loads a library into every program, which is a common rootkit technique."
    hint "Unless you put it there (some monitoring tools do), treat this machine as compromised."
  fi
  : > "${out}"
  for f in "${HOME:-/nonexistent}/.bashrc" "${HOME:-/nonexistent}/.profile" "${HOME:-/nonexistent}/.bash_profile" "${HOME:-/nonexistent}/.zshrc" "${SYSROOT}"/etc/profile.d/*.sh "${SYSROOT}/root/.bashrc"; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    grep -qE "${BAD_COMMANDS}" "${f}" 2>/dev/null && printf '%s\n' "${f#"${SYSROOT}"}" >> "${out}"
  done
  if [[ -s "${out}" ]]; then
    found=1
    high SRV-SHELL-RC "A login script downloads and runs something, or opens a remote shell:"
    show_locs "${out}" 5
  fi
  if [[ "${IS_ROOT}" -eq 1 && -d "${SYSROOT}/proc" ]]; then
    find "${SYSROOT}/proc" -maxdepth 2 -name exe -lname '*(deleted)' 2>/dev/null | head -n 20 > "${out}" || true
    if [[ -s "${out}" ]]; then
      note SRV-DELETED-EXE "$(count_lines "${out}") running program(s) whose file on disk has been deleted or replaced."
      hint "Usually this means a package was updated and the service needs a restart. Occasionally it is malware hiding itself."
    fi
  fi
  [[ "${found}" -eq 0 ]] && ok SRV-BREAKIN "None of the known signs of a break-in (miners, programs in /tmp, odd scheduled jobs, services or login scripts)."
}

server_accounts() {
  subsection "Accounts and sign-ins"
  local out="${TMP}/acct.txt" f n user before
  before="$(count_lines "${FINDINGS}")"

  if [[ -r "${SYSROOT}/etc/passwd" ]]; then
    awk -F: '$3 == 0 && $1 != "root" { print $1 }' "${SYSROOT}/etc/passwd" > "${out}"
    if [[ -s "${out}" ]]; then
      high SRV-UID0 "Account(s) other than root with full root rights (user ID 0):"
      show_locs "${out}" 5
      hint "Unless you created them on purpose, this is a classic back door."
    else
      ok SRV-UID0 "root is the only account with user ID 0."
    fi
  fi
  if [[ -r "${SYSROOT}/etc/shadow" ]]; then
    awk -F: '$2 == "" { print $1 }' "${SYSROOT}/etc/shadow" > "${out}"
    if [[ -s "${out}" ]]; then
      high SRV-EMPTY-PASSWORD "Account(s) with an empty password:"
      show_locs "${out}" 5
    else
      ok SRV-EMPTY-PASSWORD "No account has an empty password."
    fi
  elif [[ -e "${SYSROOT}/etc/shadow" ]]; then
    incomplete SRV-EMPTY-PASSWORD "Checking for empty passwords needs root. Re-run with sudo."
  fi

  : > "${out}"
  for f in "${SYSROOT}/etc/sudoers" "${SYSROOT}"/etc/sudoers.d/*; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    grep -E '^[^#]*NOPASSWD' "${f}" 2>/dev/null | awk '{ print $1 }' >> "${out}"
  done
  if [[ -s "${out}" ]]; then
    sort -u "${out}" -o "${out}"
    warn SRV-SUDO-NOPASSWD "These accounts can become root without typing a password (sudo NOPASSWD):"
    show_locs "${out}" 5
    hint "Cloud images set this up for the default user. If the app runs as one of these accounts, a break-in gets root for free."
  fi

  # Who can sign in with an SSH key.
  : > "${out}"; : > "${TMP}/keys-new.txt"
  for f in "${SYSROOT}/root/.ssh/authorized_keys" "${SYSROOT}"/home/*/.ssh/authorized_keys; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    n="$(grep -cvE '^[[:space:]]*(#|$)' "${f}" 2>/dev/null)"
    [[ "${n}" -eq 0 ]] && continue
    user="${f#"${SYSROOT}"}"; user="${user%/.ssh/authorized_keys}"; user="${user##*/}"
    printf '%s: %s key(s) [%s]\n' "${user}" "${n}" "$(grep -vE '^[[:space:]]*(#|$)' "${f}" | awk '{ c = $NF; if (NF < 3 || c ~ /^AAAA/) c = "no label"; printf "%s%s", sep, substr(c, 1, 30); sep = ", " }')" >> "${out}"
    [[ -n "$(find "${f}" -mtime -7 2>/dev/null)" ]] && printf '%s\n' "${user}" >> "${TMP}/keys-new.txt"
  done
  if [[ -s "${out}" ]]; then
    note SRV-SSH-KEYS "SSH keys that can sign in to this machine. Remove any you don't recognise:"
    show_locs "${out}" 8
  fi
  if [[ -s "${TMP}/keys-new.txt" ]]; then
    warn SRV-SSH-KEYS-NEW "The list of SSH keys was changed in the last 7 days for:"
    show_locs "${TMP}/keys-new.txt" 5
    hint "Fine if you added a key. An attacker adding their own key is the usual way to keep access."
  fi

  # Recent sign-in attempts.
  for f in "${SYSROOT}/var/log/auth.log" "${SYSROOT}/var/log/secure"; do
    [[ -f "${f}" && -r "${f}" ]] || continue
    n="$(grep -cE 'Failed password|Invalid user' "${f}" 2>/dev/null)"
    [[ "${n}" -gt 0 ]] && note SRV-SSH-FAILED "${n} failed SSH sign-in attempts in the current log. Normal for any server on the internet; it is why password sign-in should be off."
    if grep -qE 'Accepted password for root' "${f}" 2>/dev/null; then
      warn SRV-ROOT-PASSWORD-LOGIN "root has signed in over SSH with a password recently. Check that each of those was you."
    fi
    break
  done
  [[ "$(count_lines "${FINDINGS}")" == "${before}" ]] && na "No account files could be read here."
  return 0
}

server_firewall() {
  subsection "Firewall"
  local out="${TMP}/fw.txt"
  if have ufw; then
    if [[ "${IS_ROOT}" -eq 1 ]]; then
      ufw status > "${out}" 2>/dev/null || : > "${out}"
      if grep -qi '^Status: active' "${out}"; then ok SRV-FIREWALL "ufw is active."
      elif grep -qi '^Status: inactive' "${out}"; then
        warn SRV-FIREWALL "ufw is installed but switched off."
        hint "Allow SSH first, then switch it on: ufw allow OpenSSH && ufw allow 80,443/tcp && ufw enable"
      else incomplete SRV-FIREWALL "Couldn't read the ufw status."
      fi
    elif [[ -r "${SYSROOT}/etc/ufw/ufw.conf" ]]; then
      if grep -qi '^ENABLED=yes' "${SYSROOT}/etc/ufw/ufw.conf"; then ok SRV-FIREWALL "ufw is enabled (from its config file)."
      else warn SRV-FIREWALL "ufw is installed but not enabled (from its config file)."; fi
    else
      incomplete SRV-FIREWALL "Checking ufw needs root. Re-run with sudo."
    fi
    return
  fi
  if have firewall-cmd; then
    if firewall-cmd --state >/dev/null 2>&1; then ok SRV-FIREWALL "firewalld is running."
    else warn SRV-FIREWALL "firewalld is installed but not running."; fi
    return
  fi
  if [[ "${IS_ROOT}" -eq 0 ]]; then
    incomplete SRV-FIREWALL "No ufw or firewalld found, and reading other firewall rules needs root. Re-run with sudo."
    return
  fi
  local rules=0
  if have nft; then
    nft list ruleset > "${out}" 2>/dev/null || : > "${out}"
    rules="$(grep -cE '(accept|drop|reject)' "${out}")"
  fi
  if [[ "${rules}" -eq 0 ]] && have iptables; then
    iptables -S > "${out}" 2>/dev/null || : > "${out}"
    rules="$(grep -cvE '^-P ' "${out}")"
  fi
  if [[ "${rules}" -gt 0 ]]; then
    ok SRV-FIREWALL "Firewall rules are present (nftables/iptables). Their content was not analysed."
  else
    warn SRV-FIREWALL "No firewall rules found on this machine."
    hint "Your hosting provider's firewall may still protect it. If not, set one up (ufw is the simplest)."
  fi
}

# sshd_value KEY: effective value, lower case, or empty if not set.
SSHD_EFFECTIVE=""    # "yes" once "sshd -T" has given its effective settings, "no" if it couldn't
sshd_value() {
  local key="$1" files
  if [[ -z "${SSHD_EFFECTIVE}" ]]; then
    SSHD_EFFECTIVE="no"
    if [[ "${IS_ROOT}" -eq 1 ]] && have sshd && sshd -T > "${TMP}/sshd-t.txt" 2>/dev/null && [[ -s "${TMP}/sshd-t.txt" ]]; then
      SSHD_EFFECTIVE="yes"
    fi
  fi
  if [[ "${SSHD_EFFECTIVE}" == "yes" ]]; then
    awk -v k="${key}" 'tolower($1) == k { print tolower($2); exit }' "${TMP}/sshd-t.txt"
    return
  fi
  files="$(ls "${SYSROOT}"/etc/ssh/sshd_config.d/*.conf 2>/dev/null) ${SYSROOT}/etc/ssh/sshd_config"
  # shellcheck disable=SC2086  # deliberate word splitting of the file list
  cat ${files} 2>/dev/null | awk -v k="${key}" 'tolower($1) == k { print tolower($2); exit }'
}

server_ssh() {
  subsection "SSH"
  if [[ ! -r "${SYSROOT}/etc/ssh/sshd_config" ]]; then
    if [[ -e "${SYSROOT}/etc/ssh/sshd_config" ]]; then incomplete SRV-SSH "Can't read the SSH server settings without root. Re-run with sudo."
    else na "No SSH server settings found on this machine."; fi
    return
  fi
  local root_login pass_auth v
  root_login="$(sshd_value permitrootlogin)"
  pass_auth="$(sshd_value passwordauthentication)"
  case "${root_login}" in
    yes) warn SRV-SSH-ROOT "SSH allows root to sign in with a password (PermitRootLogin yes)."
         hint "Set 'PermitRootLogin prohibit-password' (keys only) or 'no', then reload sshd." ;;
    no|prohibit-password|without-password|forced-commands-only) ok SRV-SSH-ROOT "SSH root sign-in: ${root_login}." ;;
    "") ok SRV-SSH-ROOT "SSH root sign-in is not set, so OpenSSH's default applies (keys only)." ;;
    *) note SRV-SSH-ROOT "SSH PermitRootLogin is '$(clean "${root_login}")'." ;;
  esac
  case "${pass_auth}" in
    no) ok SRV-SSH-PASSWORD "SSH password sign-in is off (keys only)." ;;
    yes) warn SRV-SSH-PASSWORD "SSH accepts passwords (PasswordAuthentication yes), which invites password guessing."
         hint "Once key sign-in works, set 'PasswordAuthentication no' and reload sshd." ;;
    "") warn SRV-SSH-PASSWORD "SSH PasswordAuthentication is not set, and OpenSSH's default is to accept passwords."
        hint "Once key sign-in works, set 'PasswordAuthentication no' and reload sshd." ;;
  esac
  if ! is_quick; then
    [[ "$(sshd_value permitemptypasswords)" == "yes" ]] && high SRV-SSH-EMPTY "SSH allows accounts with an empty password to sign in (PermitEmptyPasswords yes)."
    [[ "$(sshd_value protocol)" == "1" ]] && high SRV-SSH-PROTOCOL "SSH is set to the obsolete protocol version 1."
    v="$(sshd_value maxauthtries)"
    case "${v}" in ""|*[!0-9]*) ;; *) [[ "${#v}" -le 4 && "${v}" -gt 6 ]] && note SRV-SSH-TRIES "SSH allows ${v} password attempts per connection (MaxAuthTries). 3 or 4 is plenty." ;; esac
    if [[ "${pass_auth}" == "no" ]]; then
      v="$(sshd_value kbdinteractiveauthentication)"; [[ -z "${v}" ]] && v="$(sshd_value challengeresponseauthentication)"
      [[ "${v}" == "yes" ]] && note SRV-SSH-KBD "PasswordAuthentication is off but keyboard-interactive sign-in is on, which can still accept passwords through PAM."
    fi
    [[ "$(sshd_value x11forwarding)" == "yes" ]] && note SRV-SSH-X11 "SSH X11 forwarding is on. A server rarely needs it; set 'X11Forwarding no'."
  fi
  if have fail2ban-client || have cscli || have sshguard; then
    ok SRV-SSH-GUARD "A tool that blocks repeated failed sign-ins is installed (fail2ban, CrowdSec or sshguard)."
  else
    note SRV-SSH-GUARD "No fail2ban, CrowdSec or sshguard found. They block addresses that keep failing to sign in."
  fi
}

server_updates() {
  subsection "System updates"
  if [[ -e "${SYSROOT}/var/run/reboot-required" ]]; then
    warn SRV-REBOOT "The system needs a restart to finish installing updates (/var/run/reboot-required)."
  fi
  if have apt-get; then
    local n
    apt-get -s -o Debug::NoLocking=true upgrade > "${TMP}/apt.txt" 2>/dev/null || : > "${TMP}/apt.txt"
    n="$(grep -ciE '^Inst .*security' "${TMP}/apt.txt")"
    if [[ "${n}" -gt 0 ]]; then
      warn SRV-UPDATES "${n} security update(s) waiting to be installed (as of the last 'apt update')."
      hint "Install them: sudo apt update && sudo apt upgrade"
    else
      ok SRV-UPDATES "No security updates waiting (as of the last 'apt update')."
    fi
    if have dpkg && dpkg -s unattended-upgrades >/dev/null 2>&1; then
      ok SRV-AUTO-UPDATES "unattended-upgrades is installed (automatic security updates)."
    else
      note SRV-AUTO-UPDATES "unattended-upgrades is not installed. It installs security updates automatically."
    fi
  elif have dnf; then
    local n
    with_timeout 30 dnf -q --cacheonly updateinfo list --security > "${TMP}/dnf.txt" 2>/dev/null || : > "${TMP}/dnf.txt"
    n="$(count_lines "${TMP}/dnf.txt")"
    if [[ "${n}" -gt 0 ]]; then
      warn SRV-UPDATES "${n} security update(s) waiting to be installed (from the local cache)."
      hint "Install them: sudo dnf upgrade --security"
    else
      ok SRV-UPDATES "No security updates waiting (from the local cache)."
    fi
  else
    na "Pending updates are only checked on apt and dnf systems."
  fi
}

# os_eol ID VERSION: date standard security updates end, "old", or "unknown".
os_eol() {
  local id="$1" ver="$2" major="${2%%.*}" num
  case "${major}" in ""|*[!0-9]*) echo unknown; return ;; esac
  [[ "${#major}" -gt 3 ]] && { echo unknown; return; }
  case "${id}" in
    ubuntu)
      case "${ver}" in
        14.04) echo 2019-04-30 ;; 16.04) echo 2021-04-30 ;; 18.04) echo 2023-05-31 ;; 20.04) echo 2025-05-31 ;;
        22.04) echo 2027-05-31 ;; 24.04) echo 2029-05-31 ;; 26.04) echo 2031-05-31 ;;
        [0-9][0-9].[0-9][0-9]) num="${ver%%.*}${ver##*.}"; if [[ "${num}" -lt 2610 ]]; then echo old; else echo unknown; fi ;;
        *) echo unknown ;;
      esac ;;
    debian)
      case "${major}" in
        10) echo 2024-06-30 ;; 11) echo 2026-08-31 ;; 12) echo 2028-06-30 ;; 13) echo 2030-06-30 ;;
        *) if [[ "${major}" -lt 10 ]]; then echo old; else echo unknown; fi ;;
      esac ;;
    centos)
      case "${major}" in 7) echo 2024-06-30 ;; 8) echo 2021-12-31 ;; 9) echo 2027-05-31 ;; *) if [[ "${major}" -lt 7 ]]; then echo old; else echo unknown; fi ;; esac ;;
    rhel|almalinux|rocky|ol)
      case "${major}" in 7) echo 2024-06-30 ;; 8) echo 2029-05-31 ;; 9) echo 2032-05-31 ;; *) if [[ "${major}" -lt 7 ]]; then echo old; else echo unknown; fi ;; esac ;;
    *) echo unknown ;;
  esac
}

server_os() {
  subsection "Operating system"
  local id="" ver="" name="" eol f v weak=""
  if [[ -r "${SYSROOT}/etc/os-release" ]]; then
    id="$(grep -E '^ID=' "${SYSROOT}/etc/os-release" | head -n 1 | cut -d= -f2 | tr -d '"'"'" | tr -cd 'a-z0-9._-')"
    ver="$(grep -E '^VERSION_ID=' "${SYSROOT}/etc/os-release" | head -n 1 | cut -d= -f2 | tr -d '"'"'" | tr -cd '0-9.')"
    name="${id} ${ver}"
    eol="$(os_eol "${id}" "${ver}")"
    case "${eol}" in
      unknown) na "This script has no end-of-support date for ${name}." ;;
      old) warn SRV-OS-EOL "${name} stopped getting security updates long ago. Upgrade to a supported release." ;;
      *) if [[ "${TODAY}" > "${eol}" ]]; then
           warn SRV-OS-EOL "${name}: standard security updates ended on ${eol}. Upgrade, or check that paid extended support is active."
         else
           ok SRV-OS-EOL "${name} gets security updates until ${eol}."
         fi ;;
    esac
  else
    na "No /etc/os-release, so the operating system version was not checked."
  fi

  # Kernel settings.
  if [[ -d "${SYSROOT}/proc/sys" ]]; then
    sysval() { f="${SYSROOT}/proc/sys/$1"; if [[ -r "${f}" ]]; then head -n 1 "${f}" 2>/dev/null | tr -cd '0-9'; fi; }
    v="$(sysval kernel/randomize_va_space)"
    if [[ -n "${v}" && "${v}" != "2" ]]; then
      warn SRV-KERNEL-ASLR "Address randomisation is not fully on (kernel.randomize_va_space = ${v}). It makes many exploits much harder; set it to 2."
    fi
    v="$(sysval net/ipv4/tcp_syncookies)";             [[ "${v}" == "0" ]] && weak="${weak} net.ipv4.tcp_syncookies=1"
    v="$(sysval net/ipv4/conf/all/accept_redirects)";  [[ "${v}" == "1" ]] && weak="${weak} net.ipv4.conf.all.accept_redirects=0"
    v="$(sysval net/ipv4/conf/all/accept_source_route)"; [[ "${v}" == "1" ]] && weak="${weak} net.ipv4.conf.all.accept_source_route=0"
    v="$(sysval net/ipv4/conf/all/rp_filter)";         [[ "${v}" == "0" ]] && weak="${weak} net.ipv4.conf.all.rp_filter=1"
    v="$(sysval kernel/dmesg_restrict)";               [[ "${v}" == "0" ]] && weak="${weak} kernel.dmesg_restrict=1"
    v="$(sysval kernel/kptr_restrict)";                [[ "${v}" == "0" ]] && weak="${weak} kernel.kptr_restrict=1"
    v="$(sysval fs/protected_symlinks)";               [[ "${v}" == "0" ]] && weak="${weak} fs.protected_symlinks=1"
    v="$(sysval fs/protected_hardlinks)";              [[ "${v}" == "0" ]] && weak="${weak} fs.protected_hardlinks=1"
    v="$(sysval fs/suid_dumpable)";                    [[ "${v}" == "2" || "${v}" == "1" ]] && weak="${weak} fs.suid_dumpable=0"
    if [[ -n "${weak}" ]]; then
      note SRV-KERNEL-SYSCTL "Kernel hardening settings that could be tightened (recommended values):${weak}"
      hint "Put them in /etc/sysctl.d/99-hardening.conf and run 'sysctl --system'. Test first: a router or VPN host may need some as they are."
    else
      ok SRV-KERNEL-SYSCTL "The kernel hardening settings checked are at their safe values."
    fi
  fi

  # Programs that run as root no matter who starts them.
  if is_deep; then
    local out="${TMP}/suid.txt" root="${SYSROOT:-/}"
    with_timeout 120 find "${root}" -xdev \( -path "${SYSROOT}/proc" -o -path "${SYSROOT}/sys" -o -path '*/snap/*' -o -path '*/docker/*' -o -path '*/containers/*' \) -prune -o -type f -perm -4000 -print 2>/dev/null \
      | grep -vE '/(sudo|sudoedit|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|pkexec|ping|ping6|at|crontab|fusermount3?|ssh-keysign|dbus-daemon-launch-helper|polkit-agent-helper-1|unix_chkpwd|chage|expiry|pam_timestamp_check|newuidmap|newgidmap|ntfs-3g|pppd|bwrap|doas|sg|userhelper|mount\.nfs|mount\.cifs|snap-confine|Xorg\.wrap|chrome-sandbox|traceroute6\.iputils|exim4|postdrop|postqueue|staprun|vmware-user-suid-wrapper|usernetctl|cockpit-session|ksu|opensm-helper)$' \
      | sed "s|^${SYSROOT}||" | head -n 40 > "${out}"
    if grep -qE '^/(tmp|var/tmp|dev/shm|home)/' "${out}"; then
      high SRV-SUID-TMP "A set-uid file in /tmp, /dev/shm or a home folder. It runs as its owner (often root) for anyone: a classic back door."
      grep -E '^/(tmp|var/tmp|dev/shm|home)/' "${out}" > "${out}.bad"
      show_locs "${out}.bad" 5
    fi
    grep -vE '^/(tmp|var/tmp|dev/shm|home)/' "${out}" > "${out}.other" || true
    if [[ -s "${out}.other" ]]; then
      warn SRV-SUID "Set-uid program(s) that are not on the usual list. Each runs with its owner's rights for any user:"
      show_locs "${out}.other" 8
      hint "Check that a package you installed put them there (dpkg -S <file> or rpm -qf <file>)."
    elif [[ ! -s "${out}" ]]; then
      ok SRV-SUID "No unusual set-uid programs found."
    fi
  fi
}

server_databases() {
  subsection "Databases on this machine"
  local any=0 f conf has_pass

  # Redis
  conf=""
  for f in "${SYSROOT}/etc/redis/redis.conf" "${SYSROOT}/etc/redis.conf"; do [[ -e "${f}" ]] && conf="${f}"; done
  if [[ -n "${conf}" ]]; then
    any=1
    if [[ ! -r "${conf}" ]]; then
      incomplete SRV-REDIS "Can't read the Redis settings without root. Re-run with sudo."
    else
      has_pass=0
      grep -qE '^[[:space:]]*(requirepass[[:space:]]+[^[:space:]]|aclfile[[:space:]]|user[[:space:]]+[^[:space:]]+[[:space:]]+on)' "${conf}" && has_pass=1
      if [[ "${has_pass}" -eq 1 ]]; then
        ok SRV-REDIS "Redis requires a password."
      elif port_public 6379; then
        high SRV-REDIS "Redis has no password and listens on a public interface. Anyone who reaches it can read and change everything, and often take over the server."
        hint "Set 'bind 127.0.0.1' and 'requirepass <long random value>' in redis.conf, then restart Redis."
      else
        note SRV-REDIS "Redis has no password. It only listens locally, so this is the usual setup, but any program on this machine can use it."
      fi
      if grep -qE '^[[:space:]]*protected-mode[[:space:]]+no' "${conf}" && [[ "${has_pass}" -eq 0 ]]; then
        warn SRV-REDIS-PROTECTED "Redis has protected-mode switched off and no password."
      fi
    fi
  fi

  # MongoDB
  conf="${SYSROOT}/etc/mongod.conf"
  if [[ -e "${conf}" ]]; then
    any=1
    if [[ ! -r "${conf}" ]]; then
      incomplete SRV-MONGO "Can't read the MongoDB settings without root. Re-run with sudo."
    elif grep -qE "^[[:space:]]*authorization:[[:space:]]*[\"']?enabled" "${conf}"; then
      ok SRV-MONGO "MongoDB access control is on."
    elif port_public 27017; then
      high SRV-MONGO "MongoDB access control is off and it listens on a public interface. Anyone who reaches it has full access."
      hint "Create an admin user, then set 'security: authorization: enabled' and 'bindIp: 127.0.0.1' in mongod.conf."
    else
      warn SRV-MONGO "MongoDB access control is off (no 'authorization: enabled'). Any program on this machine has full access to every database."
    fi
  fi

  # PostgreSQL
  : > "${TMP}/hba.txt"
  for f in "${SYSROOT}"/etc/postgresql/*/main/pg_hba.conf "${SYSROOT}/var/lib/pgsql/data/pg_hba.conf" "${SYSROOT}/var/lib/postgresql/data/pg_hba.conf"; do
    [[ -e "${f}" ]] || continue
    any=1
    if [[ ! -r "${f}" ]]; then incomplete SRV-POSTGRES "Can't read pg_hba.conf without root. Re-run with sudo."; continue; fi
    grep -vE '^[[:space:]]*(#|$)' "${f}" >> "${TMP}/hba.txt"
  done
  if [[ -s "${TMP}/hba.txt" ]]; then
    # host lines: type database user address [mask] method
    awk '$1 ~ /^host/ { addr = $4; method = ($5 ~ /^[0-9.]+$/) ? $6 : $5
           local = (addr ~ /^(127\.|::1|localhost|samehost)/)
           if (method == "trust" && !local) print "TRUST_REMOTE " addr
           else if (method == "trust") print "TRUST_LOCAL " addr
           if (addr == "0.0.0.0/0" || addr == "::/0" || addr == "all") print "ANY " method
           if (method == "md5" || method == "password") print "WEAK " method }
         $1 == "local" && $NF == "trust" { print "TRUST_LOCAL socket" }' "${TMP}/hba.txt" | sort -u > "${TMP}/hba-out.txt"
    if grep -q '^TRUST_REMOTE' "${TMP}/hba-out.txt"; then
      high SRV-POSTGRES-TRUST "PostgreSQL lets other machines connect with no password at all ('trust' in pg_hba.conf)."
      hint "Change the method to scram-sha-256 and reload PostgreSQL."
    fi
    if grep -q '^ANY' "${TMP}/hba-out.txt"; then
      warn SRV-POSTGRES-ANY "PostgreSQL accepts connections from any address (0.0.0.0/0 in pg_hba.conf). List the addresses that need it."
    fi
    if grep -q '^TRUST_LOCAL' "${TMP}/hba-out.txt"; then
      note SRV-POSTGRES-LOCAL-TRUST "PostgreSQL lets local connections in with no password ('trust'). Any program on this machine can connect as any database user."
    fi
    if grep -q '^WEAK' "${TMP}/hba-out.txt"; then
      note SRV-POSTGRES-MD5 "PostgreSQL uses 'md5' or 'password' sign-in somewhere. scram-sha-256 is the current, stronger method."
    fi
    if [[ ! -s "${TMP}/hba-out.txt" ]]; then ok SRV-POSTGRES "PostgreSQL's access rules (pg_hba.conf) have none of the common mistakes."; fi
  fi

  # MySQL / MariaDB
  if [[ -d "${SYSROOT}/etc/mysql" || -f "${SYSROOT}/etc/my.cnf" ]]; then
    any=1
    if grep -rhqE '^[[:space:]]*skip[-_]grant[-_]tables' "${SYSROOT}/etc/mysql" "${SYSROOT}/etc/my.cnf" 2>/dev/null; then
      high SRV-MYSQL-NOGRANT "MySQL/MariaDB runs with skip-grant-tables: every connection has full access with no password."
    else
      ok SRV-MYSQL "MySQL/MariaDB does not skip its permission checks."
    fi
  fi

  # Elasticsearch
  conf="${SYSROOT}/etc/elasticsearch/elasticsearch.yml"
  if [[ -r "${conf}" ]]; then
    any=1
    if grep -qE '^[[:space:]]*xpack\.security\.enabled:[[:space:]]*false' "${conf}"; then
      if port_public 9200; then high SRV-ELASTIC "Elasticsearch security is off and it listens on a public interface."
      else warn SRV-ELASTIC "Elasticsearch security is switched off (xpack.security.enabled: false)."; fi
    else
      ok SRV-ELASTIC "Elasticsearch security is not switched off."
    fi
  fi
  [[ "${any}" -eq 0 ]] && na "No Redis, MongoDB, PostgreSQL, MySQL or Elasticsearch settings found on this machine."
}

# Compares a Node version with the official release list.
read -r -d '' DIST_JS <<'EOF' || true
const fs = require("fs");
let list; try { list = JSON.parse(fs.readFileSync(process.env.NSC_DIST_FILE, "utf8")); } catch (e) { process.exit(1); }
if (!Array.isArray(list)) process.exit(1);
const parse = (v) => String(v).replace(/^v/, "").split(".").map((n) => parseInt(n, 10));
const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const mine = parse(process.env.NSC_VER);
if (mine.length !== 3 || mine.some(isNaN)) process.exit(1);
let latest = mine, behind = 0;
for (const r of list) {
  const v = parse(r.version);
  if (v.length !== 3 || v.some(isNaN) || v[0] !== mine[0]) continue;
  if (cmp(v, mine) > 0) { if (r.security) behind++; if (cmp(v, latest) > 0) latest = v; }
}
console.log(behind + " " + latest.join("."));
EOF

server_app() {
  [[ -s "${NODE_PS}" ]] || return 0
  subsection "The running app"
  local user pid args envf node_env node_opts cwd exe ver n=0 unreadable=0 dist="${TMP}/node-dist.json" have_dist=0 res before
  before="$(count_lines "${FINDINGS}")"
  while read -r user pid args; do
    [[ "${n}" -ge 5 ]] && break
    n=$((n + 1))
    envf="${SYSROOT}/proc/${pid}/environ"
    if [[ -r "${envf}" ]]; then
      node_env="$(tr '\0' '\n' < "${envf}" 2>/dev/null | grep -E '^NODE_ENV=' | head -n 1 | cut -d= -f2- | tr -cd 'A-Za-z0-9_-' | cut -c1-30)"
      node_opts="$(tr '\0' '\n' < "${envf}" 2>/dev/null | grep -E '^NODE_OPTIONS=' | head -n 1 | cut -d= -f2- | tr -d '\000-\037\177' | cut -c1-80)"
      if [[ "${node_env}" == "production" ]]; then
        ok SRV-NODE-ENV "PID ${pid} runs with NODE_ENV=production."
      else
        warn SRV-NODE-ENV "PID ${pid} runs with NODE_ENV=${node_env:-not set}. Without 'production', many frameworks show detailed errors to visitors and run slower."
      fi
      case "${node_opts}" in
        *--inspect*) warn SRV-NODE-OPTIONS "PID ${pid}: NODE_OPTIONS switches the debugger on (${node_opts})." ;;
        *--require*|*--import*|*-r\ *) note SRV-NODE-OPTIONS "PID ${pid}: NODE_OPTIONS loads extra code at start-up (${node_opts}). Fine for monitoring agents; check it is yours." ;;
      esac
    elif [[ -e "${envf}" ]]; then
      unreadable=1
    fi
    # Can the app rewrite its own code?
    cwd="$(readlink "${SYSROOT}/proc/${pid}/cwd" 2>/dev/null || true)"
    case "${user}" in *+*|root) ;; *)
      if [[ -n "${cwd}" && -f "${cwd}/package.json" && -n "$(find "${cwd}/package.json" -maxdepth 0 -user "${user}" 2>/dev/null)" ]]; then
        note SRV-APP-WRITABLE "PID ${pid}: the app's files (${cwd}) belong to the account it runs as (${user}), so a break-in can rewrite the app's own code."
        hint "Stronger: deploy as one account and run as another that can only read the code."
      fi ;;
    esac
    # Which Node version is it really running? Only run a binary that this
    # account or root owns, so a tampered file is never executed as root.
    exe="$(readlink "${SYSROOT}/proc/${pid}/exe" 2>/dev/null || true)"
    ver=""
    if [[ -n "${exe}" && -x "${exe}" ]]; then
      if [[ -n "$(find "${exe}" -maxdepth 0 \( -user root -o -user "${ME}" \) ! -perm -002 2>/dev/null)" ]]; then
        ver="$(with_timeout 5 "${exe}" --version 2>/dev/null | head -n 1 | tr -cd '0-9.v' | cut -c1-20)"
      else
        note SRV-NODE-BINARY "PID ${pid}: the Node program (${exe}) is not owned by root, so the account that owns it can replace it."
      fi
    fi
    case "${ver}" in v[0-9]*.[0-9]*.[0-9]*)
      check_node_major "$(printf '%s' "${ver#v}" | cut -d. -f1)" "PID ${pid}"
      if [[ "${NO_NETWORK}" -eq 0 && -n "${JS}" ]] && have curl; then
        if [[ "${have_dist}" -eq 0 ]]; then
          if curl -sS --max-time 20 -o "${dist}" "${NODE_DIST_URL}" 2>/dev/null; then have_dist=1; else have_dist=2; fi
        fi
        if [[ "${have_dist}" -eq 1 ]] && res="$(NSC_DIST_FILE="${dist}" NSC_VER="${ver}" "${JS}" -e "${DIST_JS}" 2>/dev/null)"; then
          if [[ "${res%% *}" -gt 0 ]]; then
            warn SRV-NODE-PATCH "PID ${pid} runs Node ${ver#v}, which is ${res%% *} security $(plural "${res%% *}" release releases) behind (latest in that line: ${res##* })."
            hint "Update Node, then restart the app: a running process keeps the old version until it restarts."
          else
            ok SRV-NODE-PATCH "PID ${pid} runs Node ${ver#v}, with no newer security release in that line."
          fi
        elif [[ "${have_dist}" -eq 2 ]]; then
          incomplete SRV-NODE-PATCH "Couldn't download the Node release list, so missing security releases were not checked."
          have_dist=3
        fi
      fi ;;
    esac
  done < "${NODE_PS}"
  if [[ "${unreadable}" -eq 1 ]]; then
    incomplete SRV-NODE-ENV "Can't read the environment of every Node process without root, so NODE_ENV was not fully checked."
  fi
  [[ "$(count_lines "${FINDINGS}")" == "${before}" ]] && na "Nothing more could be read about the running process(es)."
  return 0
}

server_files() {
  [[ -d "${PROJECT_DIR}" && -f "${PJ}" ]] || return
  subsection "File permissions in the project"
  find "${PROJECT_DIR}" -maxdepth 2 -name '.env*' -type f -perm -004 \
    ! -name '*.example' ! -name '*.sample' ! -name '*.template' 2>/dev/null \
    | sed "s|^${PROJECT_DIR}/||" > "${TMP}/env-perm.txt"
  if [[ -s "${TMP}/env-perm.txt" ]]; then
    warn SRV-ENV-READABLE ".env file(s) readable by every user on this machine:"
    show_locs "${TMP}/env-perm.txt" 5
    hint "Fix: chmod 600 <file>  (and make sure the app's user owns it)."
  else
    ok SRV-ENV-READABLE "No .env file is readable by every user."
  fi
  find "${PROJECT_DIR}" -path "${PROJECT_DIR}/node_modules" -prune -o -path "${PROJECT_DIR}/.git" -prune -o \
    -type f -perm -002 -print 2>/dev/null | head -n 50 | sed "s|^${PROJECT_DIR}/||" > "${TMP}/ww.txt"
  if [[ -s "${TMP}/ww.txt" ]]; then
    warn SRV-WORLD-WRITABLE "File(s) that any user on this machine can change:"
    show_locs "${TMP}/ww.txt" 5
    hint "Fix: chmod o-w <file>"
  else
    ok SRV-WORLD-WRITABLE "No project file is writable by every user."
  fi
}

server_proxy() {
  subsection "Reverse proxy (${PROXY})"
  local conf="${TMP}/proxy-conf.txt" d p
  : > "${conf}"
  case "${PROXY}" in
    none)
      note SRV-NO-PROXY "Nothing in front of Node. Make sure HTTPS is handled somewhere (a load balancer, or Node itself),"
      hint "and consider a reverse proxy: it handles TLS, limits request sizes and hides Node from direct traffic."
      ;;
    nginx)
      if [[ -z "${SYSROOT}" && "${IS_ROOT}" -eq 1 ]] && have nginx; then nginx -T > "${conf}" 2>/dev/null || : > "${conf}"; fi
      if [[ ! -s "${conf}" && -d "${SYSROOT}/etc/nginx" ]]; then
        grep -rhvE '^[[:space:]]*#' "${SYSROOT}/etc/nginx" > "${conf}" 2>/dev/null || true
      fi
      if [[ ! -s "${conf}" ]]; then incomplete SRV-NGINX "Couldn't read the nginx settings (try with sudo)."; return; fi
      if grep -qE '^[[:space:]]*server_tokens[[:space:]]+off' "${conf}"; then ok SRV-NGINX-TOKENS "nginx hides its version number (server_tokens off)."
      else note SRV-NGINX-TOKENS "nginx shows its version number. Add 'server_tokens off;' inside the http block."; fi
      if grep -E '^[[:space:]]*ssl_protocols' "${conf}" | grep -qE 'SSLv3|TLSv1([[:space:];]|$)|TLSv1\.1'; then
        warn SRV-NGINX-TLS "nginx still accepts old TLS versions (1.0 or 1.1). Use: ssl_protocols TLSv1.2 TLSv1.3;"
      else ok SRV-NGINX-TLS "nginx doesn't enable TLS 1.0 or 1.1."; fi
      if grep -qE '^[[:space:]]*autoindex[[:space:]]+on' "${conf}"; then
        warn SRV-NGINX-AUTOINDEX "nginx has 'autoindex on', which lists folder contents to visitors."
      fi
      if grep -qE '^[[:space:]]*client_max_body_size[[:space:]]+0' "${conf}"; then
        warn SRV-NGINX-BODY "nginx has no upload size limit (client_max_body_size 0)."
      fi
      is_quick && return
      if grep -E '^[[:space:]]*ssl_ciphers' "${conf}" | grep -qE "(^|[:[:space:]\"'])(RC4|3DES|DES-CBC3|EXP|EXPORT|NULL|aNULL|eNULL|MD5)"; then
        warn SRV-NGINX-CIPHERS "nginx's ssl_ciphers allows broken ciphers (RC4, 3DES, EXPORT, NULL or MD5)."
        hint "Use a current list, for example from https://ssl-config.mozilla.org"
      fi
      # Does nginx serve the app's own folder as static files?
      grep -oE '^[[:space:]]*root[[:space:]]+[^;[:space:]]+' "${conf}" | awk '{ print $2 }' | tr -d "\"'" | sort -u > "${TMP}/nginx-roots.txt" || true
      : > "${TMP}/nginx-bad-roots.txt"
      while IFS= read -r p; do
        case "${p}" in /*) ;; *) continue ;; esac
        if [[ -e "${p}/.env" || -e "${p}/.git" || -e "${p}/package.json" ]]; then printf '%s\n' "${p}" >> "${TMP}/nginx-bad-roots.txt"; fi
      done < "${TMP}/nginx-roots.txt"
      if [[ -s "${TMP}/nginx-bad-roots.txt" ]]; then
        if grep -qE 'location[[:space:]]+~[^{]*/\\\.' "${conf}"; then
          warn SRV-NGINX-ROOT "nginx serves a project folder as static files (it holds package.json, .env or .git). Hidden files are blocked, but source files are not:"
        else
          high SRV-NGINX-ROOT "nginx serves a project folder as static files, with no rule blocking hidden files, so .env or .git can be downloaded:"
        fi
        show_locs "${TMP}/nginx-bad-roots.txt" 5
        hint "Point 'root' at a public/ or dist/ folder only, and add:  location ~ /\\. { deny all; }"
      elif [[ -s "${TMP}/nginx-roots.txt" ]] && ! grep -qE 'location[[:space:]]+~[^{]*/\\\.' "${conf}"; then
        note SRV-NGINX-DOTFILES "nginx has no rule that blocks hidden files. Add:  location ~ /\\. { deny all; }"
      fi
      # location /x { alias /y/; } lets visitors step out of the folder with /x../
      if awk '/^[[:space:]]*location[[:space:]]/ { loc = $0; sub(/^[[:space:]]*location[[:space:]]+(\^~[[:space:]]+)?/, "", loc); sub(/[[:space:]]*\{.*$/, "", loc); mod = ($2 ~ /^(~|~\*|=)$/) }
               /^[[:space:]]*alias[[:space:]]/ { a = $2; sub(/;$/, "", a); if (!mod && loc != "" && loc !~ /\/$/ && a ~ /\/$/) found = 1 }
               END { exit found ? 0 : 1 }' "${conf}"; then
        warn SRV-NGINX-ALIAS "nginx has a 'location /name' without a trailing slash whose 'alias' ends in one. Visitors can read files outside that folder with /name../"
        hint "Make both end with a slash (location /name/ { alias /path/; }) or neither."
      fi
      if grep -qE '^[[:space:]]*proxy_pass[[:space:]]' "${conf}"; then
        grep -qE '^[[:space:]]*limit_req_zone[[:space:]]' "${conf}" || note SRV-NGINX-RATELIMIT "nginx has no request rate limit (limit_req_zone). It is a cheap way to slow password guessing and floods."
        grep -qE 'proxy_set_header[[:space:]]+(X-Forwarded-For|X-Real-IP)' "${conf}" || note SRV-NGINX-FORWARDED "nginx doesn't pass the visitor's address to Node (proxy_set_header X-Forwarded-For), so logs and rate limits in the app see only the proxy."
      fi
      ;;
    apache)
      for d in "${SYSROOT}/etc/apache2" "${SYSROOT}/etc/httpd"; do
        [[ -d "${d}" ]] && grep -rhvE '^[[:space:]]*#' "${d}" >> "${conf}" 2>/dev/null
      done
      if [[ ! -s "${conf}" ]]; then incomplete SRV-APACHE "Couldn't read the Apache settings (try with sudo)."; return; fi
      if grep -qiE '^[[:space:]]*ServerTokens[[:space:]]+(Prod|ProductOnly)' "${conf}"; then ok SRV-APACHE-TOKENS "Apache hides its version number (ServerTokens Prod)."
      else note SRV-APACHE-TOKENS "Apache shows its version number. Set 'ServerTokens Prod' and 'ServerSignature Off'."; fi
      if grep -iE '^[[:space:]]*SSLProtocol' "${conf}" | grep -qiE '(^|[[:space:]+])(SSLv3|TLSv1|TLSv1\.1)([[:space:]]|$)'; then
        warn SRV-APACHE-TLS "Apache still accepts old TLS versions. Use: SSLProtocol -all +TLSv1.2 +TLSv1.3"
      else ok SRV-APACHE-TLS "Apache doesn't explicitly enable TLS 1.0 or 1.1."; fi
      if grep -qiE '^[[:space:]]*Options[[:space:]].*(^|[[:space:]+])Indexes' "${conf}"; then
        note SRV-APACHE-INDEXES "Apache has 'Options Indexes' somewhere, which lists folder contents when there is no index page."
      fi
      if ! is_quick && grep -qiE '^[[:space:]]*TraceEnable[[:space:]]+on' "${conf}"; then
        warn SRV-APACHE-TRACE "Apache has TraceEnable on. Set 'TraceEnable off'."
      fi
      ;;
    caddy)
      for d in "${SYSROOT}/etc/caddy/Caddyfile" "${PROJECT_DIR}/Caddyfile"; do
        [[ -f "${d}" ]] && cat "${d}" >> "${conf}" 2>/dev/null
      done
      if [[ ! -s "${conf}" ]]; then note SRV-CADDY "Caddy sets up HTTPS by itself. No Caddyfile found to check."; return; fi
      if grep -qE '^[[:space:]]*auto_https[[:space:]]+off' "${conf}"; then
        warn SRV-CADDY-HTTPS "The Caddyfile turns off automatic HTTPS (auto_https off)."
      else ok SRV-CADDY-HTTPS "Caddy's automatic HTTPS is on."; fi
      if ! is_quick && grep -qE '^[[:space:]]*admin[[:space:]]+(0\.0\.0\.0|:[0-9]+|\[::\])' "${conf}"; then
        high SRV-CADDY-ADMIN "Caddy's admin API listens on a public interface. Anyone who reaches it can reconfigure the server."
      fi
      ;;
  esac
}

server_runner() {
  subsection "How the app is kept running (${RUNNER})"
  case "${RUNNER}" in
    systemd)
      if [[ -z "${SERVICE}" ]]; then
        na "No service name given (use --service NAME), so the service settings were not checked."
        return
      fi
      if ! have systemctl; then incomplete SRV-SERVICE "systemctl not found, so the service was not checked."; return; fi
      local show="${TMP}/unit.txt" v missing=""
      systemctl show "${SERVICE}" -p LoadState -p User -p NoNewPrivileges -p ProtectSystem -p PrivateTmp -p ProtectHome > "${show}" 2>/dev/null || : > "${show}"
      if ! grep -q '^LoadState=loaded' "${show}"; then
        incomplete SRV-SERVICE "systemd has no loaded service called '${SERVICE}'. Check the name (systemctl list-units --type=service)."
        return
      fi
      v="$(grep '^User=' "${show}" | cut -d= -f2)"
      if [[ -z "${v}" || "${v}" == "root" ]]; then
        high SRV-SERVICE-ROOT "Service ${SERVICE} runs as root. Add 'User=<an unprivileged user>' to the [Service] section."
      else
        ok SRV-SERVICE-ROOT "Service ${SERVICE} runs as user '$(clean "${v}")'."
      fi
      grep -q '^NoNewPrivileges=yes' "${show}" || missing="${missing} NoNewPrivileges=yes"
      grep -qE '^ProtectSystem=(yes|full|strict)' "${show}" || missing="${missing} ProtectSystem=full"
      grep -q '^PrivateTmp=yes' "${show}" || missing="${missing} PrivateTmp=yes"
      grep -qE '^ProtectHome=(yes|read-only|tmpfs)' "${show}" || missing="${missing} ProtectHome=read-only"
      if [[ -n "${missing}" ]]; then
        note SRV-SERVICE-HARDEN "Optional hardening not set for ${SERVICE}:${missing}"
        hint "These limit what the app can touch if it is broken into. 'systemd-analyze security ${SERVICE}' shows more."
      else
        ok SRV-SERVICE-HARDEN "Service ${SERVICE} has the basic systemd hardening options set."
      fi
      ;;
    pm2)
      if grep -E 'PM2 v[0-9]' "${PS_FILE}" | grep -qE '^root[[:space:]]'; then
        warn SRV-PM2-ROOT "PM2 runs as root, so every app it starts runs as root too."
        hint "Run PM2 as an unprivileged user: pm2 startup systemd -u <user> --hp /home/<user>"
      elif grep -qE 'PM2 v[0-9]' "${PS_FILE}"; then
        ok SRV-PM2-ROOT "PM2 does not run as root."
      else
        note SRV-PM2-ROOT "PM2 doesn't seem to be running right now."
      fi
      ;;
    other)
      na "No specific checks for this setup. Make sure the app restarts after a crash or reboot, and doesn't run as root."
      ;;
  esac
}

server_docker() {
  subsection "Docker containers"
  if ! have docker; then incomplete SRV-DOCKER "docker not found on this machine, so containers were not checked."; return; fi
  local names="${TMP}/containers.txt" c
  if [[ -n "${CONTAINER}" ]]; then
    printf '%s\n' "${CONTAINER}" > "${names}"
  else
    if ! docker ps --format '{{.Names}}|{{.Image}}|{{.Command}}' > "${TMP}/docker-ps.txt" 2>/dev/null; then
      incomplete SRV-DOCKER "Couldn't talk to Docker (permission denied?). Re-run with sudo or as a user in the docker group."
      return
    fi
    grep -iE 'node|npm|pnpm|yarn|bun|next|nuxt' "${TMP}/docker-ps.txt" | cut -d'|' -f1 > "${names}"
  fi
  if [[ ! -s "${names}" ]]; then
    note SRV-DOCKER "No running container looks like a Node app. Name it with --container NAME."
    return
  fi
  local info user priv rofs mounts netmode caps mem image n created limit
  while IFS= read -r c; do
    [[ -z "${c}" ]] && continue
    if ! info="$(docker inspect -f '{{.Config.User}}|{{.HostConfig.Privileged}}|{{.HostConfig.ReadonlyRootfs}}|{{range .Mounts}}{{.Source}} {{end}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.CapAdd}}|{{.HostConfig.Memory}}|{{.Config.Image}}' "${c}" 2>/dev/null)"; then
      incomplete SRV-DOCKER "Couldn't inspect the container '$(clean "${c}")'. Check the name (docker ps)."
      continue
    fi
    IFS='|' read -r user priv rofs mounts netmode caps mem image <<EOF
${info}
EOF
    c="$(clean "${c}")"
    if [[ -z "${user}" || "${user}" == "root" || "${user}" == "0" || "${user}" == "0:0" ]]; then
      warn SRV-DOCKER-ROOT "Container ${c} runs the app as root. Add 'USER node' to the Dockerfile, or 'user: node' in compose."
    else
      ok SRV-DOCKER-ROOT "Container ${c} runs as user '$(clean "${user}")'."
    fi
    if [[ "${priv}" == "true" ]]; then
      high SRV-DOCKER-PRIVILEGED "Container ${c} is privileged: it has full control of the host. Remove --privileged."
    fi
    case "${mounts}" in *docker.sock*)
      high SRV-DOCKER-SOCKET "Container ${c} has the Docker socket mounted: it can control every container and the host." ;;
    esac
    [[ "${netmode}" == "host" ]] && warn SRV-DOCKER-HOSTNET "Container ${c} uses the host's network directly (network_mode: host)."
    case "${caps}" in *SYS_ADMIN*|*ALL*)
      warn SRV-DOCKER-CAPS "Container ${c} has extra kernel permissions added ($(clean "${caps}"))." ;;
    esac
    [[ "${rofs}" == "true" ]] && ok SRV-DOCKER-READONLY "Container ${c} has a read-only filesystem."
    docker port "${c}" 2>/dev/null | grep -E -- '-> (0\.0\.0\.0|\[::\]|:::)' > "${TMP}/dports.txt" || true
    if [[ -s "${TMP}/dports.txt" && "${PROXY}" != "none" ]]; then
      warn SRV-DOCKER-PORTS "Container ${c} publishes port(s) on every network interface, so visitors can bypass ${PROXY}:"
      show_locs "${TMP}/dports.txt" 3
      hint "Publish on localhost only (-p 127.0.0.1:3000:3000). Ports published by Docker are NOT blocked by ufw."
    fi
    is_quick && continue
    [[ "${mem}" == "0" ]] && note SRV-DOCKER-MEMORY "Container ${c} has no memory limit, so a leak or a flood can take down the whole host."
    n="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "${c}" 2>/dev/null | cut -d= -f1 | grep -cE '(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|API_?KEY)')" || n=0
    if [[ "${n}" -gt 0 ]]; then
      note SRV-DOCKER-ENV-SECRETS "Container ${c} gets ${n} secret-looking value(s) as plain environment variables. Anyone who can run 'docker inspect' can read them."
      hint "That is common and often acceptable. Docker secrets or a mounted file keep them out of 'docker inspect'."
    fi
    created="$(docker image inspect -f '{{.Created}}' "${image}" 2>/dev/null | cut -c1-10)" || created=""
    limit="$(date -d '180 days ago' +%Y-%m-%d 2>/dev/null)" || limit=""
    case "${created}" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
      if [[ -n "${limit}" && "${created}" < "${limit}" ]]; then
        note SRV-DOCKER-IMAGE-OLD "Container ${c}'s image was built on ${created}, over 6 months ago, so it lacks the system updates since then. Rebuild it."
      fi ;;
    esac
  done < "${names}"
  is_quick && return
  # People who can use Docker are root in all but name.
  if [[ -r "${SYSROOT}/etc/group" ]]; then
    c="$(grep -E '^docker:' "${SYSROOT}/etc/group" | cut -d: -f4 | tr -cd 'A-Za-z0-9_,.-')"
    [[ -n "${c}" ]] && note SRV-DOCKER-GROUP "Members of the 'docker' group can take full control of this machine: ${c}"
  fi
  if [[ -r "${SYSROOT}/etc/docker/daemon.json" ]]; then
    grep -qE '"hosts"[[:space:]]*:[^]]*tcp://(0\.0\.0\.0|\[::\])' "${SYSROOT}/etc/docker/daemon.json" \
      && high SRV-DOCKER-API "The Docker API is set to listen on the network (daemon.json 'hosts'). Without TLS client certificates anyone who reaches it owns the host."
  fi
}

# ------------------------------------------------------------- live site --
# fetch URL [curl options...]: GET a page; headers (lower-cased names) in
# $HDR, body in $BODY, status in HTTP_CODE.
HDR="${TMP}/hdr.txt"; BODY="${TMP}/body.txt"; HTTP_CODE="000"; CURL_RC=0
fetch() {
  local url="$1"; shift
  : > "${HDR}"; : > "${BODY}"
  HTTP_CODE="$(curl -sS --max-time 15 --max-filesize 2000000 -D "${HDR}" -o "${BODY}" -w '%{http_code}' "$@" "${url}" 2>/dev/null)"
  CURL_RC=$?
  tr -d '\r' < "${HDR}" | awk '{ i = index($0, ":"); if (i > 0) print tolower(substr($0, 1, i - 1)) ":" substr($0, i + 1); else print }' > "${HDR}.lc"
  mv "${HDR}.lc" "${HDR}"
}
hdr_has() { grep -qiE "^$1:" "${HDR}"; }
hdr_val() { grep -iE "^$1:" "${HDR}" | tail -n 1 | sed -e 's/^[^:]*:[[:space:]]*//' | tr -d '\000-\037\177' | cut -c1-"${2:-80}"; }
body_is_html() { grep -qiE '^content-type:[[:space:]]*text/html' "${HDR}" || head -c 300 "${BODY}" | grep -qiE '<(!doctype|html|head|body)'; }

# probe PATH LEVEL ID "what it means" BODY-PATTERN: report PATH if it is really served.
probe() {
  local path="$1" level="$2" id="$3" msg="$4" pat="$5"
  fetch "${SITE_BASE}${path}"
  [[ "${HTTP_CODE}" == "200" ]] || return 1
  body_is_html && return 1
  head -c 4000 "${BODY}" | grep -qE -e "${pat}" || return 1
  "${level}" "${id}" "${SITE_BASE}${path} is public. ${msg}"
  return 0
}

SITE_BASE=""
server_url() {
  subsection "Live site: ${URL}"
  if [[ "${NO_NETWORK}" -eq 1 ]]; then na "Skipped (--no-network)."; return; fi
  if ! have curl; then incomplete SITE-CURL "curl is not installed, so the live site was not checked."; return; fi
  local base="${URL%/}" scheme host hostport
  scheme="${URL%%://*}"
  hostport="${URL#*://}"; hostport="${hostport%%/*}"
  host="${hostport%%:*}"
  SITE_BASE="${scheme}://${hostport}"

  fetch "${base}/"
  if [[ "${CURL_RC}" -eq 60 || "${CURL_RC}" -eq 51 ]]; then
    high SITE-CERT "The site's certificate is not trusted (expired, wrong name, or self-signed). Visitors see a warning."
    return
  fi
  if [[ "${CURL_RC}" -ne 0 || "${HTTP_CODE}" == "000" ]]; then
    incomplete SITE-REACH "Couldn't reach ${URL} (curl error ${CURL_RC}), so the live site was not checked."
    return
  fi
  say "  Answered with HTTP ${HTTP_CODE}."
  cp "${HDR}" "${TMP}/home.hdr"; cp "${BODY}" "${TMP}/home.body"

  # ---- headers ------------------------------------------------------------
  if [[ "${scheme}" == "http" ]]; then
    case "${host}" in
      localhost|127.*) note SITE-HTTP "Plain http:// on localhost: HTTPS checks skipped." ;;
      *) warn SITE-HTTP "The address is plain http://. Passwords and cookies travel unencrypted; serve the site over HTTPS." ;;
    esac
  else
    if hdr_has strict-transport-security; then
      ok SITE-HSTS "Strict-Transport-Security is set (browsers will insist on HTTPS)."
      local age
      age="$(hdr_val strict-transport-security | grep -oE 'max-age=[0-9]+' | cut -d= -f2)"
      case "${age}" in ""|*[!0-9]*) ;; *) [[ "${#age}" -lt 8 ]] && note SITE-HSTS-SHORT "Strict-Transport-Security lasts under four months (max-age=${age}). A year (31536000) is usual." ;; esac
    else
      warn SITE-HSTS "No Strict-Transport-Security header, so browsers may still try plain http:// first."
      hint "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    fi
  fi
  if grep -qiE '^x-content-type-options:[[:space:]]*nosniff' "${HDR}"; then ok SITE-NOSNIFF "X-Content-Type-Options: nosniff is set."
  else warn SITE-NOSNIFF "No 'X-Content-Type-Options: nosniff' header (stops browsers guessing file types)."; fi

  local csp
  csp="$(grep -iE '^content-security-policy:' "${HDR}" | tail -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\000-\037\177')"
  if [[ -n "${csp}" ]]; then
    ok SITE-CSP "Content-Security-Policy is set."
    if ! is_quick; then
      local script_src weak=""
      script_src="$(printf '%s' "${csp}" | tr ';' '\n' | grep -iE '^[[:space:]]*script-src([[:space:]]|$)' | head -n 1)"
      [[ -z "${script_src}" ]] && script_src="$(printf '%s' "${csp}" | tr ';' '\n' | grep -iE '^[[:space:]]*default-src([[:space:]]|$)' | head -n 1)"
      if [[ -z "${script_src}" ]]; then
        weak="${weak} no script-src or default-src;"
      else
        case "${script_src}" in *"'unsafe-inline'"*) case "${script_src}" in *"'nonce-"*|*"'sha256-"*|*"'strict-dynamic'"*) ;; *) weak="${weak} 'unsafe-inline' scripts;" ;; esac ;; esac
        case "${script_src}" in *"'unsafe-eval'"*) weak="${weak} 'unsafe-eval';" ;; esac
        if printf '%s' "${script_src}" | grep -qE '(^|[[:space:]])(\*|https?:|data:)([[:space:]]|$)'; then weak="${weak} scripts from any site (*, https: or data:);"; fi
      fi
      if [[ -n "${weak}" ]]; then
        warn SITE-CSP-WEAK "The Content-Security-Policy leaves gaps:${weak%;}"
        hint "Those settings let injected scripts run, which is what the policy is meant to stop. Use nonces or hashes instead."
      fi
      printf '%s' "${csp}" | grep -qiE '(object-src|default-src)[[:space:]]' || note SITE-CSP-OBJECT "The Content-Security-Policy sets neither default-src nor object-src."
      printf '%s' "${csp}" | grep -qiE 'base-uri[[:space:]]' || note SITE-CSP-BASE "The Content-Security-Policy has no base-uri rule (add: base-uri 'self')."
    fi
  elif hdr_has content-security-policy-report-only; then
    note SITE-CSP "Content-Security-Policy is in report-only mode: it reports problems but blocks nothing yet."
  else
    warn SITE-CSP "No Content-Security-Policy header. A policy limits the damage of cross-site scripting."
  fi
  if hdr_has x-frame-options || grep -qiE '^content-security-policy:.*frame-ancestors' "${HDR}"; then ok SITE-FRAMING "Framing by other sites is restricted (clickjacking protection)."
  else warn SITE-FRAMING "Other sites can show this site inside a frame (clickjacking). Add 'X-Frame-Options: DENY' or a frame-ancestors rule."; fi
  if hdr_has referrer-policy; then ok SITE-REFERRER "Referrer-Policy is set."
  else note SITE-REFERRER "No Referrer-Policy header. 'strict-origin-when-cross-origin' is a sensible value."; fi
  if ! is_quick && ! hdr_has permissions-policy; then
    note SITE-PERMISSIONS "No Permissions-Policy header. It switches off browser features the site doesn't use (camera, microphone, location)."
  fi
  if hdr_has x-powered-by; then
    warn SITE-POWERED-BY "The site announces its software: X-Powered-By: $(hdr_val x-powered-by)"
    hint "Express: app.disable('x-powered-by'). Next.js: poweredByHeader: false."
  else ok SITE-POWERED-BY "No X-Powered-By header."; fi
  if grep -iE '^server:' "${HDR}" | grep -qE '[0-9]+\.[0-9]+'; then
    note SITE-SERVER-VERSION "The Server header shows a version number: $(hdr_val server)"
  fi

  # Cookies: report names only, never values.
  grep -iE '^set-cookie:' "${HDR}" > "${TMP}/cookies.txt" || true
  if [[ -s "${TMP}/cookies.txt" ]]; then
    local line cname miss
    while IFS= read -r line; do
      cname="$(printf '%s' "${line}" | sed -e 's/^[^:]*:[[:space:]]*//' -e 's/=.*$//' | tr -cd 'A-Za-z0-9_.-' | cut -c1-40)"
      miss=""
      printf '%s' "${line}" | grep -qiE ';[[:space:]]*httponly' || miss="${miss} HttpOnly"
      printf '%s' "${line}" | grep -qiE ';[[:space:]]*samesite=' || miss="${miss} SameSite"
      if [[ "${scheme}" == "https" ]]; then
        printf '%s' "${line}" | grep -qiE ';[[:space:]]*secure' || miss="${miss} Secure"
      fi
      if [[ -n "${miss}" ]]; then
        warn SITE-COOKIE "Cookie '${cname}' is missing:${miss}"
      else
        ok SITE-COOKIE "Cookie '${cname}' has HttpOnly, SameSite$([[ "${scheme}" == "https" ]] && echo " and Secure")."
      fi
    done < "${TMP}/cookies.txt"
    hint "HttpOnly is right for session cookies; a cookie that page scripts must read can't have it."
  fi

  # ---- files that should never be served ----------------------------------
  local leaked=0 p
  for p in /.env /.env.local /.env.production /.env.bak; do
    probe "${p}" high SITE-ENV-PUBLIC "Every secret in it must be changed now, then block the file." '^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' && leaked=1
  done
  [[ "${leaked}" -eq 0 ]] && ok SITE-ENV-PUBLIC "/.env is not served."
  fetch "${SITE_BASE}/.git/HEAD"
  if [[ "${HTTP_CODE}" == "200" ]] && head -c 200 "${BODY}" | grep -qE '^(ref: refs/|[0-9a-f]{40}$)'; then
    high SITE-GIT-PUBLIC "${SITE_BASE}/.git/ is public. The whole source code and its history can be downloaded. Block /.git."
  else ok SITE-GIT-PUBLIC "/.git is not served."; fi

  if ! is_quick; then
    leaked=0
    probe /.npmrc high SITE-FILE-NPMRC "It can hold a registry token; revoke it if so." '(_authToken|_auth|registry)[[:space:]]*=' && leaked=1
    probe /id_rsa high SITE-FILE-KEY "That is an SSH private key. Replace it everywhere it is used." 'PRIVATE KEY-----' && leaked=1
    for p in /backup.sql /dump.sql /database.sql /db.sql; do
      probe "${p}" high SITE-FILE-SQL "That is a database dump." '(CREATE TABLE|INSERT INTO|PostgreSQL database dump|MySQL dump)' && leaked=1
    done
    probe /docker-compose.yml warn SITE-FILE-COMPOSE "It shows how the server is built and often holds passwords." '^[[:space:]]*(services|version):' && leaked=1
    probe /.DS_Store warn SITE-FILE-DSSTORE "It lists the file names in the folder." 'Bud1' && leaked=1
    probe /package.json note SITE-FILE-PACKAGE "It tells visitors exactly which package versions you run." '"(dependencies|name|version)"[[:space:]]*:' && leaked=1
    probe /server-status warn SITE-FILE-STATUS "Apache's status page shows live requests and visitor addresses." 'Apache Server Status' && leaked=1
    probe /metrics warn SITE-FILE-METRICS "The metrics page shows internal numbers; limit it to your monitoring system." '^# (HELP|TYPE) ' && leaked=1
    for p in /swagger.json /openapi.json /api-docs /v3/api-docs /api/swagger.json; do
      probe "${p}" note SITE-FILE-APIDOCS "A full description of the API is public. Fine for a public API; otherwise restrict it." '"(openapi|swagger)"[[:space:]]*:' && leaked=1 && break
    done
    [[ "${leaked}" -eq 0 ]] && ok SITE-FILES "None of the other sensitive files tried (.npmrc, keys, database dumps, compose file, status and metrics pages) is served."

    # Source maps: find the first script on the home page and ask for its .map
    local js
    js="$(grep -oE '<script[^>]+src=["'"'"'][^"'"'"']+\.js' "${TMP}/home.body" | head -n 1 | sed -E 's/.*src=["'"'"']//')"
    case "${js}" in
      /*) js="${SITE_BASE}${js}" ;;
      http://*|https://*) case "${js}" in "${SITE_BASE}"/*) ;; *) js="" ;; esac ;;
      "") ;;
      *) js="${SITE_BASE}/${js}" ;;
    esac
    case "${js}" in *[[:space:]\"\'\\\`\$\<\>\;\|\&]*) js="" ;; esac
    if [[ -n "${js}" ]]; then
      fetch "${js}.map"
      if [[ "${HTTP_CODE}" == "200" ]] && head -c 3000 "${BODY}" | grep -qE '"(sources|mappings)"[[:space:]]*:'; then
        note SITE-SOURCE-MAPS "Source maps are public (${js##*/}.map), so anyone can read your original front-end source."
        hint "Fine if the code is open; otherwise stop publishing .map files in production."
      fi
    fi

    # GraphQL: can anyone download the whole schema?
    for p in /graphql /api/graphql; do
      fetch "${SITE_BASE}${p}" -X POST -H 'Content-Type: application/json' --data-binary '{"query":"{__schema{queryType{name}}}"}'
      if [[ "${HTTP_CODE}" == "200" ]] && head -c 2000 "${BODY}" | grep -qE '"__schema"[[:space:]]*:[[:space:]]*\{'; then
        warn SITE-GRAPHQL-INTROSPECTION "GraphQL introspection is on at ${p}: anyone can download the full map of your API."
        hint "Turn introspection off in production unless the API is meant to be public."
        break
      fi
    done

    # CORS: does the site trust a website it has never heard of?
    fetch "${base}/" -H 'Origin: https://nsc-cors-test.example'
    local acao acac
    acao="$(hdr_val access-control-allow-origin)"; acac="$(hdr_val access-control-allow-credentials)"
    if [[ "${acao}" == "https://nsc-cors-test.example" ]]; then
      if [[ "${acac}" == "true" ]]; then
        high SITE-CORS "The site tells browsers to trust ANY website, with cookies (it echoes the Origin header and allows credentials)."
        hint "A malicious page could then act as a signed-in visitor. Answer only for origins on your own list."
      else
        warn SITE-CORS "The site echoes back any Origin header, so any website can read its responses (without cookies)."
      fi
    elif [[ "${acao}" == "*" ]]; then
      note SITE-CORS "The site allows any website to read its responses (Access-Control-Allow-Origin: *). Fine for public data only."
    else
      ok SITE-CORS "The site doesn't hand out CORS access to unknown websites."
    fi

    # Error pages: do they show stack traces?
    local leak=0
    for p in "/nsc-check-missing-page-$$" "/%"; do
      fetch "${SITE_BASE}${p}"
      [[ "${CURL_RC}" -ne 0 ]] && continue
      if head -c 20000 "${BODY}" | grep -qE '(^|[[:space:]>])at [][A-Za-z0-9_$.<> ]+ \(?(/|file:|node:|[A-Za-z]:\\)[^)]*:[0-9]+:[0-9]+\)?|node_modules/[a-z@][^[:space:]]*\.js:[0-9]+|(URIError|TypeError|ReferenceError|SyntaxError): '; then leak=1; fi
    done
    if [[ "${leak}" -eq 1 ]]; then
      warn SITE-ERROR-LEAK "Error pages show stack traces or internal file paths to visitors."
      hint "Run with NODE_ENV=production and add an error handler that sends a plain message."
    else
      ok SITE-ERROR-LEAK "Error pages don't show stack traces."
    fi

    # TRACE method
    fetch "${base}/" -X TRACE
    if [[ "${CURL_RC}" -eq 0 && "${HTTP_CODE}" == "200" ]] && grep -qiE '^content-type:[[:space:]]*message/http' "${HDR}"; then
      warn SITE-TRACE "The server answers the TRACE method, which can be used to read protected cookies. Switch it off."
    fi

    # security.txt
    fetch "${SITE_BASE}/.well-known/security.txt"
    if [[ "${HTTP_CODE}" == "200" ]] && head -c 2000 "${BODY}" | grep -qiE '^Contact:'; then
      ok SITE-SECURITY-TXT "The site has a security.txt, so people who find a problem know whom to tell."
    else
      note SITE-SECURITY-TXT "No /.well-known/security.txt. It tells researchers where to report a problem (see https://securitytxt.org)."
    fi
  fi

  # ---- HTTPS -------------------------------------------------------------
  if [[ "${scheme}" == "https" ]]; then
    fetch "http://${hostport%%:*}/"
    if [[ "${CURL_RC}" -ne 0 ]]; then
      ok SITE-HTTP-REDIRECT "Plain http:// is not answered at all."
    elif [[ "${HTTP_CODE}" =~ ^30[1278]$ ]] && grep -qiE '^location:[[:space:]]*https://' "${HDR}"; then
      ok SITE-HTTP-REDIRECT "Plain http:// redirects to https://."
    else
      warn SITE-HTTP-REDIRECT "Plain http:// answers (HTTP ${HTTP_CODE}) without redirecting to https://."
    fi
    if curl -sS --max-time 15 --tlsv1.0 --tls-max 1.1 -o /dev/null "${base}/" >/dev/null 2>&1; then
      warn SITE-OLD-TLS "The site accepts TLS 1.0 or 1.1, which are obsolete. Allow TLS 1.2 and 1.3 only."
    else
      ok SITE-OLD-TLS "TLS 1.0/1.1 are not accepted (as far as this machine's curl can test)."
    fi
    if have openssl; then
      local port="443" cert="${TMP}/cert.pem" info="${TMP}/cert-info.txt"
      case "${hostport}" in *:*) port="${hostport##*:}" ;; esac
      case "${port}" in *[!0-9]*) port="443" ;; esac
      with_timeout 20 openssl s_client -connect "${host}:${port}" -servername "${host}" </dev/null > "${TMP}/sclient.txt" 2>/dev/null || true
      if openssl x509 -noout -checkend 1209600 < "${TMP}/sclient.txt" > "${TMP}/cert.txt" 2>/dev/null; then
        ok SITE-CERT-EXPIRY "The certificate is valid for at least another 14 days."
      elif grep -q 'will expire' "${TMP}/cert.txt" 2>/dev/null; then
        warn SITE-CERT-EXPIRY "The certificate expires within 14 days. Check that automatic renewal works."
      fi
      if is_deep && [[ -s "${TMP}/sclient.txt" ]]; then
        openssl x509 -noout -text < "${TMP}/sclient.txt" > "${info}" 2>/dev/null || : > "${info}"
        : > "${cert}"
        if grep -qiE 'Signature Algorithm:.*(sha1|md5)' "${info}"; then
          warn SITE-CERT-SIGNATURE "The certificate is signed with SHA-1 or MD5, which browsers no longer trust."
        fi
        local bits
        bits="$(grep -oE 'Public-Key: \(([0-9]+) bit\)' "${info}" | grep -oE '[0-9]+' | head -n 1)"
        if grep -qiE 'Public Key Algorithm:.*rsa' "${info}"; then
          case "${bits}" in ""|*[!0-9]*) ;; *) [[ "${#bits}" -le 5 && "${bits}" -lt 2048 ]] && warn SITE-CERT-KEY "The certificate's RSA key is only ${bits} bits. 2048 is the minimum today." ;; esac
        fi
        if with_timeout 20 openssl s_client -connect "${host}:${port}" -servername "${host}" -tls1_2 \
             -cipher 'RC4:3DES:DES:NULL:EXPORT:aNULL:MD5' </dev/null 2>/dev/null | grep -qE '^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*[A-Z0-9]+-' ; then
          warn SITE-WEAK-CIPHER "The server accepts a broken cipher (RC4, 3DES, NULL, EXPORT or MD5)."
          hint "Use a current cipher list, for example from https://ssl-config.mozilla.org"
        else
          ok SITE-WEAK-CIPHER "The server refused the broken ciphers tried (RC4, 3DES, NULL, EXPORT, MD5)."
        fi
        if ! with_timeout 20 openssl s_client -connect "${host}:${port}" -servername "${host}" -tls1_3 </dev/null 2>/dev/null | grep -qE 'TLSv1\.3'; then
          note SITE-TLS13 "The server did not negotiate TLS 1.3 (or this machine's openssl can't). TLS 1.2 is still acceptable."
        fi
      fi
    fi
  fi

  if ! is_quick; then site_dns "${host}"; fi
  if is_deep && [[ "${NO_TOOLS}" -eq 0 && "${scheme}" == "https" ]]; then tools_site "${hostport}"; fi
}

# dns_txt NAME: print the TXT records, one per line, or nothing.
dns_txt() {
  if have dig; then dig +short +time=5 +tries=1 TXT "$1" 2>/dev/null | tr -d '"'
  elif have host; then host -W 5 -t TXT "$1" 2>/dev/null | sed -n 's/.*descriptive text //p' | tr -d '"'
  elif have nslookup; then nslookup -type=TXT "$1" 2>/dev/null | sed -n 's/.*text = //p' | tr -d '"'
  fi
}

site_dns() {
  local host="$1" d spf="" dmarc="" caa="" tried=""
  case "${host}" in localhost|*[!A-Za-z0-9.-]*|[0-9]*.[0-9]*.[0-9]*.[0-9]*) return ;; esac
  subsection "DNS records for email and certificates"
  if ! have dig && ! have host && ! have nslookup; then
    incomplete SITE-DNS "None of dig, host or nslookup is installed, so DNS records were not checked."
    return
  fi
  # Try the host name, then each parent domain down to two labels.
  d="${host#www.}"
  while :; do
    tried="${tried} ${d}"
    [[ -z "${spf}" ]] && spf="$(dns_txt "${d}" | grep -iE '^v=spf1' | head -n 1 | tr -d '\000-\037\177' | cut -c1-200)"
    [[ -z "${dmarc}" ]] && dmarc="$(dns_txt "_dmarc.${d}" | grep -iE '^v=DMARC1' | head -n 1 | tr -d '\000-\037\177' | cut -c1-200)"
    if [[ -z "${caa}" ]] && have dig; then caa="$(dig +short +time=5 +tries=1 CAA "${d}" 2>/dev/null | head -n 1 | tr -d '\000-\037\177' | cut -c1-100)"; fi
    case "${d}" in *.*.*) d="${d#*.}" ;; *) break ;; esac
  done
  if [[ -z "${spf}" ]]; then
    warn SITE-DNS-SPF "No SPF record found (tried:${tried}). Anyone can send email that claims to come from this domain."
    hint "If the domain sends no email at all, publish:  v=spf1 -all"
  else
    case "${spf}" in
      *"+all"*) warn SITE-DNS-SPF "The SPF record ends in +all, which allows every server on the internet to send as this domain." ;;
      *"?all"*) note SITE-DNS-SPF "The SPF record ends in ?all (neutral), which protects nothing. Use ~all or -all." ;;
      *) ok SITE-DNS-SPF "An SPF record is published." ;;
    esac
  fi
  if [[ -z "${dmarc}" ]]; then
    warn SITE-DNS-DMARC "No DMARC record found. Receiving mail servers have no instruction to reject email forged in this domain's name."
    hint "Start with:  _dmarc  TXT  \"v=DMARC1; p=quarantine; rua=mailto:you@yourdomain\""
  else
    case "${dmarc}" in
      *"p=none"*) note SITE-DNS-DMARC "The DMARC record is set to p=none: forged email is reported but still delivered. Move to quarantine or reject." ;;
      *) ok SITE-DNS-DMARC "A DMARC record with an enforcing policy is published." ;;
    esac
  fi
  if have dig; then
    if [[ -n "${caa}" ]]; then ok SITE-DNS-CAA "A CAA record limits which authorities may issue certificates for the domain."
    else note SITE-DNS-CAA "No CAA record. It limits which certificate authorities may issue certificates for the domain."; fi
  fi
}

# ------------------------------------------------- specialist tools (deep) --
# If these well-known tools are installed, --deep runs them and adds a one-line
# summary of each. They go deeper than pattern matching can. None is required.
# Each tool's own findings are counted, not copied: run the tool yourself for
# the detail.
count_matches() { grep -oE -e "$1" "$2" 2>/dev/null | wc -l | tr -d ' '; }

tools_code() {
  local ran=0 out n n_high

  if have gitleaks; then
    ran=1; out="${TMP}/gitleaks.json"
    (cd "${PROJECT_DIR}" && with_timeout 600 gitleaks detect --source . --no-banner --redact --exit-code 0 --report-format json --report-path "${out}") >/dev/null 2>&1
    if [[ -f "${out}" ]]; then
      n="$(count_matches '"RuleID"[[:space:]]*:' "${out}")"
      if [[ "${n}" -gt 0 ]]; then
        high TOOL-GITLEAKS "gitleaks found ${n} secret(s) in the files or their git history."
        hint "See them (values hidden) with: gitleaks detect --redact -v"
      else
        ok TOOL-GITLEAKS "gitleaks found no secrets in the files or their git history."
      fi
    else
      incomplete TOOL-GITLEAKS "gitleaks is installed but didn't produce a report."
    fi
  fi

  if have trufflehog; then
    ran=1; out="${TMP}/trufflehog.json"
    if [[ "${NO_NETWORK}" -eq 1 ]]; then
      (cd "${PROJECT_DIR}" && with_timeout 600 trufflehog filesystem . --json --no-update --no-verification) > "${out}" 2>/dev/null
    else
      (cd "${PROJECT_DIR}" && with_timeout 600 trufflehog filesystem . --json --no-update --only-verified) > "${out}" 2>/dev/null
    fi
    n="$(count_matches '"DetectorName"[[:space:]]*:' "${out}")"
    if [[ "${n}" -gt 0 ]]; then
      high TOOL-TRUFFLEHOG "trufflehog found ${n} secret(s) $([[ "${NO_NETWORK}" -eq 1 ]] && echo "(not verified, because of --no-network)" || echo "that it confirmed are live")."
      hint "See them with: trufflehog filesystem . --only-verified"
    else
      ok TOOL-TRUFFLEHOG "trufflehog found no live secrets in the project files."
    fi
  fi

  if have semgrep; then
    ran=1; out="${TMP}/semgrep.json"
    if [[ "${NO_NETWORK}" -eq 1 ]]; then
      na "semgrep skipped: it downloads its rules, and --no-network is set."
    else
      (cd "${PROJECT_DIR}" && with_timeout 900 semgrep scan --config p/javascript --config p/nodejs --json --quiet --metrics off --output "${out}") >/dev/null 2>&1
      if [[ -s "${out}" ]] && grep -q '"results"' "${out}"; then
        n_high="$(count_matches '"severity"[[:space:]]*:[[:space:]]*"ERROR"' "${out}")"
        n="$(count_matches '"check_id"[[:space:]]*:' "${out}")"
        if [[ "${n_high}" -gt 0 ]]; then
          high TOOL-SEMGREP "semgrep found ${n_high} high-severity code problem(s) (${n} findings in all)."
          hint "See them with: semgrep scan --config p/javascript --config p/nodejs"
        elif [[ "${n}" -gt 0 ]]; then
          warn TOOL-SEMGREP "semgrep found ${n} code finding(s), none at its highest severity."
          hint "See them with: semgrep scan --config p/javascript --config p/nodejs"
        else
          ok TOOL-SEMGREP "semgrep found nothing with its JavaScript and Node.js rules."
        fi
      else
        incomplete TOOL-SEMGREP "semgrep is installed but didn't produce a report (it needs the network to fetch its rules)."
      fi
    fi
  fi

  if have trivy; then
    ran=1; out="${TMP}/trivy.json"
    (cd "${PROJECT_DIR}" && with_timeout 900 trivy fs --quiet --format json --scanners vuln,secret,misconfig --output "${out}" .) >/dev/null 2>&1
    if [[ -s "${out}" ]]; then
      n_high="$(count_matches '"Severity"[[:space:]]*:[[:space:]]*"(CRITICAL|HIGH)"' "${out}")"
      if [[ "${n_high}" -gt 0 ]]; then
        warn TOOL-TRIVY "trivy found ${n_high} critical or high finding(s) across dependencies, secrets and configuration files."
        hint "See them with: trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL ."
      else
        ok TOOL-TRIVY "trivy found no critical or high findings."
      fi
    else
      incomplete TOOL-TRIVY "trivy is installed but didn't produce a report (its first run downloads a database)."
    fi
  fi

  if [[ "${ran}" -eq 0 ]]; then
    na "None of gitleaks, trufflehog, semgrep or trivy is installed. They are optional and go deeper than this script's patterns."
  fi
}

tools_server() {
  local ran=0 rep="${TMP}/lynis-report.dat" idx n
  if have lynis; then
    if [[ "${IS_ROOT}" -eq 1 ]]; then
      ran=1
      say "  Running lynis (a few minutes)..."
      with_timeout 900 lynis audit system --quick --quiet --no-colors --report-file "${rep}" --logfile "${TMP}/lynis.log" >/dev/null 2>&1
      if [[ -s "${rep}" ]]; then
        idx="$(grep -E '^hardening_index=' "${rep}" | head -n 1 | cut -d= -f2 | tr -cd '0-9')"
        n="$(grep -cE '^warning\[\]=' "${rep}")"
        if [[ "${n}" -gt 0 ]]; then
          warn TOOL-LYNIS "lynis reports ${n} warning(s) about this server (hardening score ${idx:-?} out of 100)."
          hint "See them with: sudo lynis audit system"
        else
          ok TOOL-LYNIS "lynis reports no warnings (hardening score ${idx:-?} out of 100)."
        fi
      else
        incomplete TOOL-LYNIS "lynis is installed but didn't produce a report."
      fi
    else
      na "lynis is installed but needs root; re-run with sudo to include it."
    fi
  fi
  if have trivy && have docker && [[ "${SERVER}" == "docker" && -s "${TMP}/containers.txt" ]]; then
    local c image out="${TMP}/trivy-image.json" n_high
    c="$(head -n 1 "${TMP}/containers.txt")"
    image="$(docker inspect -f '{{.Config.Image}}' "${c}" 2>/dev/null | tr -cd 'A-Za-z0-9_.:/@-')"
    if [[ -n "${image}" ]]; then
      ran=1
      with_timeout 900 trivy image --quiet --format json --severity HIGH,CRITICAL --output "${out}" "${image}" >/dev/null 2>&1
      if [[ -s "${out}" ]]; then
        n_high="$(count_matches '"Severity"[[:space:]]*:[[:space:]]*"(CRITICAL|HIGH)"' "${out}")"
        if [[ "${n_high}" -gt 0 ]]; then
          warn TOOL-TRIVY-IMAGE "trivy found ${n_high} critical or high vulnerabilities in the container image ${image}. Rebuild it on a current base image."
        else
          ok TOOL-TRIVY-IMAGE "trivy found no critical or high vulnerabilities in the container image ${image}."
        fi
      else
        incomplete TOOL-TRIVY-IMAGE "trivy didn't produce a report for the image ${image}."
      fi
    fi
  fi
  [[ "${ran}" -eq 0 ]] && na "Neither lynis nor trivy ran here. They are optional (lynis needs root)."
}

tools_site() {
  local target="$1" tool="" out="${TMP}/testssl.json" n
  if have testssl.sh; then tool="testssl.sh"; elif have testssl; then tool="testssl"; fi
  [[ -z "${tool}" ]] && return 0
  say "  Running ${tool} (a few minutes)..."
  with_timeout 900 "${tool}" --quiet --color 0 --jsonfile "${out}" "${target}" >/dev/null 2>&1
  if [[ -s "${out}" ]]; then
    n="$(count_matches '"severity"[[:space:]]*:[[:space:]]*"(HIGH|CRITICAL)"' "${out}")"
    if [[ "${n}" -gt 0 ]]; then
      warn TOOL-TESTSSL "${tool} found ${n} high or critical TLS problem(s)."
      hint "See them with: ${tool} ${target}"
    else
      ok TOOL-TESTSSL "${tool} found no high or critical TLS problems."
    fi
  else
    incomplete TOOL-TESTSSL "${tool} is installed but didn't produce a report."
  fi
}

# ---------------------------------------------------------------- reports --
RESULT_WORD="pass"; EXIT_CODE=0

write_json() {
  NSC_PROJECT="${PROJECT_DIR}" awk -F '\t' \
    -v version="${VERSION}" -v date="${TODAY}" -v level="${LEVEL}" -v result="${RESULT_WORD}" -v code="${EXIT_CODE}" \
    -v n_alert="${N_ALERT}" -v n_high="${N_HIGH}" -v n_warn="${N_WARN}" -v n_note="${N_NOTE}" \
    -v n_inc="${N_INCOMPLETE}" -v n_acc="${N_ACCEPTED}" -v n_ok="${N_OK}" '
    function esc(s,   i, c, out) {
      out = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") out = out "\\\\"
        else if (c == "\"") out = out "\\\""
        else if (c < " ") out = out " "
        else out = out c
      }
      return out
    }
    function flush() {
      if (!have) return
      printf "%s{\"level\":\"%s\",\"id\":\"%s\",\"part\":\"%s\",\"section\":\"%s\",\"message\":\"%s\",\"details\":[%s]}", sep, f_level, esc(f_id), esc(f_part), esc(f_section), esc(f_msg), details
      sep = ",\n"; have = 0
    }
    BEGIN {
      printf "{\n\"tool\":\"node-security-check\",\"version\":\"%s\",\"date\":\"%s\",\"project\":\"%s\",\"thoroughness\":\"%s\",\n", version, date, esc(ENVIRON["NSC_PROJECT"]), level
      printf "\"result\":\"%s\",\"exit_code\":%d,\n", result, code
      printf "\"counts\":{\"alert\":%d,\"high\":%d,\"warn\":%d,\"note\":%d,\"incomplete\":%d,\"accepted\":%d,\"ok\":%d},\n", n_alert, n_high, n_warn, n_note, n_inc, n_acc, n_ok
      printf "\"findings\":[\n"
    }
    $1 == "hint" || $1 == "loc" { if (have) { details = details dsep "\"" esc($5) "\""; dsep = "," } next }
    { flush(); have = 1; f_level = $1; f_id = $2; f_part = $3; f_section = $4; f_msg = $5; details = ""; dsep = "" }
    END { flush(); printf "\n]\n}\n" }
  ' "${FINDINGS}" > "$1"
}

write_markdown() {
  {
    printf '# Security check: %s\n\n' "$(basename "${PROJECT_DIR}")"
    printf -- '- **Result:** %s (exit code %s)\n' "${RESULT_LINE}" "${EXIT_CODE}"
    printf -- '- **Date:** %s\n- **Thoroughness:** %s\n- **Tool:** node-security-check.sh %s\n\n' "${TODAY}" "${LEVEL}" "${VERSION}"
    printf '| Compromise indicators | High-level problems | Warnings | Notes | Did not run | Accepted | Passed |\n'
    printf '|---|---|---|---|---|---|---|\n'
    printf '| %s | %s | %s | %s | %s | %s | %s |\n\n' "${N_ALERT}" "${N_HIGH}" "${N_WARN}" "${N_NOTE}" "${N_INCOMPLETE}" "${N_ACCEPTED}" "${N_OK}"
    awk -F '\t' '
      function md(s) { gsub(/</, "\\&lt;", s); gsub(/`/, "\047", s); gsub(/\|/, "/", s); return s }
      function label(l) { return l == "alert" ? "ALERT" : l == "high" ? "HIGH" : l == "warn" ? "WARN" : l == "note" ? "NOTE" : l == "incomplete" ? "DID NOT RUN" : l == "accepted" ? "ACCEPTED" : "OK" }
      function title(p) { return p == "packages" ? "Packages and dependencies" : p == "code" ? "Code and project files" : p == "server" ? "Server and live site" : "Setup" }
      $1 == "ok" { passed[$3]++; skip = 1; next }
      $1 == "hint" || $1 == "loc" { if (!skip) printf "  - %s\n", md($5); next }
      { skip = 0
        if ($3 != part) { part = $3; printf "\n## %s\n\n", title(part) }
        printf "- **%s** `%s` %s\n", label($1), $2, md($5) }
      END { printf "\n## Passed\n\n"; for (p in passed) printf "- %s: %d checks passed\n", title(p), passed[p] }
    ' "${FINDINGS}"
    printf '\nThis is a first look, not a guarantee. It checks for known problems and common mistakes; it cannot see everything.\n'
  } > "$1"
}

write_html() {
  {
    cat <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security check</title>
<style>
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:#f6f7f9;color:#1b1f24}
main{max-width:980px;margin:0 auto;padding:24px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:28px 0 8px}
.meta{color:#57606a;font-size:.9rem;margin-bottom:16px}
.result{padding:12px 16px;border-radius:8px;font-weight:600;margin:12px 0}
.r-pass{background:#dafbe1;color:#116329}.r-fail{background:#ffebe9;color:#a40e26}.r-incomplete{background:#fff8c5;color:#7d4e00}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.counts div{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:8px 12px;min-width:104px}
.counts b{display:block;font-size:1.3rem}
.f{background:#fff;border:1px solid #d0d7de;border-left-width:5px;border-radius:6px;padding:10px 12px;margin:8px 0}
.f.alert,.f.high{border-left-color:#cf222e}.f.warn{border-left-color:#bf8700}.f.note{border-left-color:#0969da}
.f.incomplete{border-left-color:#8250df}.f.accepted{border-left-color:#8c959f;color:#57606a}
.tag{display:inline-block;font-size:.72rem;font-weight:700;padding:1px 7px;border-radius:10px;margin-right:6px;color:#fff;vertical-align:1px}
.t-alert,.t-high{background:#cf222e}.t-warn{background:#9a6700}.t-note{background:#0969da}.t-incomplete{background:#8250df}.t-accepted{background:#6e7781}
.id{font:.78rem ui-monospace,SFMono-Regular,Menlo,monospace;color:#57606a;margin-left:6px}
.f ul{margin:6px 0 0;padding-left:20px;font-size:.92rem;color:#3d444d}
.f li{overflow-wrap:anywhere}
footer{color:#57606a;font-size:.85rem;margin-top:28px}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}.f,.counts div{background:#161b22;border-color:#30363d}.f ul{color:#c9d1d9}.meta,.id,footer{color:#9198a1}
.r-pass{background:#12261e;color:#7ee787}.r-fail{background:#2d1215;color:#ff9492}.r-incomplete{background:#272115;color:#e3b341}}
</style></head><body><main>
EOF
    FINDINGS_FILE="${FINDINGS}" NSC_PROJECT="${PROJECT_DIR}" NSC_RESULT="${RESULT_LINE}" awk -F '\t' \
      -v date="${TODAY}" -v level="${LEVEL}" -v version="${VERSION}" -v word="${RESULT_WORD}" \
      -v n_alert="${N_ALERT}" -v n_high="${N_HIGH}" -v n_warn="${N_WARN}" -v n_note="${N_NOTE}" \
      -v n_inc="${N_INCOMPLETE}" -v n_acc="${N_ACCEPTED}" -v n_ok="${N_OK}" '
      function h(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); gsub(/"/, "\\&quot;", s); return s }
      function label(l) { return l == "alert" ? "ALERT" : l == "high" ? "HIGH" : l == "warn" ? "WARN" : l == "note" ? "NOTE" : l == "incomplete" ? "DID NOT RUN" : "ACCEPTED" }
      function title(p) { return p == "packages" ? "Packages and dependencies" : p == "code" ? "Code and project files" : p == "server" ? "Server and live site" : "Setup" }
      function close_f() { if (open) { if (inlist) printf "</ul>"; printf "</div>\n"; open = 0; inlist = 0 } }
      BEGIN {
        cls = (word == "pass") ? "r-pass" : (word == "incomplete") ? "r-incomplete" : "r-fail"
        printf "<h1>Security check</h1>\n<div class=\"meta\">%s &middot; %s &middot; thoroughness: %s &middot; node-security-check.sh %s</div>\n", h(ENVIRON["NSC_PROJECT"]), date, level, version
        printf "<div class=\"result %s\">%s</div>\n", cls, h(ENVIRON["NSC_RESULT"])
        printf "<div class=\"counts\"><div><b>%d</b>Compromise indicators</div><div><b>%d</b>High-level problems</div><div><b>%d</b>Warnings</div><div><b>%d</b>Notes</div><div><b>%d</b>Did not run</div><div><b>%d</b>Accepted</div><div><b>%d</b>Passed</div></div>\n", n_alert, n_high, n_warn, n_note, n_inc, n_acc, n_ok
      }
      $1 == "ok" { close_f(); skip = 1; next }
      $1 == "hint" || $1 == "loc" { if (!skip && open) { if (!inlist) { printf "<ul>"; inlist = 1 } printf "<li>%s</li>", h($5) } next }
      { close_f(); skip = 0
        if ($3 != part) { part = $3; printf "<h2>%s</h2>\n", title(part) }
        printf "<div class=\"f %s\"><span class=\"tag t-%s\">%s</span>%s<span class=\"id\">%s</span>", $1, $1, label($1), h($5), h($2); open = 1 }
      END { close_f(); printf "<footer>This is a first look, not a guarantee. It checks for known problems and common mistakes; it cannot see everything.</footer>\n" }
    ' "${FINDINGS}"
    printf '</main></body></html>\n'
  } > "$1"
}

# compare_previous: what is new and what was fixed since an earlier --json report.
compare_previous() {
  local prev="${TMP}/previous.json" old="${TMP}/cmp-old.tsv" new="${TMP}/cmp-new.tsv" pdate
  sed -n "s/^,\{0,1\}{\"level\":\"\([a-z]*\)\",\"id\":\"\([A-Za-z0-9_-]*\)\".*\"message\":\"\(.*\)\",\"details\":.*\$/\1${TAB}\2${TAB}\3/p" "${prev}" \
    | awk -F '\t' '$1 == "alert" || $1 == "high" || $1 == "warn" || $1 == "incomplete"' > "${old}"
  awk -F '\t' '$1 == "alert" || $1 == "high" || $1 == "warn" || $1 == "incomplete" { print $1 "\t" $2 "\t" $5 }' "${FINDINGS}" > "${new}"
  pdate="$(grep -oE '"date":"[0-9-]{10}"' "${prev}" | head -n 1 | cut -d'"' -f4)"
  if ! grep -q '"tool":"node-security-check"' "${prev}"; then
    say ""; say "${C_YELLOW}The --compare file is not a report from this script, so nothing was compared.${C_RESET}"
    return
  fi
  section compare "Compared with the earlier report${pdate:+ of ${pdate}}"
  local n_new n_fixed n_same line
  awk -F '\t' 'NR == FNR { seen[$2] = 1; next } !($2 in seen) && !done[$2]++ { print "[" toupper($1) "] " $3 "  (" $2 ")" }' "${old}" "${new}" > "${TMP}/cmp-added.txt"
  awk -F '\t' 'NR == FNR { seen[$2] = 1; next } !($2 in seen) && !done[$2]++ { print "[" toupper($1) "] " $3 "  (" $2 ")" }' "${new}" "${old}" > "${TMP}/cmp-fixed.txt"
  n_new="$(count_lines "${TMP}/cmp-added.txt")"; n_fixed="$(count_lines "${TMP}/cmp-fixed.txt")"
  n_same="$(awk -F '\t' 'NR == FNR { seen[$2] = 1; next } ($2 in seen) && !done[$2]++ { n++ } END { print n + 0 }' "${old}" "${new}")"
  say "  New: ${n_new}    Fixed: ${n_fixed}    Still there: ${n_same}"
  if [[ "${n_new}" -gt 0 ]]; then
    say ""; say "  ${C_RED}New since then:${C_RESET}"
    while IFS= read -r line; do say "    $(clean "${line}" | cut -c1-220)"; done < "${TMP}/cmp-added.txt"
  fi
  if [[ "${n_fixed}" -gt 0 ]]; then
    say ""; say "  ${C_GREEN}Fixed since then:${C_RESET}"
    while IFS= read -r line; do line="${line//\\\"/\"}"; say "    $(clean "${line}" | cut -c1-220)"; done < "${TMP}/cmp-fixed.txt"
  fi
}

# ================================================================= run ====
[[ "${DO_PKG}" -eq 1 ]]    && part_packages
[[ "${DO_CODE}" -eq 1 ]]   && part_code
[[ "${DO_SERVER}" -eq 1 ]] && part_server

[[ -n "${COMPARE}" ]] && compare_previous

# ------------------------------------------------------------- summary ----
CUR_PART="summary"; CUR_SECTION=""; MUTED=0
say ""; say "${C_BOLD}== Summary ==${C_RESET}"
say "  Compromise indicators   : ${N_ALERT}"
say "  High-level problems     : ${N_HIGH}"
say "  Warnings                : ${N_WARN}"
say "  Notes                   : ${N_NOTE}"
say "  Checks that didn't run  : ${N_INCOMPLETE}"
say "  Accepted in .nsc-ignore : ${N_ACCEPTED}"
say "  Passed                  : ${N_OK}"
say ""

RESULT_LINE=""
if [[ "${N_ALERT}" -gt 0 ]]; then
  EXIT_CODE=1; RESULT_WORD="compromise"
  RESULT_LINE="FAIL - possible supply-chain COMPROMISE."
  say "${C_RED}${C_BOLD}RESULT: ${RESULT_LINE}${C_RESET}"
  printf '%s' "${LIST_ALERT}" | while IFS= read -r _l; do say "${_l}"; done
  say ""
  say " Do NOT build, run or deploy this install. Then, in this order:"
  say "   1. Remove the persistence FIRST: any gh-token-monitor service, LaunchAgent"
  say "      or script listed above. Snyk reports that it watches the GitHub token"
  say "      and deletes the home folder if the token is revoked while it runs."
  say "   2. THEN revoke and replace every credential this machine could reach:"
  say "      GitHub and npm tokens, SSH keys, cloud keys, values in .env files."
  say "   3. Delete node_modules and the lockfile, and reinstall with fixed versions"
  say "      (for each affected package, a release from after the bad ones)."
  say "   4. If this ran in CI, treat the CI secrets as stolen too."
  say "   5. Check your GitHub account for repositories or workflows you didn't create."
elif [[ "${N_HIGH}" -gt 0 || ( "${FAIL_ON_WARN}" -eq 1 && "${N_WARN}" -gt 0 ) ]]; then
  EXIT_CODE=2; RESULT_WORD="fail"
  if [[ "${N_HIGH}" -gt 0 ]]; then
    RESULT_LINE="FAIL - ${N_HIGH} high-level problem(s)."
    say "${C_RED}${C_BOLD}RESULT: FAIL - ${N_HIGH} high-level problem(s). Fix these first:${C_RESET}"
    printf '%s' "${LIST_HIGH}" | while IFS= read -r _l; do say "${_l}"; done
  else
    RESULT_LINE="FAIL - ${N_WARN} warning(s), and --fail-on-warn is set."
    say "${C_RED}${C_BOLD}RESULT: ${RESULT_LINE}${C_RESET}"
  fi
elif [[ "${N_INCOMPLETE}" -gt 0 && "${STRICT}" == "1" ]]; then
  EXIT_CODE=3; RESULT_WORD="incomplete"
  RESULT_LINE="NOT COMPLETE - ${N_INCOMPLETE} check(s) could not run, and --strict is set."
  say "${C_YELLOW}${C_BOLD}RESULT: ${RESULT_LINE}${C_RESET}"
else
  if [[ "${N_WARN}" -gt 0 ]]; then RESULT_LINE="PASS, with ${N_WARN} warning(s) to review."; else RESULT_LINE="PASS."; fi
  say "${C_GREEN}${C_BOLD}RESULT: ${RESULT_LINE}${C_RESET}"
fi
if [[ "${N_INCOMPLETE}" -gt 0 ]]; then
  say ""
  say " These checks did not run, so the result does not cover them:"
  printf '%s' "${LIST_INCOMPLETE}" | while IFS= read -r _l; do say "${_l}"; done
fi
say ""
say " Each finding ends with its ID in brackets. To accept one you have looked at,"
say " add a line to .nsc-ignore:   THE-ID   # why this is acceptable"
say ""
say " This is a first look, not a guarantee. It checks for known problems and"
say " common mistakes (compromise data checked ${DATA_DATE}); it can't see everything."

if [[ -n "${JSON_OUT}" ]]; then if write_json "${JSON_OUT}"; then say " JSON report saved to ${JSON_OUT}"; else say " Couldn't write ${JSON_OUT}"; fi; fi
if [[ -n "${MD_OUT}" ]]; then if write_markdown "${MD_OUT}"; then say " Markdown report saved to ${MD_OUT}"; else say " Couldn't write ${MD_OUT}"; fi; fi
if [[ -n "${HTML_OUT}" ]]; then if write_html "${HTML_OUT}"; then say " Web page report saved to ${HTML_OUT}"; else say " Couldn't write ${HTML_OUT}"; fi; fi
[[ -n "${REPORT}" ]] && say " Report saved to ${REPORT}"

exit "${EXIT_CODE}"
