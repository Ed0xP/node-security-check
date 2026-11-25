# node-security-check

A security check for any Node.js app. One Bash script, three parts:

| Part | What it looks at |
|---|---|
| **Packages** | Known-malicious and vulnerable packages, what is really installed in `node_modules`, registry signatures, install settings, Node.js version |
| **Code** | Committed secrets (now and in git history), risky code patterns, framework settings, Docker, Kubernetes and GitHub Actions files |
| **Server** | Signs of a break-in, accounts, ports, firewall, SSH, databases, updates, the running app, the reverse proxy, containers, and the live site's HTTPS, headers and DNS |

It works with **npm, pnpm, Yarn and Bun**. It only reads: it never installs,
updates or deletes anything. The only files it writes are the reports and
saved answers you ask for.

![Terminal output of the script run against the demo app](demo/demo.gif)

*An excerpt of real output, from a quick check of the fake [demo app](demo/README.md).
The full, current output of every run is on the summary page of the latest
[workflow run](../../actions).*

## Quick start

```bash
chmod +x node-security-check.sh
./node-security-check.sh /path/to/your/project
```

Run in a terminal, it asks a few questions first (press Enter to accept each
suggestion): what to check, how thorough to be, the package manager, where the
app runs, what sits in front of Node, what keeps it running, and the site's
live address. It can save the answers to `.nsc.conf` so it only asks once.

**To check a server, run the script on that server**, ideally with `sudo`, so
it can see every process, port and setting.

## Try the demo

Want to see it find things first? The `demo/` folder holds a throwaway,
deliberately insecure server in a Docker container, with a fake app full of
the mistakes this script looks for:

```bash
bash demo/run-demo.sh
```

It builds the container, runs the check inside it and saves a web-page report.
Nothing in it is real, and it is only reachable from your own machine. See
[demo/README.md](demo/README.md).

## How thorough

| Level | What runs | Typical time |
|---|---|---|
| `--quick` | Lockfile, known-bad list, audit, main secret and code patterns, core server checks | Seconds |
| standard (default) | Adds the OSV lookup, `node_modules` scan, all code patterns, Kubernetes, break-in signs, accounts, databases, the running app, the live-site probes and DNS | Under a minute |
| `--deep` | Adds git history, registry signatures and package age, TLS probing, set-uid files, and specialist tools if installed | Minutes |

## Running without questions

```bash
# On your own machine or in CI: packages and code only
./node-security-check.sh --yes --skip server --strict --fail-on high .

# On the server
sudo ./node-security-check.sh --yes --server vps --proxy nginx \
  --runner systemd --service myapp --url https://example.com /srv/myapp

# Keep a record and see what changed since last time
./node-security-check.sh --yes --compare last.json --json last.json --html report.html .
```

| Option | Meaning |
|---|---|
| `--pm NAME` | `npm`, `pnpm`, `yarn` or `bun` (default: detected) |
| `--server TYPE` | `vps`, `docker`, `managed` or `dev` |
| `--proxy NAME` | `nginx`, `apache`, `caddy` or `none` |
| `--runner NAME` | `systemd`, `pm2` or `other` |
| `--service NAME` / `--container NAME` | The app's systemd service or Docker container |
| `--url URL` | Live site to check. Only use an address you own or may test. |
| `--quick` / `--deep` | Thoroughness (see above) |
| `--only LIST` / `--skip LIST` | Choose parts: `packages,code,server` |
| `--history` | Scan git history for secrets without the rest of `--deep` |
| `--prod-only` | Audit production dependencies only |
| `--ioc-file FILE` | Your own known-bad versions; may be repeated |
| `--no-network` / `--no-osv` / `--no-tools` | Skip network checks, the OSV lookup, or the specialist tools |
| `--ignore-file FILE` | Accepted findings (default `.nsc-ignore`) |
| `--config FILE`, `--save-config`, `--ask` | Saved answers (default `.nsc.conf`) |
| `--fail-on LEVEL` | Audit level that counts as a problem: `critical` (default), `high`, `moderate`, `low` |
| `--strict` | Exit 3 if any check could not run |
| `--fail-on-warn` | Treat warnings as problems |
| `--report FILE`, `--json FILE`, `--markdown FILE`, `--html FILE` | Save the result as text, JSON, Markdown or a web page |
| `--compare FILE` | Compare with an earlier `--json` report |
| `-y`, `--yes` | Don't ask questions |

`FAIL_ON=high` and `STRICT=1` also work as environment variables.

## Reading the result

| Mark | Meaning |
|---|---|
| `[ OK ]` | Checked and fine |
| `[NOTE]` | Worth knowing; no action needed |
| `[WARN]` | Should be reviewed; does not fail the check |
| `[HIGH]` | A problem to fix; fails the check |
| `[ALERT]` | Sign of a compromise in your packages; stop |
| `[ ?? ]` | The check could not run, so the result does not cover it |
| `[SKIP]` | A finding you accepted in `.nsc-ignore` |
| `[ -- ]` | Not applicable or skipped |

| Exit code | Meaning |
|---|---|
| 0 | No high-level problems. Warnings may remain. |
| 1 | Possible supply-chain compromise. Do not build or deploy. |
| 2 | High-level problems. |
| 3 | Could not complete: a bad option, no project, cancelled, or with `--strict` a check that could not run. |

Without `--strict`, a check that could not run is reported but does not change
the exit code. **In CI, use `--strict`**, or "no network" will look like a pass.

## Accepting a finding

Pattern checks give false alarms, and some findings are decisions you have
already made. Each finding ends with its ID in brackets. To accept one, add it
to `.nsc-ignore` in the project **with a reason**:

```
# FINDING-ID [path]   # why this is acceptable
CODE-HELMET                  # nginx sets the security headers
CODE-EVAL src/legacy/*       # admin-only tool; input never comes from visitors
CODE-HISTORY-SECRET config.js   # key rotated on 2026-11-25
SRV-SSH-*                    # reviewed with the hosting provider, March 2026
```

- An entry without a reason is refused, and the finding still counts.
- A path limits the entry to matching files; the rest are still reported.
- An ID ending in `*` accepts a group.
- `[ALERT]` findings can never be accepted.

## If you get an ALERT

Do not build, run or deploy. Then, **in this order**:

1. **Remove the persistence first**: any `gh-token-monitor` service, LaunchAgent
   or script the output lists. Snyk reports that the TanStack payload checks the
   stolen GitHub token every 60 seconds and deletes the home folder if the token
   is revoked.
2. **Then** revoke and replace every credential the machine could reach.
3. Delete `node_modules` and the lockfile, and reinstall with fixed versions.
4. Check your GitHub account for repositories or workflows you didn't create.

## What it knows about malicious packages

Three layers:

1. **A built-in list** that works offline: TanStack (May 2026, 42 packages),
   axios (March 2026), chalk/debug (September 2025, 21 packages) and Nx (August
   2025, 8 packages), plus the file names the Shai-Hulud worm leaves behind.
2. **The OSV database**, looked up live. It includes the OpenSSF
   malicious-packages feed, so it covers the large worm campaigns (Shai-Hulud,
   ChainDrop and others) that are too big to list in a script.
3. **Your own list**, with `--ioc-file`: one package per line, `name version
   [version...]`.

Both the lockfile and what is actually in `node_modules` are checked.

## Specialist tools

With `--deep`, the script runs these if they are installed, and adds a one-line
summary of each: **gitleaks**, **trufflehog**, **semgrep**, **trivy**, **lynis**
and **testssl.sh**. They go further than pattern matching can. None is required.

## What it can't do

- **It is a first look, not a penetration test.** A pass does not prove the app
  is safe.
- **The code checks are pattern matches** on single lines. They raise questions
  for a person to answer, give false alarms, and miss anything that spans
  several lines or flows through variables.
- **Break-in signs are the common ones.** Careful attackers leave none of them.
- **Lockfiles it reads:** `package-lock.json`, `npm-shrinkwrap.json`,
  `pnpm-lock.yaml`, `yarn.lock` (v1 and v2+) and the text `bun.lock`. Not the old
  binary `bun.lockb`. In a monorepo it reads the folder you point it at.
- **Server checks need Linux**, and root to see everything. Database, proxy and
  firewall settings are checked for common mistakes, not analysed in full.
- **It is a Bash script.** On Windows it needs WSL or Git Bash.

### How it has been tested

- 512 automated checks, using fake projects and stand-ins for system tools.
  They include building the demo app and checking the demo web site for real.
- Run for real: the npm, pnpm, Yarn and Bun audits; the npm registry lookups;
  the code and package checks against an open-source Express app; the
  live-site checks over plain HTTP against the demo site.
- **Not yet run for real:** the server checks on an actual server, the demo
  container itself, the OSV lookup, the Node release-list lookup,
  `npm audit signatures`, the DNS and TLS probes, and the six specialist tools.
  These are tested against stand-ins only, written from each tool's documented
  behaviour. Treat their first real run as the test.
- Tested on Linux with bash 5. It avoids bash-4-only features so the older bash
  on macOS should work, but that has not been tested.

## Privacy

- The audit sends your package names and versions to the package registry, and
  the OSV lookup sends them to osv.dev. `--no-osv` or `--no-network` skips them.
- `--url` makes a few dozen ordinary requests to that address, including for
  files such as `/.env` and `/.git/HEAD`, to see whether they are served.
- Secrets it finds are never printed: the output shows the file and line only.
- Reports contain file paths, account names and software versions from the
  machine. Treat them as confidential.
- Running a package manager inside a project uses that project's settings files.
  The script never runs an install or an install script.

## Tests

```bash
bash tests/run-tests.sh                      # no network needed
RUN_NETWORK_TESTS=1 bash tests/run-tests.sh  # also the real audits and registry
```

The tests need bash, git and node. They change nothing on the machine.

The workflow in `.github/workflows/ci.yml` runs the linter and these tests on
every push, then runs the demo and puts its report on the run's summary page.

## Sources

- [GitHub advisory GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx) and [Snyk's write-up](https://snyk.io/blog/tanstack-npm-packages-compromised) (TanStack)
- [Nx post-mortem](https://nx.dev/blog/s1ngularity-postmortem)
- [The Register on the chalk/debug compromise](https://www.theregister.com/2025/09/08/dev_falls_for_phishing_email)
- [Unit 42 on Shai-Hulud](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [OSV API](https://google.github.io/osv.dev/post-v1-querybatch)
- [Node.js releases](https://nodejs.org/en/about/previous-releases), [Ubuntu release cycle](https://ubuntu.com/about/release-cycle)

## Licence

[MIT](LICENSE), copyright 2026 Edward Pope.
