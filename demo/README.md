# Demo server

A throwaway, **deliberately insecure** server in a Docker container, so you can
watch `node-security-check.sh` find real problems without pointing it at
anything that matters.

> **Never deploy this, and never publish its ports beyond `127.0.0.1`.**
> It runs as root, uses an end-of-life Node.js, has no passwords where there
> should be some, and serves its own secrets. All of that is the point.

## Run it

```bash
bash demo/run-demo.sh            # build, start, run the check, save a report
bash demo/run-demo.sh --deep     # also scan git history and probe further
bash demo/run-demo.sh --stop     # stop and remove the container
```

It needs Docker with the `docker compose` command. The first run downloads a
base image and a few packages, so it takes a minute or two.

When it finishes you have:

- the check's output in your terminal;
- `demo/demo-report.html`, the same result as a web page;
- the demo site itself at <http://127.0.0.1:8080>, until you stop it.

The check ends with exit code 1. That is expected: the demo is built to fail.

## Without Docker

The package and code checks, and the live-site checks, work without it:

```bash
bash demo/make-demo-app.sh /tmp/demo-shop
./node-security-check.sh --skip server /tmp/demo-shop

# The demo site on this machine only, in a second terminal:
HOST=127.0.0.1 PORT=3000 node /tmp/demo-shop/src/server.js
./node-security-check.sh --only server --server managed --url http://127.0.0.1:3000 /tmp/demo-shop
```

## What is in it

| Area | What is wrong, on purpose |
|---|---|
| Packages | A known-malicious version (`@tanstack/history` 1.161.9), old `lodash` and `minimist`, a dependency set to `latest`, an install script, a made-up installed package whose install script downloads and runs something |
| Secrets | A committed `.env`; fake AWS, Stripe and Slack values in files; a fake GitHub token that was "removed" but is still in git history; a fake key inside the build output |
| Code | About twenty risky patterns: `eval`, shell commands and SQL built from request data, weak hashing, open CORS, a hard-coded session secret, stack traces sent to visitors, and more |
| Project files | A Dockerfile, compose file, Kubernetes deployment and GitHub Actions workflow, each with the usual mistakes |
| Server | Node running as root in development mode with the debugger on; Redis with no password; weak SSH settings; an nginx configuration with old TLS versions and the project folder as its root |
| "Break-in" | A second root account, a scheduled job that downloads a script, an odd systemd service, and a process named like a crypto-miner |
| Live site | No security headers, a cookie with no protections, `/.env` and `/.git` readable, a database dump, open CORS with cookies, stack traces, GraphQL introspection, public source maps |

One finding is accepted in the app's `.nsc-ignore`, to show how that looks.

## Why it is safe to run

- **Nothing is real.** Every "secret" is a made-up value that only looks like
  one. They are assembled when the app is built, so this repository never
  holds a secret-shaped string.
- **Nothing harmful runs.** The "crypto-miner" is the `sleep` command under
  another name. The scheduled job and the odd service are text in files: the
  container has no cron, no systemd and no SSH server, and the addresses in
  them do not exist.
- **Nothing is exposed.** Only the web port is published, and only on
  `127.0.0.1`. Redis and the Node debugger are reachable inside the container
  only.
- **It can't be applied to a real machine by accident.**
  `make-insecure-server.sh` refuses to run unless it is inside the container's
  build or is given an empty scratch folder.

## The picture and the recording in the README

- `demo-output.svg` is a still picture of real output from a quick check of
  the demo app.
- For an animated version, install [VHS](https://github.com/charmbracelet/vhs)
  and run `vhs demo/demo.tape` from the repository root. It writes
  `demo/demo.gif`; point the image line at the top of the main README at that
  file instead.

## Files

| File | Purpose |
|---|---|
| `run-demo.sh` | One command: build, start, check, save the report |
| `Dockerfile`, `docker-compose.yml` | The container |
| `make-demo-app.sh` | Builds the fake app (`demo-shop`) into a new folder |
| `make-insecure-server.sh` | Writes the weak server settings (container or scratch folder only) |
| `start.sh` | Starts Redis, the app, the fake miner and nginx inside the container |
| `demo.tape` | Script for recording the terminal GIF with VHS |
| `demo-output.svg` | Still picture of the output, shown in the main README |
