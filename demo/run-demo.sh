#!/usr/bin/env bash
#
# Builds the demo server, runs node-security-check.sh inside it, and saves a
# web-page report next to this file.
#
#   bash demo/run-demo.sh            # standard check
#   bash demo/run-demo.sh --deep     # everything, including git history
#   bash demo/run-demo.sh --quick
#   bash demo/run-demo.sh --stop     # stop and remove the demo container
#
# Needs Docker with the "docker compose" command. Any other options are
# passed straight to node-security-check.sh.
#
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "This demo needs Docker with the 'docker compose' command." >&2
  echo "Without Docker you can still try the package and code checks:" >&2
  echo "  bash demo/make-demo-app.sh /tmp/demo-shop" >&2
  echo "  ./node-security-check.sh --skip server /tmp/demo-shop" >&2
  exit 1
fi

if [[ "${1:-}" == "--stop" ]]; then
  docker compose down
  exit 0
fi

echo "Building and starting the demo server (deliberately insecure; this machine only)..."
docker compose up -d --build

# Wait for the web server inside the container to answer.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if docker compose exec -T demo curl -fsS -o /dev/null http://localhost/ 2>/dev/null; then break; fi
  sleep 1
done

tty_flag="-T"
if [[ -t 0 && -t 1 ]]; then tty_flag=""; fi

# The check exits 1 or 2 here by design: the demo server is meant to fail.
set +e
# shellcheck disable=SC2086  # tty_flag is deliberately empty or "-T"
docker compose exec ${tty_flag} demo bash /opt/nsc/node-security-check.sh \
  --yes --server vps --proxy nginx --runner other --url http://localhost \
  --html /tmp/demo-report.html "$@" /srv/demo-app
code=$?
set -e

docker compose cp demo:/tmp/demo-report.html ./demo-report.html >/dev/null 2>&1 \
  && echo && echo "Web-page report saved to demo/demo-report.html"
echo "The check finished with exit code ${code} (1 = compromise found, 2 = high-level problems)."
echo "The demo site is at http://127.0.0.1:8080 while the container runs."
echo "Stop it with:  bash demo/run-demo.sh --stop"
