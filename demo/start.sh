#!/usr/bin/env bash
#
# Starts the demo container's services. Deliberately insecure: for local
# demonstration only.
#
set -u

echo "nsc-demo: a deliberately insecure demo server. Nothing in it is real."

# Redis with no password, on every interface (not published outside the container).
redis-server /etc/redis/redis.conf --daemonize yes >/dev/null

# The demo app: as root, in development mode, with the debugger switched on.
cd /srv/demo-app || exit 1
NODE_ENV=development HOST=0.0.0.0 PORT=3000 node --inspect src/server.js &

# A harmless stand-in for a crypto-miner: it is only "sleep" under another
# name, started from /tmp, which is where real ones usually land.
mkdir -p /tmp/.cache
cp "$(command -v sleep)" /tmp/.cache/xmrig
/tmp/.cache/xmrig infinity &

# nginx in front, in the foreground so the container keeps running.
exec nginx -g 'daemon off;'
