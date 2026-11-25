# The demo server for node-security-check: DELIBERATELY INSECURE.
#
# It exists so that people can watch the script find real problems. It runs
# as root, uses an end-of-life Node.js on purpose, and is full of weak
# settings. Never deploy it, and never publish its ports beyond 127.0.0.1.
#
# Build and run it with:  bash demo/run-demo.sh
#
FROM node:18-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nginx redis-server git curl ca-certificates iproute2 procps dnsutils openssl \
 && rm -rf /var/lib/apt/lists/*

COPY demo/make-demo-app.sh demo/make-insecure-server.sh demo/start.sh /opt/demo/

# Build the fake app and write the weak settings, then check nginx accepts them.
RUN bash /opt/demo/make-demo-app.sh /srv/demo-app \
 && NSC_DEMO_CONTAINER=yes bash /opt/demo/make-insecure-server.sh \
 && chmod 666 /srv/demo-app/uploads/.gitkeep \
 && nginx -t

EXPOSE 80
CMD ["bash", "/opt/demo/start.sh"]
