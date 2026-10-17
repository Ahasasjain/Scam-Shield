#!/usr/bin/env bash
#
# ScamShield — EC2 bootstrap (Amazon Linux 2023).
#
# Paste this file's contents into the instance's "User data" field when
# launching it (Advanced details → User data), or run it as root on an
# existing instance. It installs Docker + the Compose v2 plugin and clones
# this repo to /home/ec2-user/scamshield.
#
# Private fork? Change REPO_URL and give the instance a read-only deploy key,
# or clone manually and skip the git step. See docs/DEPLOYMENT.md, Option B.
set -euxo pipefail

REPO_URL="https://github.com/Ahasasjain/Scam-Shield.git"
APP_DIR="/home/ec2-user/scamshield"

dnf update -y
dnf install -y docker git curl
systemctl enable --now docker
usermod -aG docker ec2-user

# Docker Compose v2 as a CLI plugin — AL2023 packages don't ship it.
# `uname -m` (x86_64 / aarch64) matches the release asset names exactly.
COMPOSE_ARCH="$(uname -m)"
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${COMPOSE_ARCH}" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

if [ ! -d "$APP_DIR" ]; then
  git clone --depth 1 "$REPO_URL" "$APP_DIR"
fi
chown -R ec2-user:ec2-user "$APP_DIR"

# Remaining manual steps (see docs/DEPLOYMENT.md, "Option B"):
#   1. cp "$APP_DIR/server/.env.example" "$APP_DIR/server/.env" and fill it in
#   2. cd "$APP_DIR" && docker compose up -d
#   3. optional HTTPS: echo "DOMAIN=api.example.com" >> "$APP_DIR/.env"
#      then: docker compose --profile edge up -d
