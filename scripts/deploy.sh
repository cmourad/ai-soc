#!/usr/bin/env bash
# Publish executable code to root-owned, versioned runtime trees.
#
# systemd runs four of these units as root (or with CAP_NET_ADMIN), and the
# repo lives under a user-writable path — writable by the unprivileged desktop
# user. ExecStart'ing a user-writable file from a root unit means anything that
# can write as the user owns root on the next timer fire. So units point at
# /usr/local/libexec/aisoc, which only root can write, and this script is the
# only way code gets there.
#
# Build the console as the unprivileged developer first, then run:
#
#     pnpm -C console check && pnpm -C console build
#     sudo scripts/deploy.sh
#
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DST=/usr/local/libexec/aisoc
RELEASE_ROOT=/opt/aisoc/releases
CURRENT=/opt/aisoc/current

[[ $EUID -eq 0 ]] || { echo "must run as root: sudo $0" >&2; exit 1; }

SERVER_BUILD="$SRC/console/dist/server/index.js"
UI_BUILD="$SRC/console/ui/dist"
[[ -f "$SERVER_BUILD" ]] || {
  echo "missing $SERVER_BUILD; run: pnpm -C console build" >&2
  exit 1
}
[[ -f "$UI_BUILD/index.html" ]] || {
  echo "missing $UI_BUILD/index.html; run: pnpm -C console build" >&2
  exit 1
}
if find "$SRC/console/ui/src" "$SRC/console/ui/package.json" \
  -type f -newer "$UI_BUILD/index.html" -print -quit | grep -q .; then
  echo "stale $UI_BUILD; run: pnpm -C console build" >&2
  exit 1
fi
if find "$SRC/console/server/src" "$SRC/console/server/package.json" "$SRC/console/bin" \
  "$SRC/console/scripts/build-server.mjs" -type f -newer "$SERVER_BUILD" -print -quit | grep -q .; then
  echo "stale $SERVER_BUILD; run: pnpm -C console build" >&2
  exit 1
fi
if find "$SRC/console/dist" "$UI_BUILD" -type l -print -quit | grep -q .; then
  echo "refusing console build containing symlinks" >&2
  exit 1
fi

getent group aisoc-control >/dev/null || groupadd --system aisoc-control
id aisoc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin aisoc
id aisoc-core >/dev/null 2>&1 || \
  useradd --system --user-group --no-create-home --shell /usr/sbin/nologin aisoc-core
usermod --append --groups aisoc-control aisoc
usermod --append --groups aisoc-control aisoc-core
desktop_user="${AISOC_DESKTOP_USER:-${SUDO_USER:-}}"
if [[ -z "$desktop_user" || "$desktop_user" == root ]] || ! id "$desktop_user" >/dev/null 2>&1; then
  echo "cannot determine desktop user; run with sudo or set AISOC_DESKTOP_USER" >&2
  exit 1
fi

install -d -o root -g root -m 0755 "$DST" "$DST/agent" "$DST/scripts"

# The agent is a package of modules now; every one of them is executable code a
# root unit imports, so all of them are installed root-owned and read-only.
for module in aisoc config guard helpers history ipc nft prompt; do
  install -o root -g root -m 0644 "$SRC/agent/$module.py" "$DST/agent/$module.py"
done
install -o root -g root -m 0755 "$SRC/agent/process_helper.py" "$DST/agent/process_helper.py"
install -o root -g root -m 0755 "$SRC/agent/vpn_helper.py"     "$DST/agent/vpn_helper.py"
install -o root -g root -m 0644 "$SRC/scripts/audit_tail.py"   "$DST/scripts/audit_tail.py"
install -o root -g root -m 0644 "$SRC/scripts/cluster_tail.py" "$DST/scripts/cluster_tail.py"
install -o root -g root -m 0644 "$SRC/scripts/daily_digest.py" "$DST/scripts/daily_digest.py"
install -o root -g root -m 0644 "$SRC/scripts/watchdog.py"     "$DST/scripts/watchdog.py"
install -o root -g root -m 0755 "$SRC/scripts/sensor-control-helper.py" \
                                                       "$DST/sensor-control-helper.py"
install -o root -g root -m 0755 "$SRC/scripts/pihole-resolver.py" \
                                                       "$DST/pihole-resolver.py"
install -o root -g root -m 0644 "$SRC/scripts/notify.py"       "$DST/scripts/notify.py"
install -o root -g root -m 0755 "$SRC/update-rules.sh"         "$DST/update-rules.sh"
install -o root -g root -m 0755 "$SRC/console/systemd/aisoc-console-health.sh" \
                                                                "$DST/console-health.sh"
# read by Guard: a writable allowlist is a permanently un-blockable IP
install -o root -g root -m 0644 "$SRC/allowlist.txt"           "$DST/allowlist.txt"

# Immutable console release. esbuild bundles application and npm code into one
# artifact. node-pty remains external because its native addon must be resolved
# beside its package at runtime; the build copies that one package into dist.
# The runtime still needs no repository source or package manager.
revision="$(git -C "$SRC" rev-parse --short=12 HEAD 2>/dev/null || echo uncommitted)"
release_id="$(date -u +%Y%m%dT%H%M%S%NZ)-$revision"
release="$RELEASE_ROOT/$release_id"
install -d -o root -g root -m 0755 \
  "$RELEASE_ROOT" "$release" "$release/console" "$release/console/dist" \
  "$release/console/bin" "$release/console/dist/server" \
  "$release/console/ui" "$release/console/ui/dist" \
  "$release/suricata" "$release/suricata/logs" "$release/suricata/logs-vpn"
install -o root -g root -m 0644 "$SERVER_BUILD" "$release/console/dist/server/index.js"
install -o root -g root -m 0644 "$SRC/console/dist/server/geo-table.txt" \
  "$release/console/dist/server/geo-table.txt"
install -o root -g root -m 0755 "$SRC/console/bin/aisocctl" \
  "$release/console/bin/aisocctl"
cp -a --no-preserve=ownership "$SRC/console/dist/server/node_modules" \
  "$release/console/dist/server/node_modules"
chown -R root:root "$release/console/dist/server/node_modules"
cp -a --no-preserve=ownership "$UI_BUILD/." "$release/console/ui/dist/"
chown -R root:root "$release/console/ui/dist"
find "$release/console/ui/dist" -type d -exec chmod 0755 {} +
find "$release/console/ui/dist" -type f -exec chmod 0644 {} +

# Relative EVE paths are resolved from the immutable release root. Link only
# the two untrusted sensor streams into that namespace; do not expose source,
# rules, or writable application code to the production process. The symlinks
# are root-owned while their targets remain sensor-owned append-only inputs.
ln -s "$SRC/suricata/logs/eve.json" "$release/suricata/logs/eve.json"
ln -s "$SRC/suricata/logs-vpn/eve.json" "$release/suricata/logs-vpn/eve.json"
chown -h root:root \
  "$release/suricata/logs/eve.json" "$release/suricata/logs-vpn/eve.json"

manifest="$release/MANIFEST.sha256"
(
  cd "$release"
  find console -type f -print0 | sort -z | xargs -0 sha256sum
) > "$manifest"
chown root:root "$manifest"
chmod 0644 "$manifest"

next_link="/opt/aisoc/.current-$release_id"
ln -s "$release" "$next_link"
mv -Tf "$next_link" "$CURRENT"

# Migrate current state once. This does not claim to solve key-at-rest storage;
# it does remove world-readable state and separates it from the interactive user.
install -d -o aisoc-core -g aisoc-core -m 0700 /var/lib/aisoc-core
for state_file in settings.json state.json secret.key secrets.enc.json network-compass.db; do
  if [[ -f "$SRC/console/data/$state_file" && ! -e "/var/lib/aisoc-core/$state_file" ]]; then
    install -o aisoc-core -g aisoc-core -m 0600 \
      "$SRC/console/data/$state_file" "/var/lib/aisoc-core/$state_file"
  fi
done
if [[ ! -e /var/lib/aisoc-core/bootstrap.key ]]; then
  openssl rand -hex -out /var/lib/aisoc-core/bootstrap.key 32
fi
chown aisoc-core:aisoc-core /var/lib/aisoc-core/bootstrap.key
chmod 0400 /var/lib/aisoc-core/bootstrap.key
# The resolver ledger the DNS view reads. FTL runs as its own uid inside the
# Kubernetes pod and writes 0640, so setgid on the directory is what makes new
# files land in aisoc-control and stay readable by the console user.
# config/ and logs/ must be group-Writable (2770), not just readable: FTL
# drops to the pihole user after the root entrypoint exits, and SQLite needs
# to create gravity.db-wal/-shm (and rotated logs) in the directory on every
# gravity rebuild. 2750 there made every adlist change fail with
# "attempt to write a readonly database".
install -d -o root -g aisoc-control -m 2750 /var/lib/aisoc-pihole
install -d -o root -g aisoc-control -m 2770 \
  /var/lib/aisoc-pihole/config /var/lib/aisoc-pihole/logs

# The Kubernetes workload uses the host aisoc-control gid so its 0640 ledger
# stays readable by the console. Fail loudly if the host allocation drifts from
# the GitOps manifest instead of silently breaking the DNS view.
control_gid="$(getent group aisoc-control | cut -d: -f3)"
[[ "$control_gid" == 979 ]] || {
  echo "aisoc-control gid is $control_gid; update the platform Pi-hole manifest" >&2
  exit 1
}

install -d -o "$desktop_user" -g "$desktop_user" -m 0700 /var/lib/aisoc-desktop
install -o "$desktop_user" -g "$desktop_user" -m 0400 \
  /var/lib/aisoc-core/bootstrap.key /var/lib/aisoc-desktop/bootstrap.key

install -o root -g root -m 0644 "$SRC/systemd/aisoc-agent.service" \
  /etc/systemd/system/aisoc-agent.service
install -o root -g root -m 0644 "$SRC/systemd/aisoc-host-events.service" \
  /etc/systemd/system/aisoc-host-events.service
install -o root -g root -m 0644 "$SRC/systemd/aisoc-cluster-events.service" \
  /etc/systemd/system/aisoc-cluster-events.service
# Spool and sensor-log rotation. Left out of the first rollout, which is how
# eve.json reached 936 MB and the collector spool was heading for 1.2 GB a day.
install -o root -g root -m 0644 "$SRC/systemd/logrotate-aisoc" \
  /etc/logrotate.d/aisoc
install -o root -g root -m 0644 "$SRC/systemd/aisoc-vpn-helper.service" \
  /etc/systemd/system/aisoc-vpn-helper.service
install -o root -g root -m 0644 "$SRC/systemd/aisoc-process-helper.service" \
  /etc/systemd/system/aisoc-process-helper.service
install -o root -g root -m 0644 "$SRC/systemd/aisoc-sensor-control.service" \
  /etc/systemd/system/aisoc-sensor-control.service
install -o root -g root -m 0644 "$SRC/systemd/aisoc-pihole-resolver.service" \
  /etc/systemd/system/aisoc-pihole-resolver.service
install -o root -g root -m 0644 "$SRC/console/systemd/aisoc-console.service" \
  /etc/systemd/system/aisoc-console.service
systemctl daemon-reload
systemctl enable --now \
  aisoc-vpn-helper.service aisoc-process-helper.service aisoc-sensor-control.service \
  aisoc-pihole-resolver.service

echo "deployed to $DST"
echo "console release: $release"
echo "restart what changed: systemctl restart aisoc-agent.service aisoc-process-helper.service aisoc-sensor-control.service aisoc-pihole-resolver.service aisoc-console.service"
