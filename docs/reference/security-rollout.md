Technical reference: Operational hardening procedure and service isolation rollout.

# Security hardening rollout

The first target-architecture security tranche is implemented and verified in the
worktree. Activation requires an administrator because it creates service identities,
writes root-owned releases and units, migrates state ownership, and restarts services.

## What activates

- `aisoc-core` replaces the interactive desktop user as the console service identity.
- Production executes a root-owned bundled artifact under `/opt/aisoc/current`, not `tsx`,
  repository source, or writable `node_modules`.
- The firewall control socket authorizes the exact core UID with `SO_PEERCRED`, uses a
  bounded length-framed protocol, and journals UUID action intents for idempotency.
- Local and tailnet API clients require an application session; mutations additionally
  require CSRF, valid Host/Origin/Fetch-Metadata, and stay within rate/body limits.
- Local session bootstrap requires a deploy-generated credential readable by the desktop
  user and core service only; Electron injects it only into the bootstrap request.
- Console state moves to `/var/lib/aisoc-core` with directory mode `0700` and files `0600`.
- The console service has no sudo path, capabilities, home access, writable code, or broad
  system calls. Real VPN mutation remains disabled until its separate helper exists.

## Activate

From the repository root:

```sh
pnpm -C console check
pnpm -C console build
sudo scripts/deploy.sh
sudo systemctl restart aisoc-agent.service aisoc-console.service
```

The deployment is versioned and atomic. `/opt/aisoc/current` points to the activated
release; each release includes `MANIFEST.sha256`.

## Verify

```sh
systemctl is-active aisoc-agent.service aisoc-console.service
systemctl show aisoc-console.service -p User -p Group -p ExecStart -p NoNewPrivileges
stat -c '%A %U:%G %n' /opt/aisoc/current /var/lib/aisoc-core /run/aisoc/control.sock
curl -i http://127.0.0.1:4319/api/health
journalctl -u aisoc-agent.service -u aisoc-console.service --since '-10 min'
```

Expected results:

- both units are active;
- console `User=aisoc-core`, `NoNewPrivileges=yes`, and `ExecStart` points under
  `/opt/aisoc/current`;
- the state directory is `0700 aisoc-core:aisoc-core`;
- the control socket group is `aisoc-control`, and an unauthorized UID receives
  `unauthorized_peer`;
- health returns 200 with CSP, no-sniff, no-store, frame-denial, referrer, and permissions
  headers.

## Host sudo policy still requiring an explicit operator decision

The interactive operator account still has several root-equivalent `NOPASSWD` grants.
They are outside this repository and the deploy script deliberately does not rewrite
sudoers automatically. Review with `sudo visudo`/`sudo visudo -f /etc/sudoers.d/<file>` and
remove passwordless grants for `apt`, `apt-get`, `systemctl`, `cp`, `rm`, module tools, and
other general-purpose commands. Keep only grants independently justified for unrelated
host administration.

The hardened server no longer runs as an interactive operator account, so those grants are no longer inherited by
a server-side dependency compromise after activation. They still magnify compromise of
the interactive desktop/Electron account and therefore remain a host-level Critical risk.
