Technical reference: Single-host topology, telemetry flows, and boundary invariants.

# Estate map — 2026-08-25

Orientation for one machine that is simultaneously a desktop, a Kubernetes
cluster, and the SOC that watches both. This is the *shape* of things: what runs
where, which way the dependencies point, and where telemetry actually flows.

For the security assessment of the host appliance see
[`architecture-current.md`](architecture-current.md); for where it is going,
[`architecture-target.md`](architecture-target.md); for the drill program, the
findings register and the coverage ledger, [`attack-lab.md`](attack-lab.md).

## What runs where

```
+== soc-host · 192.0.2.9 · single machine ===========================================+
|                                                                                  |
|  HOST BOUNDARY (systemd + docker)          |  k3s v1.36.3 (single node)           |
|  ----------------------------------        |  ---------------------------------  |
|  suricata      docker · eth0     [OK]      |  tetragon DaemonSet      [OK]        |
|  suricata-vpn  docker · aisoc0   [OK]      |  k3s apiserver + audit   [OK]        |
|  auditd                          [OK]      |  alloy --> platform-loki [OK]        |
|  audit_tail.py    root           [OK]      |  argocd · authentik · infisical      |
|  cluster_tail.py  root           [OK]      |  prod · dev · attack-lab             |
|  agent/aisoc.py   aisoc          [OK]      |                                      |
|  console          aisoc-core     [OK]      |  cluster agent                        |
|  nftables  inet aisoc            [OK]      |                          [no telem]  |
|  wg tunnel aisoc0                [fixed]   |                                      |
+==================================================================================+
         the host watches the cluster; the cluster never gates the host
```

That last line is the load-bearing invariant. Identity, secrets, evidence and
enforcement each have a path that survives the cluster being gone or hostile —
which is why F21 below was survivable at all. A sensor living inside k3s would
have gone down with the API server it was trying to reach.

## Where telemetry goes

```
  SOURCES                    ROOT READERS            SPOOL / FILE        DECIDE        ACT
  -------                    ------------            ------------        ------        ---

  wlp7s0 --> suricata ------------------------------> eve.json ------+
                    (sees only ciphertext                            |
                     while the VPN is up)                            |
                                                                     |
  aisoc0 --> suricata-vpn --------------------------> eve.json ------+--> console
                    (the sensor with real visibility today)          |    :4319
                                                                     |    aisoc-core
  syscalls -> auditd --> audit_tail.py -----> host-events.jsonl -----+       |
                         merges SYSCALL+                             |       |
                         EXECVE, adds tty                            +--> agent/aisoc.py
                         + parent_exe                                        |
  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|- - - - -
                                                                             v
  tetragon DS --> tetragon.log 0600 --+                                 Huihui :8082
                                      |                                      |
  apiserver ---> /var/log/k3s-audit/ -+--> cluster_tail.py ---> cluster-     |
                 audit.log                 root · minimises      events      v
                                           · priority-sheds      .jsonl --> verdict
                                                                     |       |
  tetragon.log + audit.log ---> alloy ---> platform-loki             |       v
                               (evidence copy, 24h)                  |    nftables
                                                                     |    inet aisoc
                                                                     +--> detection    (auto-expiring)
                                                                          engine
                                                                          AISOC-HOST-2xxx
                                                                          AISOC-K8S-2xxx
```

Two properties worth keeping in mind when reading this:

- **The root readers are the trust boundary.** Both cluster sources are
  root-only for good reason — one carries every process argument on this host,
  the other the cluster's object metadata. `cluster_tail.py` is the only reader
  and it writes a minimised spool: no request or response bodies, no labels,
  every field capped. The console never opens the source files.
- **Loki is the evidence copy, not the detection path.** A query in Grafana is
  evidence; coverage means a versioned rule that fired on replay.

## The routing bug that cost 2026-08-25

Kept because it was unrecognisable while it was happening, and the shape will
recur.

```
   BEFORE  (07:59 - 14:50)                    AFTER

   host --> 10.43.0.1:443                     host --> 10.43.0.1:443
      |                                          |
      | ip route get -> dev aisoc0               | ip route get -> main
      v     table 51820                          v
   [ wg tunnel ] --> exit node                DNAT -> 192.0.2.9:6443 --> 401
      X  never comes back                        OK

   symptom: tetragon crash-loop, "i/o timeout"    NAT was correct the whole time:
            every hostNetwork client broken       2 pkts on the DNAT counter,
            looked exactly like a k8s fault       KUBE-SEP right, MASQUERADE loaded
```

A full-tunnel WireGuard profile takes the route to every ClusterIP with it. The
cluster CIDRs are now a mandatory exclusion in every split-tunnel mode
(`console/server/src/vpn/wireguard.ts`), on the same principle that stops the
Guard blocking its own gateway.

## The day's failures, by where they lived

```
  F21  VPN swallowed 10.42/16 + 10.43/16 ....... aisoc's own routing   [FIXED in code]
  F19  repo-server 1s probe vs 5.6s render ..... argocd chart default  [FIXED, needs Scalr]
  F20  AppProject refused the sensor ........... argocd, working right [FIXED, own project]
  F23  physical wire sensor stopped ............ docker compose        [FIXED]
  F25  spool chowned to the wrong user ......... the collector         [FIXED]
  F26  clusterTelemetry never took effect ...... no UI control         [set by hand]

  three of these were SILENT. that is the actual finding.
```

Full detail, severity and status for each: the findings register in
[`attack-lab.md`](attack-lab.md).

## Open

```
  [ ] confirm the console has the spool open   sudo ls -l /proc/$(systemctl show \
                                                -p MainPID --value aisoc-console)/fd
  [ ] Scalr run  -> or the next tofu apply reverts the repo-server probe fix
  [ ] why the eve deadman never fired  (ingest.source WAS eve, so it should have)
  [ ] durable cursors  -> console tails from EOF; a restart loses the gap
  [ ] Authentik OIDC + step-up (F9) · Infisical key delivery
  [ ] physical sensor is blind while the VPN is up -> document as a visibility limit
  [ ] 4 cluster rules written but never fired at: S1 S2 S4 S5 S8
```
