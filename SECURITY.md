# Security Policy & Trust Model

## Threat Model

`aisoc` is designed as a single-host, local-first defensive security appliance monitoring network packets, container operations, and host telemetry.

The pipeline ingests untrusted, attacker-controlled data (packet payloads, HTTP headers, TLS SNI records, reverse-DNS names, and system logs). It feeds structured abstractions of this telemetry to local rule engines and LLM triage pipelines whose verdicts drive automated firewall responses.

Key protections against hostile inputs:
- **Prompt Injection Defense**: Wire-derived strings are sanitized (ANSI and control characters stripped, lengths bounded) and isolated under explicit untrusted data keys in model prompts. High-severity alerts require explicit confirmation before demotion.
- **Fail-Safe Enforcer Guardrails**: Automated response logic (`agent/guard.py`) validates candidate IP targets against non-bypassable host, gateway, DNS resolver, loopback, multicast, and RFC 1918 bridge addresses before any block can be submitted to nftables.
- **Time-Bounded Blast Radius**: All nftables set entries carry explicit auto-expiration timeouts (1 hour for initial detections, escalating to 24 hours and 30 days for repeated offenses). An automated block rate ceiling limits mutations to 30 operations per hour.

## Trust Boundaries & Privilege Model

Understanding the system's security posture requires distinguishing between **OS privilege boundaries** and **architectural design boundaries**:

1. **Firewall Enforcement Boundary**:
   - The Python agent (`agent/aisoc.py`) runs as an unprivileged service account (`aisoc`) restricted with `CAP_NET_ADMIN` and systemd filesystem sandboxing (`ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`).
   - The agent is the single entity that directly invokes netlink/nftables commands.
   - It exposes a local AF_UNIX control socket (`/run/aisoc/control.sock`) with `SO_PEERCRED` caller verification, framed requests, and idempotent action tracking.

2. **Console Privilege & Docker Socket Access**:
   - The TypeScript console (`console/server`) does not have `CAP_NET_ADMIN` and submits all block and unblock requests over the agent's control socket.
   - However, the console backend runs with `SupplementaryGroups=docker` (see [`console/systemd/aisoc-console.service`](console/systemd/aisoc-console.service)) to manage sensor containers via `docker compose` and orchestrate local security scans.
   - Because access to the Docker daemon socket is **root-equivalent on Linux hosts**, the separation between console suggestions and agent enforcement is an **architectural design boundary enforced by convention and IPC design**, not an unbreachable OS privilege ring. If the console process were compromised, Docker socket access would permit root escalation on the host.

3. **Telemetry Collection Boundary**:
   - Privileged host collectors (`scripts/audit_tail.py` and `scripts/cluster_tail.py`) run with required root privileges to read kernel audit logs and container exports.
   - Collectors emit minimized, sanitized event records to unprivileged JSONL spools; the console never opens raw root-only logs directly.

## Known Limitations

- **Local Scope**: Promiscuous packet capture is bounded to the physical and VPN interfaces of the host; non-mirrored LAN switch traffic is not visible.
- **Encrypted Payloads**: As modern network traffic is predominantly TLS-encrypted, detection relies on metadata (SNI, IP reputation, certificate fingerprints, flow characteristics) rather than deep payload inspection.
- **Detection vs Prevention**: Suricata operates in AF-PACKET copy mode (IDS). Blocks drop subsequent connection attempts rather than terminating the triggering packet in-flight.

## Reporting a Security Issue

If you discover a security vulnerability or privilege bypass in `aisoc`:
- Please open a private GitHub Security Advisory or report it directly to the repository maintainer.
- Include a minimal reproducible proof-of-concept and affected component details.
- Avoid publicly disclosing the issue until a patch or mitigation is made available.
