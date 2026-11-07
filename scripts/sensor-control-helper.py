#!/usr/bin/env python3
"""Narrow sensor control socket for Docker Suricata and Kubernetes Pi-hole."""

import grp
import json
import os
import pwd
import socket
import struct
import subprocess


SOCKET = os.environ.get("AISOC_SENSOR_CONTROL_SOCKET", "/run/aisoc-sensor-control/control.sock")
COMPOSE_FILE = os.environ.get("AISOC_COMPOSE_FILE", "/opt/aisoc/compose.yml")
K3S = os.environ.get("AISOC_K3S", "/usr/local/bin/k3s")
KUBECONFIG = os.environ.get("AISOC_KUBECONFIG", "/etc/rancher/k3s/kubeconfig")
RESOLVER_SCRIPT = os.environ.get(
    "AISOC_PIHOLE_RESOLVER", "/usr/local/libexec/aisoc/pihole-resolver.py"
)
ALLOWED_USER = os.environ.get("AISOC_SENSOR_CONTROL_USER", "aisoc-core")
SOCKET_GROUP = os.environ.get("AISOC_SENSOR_CONTROL_GROUP", "aisoc-control")
ALLOWED_RESTART_SERVICES = {"suricata", "suricata-vpn", "pihole"}
# `revert` is deliberately absent: tearing the host's resolver down belongs to
# stopping the unit, not to a console command that cannot put it back on boot.
ALLOWED_RESOLVER_MODES = {"status", "apply"}
MAX_REQUEST = 65536


def reply(conn, value):
    conn.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def read_request(conn):
    body = bytearray()
    while b"\n" not in body:
        chunk = conn.recv(4096)
        if not chunk:
            raise ValueError("truncated request")
        body.extend(chunk)
        if len(body) > MAX_REQUEST:
            raise ValueError("request too large")
    return json.loads(bytes(body).split(b"\n", 1)[0])


def pihole_status():
    result = subprocess.run(
        [
            K3S,
            "kubectl",
            "--kubeconfig",
            KUBECONFIG,
            "get",
            "deployment",
            "aisoc-pihole",
            "--namespace",
            "aisoc",
            "--output",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0 and "not found" in result.stderr.lower():
        return {
            "ok": True,
            "pihole": {"installed": False, "running": False, "state": "missing", "health": ""},
        }
    if result.returncode != 0:
        return {"ok": False, "error": (result.stdout + result.stderr)[-32000:]}
    output = result.stdout.strip()
    if not output:
        return {
            "ok": True,
            "pihole": {"installed": False, "running": False, "state": "missing", "health": ""},
        }
    deployment = json.loads(output)
    desired = int(deployment.get("spec", {}).get("replicas", 0))
    status = deployment.get("status", {})
    available = int(status.get("availableReplicas", 0))
    updated = int(status.get("updatedReplicas", 0))
    running = desired > 0
    ready = running and available == desired and updated == desired
    state = "running" if ready else ("stopped" if desired == 0 else "starting")
    return {
        "ok": True,
        "pihole": {
            "installed": True,
            "running": running,
            "state": state,
            "health": "healthy" if ready else ("stopped" if desired == 0 else "starting"),
            "status": f"{available}/{desired} replicas available",
        },
    }


def resolver(mode):
    result = subprocess.run(
        ["/usr/bin/python3", RESOLVER_SCRIPT, mode],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return {"ok": False, "error": (result.stdout + result.stderr)[-32000:]}
    if mode == "apply":
        return {"ok": True, "output": result.stdout.strip() or "Resolver route applied."}
    return {"ok": True, "resolver": json.loads(result.stdout)}


def execute(request):
    if not isinstance(request, dict):
        raise ValueError("unsupported action")
    if request.get("action") == "status":
        if request.get("service") != "pihole" or set(request) != {"action", "service"}:
            raise ValueError("status service is not allowlisted")
        return pihole_status()
    if request.get("action") == "resolver":
        if request.get("mode") not in ALLOWED_RESOLVER_MODES or set(request) != {"action", "mode"}:
            raise ValueError("resolver mode is not allowlisted")
        return resolver(request["mode"])
    if request.get("action") != "restart":
        raise ValueError("unsupported action")
    services = request.get("services")
    if (
        not isinstance(services, list)
        or not services
        or len(services) > len(ALLOWED_RESTART_SERVICES)
    ):
        raise ValueError("invalid services")
    if any(
        not isinstance(service, str) or service not in ALLOWED_RESTART_SERVICES
        for service in services
    ):
        raise ValueError("service is not allowlisted")
    services = list(dict.fromkeys(services))
    output = []
    compose_services = [service for service in services if service != "pihole"]
    if compose_services:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                COMPOSE_FILE,
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                *compose_services,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        compose_output = (result.stdout + result.stderr)[-32000:]
        if result.returncode != 0:
            return {"ok": False, "error": compose_output or f"docker exited {result.returncode}"}
        output.append(compose_output)
    if "pihole" in services:
        result = subprocess.run(
            [
                K3S,
                "kubectl",
                "--kubeconfig",
                KUBECONFIG,
                "delete",
                "pod",
                "--namespace",
                "aisoc",
                "--selector",
                "app.kubernetes.io/name=aisoc-pihole",
                "--wait=true",
                "--timeout=60s",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=70,
        )
        k8s_output = (result.stdout + result.stderr)[-32000:]
        if result.returncode != 0:
            return {"ok": False, "error": k8s_output or f"kubectl exited {result.returncode}"}
        output.append(k8s_output)
    return {"ok": True, "output": "\n".join(part for part in output if part) or "Sensors restarted."}


def main():
    allowed_uid = pwd.getpwnam(ALLOWED_USER).pw_uid
    socket_gid = grp.getgrnam(SOCKET_GROUP).gr_gid
    os.makedirs(os.path.dirname(SOCKET), mode=0o750, exist_ok=True)
    try:
        os.unlink(SOCKET)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(SOCKET)
    os.chown(SOCKET, -1, socket_gid)
    os.chmod(SOCKET, 0o660)
    listener.listen(8)
    while True:
        conn, _ = listener.accept()
        with conn:
            try:
                conn.settimeout(130)
                _, uid, _ = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if uid != allowed_uid:
                    raise PermissionError("unauthorized peer")
                reply(conn, execute(read_request(conn)))
            except Exception as exc:
                reply(conn, {"ok": False, "error": str(exc)})


if __name__ == "__main__":
    main()
