#!/usr/bin/env bash
# aisoc-control — interactive service management menu
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT/compose.yml"
KUBECONFIG_FILE=/etc/rancher/k3s/kubeconfig

red='\033[0;31m'
grn='\033[0;32m'
ylw='\033[1;33m'
blu='\033[0;34m'
mgt='\033[0;35m'
cyn='\033[0;36m'
bold='\033[1m'
reset='\033[0m'

sep() { echo -e "${cyn}────────────────────────────────────────${reset}"; }

status_icon() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo -e "${grn}●${reset}"
    else
        echo -e "${red}●${reset}"
    fi
}

docker_status() {
    if docker compose -f "$COMPOSE_FILE" ps "$1" --format json 2>/dev/null | grep -q '"Running": true'; then
        echo -e "${grn}●${reset}"
    else
        echo -e "${red}●${reset}"
    fi
}

pihole_status() {
    if [[ "$(k3s kubectl --kubeconfig "$KUBECONFIG_FILE" get deployment \
        aisoc-pihole -n aisoc -o jsonpath='{.status.availableReplicas}' 2>/dev/null)" == "1" ]]; then
        echo -e "${grn}●${reset}"
    else
        echo -e "${red}●${reset}"
    fi
}

show_status() {
    echo ""
    echo -e "${bold}${blu}aisoc — Service Status${reset}"
    sep
    echo -e " ${mgt}Docker Services${reset}"
    printf "   %-6s %-25s\n" "$(docker_status suricata)" "Suricata (LAN)"
    printf "   %-6s %-25s\n" "$(docker_status suricata-vpn)" "Suricata (VPN)"
    echo ""
    echo -e " ${mgt}Kubernetes Services${reset}"
    printf "   %-6s %-25s\n" "$(pihole_status)" "Pi-hole"
    echo ""
    echo -e " ${mgt}Systemd Services${reset}"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-console.service)" "aisoc-console"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-agent.service)" "aisoc-agent"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-host-events.service)" "aisoc-host-events"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-process-helper.service)" "aisoc-process-helper"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-vpn-helper.service)" "aisoc-vpn-helper"
    echo ""
    echo -e " ${mgt}Timers${reset}"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-digest.timer)" "aisoc-digest"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-rules.timer)" "aisoc-rules"
    printf "   %-6s %-25s\n" "$(status_icon aisoc-watchdog.timer)" "aisoc-watchdog"
    sep
    echo ""
}

menu() {
    show_status
    echo -e "${bold}Choose an action:${reset}"
    echo ""
    echo -e " ${ylw}Docker Services${reset}"
    echo "  1) Suricata (LAN)    — start/stop/restart/logs"
    echo "  2) Suricata (VPN)    — start/stop/restart/logs"
    echo "  3) Pi-hole (k3s)     — status/restart/logs"
    echo "  4) All Docker        — Suricata up/down/restart/ps"
    echo ""
    echo -e "${ylw}Systemd Services${reset}"
    echo "  5) aisoc-console     — start/stop/restart/logs"
    echo "  6) aisoc-agent       — start/stop/restart/logs"
    echo "  7) aisoc-host-events — start/stop/restart/logs"
    echo "  8) aisoc-process-helper — start/stop/restart/logs"
    echo "  9) aisoc-vpn-helper  — start/stop/restart/logs"
    echo ""
    echo -e "${ylw}Timers${reset}"
    echo "  10) aisoc-digest    — status/run now/disable"
    echo "  11) aisoc-rules     — status/run now/disable"
    echo "  12) aisoc-watchdog  — status/run now/disable"
    echo ""
    echo -e "${ylw}Other${reset}"
    echo "  13) Deploy           — check → build → deploy → restart"
    echo "  14) Agent CLI        — status/block/unblock/test-llm"
    echo ""
    echo "  s) Refresh status"
    echo "  q) Quit"
    echo ""
    read -r -e -p "  > " choice
    echo ""
    case "$choice" in
        1)  docker_service "suricata" ;;
        2)  docker_service "suricata-vpn" ;;
        3)  pihole_service ;;
        4)  docker_all ;;
        5)  systemd_service "aisoc-console" ;;
        6)  systemd_service "aisoc-agent" ;;
        7)  systemd_service "aisoc-host-events" ;;
        8)  systemd_service "aisoc-process-helper" ;;
        9)  systemd_service "aisoc-vpn-helper" ;;
        10) systemd_timer "aisoc-digest" ;;
        11) systemd_timer "aisoc-rules" ;;
        12) systemd_timer "aisoc-watchdog" ;;
        13) deploy ;;
        14) agent_cli ;;
        s|S) menu ;;
        q|Q) exit 0 ;;
        *)  echo -e "  ${red}Unknown option${reset}"; sleep 1; menu ;;
    esac
}

docker_service() {
    local name="$1"
    echo -e "${bold}Manage: ${blu}${name}${reset}${bold}${reset}"
    read -r -e -p "  [s]tart [S]top [r]estart [l]ogs [b]ack ? " action
    echo ""
    case "$action" in
        s|S) docker compose -f "$COMPOSE_FILE" up -d "$name" ;;
        r|R) docker compose -f "$COMPOSE_FILE" up -d "$name" ;;
        l|L) docker compose -f "$COMPOSE_FILE" logs -f --tail=50 "$name" ;;
        b|B) docker compose -f "$COMPOSE_FILE" logs --tail=100 "$name" | tee "/tmp/${name}-logs.txt"; echo "Saved to /tmp/${name}-logs.txt" ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

pihole_service() {
    echo -e "${bold}Manage: ${blu}aisoc-pihole${reset}${bold}${reset}"
    read -r -e -p "  [s]tatus [r]estart [l]ogs [b]ack ? " action
    echo ""
    case "$action" in
        s|S) k3s kubectl --kubeconfig "$KUBECONFIG_FILE" get deployment,pod -n aisoc ;;
        r|R)
            k3s kubectl --kubeconfig "$KUBECONFIG_FILE" delete pod -n aisoc \
                -l app.kubernetes.io/name=aisoc-pihole --wait=true --timeout=60s
            k3s kubectl --kubeconfig "$KUBECONFIG_FILE" rollout status \
                deployment/aisoc-pihole -n aisoc --timeout=90s
            ;;
        l|L) k3s kubectl --kubeconfig "$KUBECONFIG_FILE" logs -n aisoc \
                deployment/aisoc-pihole -f --tail=50 ;;
        b|B) ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

docker_all() {
    echo -e "${bold}All Docker Services${reset}"
    read -r -e -p "  [u]p [d]own [r]estart [p]s ? " action
    echo ""
    case "$action" in
        u|U) docker compose -f "$COMPOSE_FILE" up -d ;;
        d|D) docker compose -f "$COMPOSE_FILE" down ;;
        r|R) docker compose -f "$COMPOSE_FILE" up -d ;;
        p|P) docker compose -f "$COMPOSE_FILE" ps ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

systemd_service() {
    local name="${1}.service"
    echo -e "${bold}Manage: ${blu}${name}${reset}${bold}${reset}"
    read -r -e -p "  [s]tart [S]top [r]estart [l]ogs [c]at unit [b]ack ? " action
    echo ""
    case "$action" in
        s|S) sudo systemctl start "$name" ;;
        r|R) sudo systemctl restart "$name" ;;
        l|L) sudo journalctl -u "${name%.service}" -f --no-pager ;;
        c|C) systemctl cat "$name" ;;
        b|B) sudo journalctl -u "${name%.service}" --no-pager | tee "/tmp/${name}-logs.txt"; echo "Saved to /tmp/${name}-logs.txt" ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

systemd_timer() {
    local name="$1"
    echo -e "${bold}Manage: ${blu}${name}${reset}${bold}${reset}"
    read -r -e -p "  [s]tatus [r]un now [d]isable [e]nable [l]ogs [c]at ? " action
    echo ""
    case "$action" in
        s|S) systemctl list-timers "${name}.timer" --all ;;
        r|R) sudo systemctl start "${name}.service" ;;
        d|D) sudo systemctl disable "${name}.timer" ;;
        e|E) sudo systemctl enable "${name}.timer" ;;
        l|L) sudo journalctl -u "${name}.service" -f --no-pager ;;
        c|C) systemctl cat "${name}.timer"; systemctl cat "${name}.service" ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

deploy() {
    echo -e "${bold}Deploy Pipeline${reset}"
    echo -e "  ${ylw}Will run:${reset}"
    echo "    pnpm -C console check"
    echo "    pnpm -C console build"
    echo "    sudo scripts/deploy.sh"
    echo "    sudo systemctl restart aisoc-agent.service aisoc-console.service"
    echo ""
    read -r -p "  Deploy? [y/N] " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        pnpm -C console check && \
        pnpm -C console build && \
        sudo "$ROOT/scripts/deploy.sh" && \
        sudo systemctl restart aisoc-agent.service aisoc-console.service
        echo ""
        echo -e "  ${grn}Deploy complete.${reset}"
    else
        echo -e "  ${ylw}Cancelled.${reset}"
    fi
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

agent_cli() {
    echo -e "${bold}aisoc-agent CLI${reset}"
    echo "  Commands run as: sudo python3 agent/aisoc.py <cmd>"
    echo ""
    read -r -e -p "  [s]tatus [b]lock [u]nblock [t]est-llm [c]ustom ? " action
    echo ""
    case "$action" in
        s|S) sudo python3 "$ROOT/agent/aisoc.py" status ;;
        b|B)
            read -r -p "  IP: " ip
            read -r -p "  Minutes: " mins
            sudo python3 "$ROOT/agent/aisoc.py" block "$ip" "$mins"
            ;;
        u|U)
            read -r -p "  IP: " ip
            sudo python3 "$ROOT/agent/aisoc.py" unblock "$ip"
            ;;
        t|T) sudo python3 "$ROOT/agent/aisoc.py" test-llm ;;
        c|C)
            read -r -e -p "  Command: " cmd
            sudo python3 "$ROOT/agent/aisoc.py" $cmd
            ;;
        *)   echo -e "  ${red}Unknown action${reset}"; sleep 1 ;;
    esac
    echo ""
    read -r -p "  Press Enter to continue..."
    menu
}

menu
