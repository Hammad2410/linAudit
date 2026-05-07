#!/usr/bin/env bash

set -o pipefail

REPORT_DIR="/var/tmp/kvm-security-audit"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$REPORT_DIR/kvm-audit-$TIMESTAMP.txt"

mkdir -p "$REPORT_DIR"

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

section() {
    log "\n============================================================"
    log "$1"
    log "============================================================"
}

run_cmd() {
    local title="$1"
    local cmd="$2"

    log "\n--- $title ---"
    log "\$ $cmd"

    bash -c "$cmd" >> "$REPORT_FILE" 2>&1

    if [ $? -ne 0 ]; then
        log "[!] Command failed or returned non-zero."
    fi
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Run as root: sudo bash $0"
        exit 1
    fi
}

detect_pkg_manager() {
    if command -v apt >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

system_inventory() {
    section "System and KVM Inventory"

    run_cmd "Hostname and OS" "hostnamectl 2>/dev/null || hostname; cat /etc/os-release 2>/dev/null || true"
    run_cmd "Kernel version" "uname -a"
    run_cmd "CPU virtualization support" "egrep -c '(vmx|svm)' /proc/cpuinfo; lscpu | grep -Ei 'virtualization|hypervisor|model name' || true"
    run_cmd "KVM kernel modules" "lsmod | grep -E '^kvm|^vhost|^vfio' || true"

    if command -v kvm-ok >/dev/null 2>&1; then
        run_cmd "kvm-ok" "kvm-ok || true"
    fi
}

kvm_versions() {
    section "KVM / QEMU / libvirt Versions"

    run_cmd "QEMU version" "qemu-system-x86_64 --version 2>/dev/null || qemu-kvm --version 2>/dev/null || true"
    run_cmd "libvirtd version" "libvirtd --version 2>/dev/null || virtqemud --version 2>/dev/null || true"
    run_cmd "virsh version" "virsh --version=long 2>/dev/null || virsh --version 2>/dev/null || true"

    run_cmd "Installed KVM/QEMU/libvirt packages" \
"if command -v dpkg >/dev/null 2>&1; then
    dpkg -l | grep -Ei 'qemu|kvm|libvirt|virt-manager|virtinst|ovmf|edk2'
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa | grep -Ei 'qemu|kvm|libvirt|virt-manager|virt-install|ovmf|edk2'
fi"
}

patch_status() {
    section "Security Update / Patch Status"

    PM="$(detect_pkg_manager)"

    case "$PM" in
        apt)
            run_cmd "APT security/update check" "apt-get update -qq && apt list --upgradable 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|linux-image|linux-modules|ovmf|edk2|virt' || true"
            run_cmd "Reboot required check" "test -f /var/run/reboot-required && cat /var/run/reboot-required || echo 'No reboot-required file found'"
            ;;
        dnf)
            run_cmd "DNF security updates for KVM stack" "dnf updateinfo list security --available 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|kernel|ovmf|edk2|virt' || true"
            run_cmd "DNF available updates for KVM stack" "dnf check-update 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|kernel|ovmf|edk2|virt' || true"
            run_cmd "Needs restarting" "needs-restarting -r 2>/dev/null || true"
            ;;
        yum)
            run_cmd "YUM security updates for KVM stack" "yum updateinfo list security available 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|kernel|ovmf|edk2|virt' || true"
            run_cmd "YUM available updates for KVM stack" "yum check-update 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|kernel|ovmf|edk2|virt' || true"
            run_cmd "Needs restarting" "needs-restarting -r 2>/dev/null || true"
            ;;
        zypper)
            run_cmd "Zypper security patches" "zypper list-patches --category security 2>/dev/null | grep -Ei 'qemu|kvm|libvirt|kernel|ovmf|edk2|virt' || true"
            ;;
        *)
            log "[!] Unknown package manager. Check security updates manually."
            ;;
    esac
}

libvirt_status() {
    section "libvirt Services and VM Inventory"

    run_cmd "libvirt-related services" "systemctl list-units --type=service --all | grep -Ei 'libvirt|virtqemu|virtlog|virtlock|qemu' || true"
    run_cmd "Running VMs" "virsh list --all 2>/dev/null || true"
    run_cmd "libvirt networks" "virsh net-list --all 2>/dev/null || true"
    run_cmd "libvirt storage pools" "virsh pool-list --all 2>/dev/null || true"
    run_cmd "VM XML security-sensitive items" \
"for vm in \$(virsh list --all --name 2>/dev/null | sed '/^$/d'); do
    echo '### VM:' \$vm
    virsh dumpxml \"\$vm\" 2>/dev/null | grep -Ei '<graphics|<interface|<filesystem|<hostdev|<serial|<console|<channel|<redirdev|<rng|<cpu|<memoryBacking|<loader|<nvram|<seclabel'
done"
}

network_services() {
    section "Local Listening Ports and Network Exposure"

    if command -v ss >/dev/null 2>&1; then
        run_cmd "Listening TCP/UDP ports" "ss -tulpen"
    else
        run_cmd "Listening TCP/UDP ports" "netstat -tulpen 2>/dev/null || true"
    fi

    run_cmd "Bridge interfaces" "ip -br link show type bridge 2>/dev/null || brctl show 2>/dev/null || true"
    run_cmd "IP addresses" "ip -br address"
    run_cmd "Routes" "ip route"
}

firewall_status() {
    section "Firewall Status"

    run_cmd "nftables rules" "nft list ruleset 2>/dev/null || true"
    run_cmd "iptables rules" "iptables -S 2>/dev/null || true"
    run_cmd "firewalld status" "firewall-cmd --state 2>/dev/null && firewall-cmd --list-all 2>/dev/null || true"
    run_cmd "ufw status" "ufw status verbose 2>/dev/null || true"
}

ssh_hardening() {
    section "SSH Hardening"

    if [ -f /etc/ssh/sshd_config ]; then
        run_cmd "Effective sshd config" "sshd -T 2>/dev/null | grep -Ei 'permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|allowusers|allowgroups|clientalive'"
    else
        log "[!] /etc/ssh/sshd_config not found."
    fi

    log "\nRecommended SSH baseline:"
    log "PermitRootLogin no"
    log "PasswordAuthentication no, if key-based access is ready"
    log "PermitEmptyPasswords no"
    log "X11Forwarding no"
    log "MaxAuthTries 3"
}

permissions_accounts() {
    section "Permissions and Local Account Checks"

    run_cmd "Users with UID 0" "awk -F: '($3 == 0) {print}' /etc/passwd"
    run_cmd "Users with shell access" "awk -F: '($7 ~ /(bash|sh|zsh|ksh)$/) {print \$1\":\"\$3\":\"\$6\":\"\$7}' /etc/passwd"
    run_cmd "Empty password accounts" "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null || true"
    run_cmd "SUID files" "find / -xdev -perm -4000 -type f -ls 2>/dev/null || true"
    run_cmd "World-writable directories without sticky bit" "find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null || true"
}

logs_check() {
    section "Recent Auth and KVM Logs"

    run_cmd "Recent failed logins" "grep -Ei 'failed password|authentication failure|invalid user' /var/log/auth.log /var/log/secure 2>/dev/null | tail -100 || true"
    run_cmd "Recent successful SSH logins" "grep -Ei 'accepted password|accepted publickey|session opened' /var/log/auth.log /var/log/secure 2>/dev/null | tail -100 || true"
    run_cmd "Recent libvirt/qemu errors" "journalctl -u libvirtd -u virtqemud -u virtlogd -u virtlockd --since '7 days ago' --no-pager 2>/dev/null | tail -200 || true"
}

summary() {
    section "What to Review First"

    log "High-priority items:"
    log "- Any pending kernel/qemu/libvirt security update"
    log "- Host reboot required after kernel/qemu/libvirt update"
    log "- libvirt TCP sockets exposed externally"
    log "- VNC/SPICE graphics listening on 0.0.0.0"
    log "- SSH root login or password login enabled"
    log "- Weak firewall or unexpected listening services"
    log "- VMs using host filesystem passthrough unnecessarily"
    log "- PCI/USB hostdev passthrough without isolation review"
    log "- Unknown SUID binaries or world-writable directories"

    log "\nReport saved to:"
    log "$REPORT_FILE"
}

main() {
    require_root

    log "KVM/libvirt Local Security Audit"
    log "Started: $(date)"
    log "Host: $(hostname -f 2>/dev/null || hostname)"

    system_inventory
    kvm_versions
    patch_status
    libvirt_status
    network_services
    firewall_status
    ssh_hardening
    permissions_accounts
    logs_check
    summary

    log "\nCompleted: $(date)"
}

main
