#!/bin/bash

OUTPUT_FILE="linux_system_info_$(date +%Y%m%d%H%M%S).log"

echo -e "\e[32m"
cat << "EOF"
********************************************************************
*                                                                  *
*    ██╗     ██╗███╗   ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗    *
*    ██║     ██║████╗  ██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝    *
*    ██║     ██║██╔██╗ ██║███████║██║   ██║██║  ██║██║   ██║       *
*    ██║     ██║██║╚██╗██║██╔══██║██║   ██║██║  ██║██║   ██║       *
*    ███████╗██║██║ ╚████║██║  ██║╚██████╔╝██████╔╝██║   ██║       *
*    ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝       *
*                                                                  *
********************************************************************
EOF
echo -e "\e[0m"

log_and_echo() {
    echo -e "\n===== $1 =====" | tee -a "$OUTPUT_FILE"
}

run_and_log() {

    echo -e "\n--- $1 ---" >> "$OUTPUT_FILE"
    eval "$2" >> "$OUTPUT_FILE" 2>&1

}

echo -e "\e[33m"
log_and_echo "Section 1 - System Information"
echo -e "\e[0m"

run_and_log "OS Distribution" "cat /etc/*-release | grep PRETTY_NAME | cut -d '\"' -f2"
run_and_log "Kernel" "uname -r"
run_and_log "Hostname" "hostname -f"
run_and_log "Uptime" "uptime -p"
run_and_log "Architecture" "uname -m"

echo -e "\e[33m"
log_and_echo "Section 2 - Hardware Information"
echo -e "\e[0m"

run_and_log "CPU Info" "lscpu"
run_and_log "Memory Info" "free -h"
run_and_log "Disk Information" "df -h; lsblk"
run_and_log "Network Interfaces" "ip addr show"

echo -e "\e[33m"
log_and_echo "Section 3 - User & Account Information"
echo -e "\e[0m"

run_and_log "Users" "cat /etc/passwd | awk -F: '{print \$1}'"
run_and_log "Password Policies" "chage -l $(whoami)"
run_and_log "Privileged Accounts" "getent group sudo wheel"
run_and_log "Currently Logged-in Users" "w"

echo -e "\e[33m"
log_and_echo "Section 4 - Security Configurations"
echo -e "\e[0m"

run_and_log "Firewall Rules" "sudo iptables -L -n; sudo firewall-cmd --list-all"
run_and_log "SELinux Status" "sestatus || echo 'SELinux not installed'"
run_and_log "Listening Ports" "ss -tuln"
run_and_log "SSH Configuration" "grep -Ev '^#|^$' /etc/ssh/sshd_config"

echo -e "\e[33m"
log_and_echo "Section 5 - Installed Software"
echo -e "\e[0m"
run_and_log "Packages" "dpkg -l || rpm -qa"

echo -e "\e[33m"
log_and_echo "Section 6 - Process & Service Information"
echo -e "\e[0m"

run_and_log "Running Processes" "ps aux"
run_and_log "Cron Jobs" "ls -l /etc/cron.*; crontab -l; systemctl list-timers"
run_and_log "Active Services" "systemctl list-units --type=service --state=running"

echo -e "\e[33m"
log_and_echo "Section 7 - Network Information"
echo -e "\e[0m"

run_and_log "Routing Table" "ip route"
run_and_log "DNS Configuration" "cat /etc/resolv.conf"
run_and_log "ARP Table" "ip neigh"

echo -e "\e[33m"
log_and_echo "Section 8 - Logging & Monitoring"
echo -e "\e[0m"

run_and_log "Log Rotation" "cat /etc/logrotate.conf; ls /etc/logrotate.d/"

echo -e "\e[33m"
log_and_echo "Section 9 - File System Information"
echo -e "\e[0m"

run_and_log "SUID/SGID Files" "find / -perm /6000 -type f 2>/dev/null"
run_and_log "World-Writable Files" "find / -xdev -type d -perm -0002 2>/dev/null"

echo -e "\e[33m"
log_and_echo "Section 10 - Critical Configuration Files"
echo -e "\e[0m"
for file in /etc/passwd /etc/shadow /etc/hosts /etc/fstab /etc/sudoers; do
    run_and_log "$file permissions" "ls -l $file"
done

echo -e "\e[33m"
log_and_echo "Section 11 - Backup and Recovery"
echo -e "\e[0m"

run_and_log "Cron backups" "grep backup /etc/crontab; ls -l /etc/cron.* | grep backup"

echo -e "\e[33m"
log_and_echo "Section 12 - Vulnerability Assessment"
echo -e "\e[0m"
run_and_log "Kernel version for CVE checks" "uname -a"

echo -e "\e[32m"
echo -e "\n\nInformation collection complete. Output saved to $OUTPUT_FILE"
