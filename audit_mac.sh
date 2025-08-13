#!/bin/bash

OUTPUT_FILE="mac_system_info_$(date +%Y%m%d%H%M%S).log"

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

run_and_log "macOS Version" "sw_vers"
run_and_log "Kernel" "uname -r"
run_and_log "Hostname" "hostname -f"
run_and_log "Uptime" "uptime"
run_and_log "Architecture" "uname -m"

echo -e "\e[33m"
log_and_echo "Section 2 - Hardware Information"
echo -e "\e[0m"

run_and_log "CPU Info" "sysctl -a | grep machdep.cpu"
run_and_log "Memory Info" "vm_stat"
run_and_log "Disk Information" "df -h; diskutil list"
run_and_log "Network Interfaces" "ifconfig"

echo -e "\e[33m"
log_and_echo "Section 3 - User & Account Information"
echo -e "\e[0m"

run_and_log "Users" "dscl . list /Users"
run_and_log "Password Policies" "pwpolicy -getaccountpolicies"
run_and_log "Privileged Accounts" "dscl . -read /Groups/admin"
run_and_log "Currently Logged-in Users" "who"

echo -e "\e[33m"
log_and_echo "Section 4 - Security Configurations"
echo -e "\e[0m"

run_and_log "Firewall Rules" "sudo pfctl -sr; sudo pfctl -ss"
run_and_log "System Integrity Protection" "csrutil status"
run_and_log "Listening Ports" "netstat -an | grep LISTEN"
run_and_log "SSH Configuration" "cat /etc/sshd_config"

echo -e "\e[33m"
log_and_echo "Section 5 - Installed Software"
echo -e "\e[0m"
run_and_log "Homebrew Packages" "brew list"
run_and_log "System Applications" "ls /Applications"

echo -e "\e[33m"
log_and_echo "Section 6 - Process & Service Information"
echo -e "\e[0m"

run_and_log "Running Processes" "ps aux"
run_and_log "Launch Agents" "ls /Library/LaunchAgents /Users/$USER/Library/LaunchAgents"
run_and_log "Active Services" "sudo launchctl list"

echo -e "\e[33m"
log_and_echo "Section 7 - Network Information"
echo -e "\e[0m"

run_and_log "Routing Table" "netstat -rn"
run_and_log "DNS Configuration" "cat /etc/resolv.conf"
run_and_log "ARP Table" "arp -a"

echo -e "\e[33m"
log_and_echo "Section 8 - Logging & Monitoring"
echo -e "\e[0m"

run_and_log "Log Rotation" "cat /etc/newsyslog.conf"
run_and_log "System Logs" "log show --predicate 'eventMessage contains \"install\"' --last 30d"

echo -e "\e[33m"
log_and_echo "Section 9 - File System Information"
echo -e "\e[0m"

run_and_log "SUID/SGID Files" "find / -perm /6000 -type f 2>/dev/null"
run_and_log "World-Writable Files" "find / -xdev -type d -perm -0002 2>/dev/null"

echo -e "\e[33m"
log_and_echo "Section 10 - Critical Configuration Files"
echo -e "\e[0m"
for file in /etc/passwd /etc/hosts /etc/sudoers; do
    run_and_log "$file permissions" "ls -l $file"
done

echo -e "\e[33m"
log_and_echo "Section 11 - Backup and Recovery"
echo -e "\e[0m"

run_and_log "Backup Cron Jobs" "cat /etc/crontab; ls /etc/cron.*"

echo -e "\e[33m"
log_and_echo "Section 12 - Vulnerability Assessment"
echo -e "\e[0m"
run_and_log "Kernel version for CVE checks" "uname -a"

echo -e "\e[32m"
echo -e "\n\nInformation collection complete. Output saved to $OUTPUT_FILE"
