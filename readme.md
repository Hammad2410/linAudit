```
*****************************************************************
*                                                               *
*    ██╗     ██╗███╗   ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗ *
*    ██║     ██║████╗  ██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝ *
*    ██║     ██║██╔██╗ ██║███████║██║   ██║██║  ██║██║   ██║    *
*    ██║     ██║██║╚██╗██║██╔══██║██║   ██║██║  ██║██║   ██║    *
*    ███████╗██║██║ ╚████║██║  ██║╚██████╔╝██████╔╝██║   ██║    *
*    ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    *
*                                                               *
*****************************************************************
```

# AI-Analysis

The Project will cover up LLM-utilization, so that System outputs should be converted into AI-based Reports

# LinAudit

LinAudit is a comprehensive auditing tool designed to systematically gather detailed information from Linux operating systems, aiding in security reviews, compliance checks, and system audits.

---

## Information Collected

### System Information
- OS distribution, kernel version, and architecture
- Hostname and Fully Qualified Domain Name (FQDN)
- System uptime and reboot history

### Hardware Information
- CPU details (model, cores, usage)
- RAM details (total, used, available)
- Storage details (disk partitions, usage, filesystem types)
- Swap space details
- Network interfaces (IP addresses, MAC addresses, subnet masks)
- Device drivers and firmware versions

### User & Account Information
- List of local and system users
- Password policies (expiration, complexity)
- User group memberships
- Privileged accounts (root, sudo users)
- Last login details (time, IP address, terminal used)
- Currently logged-in users

### Security Configurations
- Firewall status and rules (iptables/firewalld/ufw)
- SELinux/AppArmor status
- Open ports and listening services
- SSH configurations (authentication methods, permitted users, encryption algorithms)
- PAM (Pluggable Authentication Modules) configurations

### Installed Software
- Installed packages with versions
- Configured software repositories and updates
- Antivirus software status
- Installed compilers/interpreters (gcc, perl, python, ruby)

### Process & Service Information
- Running processes
- Scheduled cron jobs and their permissions
- Startup scripts and active services (systemd, init scripts)

### Network Information
- Routing tables and network gateways
- DNS configurations
- ARP tables and neighbor discovery details
- Proxy settings

### Logging & Monitoring
- System log files and locations
- Log rotation policies
- Centralized logging (Syslog, rsyslog)
- Installed monitoring tools (Nagios, Zabbix, Prometheus)

### File System Information
- Permissions and ownership of critical files/directories
- SUID/SGID executables
- World-writable files/directories
- File integrity check tools (AIDE, Tripwire)

### Configuration Information
- Critical configuration files permissions (`passwd`, `shadow`, `hosts`, `fstab`, `sudoers`)
- Environment variables
- IDS/IPS configurations (Fail2ban, OSSEC)
- Containers/virtualization status (Docker, Kubernetes, LXC)

### Backup and Recovery
- Backup configurations and schedules
- Availability of disaster recovery plans

### Vulnerability Assessment
- Known vulnerabilities (CVE) for installed software
- Kernel vulnerabilities and patches applied
- Compliance with security baseline (e.g., CIS benchmarks)

---

## Purpose
LinAudit ensures structured, comprehensive, and efficient system auditing, supporting administrators, auditors, and security professionals in maintaining secure and compliant Linux environments.

