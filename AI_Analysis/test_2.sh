#!/bin/bash

# Set threshold for JSON data size (in bytes) for LLM ingestion.
LLM_INPUT_LIMIT=4000

# Main log file for detailed output.
OUTPUT_FILE="linux_system_info_$(date +%Y%m%d%H%M%S).log"

# Global arrays to hold the current section’s keys and values.
declare -a current_keys
declare -a current_values
current_section=""

# Function to log and echo section headers.
log_and_echo() {
    echo -e "\n===== $1 =====" | tee -a "$OUTPUT_FILE"
}

# Function to run a command, log its output, and collect the result.
run_and_log_and_collect() {
    local key="$1"
    local cmd="$2"
    echo -e "\n--- $key ---" >> "$OUTPUT_FILE"
    local output
    output=$(eval "$cmd" 2>&1)
    echo "$output" >> "$OUTPUT_FILE"
    # Save the output for JSON analytics.
    current_keys+=("$key")
    current_values+=("$output")
}

# Function to escape special characters for valid JSON.
escape_json() {
    # Escapes backslashes, double quotes, and newlines.
    echo -n "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n'
}

# Function to sanitize a section name so it can be used as a filename.
sanitize() {
    echo "$1" | tr ' ' '_' | tr -cd '[:alnum:]_-'
}

# Function to write out the JSON data for the current section.
# If the JSON string exceeds the threshold, it splits the data into parts.
write_json_parts() {
    local section_name="$1"
    local threshold="$2"
    local sanitized_name
    sanitized_name=$(sanitize "$section_name")
    
    # Build the complete JSON string for the section.
    local json_header="{\n  \"Section\": \"$(escape_json "$section_name")\",\n  \"Data\": {\n"
    local json_footer="\n  }\n}"
    local json_body=""
    local first_entry=true
    
    for i in "${!current_keys[@]}"; do
        local key=$(escape_json "${current_keys[$i]}")
        local value=$(escape_json "${current_values[$i]}")
        local entry
        if $first_entry; then
            entry="    \"${key}\": \"${value}\""
            first_entry=false
        else
            entry=",\n    \"${key}\": \"${value}\""
        fi
        json_body="${json_body}${entry}"
    done
    
    local full_json="${json_header}${json_body}${json_footer}"
    local full_length
    full_length=$(echo -n "$full_json" | wc -c)
    
    if [ "$full_length" -le "$threshold" ]; then
        # If the full JSON is below the threshold, write it in one file.
        echo -e "$full_json" > "${sanitized_name}.json"
        echo "Saved ${sanitized_name}.json (size: ${full_length} bytes)"
    else
        # Otherwise, split the data into parts.
        local part_index=0
        local part_letter=a
        local part_header="{\n  \"Section\": \"$(escape_json "$section_name")\",\n  \"Part\": \"${part_letter}\",\n  \"Data\": {\n"
        local part_footer="\n  }\n}"
        local part_body=""
        local current_part_length
        current_part_length=$(echo -n "${part_header}${part_footer}" | wc -c)
        first_entry=true
        for i in "${!current_keys[@]}"; do
            local key=$(escape_json "${current_keys[$i]}")
            local value=$(escape_json "${current_values[$i]}")
            local entry
            if $first_entry; then
                entry="    \"${key}\": \"${value}\""
            else
                entry=",\n    \"${key}\": \"${value}\""
            fi
            local entry_length
            entry_length=$(echo -n "$entry" | wc -c)
            # If adding this entry would exceed the threshold and we already have some entries...
            if [ $(( current_part_length + entry_length )) -gt "$threshold" ] && [ -n "$part_body" ]; then
                local part_json="${part_header}${part_body}${part_footer}"
                local filename="${sanitized_name}_${part_letter}.json"
                echo -e "$part_json" > "$filename"
                echo "Saved $filename"
                # Prepare for the next part.
                part_index=$(( part_index + 1 ))
                part_letter=$(printf "\x$(printf %x $((97 + part_index)) )")
                part_header="{\n  \"Section\": \"$(escape_json "$section_name")\",\n  \"Part\": \"${part_letter}\",\n  \"Data\": {\n"
                part_body=""
                first_entry=true
                current_part_length=$(echo -n "${part_header}${part_footer}" | wc -c)
            fi
            # Append the current entry.
            if $first_entry; then
                part_body="${entry}"
                first_entry=false
            else
                part_body="${part_body}${entry}"
            fi
            current_part_length=$(echo -n "${part_header}${part_body}${part_footer}" | wc -c)
        done
        # Write the final part.
        if [ -n "$part_body" ]; then
            local filename="${sanitized_name}_${part_letter}.json"
            local part_json="${part_header}${part_body}${part_footer}"
            echo -e "$part_json" > "$filename"
            echo "Saved $filename"
        fi
    fi
}

#######################################
# Section 1 - System Information
#######################################
current_section="Section 1 - System Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "OS Distribution" "cat /etc/*-release | grep PRETTY_NAME | cut -d '\"' -f2"
run_and_log_and_collect "Kernel" "uname -r"
run_and_log_and_collect "Hostname" "hostname -f"
run_and_log_and_collect "Uptime" "uptime -p"
run_and_log_and_collect "Architecture" "uname -m"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 2 - Hardware Information
#######################################
current_section="Section 2 - Hardware Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "CPU Info" "lscpu"
run_and_log_and_collect "Memory Info" "free -h"
run_and_log_and_collect "Disk Information" "df -h; lsblk"
run_and_log_and_collect "Network Interfaces" "ip addr show"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 3 - User & Account Information
#######################################
current_section="Section 3 - User & Account Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Users" "cut -d: -f1 /etc/passwd"
run_and_log_and_collect "Password Policies" "chage -l \$(whoami)"
run_and_log_and_collect "Privileged Accounts" "getent group sudo wheel"
run_and_log_and_collect "Currently Logged-in Users" "w"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 4 - Security Configurations
#######################################
current_section="Section 4 - Security Configurations"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Firewall Rules" "sudo iptables -L -n; sudo firewall-cmd --list-all"
run_and_log_and_collect "SELinux Status" "sestatus || echo 'SELinux not installed'"
run_and_log_and_collect "Listening Ports" "ss -tuln"
run_and_log_and_collect "SSH Configuration" "grep -Ev '^#|^$' /etc/ssh/sshd_config"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 5 - Installed Software
#######################################
current_section="Section 5 - Installed Software"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Packages" "dpkg -l || rpm -qa"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 6 - Process & Service Information
#######################################
current_section="Section 6 - Process & Service Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Running Processes" "ps aux"
run_and_log_and_collect "Cron Jobs" "ls -l /etc/cron.*; crontab -l; systemctl list-timers"
run_and_log_and_collect "Active Services" "systemctl list-units --type=service --state=running"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 7 - Network Information
#######################################
current_section="Section 7 - Network Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Routing Table" "ip route"
run_and_log_and_collect "DNS Configuration" "cat /etc/resolv.conf"
run_and_log_and_collect "ARP Table" "ip neigh"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 8 - Logging & Monitoring
#######################################
current_section="Section 8 - Logging & Monitoring"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Log Rotation" "cat /etc/logrotate.conf; ls /etc/logrotate.d/"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 9 - File System Information
#######################################
current_section="Section 9 - File System Information"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "SUID/SGID Files" "find / -perm /6000 -type f 2>/dev/null"
run_and_log_and_collect "World-Writable Files" "find / -xdev -type d -perm -0002 2>/dev/null"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 10 - Critical Configuration Files
#######################################
current_section="Section 10 - Critical Configuration Files"
current_keys=()
current_values=()
log_and_echo "$current_section"
for file in /etc/passwd /etc/shadow /etc/hosts /etc/fstab /etc/sudoers; do
    run_and_log_and_collect "$file permissions" "ls -l $file"
done
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 11 - Backup and Recovery
#######################################
current_section="Section 11 - Backup and Recovery"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Cron backups" "grep backup /etc/crontab; ls -l /etc/cron.* | grep backup"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

#######################################
# Section 12 - Vulnerability Assessment
#######################################
current_section="Section 12 - Vulnerability Assessment"
current_keys=()
current_values=()
log_and_echo "$current_section"
run_and_log_and_collect "Kernel version for CVE checks" "uname -a"
write_json_parts "$current_section" "$LLM_INPUT_LIMIT"

echo -e "\n\nInformation collection complete. Output saved to $OUTPUT_FILE"
