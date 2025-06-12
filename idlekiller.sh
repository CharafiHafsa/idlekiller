#!/usr/bin/env bash

# ========= Configuration =========
CONFIG_DIR="./config"
CONFIG_FILE="$CONFIG_DIR/default.conf"
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/history.log"
# Fallback user log directory if not root
USER_LOG_DIR="$HOME/.local/log/idlekiller"
USER_LOG_FILE="$USER_LOG_DIR/history.log"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
LOCK_FILE="/tmp/idlekiller.lock"

# ========= Color codes for output =========
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
RESET="\033[0m"
BOLD="\033[1m"

# ========= Default values =========
CPU_THRESHOLD=1
IDLE_TIME=1
DRY_RUN=false
SHOW_ONLY=false
HIGHPROCESSES=false
FORK=false
THREADS=false
SUBSHELL=false
VERBOSE=false
FORCE=false
INTERACTIVE=false  
AUTO_KILL=false    

# ========= System user filter =========
SYSTEM_USERS=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" 
              "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd" 
              "messagebus" "syslog" "_apt" "uuidd" "avahi" "dnsmasq" "colord" "speech-dispatcher" 
              "kernoops" "saned" "whoopsie" "avahi-autoipd" "usbmux" "rtkit" "cups-pk-helper" 
              "pulse" "geoclue" "gnome-initial-setup" "gdm" "sshd" "systemd+" "message+")

# ========= Initialize directories =========
# Function to create necessary directories and log file
# Exits with error code if creation fails
# Error codes:
#   101 - Failed to create directories
#   102 - Failed to create log file
init_dirs() {
    # Create config directory (user accessible)
    mkdir -p "$CONFIG_DIR" || {
        echo -e "${RED}Failed to create config directory${RESET}"
        exit 101
    }
    
    # Handle log directory based on privileges
    if [ "$(id -u)" -eq 0 ]; then
        # Running as root - use system log directory
        mkdir -p "$LOG_DIR" || {
            echo -e "${RED}Failed to create log directory${RESET}"
            exit 102
        }
        touch "$LOG_FILE" || {
            echo -e "${RED}Failed to create log file${RESET}"
            exit 103
        }
        # Ensure proper permissions for the log file
        chmod 644 "$LOG_FILE"
    else
        # Not root - use user-accessible directory
        echo -e "${YELLOW}Note: Running without root privileges. Using user log directory: $USER_LOG_DIR${RESET}"
        mkdir -p "$USER_LOG_DIR" || {
            echo -e "${RED}Failed to create user log directory${RESET}"
            exit 104
        }
        LOG_FILE="$USER_LOG_FILE"
        touch "$LOG_FILE" || {
            echo -e "${RED}Failed to create user log file${RESET}"
            exit 105
        }
    fi
}

# ========= Lock management =========
# Function to acquire a lock file to prevent multiple instances
# Checks for existing lock file and verifies if the process is still running
# If stale lock is found (process not running), it removes the lock file
# Exits with error code 104 if another instance is running
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${RED}Another instance is already running (PID $pid)${RESET}"
            exit 104
        else
            echo -e "${YELLOW}Stale lock file found. Removing...${RESET}"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}
# Function to release the lock file
# Should be called when script exits or finishes
release_lock() {
    rm -f "$LOCK_FILE"
}

# ========= Logging =========
# Function to log messages with different severity levels
# Parameters:
#   $1 - LEVEL (ERROR, WARN, INFO, DEBUG)
#   $2 - MSG (message to log)
# Behavior:
#   - Always logs to file
#   - Prints to console if VERBOSE=true or for ERROR/WARN levels
#   - Adds timestamp and user information to each log entry
#   - Applies color coding based on log level
log_msg() {
    local LEVEL=$1
    local MSG=$2
    local TIMESTAMP
    TIMESTAMP=$(date '+%Y-%m-%d-%H-%M-%S')
    
    case "$LEVEL" in
        "ERROR") COLOR="$RED" ;;
        "WARN") COLOR="$YELLOW" ;;
        "INFO") COLOR="$GREEN" ;;
        "DEBUG") COLOR="$BLUE" ;;
        *) COLOR="$RESET" ;;
    esac
    
    [[ "$VERBOSE" == true || "$LEVEL" == "ERROR" || "$LEVEL" == "WARN" ]] && \
        echo -e "${COLOR}${TIMESTAMP} : $USER : $LEVEL : $MSG${RESET}"
    echo -e "${TIMESTAMP} : $USER : $LEVEL : $MSG" >> "$LOG_FILE"
}

# ========= Show Help =========
show_help() {
    echo -e "${GREEN}${BOLD}NAME${RESET}"
    echo -e "    ${0##*/} - Intelligent process killer with safety checks\n"
    
    echo -e "${GREEN}${BOLD}SYNOPSIS${RESET}"
    echo -e "    ${0##*/} [OPTIONS] [PATTERN]\n"
    
    echo -e "${GREEN}${BOLD}DESCRIPTION${RESET}"
    echo -e "    This script helps manage system resources by identifying and optionally terminating:"
    echo -e "    - Long-running idle processes (CPU < threshold)"
    echo -e "    - High CPU usage processes"
    echo -e "    - Processes matching specific patterns"
    echo -e "    Includes multiple safety mechanisms to prevent killing critical system processes.\n"
    
    echo -e "${GREEN}${BOLD}OPTIONS${RESET}"
    echo -e "    ${BOLD}-h${RESET}"
    echo -e "        Display this help message and exit\n"
    
    echo -e "    ${BOLD}-f${RESET}"
    echo -e "        Fork mode - run scans in background (useful for automated tasks)\n"
    
    echo -e "    ${BOLD}-t${RESET}"
    echo -e "        Thread simulation - perform parallel process checking (faster scanning)\n"
    
    echo -e "    ${BOLD}-s${RESET}"
    echo -e "        Run in subshell - creates isolated environment for process scanning\n"
    
    echo -e "    ${BOLD}-d${RESET}"
    echo -e "        Dry run mode - show what would be killed without actually terminating processes\n"
    
    echo -e "    ${BOLD}-x${RESET}"
    echo -e "        Show only - display matching processes without killing them\n"
    
    echo -e "    ${BOLD}-v${RESET}"
    echo -e "        Verbose output - show detailed debugging information\n"
    
    echo -e "    ${BOLD}-F${RESET}"
    echo -e "        Force operation - ignore lock files and run anyway (use with caution)\n"
    
    echo -e "    ${BOLD}-l [path]${RESET}"
    echo -e "        Set custom log directory (default: ./logs/)\n"
    
    echo -e "    ${BOLD}-i [minutes]${RESET}"
    echo -e "        Set idle time threshold - minimum minutes a process must be idle (default: 1)\n"
    
    echo -e "    ${BOLD}-c [percent]${RESET}"
    echo -e "        Set CPU usage threshold - maximum CPU% a process can use (default: 1%)\n"
    
    echo -e "    ${BOLD}-w [file]${RESET}"
    echo -e "        Specify custom whitelist file (format: one PID or username per line)\n"
    
    echo -e "    ${BOLD}-r${RESET}"
    echo -e "        Reset configuration to defaults (requires admin privileges)\n"
    
    echo -e "    ${BOLD}-z${RESET}"
    echo -e "        High CPU mode - scan for processes exceeding CPU threshold instead of idle ones\n"
    
    echo -e "    ${BOLD}-a${RESET}"
    echo -e "        Auto-kill mode - terminate matching processes without confirmation\n"
    
    echo -e "    ${BOLD}-I${RESET}"
    echo -e "        Interactive mode - use fzf to select which processes to kill\n"
    
    echo -e "${GREEN}${BOLD}PROCESS SELECTION${RESET}"
    echo -e "    PATTERN can be:"
    echo -e "    - A process name (e.g. 'chrome')"
    echo -e "    - A regex pattern (e.g. 'python.*script')"
    echo -e "    - Omitted to scan all non-system processes\n"
    
    echo -e "${GREEN}${BOLD}SAFETY FEATURES${RESET}"
    echo -e "    - Automatically excludes:"
    echo -e "      * System processes (PID < 100)"
    echo -e "      * Current terminal session"
    echo -e "      * Critical processes (init, systemd, etc.)"
    echo -e "      * Virtualization processes (WSL, VirtualBox, VMware)"
    echo -e "    - Emergency stop if critical process detected\n"
    
    echo -e "${GREEN}${BOLD}EXAMPLES${RESET}"
    echo -e "    ${BOLD}Basic idle process scan:${RESET}"
    echo -e "    ${0##*/} -i 15 -c 5  # Find processes idle >15min using <5% CPU\n"
    
    echo -e "    ${BOLD}Interactive high CPU process management:${RESET}"
    echo -e "    ${0##*/} -I -c 20    # Select processes using >20% CPU\n"
    
    echo -e "    ${BOLD}Target specific processes:${RESET}"
    echo -e "    ${0##*/} -a -i 30 chrome  # Auto-kill Chrome processes idle >30min\n"
    
    echo -e "    ${BOLD}Safe inspection mode:${RESET}"
    echo -e "    ${0##*/} -x -i 10    # Show what would be killed (no action)\n"
    
    echo -e "    ${BOLD}Custom configuration:${RESET}"
    echo -e "    ${0##*/} -w ~/safe.txt -l /var/log/killer -i 20\n"
    
    echo -e "${GREEN}${BOLD}FILES${RESET}"
    echo -e "    ${CONFIG_DIR}/default.conf    Default configuration"
    echo -e "    ${CONFIG_DIR}/current.conf    Active configuration"
    echo -e "    ${WHITELIST_FILE}             Default whitelist location"
    echo -e "    ${LOG_FILE}                   Default log file\n"
    
    echo -e "${GREEN}${BOLD}EXIT STATUS${RESET}"
    echo -e "    0       Success"
    echo -e "    1-100   Configuration errors"
    echo -e "    101-108 Runtime errors"
    echo -e "    255     Emergency stop (critical process protection)\n"
    
    echo -e "${GREEN}${BOLD}SEE ALSO${RESET}"
    echo -e "    ps(1), top(1), kill(1), fzf(1)\n"
    
    exit 0
}
# ========= Argument Parsing =========
# Function to parse command line arguments and set corresponding flags
# Handles both short options (-h) and options with arguments (-l path)
# Sets global variables based on provided options
# Exits with error codes for invalid inputs or combinations
# Error codes:
#   100 - Invalid option
#   103 - Non-admin trying to reset config
#   105 - Invalid idle time
#   106 - Invalid CPU threshold
#   108 - Conflicting modes (auto-kill and interactive)
parse_arguments() {
    while getopts "hftsdxvFl:i:c:w:rzaI" opt; do
        case "$opt" in
            h) show_help ;;
            f) FORK=true ;;
            t) THREADS=true ;;
            s) SUBSHELL=true ;;
            d) DRY_RUN=true ;;
            x) SHOW_ONLY=true ;;
            v) VERBOSE=true ;;
            F) FORCE=true ;;
            l) LOG_DIR="$OPTARG"; mkdir -p "$LOG_DIR"; LOG_FILE="$LOG_DIR/history.log" ;;
            i) 
                if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                    IDLE_TIME="$OPTARG"
                else
                    echo -e "${RED}Invalid idle time: must be a positive integer${RESET}"
                    exit 105
                fi
                ;;
            c) 
                if [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                    CPU_THRESHOLD="$OPTARG"
                else
                    echo -e "${RED}Invalid CPU threshold: must be a positive integer${RESET}"
                    exit 106
                fi
                ;;
            w) WHITELIST_FILE="$OPTARG" ;;
            r)
                if [[ "$EUID" -ne 0 ]]; then
                    log_msg "ERROR" "Only admin can reset config"
                    exit 103
                fi
                cp "$CONFIG_DIR/default.conf" "$CONFIG_DIR/current.conf"
                log_msg "INFO" "Configuration reset to default"
                exit 0
                ;;
            z) HIGHPROCESSES=true ;;
            a) AUTO_KILL=true ;;
            I) INTERACTIVE=true ;;
            ?) echo -e "${RED}Invalid option. Use -h for help.${RESET}"; exit 100 ;;
        esac
    done
    shift $((OPTIND - 1))
    PATTERN="${1:-ALL}"
    [[ "$PATTERN" == "ALL" ]] && log_msg "INFO" "No pattern provided, scanning ALL processes"
    
    # Validate mode selection
    if [[ "$AUTO_KILL" == true && "$INTERACTIVE" == true ]]; then
        echo -e "${RED}Error: Cannot use both auto-kill (-a) and interactive (-I) modes together${RESET}"
        exit 108
    fi
}

# ========= Load Whitelist =========
# Function to load process whitelist from file
# Processes the whitelist file by:
#   - Removing comment lines (starting with #)
#   - Removing empty lines
#   - Trimming whitespace
# Sets WHITELIST variable with cleaned entries
# Logs warning if whitelist file is not found
load_whitelist() {
    if [[ -f "$WHITELIST_FILE" ]]; then
        # Read whitelist, remove comments and empty lines, and trim whitespace
        WHITELIST=$(grep -v '^#' "$WHITELIST_FILE" | grep -v '^$' | awk '{$1=$1};1')
        log_msg "DEBUG" "Loaded whitelist with $(echo "$WHITELIST" | wc -l) entries"
    else
        WHITELIST=""
        log_msg "WARN" "Whitelist file not found: $WHITELIST_FILE"
    fi
}

# ========= Editor Checker =========
# Function to check if a process is a text editor
# Parameters:
#   $1 - cmd: The process command/name
#   $2 - ppid: The parent process ID
# Returns true (0) if either the process or its parent is a known editor
# Checks against common editor commands:
#   nano, vim, vi, code, gedit, sublime, emacs, pico
is_editor() {
    # Check both the command and parent process
    local cmd="$1"
    local ppid="$2"
    local parent_cmd=""
    
    if [[ -n "$ppid" && "$ppid" -gt 1 ]]; then
        parent_cmd=$(ps -o comm= -p "$ppid")
    fi
    
    [[ "$cmd" =~ nano|vim|vi|code|gedit|sublime|emacs|pico ]] || \
    [[ "$parent_cmd" =~ nano|vim|vi|code|gedit|sublime|emacs|pico ]]
}

# ========= ETime to Minutes =========
# Converts process elapsed time (ETIME) from various formats to total minutes
# Supported input formats:
#   DD-HH:MM:SS (days-hours:minutes:seconds)
#   HH:MM:SS (hours:minutes:seconds)
#   MM:SS (minutes:seconds)
# Parameters:
#   $1 - etime: The elapsed time string to convert
# Returns: Total minutes as integer via echo
# Note: Seconds are ignored in the conversion (rounded down)
etime_to_minutes() {
    local etime="$1"
    local days=0 hours=0 mins=0
    
    # Handle format: DD-HH:MM:SS
    if [[ "$etime" =~ ^([0-9]+)-([0-9]+):([0-9]+):([0-9]+)$ ]]; then
        days=${BASH_REMATCH[1]}
        hours=${BASH_REMATCH[2]}
        mins=${BASH_REMATCH[3]}
    # Handle format: HH:MM:SS
    elif [[ "$etime" =~ ^([0-9]+):([0-9]+):([0-9]+)$ ]]; then
        hours=${BASH_REMATCH[1]}
        mins=${BASH_REMATCH[2]}
    # Handle format: MM:SS
    elif [[ "$etime" =~ ^([0-9]+):([0-9]+)$ ]]; then
        mins=${BASH_REMATCH[1]}
    fi
    
    echo $((days*1440 + hours*60 + mins))
}

# ========= Skip system users =========
# Checks if a user is in the system users list that should be excluded
# Parameters:
#   $1 - user: The username to check
# Returns:
#   0 (true) if user is a system user
#   1 (false) if user is not a system user
# Note: SYSTEM_USERS array should be defined before calling this function
is_system_user() {
    local user="$1"
    for su in "${SYSTEM_USERS[@]}"; do
        [[ "$user" == "$su" ]] && return 0
    done
    return 1
}

# ========= Check if process should be skipped =========
# Determines whether a process should be excluded from processing based on multiple criteria
# Parameters:
#   $1 - pid: Process ID
#   $2 - cmd: Process command/name
#   $3 - user: Process owner
#   $4 - ppid: Parent process ID
# Returns:
#   0 (true) if process should be skipped
#   1 (false) if process should be processed
# Skip conditions (in order of checking):
#   1. System users (from predefined list)
#   2. Whitelisted PIDs or users
#   3. Critical system processes (PID < 100)
#   4. The script itself and its parent process
#   5. Kernel threads (parent PID 2)
#   6. Processes with empty command
#   7. Common system processes (systemd, dbus, etc.)
#   8. Processes in system directories
#   9. Virtualization/WSL processes
#   10. Development environment processes
#   11. Terminal/shell processes (unless matching pattern)
#   12. Processes in current terminal session
#   13. Explicit allowance for sleep processes
#   14. Pattern matching (if specified)
should_skip_process() {
    local pid="$1"
    local cmd="$2"
    local user="$3"
    local ppid="$4"
    
    # Skip system users
    is_system_user "$user" && return 0
    
    # Skip whitelist entries
    if echo "$WHITELIST" | grep -q -w "^$pid$"; then 
        log_msg "DEBUG" "Skipping whitelisted PID: $pid"
        return 0
    fi
    if echo "$WHITELIST" | grep -q -w "^$user$"; then
        log_msg "DEBUG" "Skipping whitelisted user: $user"
        return 0
    fi
    
    # Skip critical system processes (PID < 100)
    [[ "$pid" -lt 100 ]] && return 0
    
    # Skip the script itself and its parent
    [[ "$pid" == $$ || "$pid" == $PPID ]] && return 0
    
    # Skip kernel threads
    [[ "$ppid" -eq 2 ]] && return 0
    
    # Skip processes with no command
    [[ -z "$cmd" ]] && return 0
    
    # Skip systemd and related processes
    [[ "$cmd" =~ systemd|dbus|pipewire|pulseaudio|gnome|gdm|gvfs|ibus|xdg ]] && return 0
    
    # Skip processes in important system directories
    [[ "$cmd" =~ /usr/lib|/lib/systemd|/snap ]] && return 0
    
    # Skip WSL/VirtualBox/VM processes
    [[ "$cmd" =~ init|WSL|wsl|wslinit|wslhost|/init|\[init\]|\[WSL\] ]] && return 0
    [[ "$cmd" =~ (vmware|vbox|qemu|kvm|hyperv) ]] && return 0
    [[ "$cmd" =~ VBox|VirtualBox|vbox ]] && return 0
    
    # Skip VS Code and development processes
    [[ "$cmd" =~ .vscode-server|vscode-remote|code-server|node|npm ]] && return 0
    
    # Skip terminals and shells unless they match our pattern
    if [[ "$cmd" =~ bash|zsh|sh|ksh|tmux|screen|gnome-terminal|konsole ]]; then
        if [[ "$PATTERN" == "ALL" ]]; then
            return 0
        fi
    fi
    
    # Skip processes in current session/terminal tree
    if [[ " ${terminal_procs[@]} " =~ " $pid " ]]; then
        return 0
    fi
    
    # Explicitly allow sleep processes when they match our pattern
    if [[ "$cmd" =~ sleep ]] && [[ "$PATTERN" == "ALL" || "$cmd" =~ $PATTERN ]]; then
        return 1  # DO NOT skip sleep processes
    fi
    
    # Filter by pattern if specified
    if [[ "$PATTERN" != "ALL" ]]; then
        if ! [[ "$cmd" =~ $PATTERN ]]; then
            return 0
        fi
    fi
    
    return 1
}

# ========= Process Killing =========
# Function to safely terminate processes with multiple safeguards
# Parameters:
#   $1 - pid: Process ID to kill
#   $2 - cmd: Process command/name (for logging)
#   $3 - user: Process owner (for logging)
#   $4 - cpu: CPU usage percentage (for display)
#   $5 - etime: Elapsed time (for display)
# Returns:
#   0 - Successfully terminated process
#   1 - Failed to terminate or critical system process
# Behavior:
#   1. First checks emergency stop conditions
#   2. Verifies process still exists
#   3. Blocks attempts to kill critical system processes
#   4. Respects dry-run mode
#   5. Attempts graceful TERM signal first
#   6. Falls back to forceful KILL signal if needed
#   7. Provides visual feedback and detailed logging
kill_processes() {
    local pid="$1" cmd="$2" user="$3" cpu="$4" etime="$5"
    local attempts=0 max_attempts=2
    
    emergency_stop "$pid" "$cmd"
    
    # Check if process still exists
    if ! ps -p "$pid" >/dev/null 2>&1; then
        log_msg "DEBUG" "Process $pid already terminated"
        return 0
    fi
    
    if [[ "$cmd" =~ (init|systemd|kernel|vmtoolsd|dbus) ]]; then
        log_msg "ERROR" "CRITICAL: Attempted to kill system process $cmd (PID $pid)"
        return 1
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log_msg "DRYRUN" "Would kill $cmd (PID $pid)"
        return 0
    fi
    
    while (( attempts < max_attempts )); do
        if kill -TERM "$pid" 2>/dev/null; then
            # Wait for process to actually terminate
            local waited=0
            while ps -p "$pid" >/dev/null 2>&1 && (( waited < 3 )); do
                sleep 0.5
                ((waited++))
            done
            
            if ! ps -p "$pid" >/dev/null 2>&1; then
                log_msg "INFO" "Sent TERM to $cmd (PID $pid)"
                echo -e "${GREEN}Terminated: ${cmd} (PID ${pid}) - ${cpu}% CPU, running ${etime}${RESET}"
                return 0
            fi
        fi
        ((attempts++))
        sleep 0.5
    done
    
    log_msg "WARN" "Failed to send TERM to $cmd (PID $pid), trying KILL"
    if kill -KILL "$pid" 2>/dev/null; then
        log_msg "INFO" "Killed $cmd (PID $pid) with KILL"
        echo -e "${YELLOW}Force killed: ${cmd} (PID ${pid})${RESET}"
        return 0
    else
        log_msg "ERROR" "Failed to kill $cmd (PID $pid)"
        echo -e "${RED}Failed to kill: ${cmd} (PID ${pid})${RESET}"
        return 1
    fi
}

# ========= Interactive Process Selection =========
# Provides an interactive interface for selecting processes to terminate using fzf
# Parameters:
#   $1 - candidates_ref: Reference to array of candidate processes (passed by reference)
# Behavior:
#   1. Displays formatted process list with key details
#   2. Allows multi-selection with preview of process details
#   3. Shows confirmation prompt before killing
#   4. Provides visual feedback on success/failure
#   5. Preserves original terminal colors through ANSI escape codes
# Notes:
#   - Requires fzf to be installed
#   - Processes are displayed in format: PID|COMMAND|USER|CPU%|ETIME|TTY
#   - Uses awk for precise column formatting
interactive_selection() {
    local -n candidates_ref=$1
    local header="PID     COMMAND              USER       CPU%  ETIME    TTY"
    local preview_cmd="echo -e 'Process details:\n--------------'; ps -p {1} -o pid,user,pcpu,pmem,vsz,rss,tty,stat,start_time,cmd --no-headers"
    
    local selected=$(
        (
            printf "%s\n" "${candidates_ref[@]}"
        ) | awk -F'|' '{printf "%-8s %-20s %-10s %-6s %-10s %-12s\n", $1, $2, $3, $4, $5, $6}' | \
        fzf --multi --ansi --header="$header" \
            --prompt="Select process(es) to kill > " \
            --preview="$preview_cmd" \
            --preview-window=right:60%:wrap
    )
    
    [[ -z "$selected" ]] && {
        echo -e "${YELLOW}No processes selected${RESET}"
        return
    }
    
    echo -e "\n${RED}${BOLD}WARNING: The following processes will be terminated:${RESET}"
    echo "$selected"
    
    read -rp "${BOLD}Are you sure you want to kill these processes? [y/N]: ${RESET}" answer
    [[ "$answer" =~ ^[Yy]$ ]] || {
        echo -e "${YELLOW}Aborted${RESET}"
        return
    }
    
    local killed=0
    local failed=0
    
    while read -r line; do
        local pid=$(echo "$line" | awk '{print $1}')
        local cmd=$(echo "$line" | awk '{print $2}')
        local user=$(echo "$line" | awk '{print $3}')
        local cpu=$(echo "$line" | awk '{print $4}')
        local etime=$(echo "$line" | awk '{print $5}')
        
        if kill_processes "$pid" "$cmd" "$user" "$cpu" "$etime"; then
            ((killed++))
        else
            ((failed++))
        fi
    done <<< "$selected"
    
    echo -e "\n${GREEN}Successfully terminated: $killed${RESET}"
    [[ "$failed" -gt 0 ]] && echo -e "${RED}Failed to terminate: $failed${RESET}"
}

# ========= Main Process Scanner =========
# Scans all running processes and identifies candidates for termination based on:
# - Idle time (> IDLE_TIME minutes)
# - CPU usage (< CPU_THRESHOLD %)
# - Various exclusion criteria (system processes, whitelist, etc.)
# Parameters: None (uses global configuration variables)
# Outputs: 
# - Lists candidate processes to stdout
# - Logs detailed scan information
# Behavior:
# 1. Gathers terminal processes to protect current session
# 2. Efficiently scans processes with custom ps format
# 3. Applies multiple filtering criteria
# 4. Handles interactive/auto-kill/show-only modes
# 5. Provides comprehensive logging and statistics
scan_processes() {
    local start_time=$(date +%s)
    log_msg "INFO" "Scanning for inactive processes (Idle > ${IDLE_TIME}min, CPU < ${CPU_THRESHOLD}%)..."
    
    declare -a CANDIDATES=()
    local total_processes=0
    local skipped_processes=0
    
    # More efficient ps format that excludes kernel threads
    local ps_format="pid,tty:30,comm:30,%cpu,etime,user,ppid,args"
    
    # Get current terminal processes to protect
    local current_tty=$(tty 2>/dev/null || echo "notty")
    local terminal_procs=()
    if [[ "$current_tty" != "notty" ]]; then
        terminal_procs=($(ps -t "$current_tty" -o pid= 2>/dev/null || echo ""))
        terminal_procs+=($(ps -o pid= -p $$ 2>/dev/null))  # Current process
        terminal_procs+=($(ps -o pid= --ppid $$ 2>/dev/null)) # Direct children
    fi

    # More efficient process scanning with early filtering
    while read -r pid tty cmd cpu etime user ppid args; do
        cmd="$cmd $args"
        cmd=$(echo "$cmd" | awk '{$1=$1};1')
        ((total_processes++))
        
        [[ "$VERBOSE" == true ]] && log_msg "DEBUG" "Processing PID $pid: cmd='$cmd' user='$user' cpu='$cpu' etime='$etime' tty='$tty'"
        
        # Early skip for system processes
        if [[ "$user" == "root" ]] && [[ "$pid" -lt 1000 ]] && [[ ! "$cmd" =~ sleep ]]; then
            ((skipped_processes++))
            continue
        fi
        
        if should_skip_process "$pid" "$cmd" "$user" "$ppid"; then
            ((skipped_processes++))
            continue
        fi
        
        # Skip processes associated with current terminal
        if [[ " ${terminal_procs[@]} " =~ " $pid " ]]; then
            ((skipped_processes++))
            [[ "$VERBOSE" == true ]] && log_msg "DEBUG" "Skipping terminal process PID $pid"
            continue
        fi
        
        local cpu_val=${cpu//,/.}
        cpu_val=${cpu_val%%.*}
        local idle_minutes=$(etime_to_minutes "$etime")
        
        [[ "$VERBOSE" == true ]] && log_msg "DEBUG" "PID $pid: idle_minutes=$idle_minutes, cpu_val=$cpu_val"
        
        if (( $(echo "$idle_minutes >= $IDLE_TIME && $cpu_val < $CPU_THRESHOLD" | bc -l) )); then
            CANDIDATES+=("$pid|$cmd|$user|$cpu|$etime|$tty")
            [[ "$SHOW_ONLY" == true ]] && echo -e "${YELLOW}Detected: PID=$pid | CMD=$cmd | CPU=$cpu% | USER=$user | ETIME=$etime | TTY=$tty${RESET}"
        fi
    done < <(ps -eo "$ps_format" --no-headers | grep -v -E "(kworker|kthreadd|ksoftirqd|rcu_)" 2>/dev/null) 
    
    log_msg "INFO" "Scanned $total_processes processes, skipped $skipped_processes ($((total_processes - skipped_processes)) considered"
    
    if (( ${#CANDIDATES[@]} > 0 )); then
        if [[ "$INTERACTIVE" == true ]]; then
            PATTERN="ALL"
            interactive_selection CANDIDATES
        else
            echo -e "\n${YELLOW}${BOLD}Candidate processes for killing (${#CANDIDATES[@]} found):${RESET}"
            printf "%-8s %-25s %-15s %-6s %-10s %-12s\n" "PID" "COMMAND" "USER" "CPU%" "ETIME" "TTY"
            printf "%-8s %-25s %-15s %-6s %-10s %-12s\n" "------" "-------------------------" "--------------" "-----" "----------" "------------"
            
            for c in "${CANDIDATES[@]}"; do
                IFS='|' read -r pid cmd user cpu etime tty <<< "$c"
                printf "%-8s %-25s %-15s %-6s %-10s %-12s\n" "$pid" "${cmd:0:24}" "$user" "$cpu" "$etime" "$tty"
            done
            
            if [[ "$SHOW_ONLY" == false ]]; then
                if [[ "$AUTO_KILL" == true ]] || [[ "$FORK" == true ]] || [[ "$THREADS" == true ]]; then
                    # Auto-kill in non-interactive modes
                    local killed=0 failed=0
                    for c in "${CANDIDATES[@]}"; do
                        IFS='|' read -r pid cmd user cpu etime tty <<< "$c"
                        if kill_processes "$pid" "$cmd" "$user" "$cpu" "$etime"; then
                            ((killed++))
                        else
                            ((failed++))
                        fi
                    done
                    echo -e "\n${GREEN}Successfully terminated: $killed${RESET}"
                    [[ "$failed" -gt 0 ]] && echo -e "${RED}Failed to terminate: $failed${RESET}"
                else
                    # Interactive prompt in normal/subshell mode
                    echo -e "\n${CYAN}Thresholds: Idle > ${IDLE_TIME}min, CPU < ${CPU_THRESHOLD}%${RESET}"
                    read -rp "${BOLD}Do you want to kill these processes? [y/N]: ${RESET}" answer
                    if [[ "$answer" =~ ^[Yy]$ ]]; then
                        local killed=0 failed=0
                        for c in "${CANDIDATES[@]}"; do
                            IFS='|' read -r pid cmd user cpu etime tty <<< "$c"
                            if kill_processes "$pid" "$cmd" "$user" "$cpu" "$etime"; then
                                ((killed++))
                            else
                                ((failed++))
                            fi
                        done
                        echo -e "\n${GREEN}Successfully terminated: $killed${RESET}"
                        [[ "$failed" -gt 0 ]] && echo -e "${RED}Failed to terminate: $failed${RESET}"
                    else
                        log_msg "INFO" "User aborted process termination"
                    fi
                fi
            fi
        fi
    else
        echo -e "${GREEN}No candidate idle processes found matching criteria${RESET}"
        [[ "$VERBOSE" == true ]] && log_msg "DEBUG" "Last process scanned: PID=$pid, CMD=$cmd, CPU=$cpu%, ETIME=$etime, TTY=$tty"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_msg "DEBUG" "Process scan completed in ${duration}s"
}

# ========= High CPU Scanner =========
# Identifies and manages processes consuming excessive CPU resources
# Parameters: None (uses global CPU_THRESHOLD variable)
# Requirements: fzf must be installed
# Behavior:
# 1. Scans all processes sorted by CPU usage
# 2. Filters processes above CPU_THRESHOLD
# 3. Provides interactive selection interface
# 4. Handles dry-run mode
# 5. Provides detailed logging
scan_high_cpu() {
    command -v fzf >/dev/null || {
        echo -e "${RED}fzf is required. Install it with:\n  sudo apt install fzf (Debian/Ubuntu)\n  brew install fzf (macOS)${RESET}"
        exit 107
    }

    local start_time=$(date +%s)
    log_msg "INFO" "Scanning high CPU usage processes (> ${CPU_THRESHOLD}%)..."
    
    local ps_cmd="ps -eo pid,pcpu,pmem,user,comm,etime --sort=-pcpu --no-headers"
    local header="PID     CPU%   MEM%  USER       COMMAND             ELAPSED"
    
    local selected=$(
        $ps_cmd | \
        awk -v threshold="$CPU_THRESHOLD" '$2+0 > threshold' | \
        awk '{printf "%-8s %-6s %-6s %-10s %-18s %-12s\n", $1, $2, $3, $4, $5, $6}' | \
        fzf --multi --ansi --header="$header" \
            --prompt="Select process(es) to kill (${CPU_THRESHOLD}%+ CPU) > " \
            --preview="echo -e '\nProcess details:\n--------------'; ps -p {1} -o pid,user,pcpu,pmem,vsz,rss,tty,stat,start_time,cmd --no-headers" \
            --preview-window=right:60%:wrap
    )
    
    [[ -z "$selected" ]] && {
        echo -e "${YELLOW}No processes selected${RESET}"
        return
    }
    
    echo -e "\n${RED}${BOLD}WARNING: The following processes will be terminated:${RESET}"
    echo "$selected"
    
    read -rp "${BOLD}Are you sure you want to kill these processes? [y/N]: ${RESET}" answer
    [[ "$answer" =~ ^[Yy]$ ]] || {
        echo -e "${YELLOW}Aborted${RESET}"
        return
    }
    
    local killed=0
    while read -r line; do
        local pid=$(echo "$line" | awk '{print $1}')
        local cmd=$(echo "$line" | awk '{print $5}')
        local cpu=$(echo "$line" | awk '{print $2}')
        local user=$(echo "$line" | awk '{print $4}')
        
        if [[ "$DRY_RUN" == true ]]; then
            echo -e "${YELLOW}DRYRUN: Would kill $cmd (PID $pid) - $cpu% CPU by $user${RESET}"
            ((killed++))
        else
            if kill -TERM "$pid" 2>/dev/null; then
                echo -e "${GREEN}Terminated $cmd (PID $pid) - $cpu% CPU by $user${RESET}"
                log_msg "INFO" "Killed high CPU: $cmd (PID $pid, $cpu% CPU)"
                ((killed++))
            else
                echo -e "${RED}Failed to terminate $cmd (PID $pid)${RESET}"
                log_msg "ERROR" "Failed to kill high CPU: $cmd (PID $pid)"
            fi
        fi
    done <<< "$selected"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_msg "DEBUG" "High CPU scan completed in ${duration}s, killed $killed processes"
}

# ========= Virtual Machine Detection =========
# Detects if running in a virtual machine environment
# Sets VM_MODE and VIRTUALBOX_MODE flags if detected
# Parameters: None
# Outputs: None (sets environment variables)
detect_vm() {
    if [[ -f /sys/class/dmi/id/product_name ]] && 
       grep -qi "vmware\|virtual\|kvm\|qemu" /sys/class/dmi/id/product_name; then
        log_msg "INFO" "VM detected - enabling extra protections"
        export VM_MODE=true
    fi
    if [[ -f /sys/class/dmi/id/product_name ]] && 
       grep -qi "VirtualBox" /sys/class/dmi/id/product_name; then
        log_msg "INFO" "VirtualBox detected - enabling extra protections"
        export VM_MODE=true
        export VIRTUALBOX_MODE=true
    fi
}

# ========= Emergency Stop =========
# Critical safety check to prevent termination of essential system processes
# Parameters:
#   $1 - pid: Process ID
#   $2 - cmd: Process command/name
# Behavior:
# - Immediately exits script (255) if critical process detected
# - Special handling for VirtualBox processes
# - Protects core system processes and development tools
emergency_stop() {
    local pid=$1
    local cmd=$2
    
    local vbox_critical=(
        "VBoxClient" "VBoxService" "vboxadd" 
        "vboxnetflt" "vboxnetadp" "vboxdrv"
    )
    
    for proc in "${vbox_critical[@]}"; do
        if [[ "$cmd" =~ $proc ]]; then
            log_msg "EMERGENCY" "Attempted to kill VirtualBox process: $cmd (PID $pid)"
            echo -e "${RED}EMERGENCY STOP: Attempted to kill VirtualBox system process${RESET}"
            exit 255
        fi
    done
    
    # Critical system processes that should never be killed
    local critical_procs=(
        "init" "systemd" "kernel" "dbus" "vmtoolsd" 
        "NetworkManager" "sshd" "agetty" "cron"
        "WSL" "wsl" "wslinit" "wslhost" "init"  # WSL processes
        "vscode" "code" "node"  # Development processes
    )
    
    for proc in "${critical_procs[@]}"; do
        if [[ "$cmd" =~ $proc ]]; then
            log_msg "EMERGENCY" "Attempted to kill critical process: $cmd (PID $pid)"
            echo -e "${RED}EMERGENCY STOP: Attempted to kill critical system process${RESET}"
            exit 255  # Special exit code for critical failure
        fi
    done
}

# ========= Execution Modes =========
# Forked execution mode - runs process scanning in a background child process
# Behavior:
# - Creates child process for scanning
# - Handles interactive/show-only modes in main process
# - Forces auto-kill in background unless explicitly disabled
# - Waits for child completion and propagates exit status
# Notes:
# - Not compatible with interactive mode (runs in main process)
# - Show-only mode runs in main process for better output control
fork_execution() {
    log_msg "INFO" "Starting forked execution (Parent PID: $$)"
    
    # Don't fork if in interactive mode - needs terminal access
    if [[ "$INTERACTIVE" == true ]]; then
        log_msg "WARN" "Interactive mode (-I) not supported with fork (-f), running in main process"
        init_dirs
        load_whitelist
        detect_vm
        scan_processes
        return $?
    fi
    
    # Don't fork if in show-only mode - no need for background
    if [[ "$SHOW_ONLY" == true ]]; then
        log_msg "INFO" "Show-only mode (-x) detected, running in main process"
        init_dirs
        load_whitelist
        detect_vm
        scan_processes
        return $?
    fi
    
    {
        # Child process work
        init_dirs
        load_whitelist
        detect_vm
        
        # Force auto-kill in fork mode unless explicitly disabled
        local effective_auto_kill=true
        [[ "$AUTO_KILL" == false ]] && effective_auto_kill=false
        
        AUTO_KILL=$effective_auto_kill scan_processes
    } &
    
    local child_pid=$!
    log_msg "INFO" "Forked child process PID: $child_pid"
    
    # Parent waits for child
    if wait "$child_pid" 2>/dev/null; then
        log_msg "INFO" "Child process completed successfully"
        return 0
    else
        local exit_status=$?
        log_msg "ERROR" "Child process failed with status $exit_status"
        return $exit_status
    fi
}

# Threaded execution mode - uses parallel processing for scanning/killing
# Features:
# - Coordinator thread gathers candidate processes
# - Worker threads handle process termination
# - File-based locking for process safety
# - Detailed thread-level logging
# - Supports interactive/show-only modes

thread_execution() {
    local pids=() worker_pids=()
    local lock_acquired=false
    local temp_file=$(mktemp)
    
    log_msg "INFO" "Starting threaded execution"
    log_msg "THREAD" "MAIN THREAD: PID=$$ (Starting threaded execution)"
    
    # Create shared lock
    if [[ "$FORCE" == false ]]; then
        log_msg "THREAD" "MAIN THREAD: Attempting to acquire lock"
        acquire_lock || return 1
        lock_acquired=true
        log_msg "THREAD" "MAIN THREAD: Lock acquired successfully"
    fi
    
    # Start coordinator process
    (
        log_msg "THREAD" "COORDINATOR THREAD: Started (PID=$$, Parent=$PPID)"
        log_msg "THREAD" "COORDINATOR THREAD: Initializing directories and loading whitelist"
        
        # Collect all candidate PIDs first
        declare -a CANDIDATES=()
        init_dirs
        load_whitelist
        detect_vm
        
        log_msg "THREAD" "COORDINATOR THREAD: Scanning processes..."
        # Scan processes just once
        while read -r pid tty cmd cpu etime user ppid args; do
            cmd="$cmd $args"
            cmd=$(echo "$cmd" | awk '{$1=$1};1')
            
            if ! should_skip_process "$pid" "$cmd" "$user" "$ppid"; then
                local cpu_val=${cpu//,/.}
                cpu_val=${cpu_val%%.*}
                local idle_minutes=$(etime_to_minutes "$etime")
                
                if (( $(echo "$idle_minutes >= $IDLE_TIME && $cpu_val < $CPU_THRESHOLD" | bc -l) )); then
                    CANDIDATES+=("$pid|$cmd|$user|$cpu|$etime|$tty")
                    log_msg "THREAD" "COORDINATOR THREAD: Found candidate PID=$pid (CMD=$cmd, USER=$user, CPU=$cpu, ETIME=$etime)"
                fi
            fi
        done < <(ps -eo pid,tty:30,comm:30,%cpu,etime,user,ppid,args --no-headers | grep -v "killer_v2" 2>/dev/null)
        
        log_msg "THREAD" "COORDINATOR THREAD: Found ${#CANDIDATES[@]} candidate processes"
        # Write candidates to temp file
        printf "%s\n" "${CANDIDATES[@]}" > "$temp_file"
        log_msg "THREAD" "COORDINATOR THREAD: Wrote candidates to temp file $temp_file"
    ) & coordinator_pid=$!
    
    log_msg "THREAD" "MAIN THREAD: Waiting for coordinator (PID=$coordinator_pid) to complete"
    wait $coordinator_pid
    log_msg "THREAD" "MAIN THREAD: Coordinator process completed"
    
    # Handle interactive mode
    if [[ "$INTERACTIVE" == true ]]; then
        log_msg "THREAD" "MAIN THREAD: Entering interactive mode"
        # Read candidates from temp file into array
        mapfile -t CANDIDATES < "$temp_file"
        
        # Call interactive selection
        interactive_selection CANDIDATES
        
        rm -f "$temp_file"
        [[ "$lock_acquired" == true ]] && release_lock
        log_msg "THREAD" "MAIN THREAD: Interactive mode completed, cleaning up"
        return 0
    fi
    
    # Show candidates if in show-only mode
    if [[ "$SHOW_ONLY" == true ]]; then
        log_msg "THREAD" "MAIN THREAD: Showing candidates (show-only mode)"
        echo -e "\n${YELLOW}${BOLD}Candidate processes for killing ($(wc -l < "$temp_file") found):${RESET}"
        printf "%-8s %-25s %-15s %-6s %-10s %-12s\n" "PID" "COMMAND" "USER" "CPU%" "ETIME" "TTY"
        
        while read -r line; do
            IFS='|' read -r pid cmd user cpu etime tty <<< "$line"
            printf "%-8s %-25s %-15s %-6s %-10s %-12s\n" "$pid" "${cmd:0:24}" "$user" "$cpu" "$etime" "$tty"
        done < "$temp_file"
        
        rm -f "$temp_file"
        [[ "$lock_acquired" == true ]] && release_lock
        log_msg "THREAD" "MAIN THREAD: Show-only mode completed, cleaning up"
        return 0
    fi
    
    # Start workers to process the candidates (only for auto-kill modes)
    log_msg "THREAD" "MAIN THREAD: Starting worker threads for auto-kill mode"
    for i in {1..2}; do
        (
            log_msg "THREAD" "WORKER THREAD $i: Started (PID=$$, Parent=$PPID)"
            local worker_processed=0
            
            while read -r line; do
                IFS='|' read -r pid cmd user cpu etime tty <<< "$line"
                
                # Try to acquire process-specific lock
                log_msg "THREAD" "WORKER THREAD $i: Attempting to lock PID $pid"
                if ln -s "$temp_file" "${temp_file}.${pid}.lock" 2>/dev/null; then
                    log_msg "THREAD" "WORKER THREAD $i: Acquired lock for PID $pid"
                    if kill_processes "$pid" "$cmd" "$user" "$cpu" "$etime"; then
                        echo "SUCCESS:$pid" >> "${temp_file}.results"
                        log_msg "THREAD" "WORKER THREAD $i: Successfully killed PID $pid"
                    else
                        echo "FAILED:$pid" >> "${temp_file}.results"
                        log_msg "THREAD" "WORKER THREAD $i: Failed to kill PID $pid"
                    fi
                    rm -f "${temp_file}.${pid}.lock"
                    ((worker_processed++))
                else
                    log_msg "THREAD" "WORKER THREAD $i: Could not acquire lock for PID $pid (already being processed)"
                fi
            done < "$temp_file"
            
            log_msg "THREAD" "WORKER THREAD $i: Completed, processed $worker_processed processes"
        ) & worker_pids+=($!)
        log_msg "THREAD" "MAIN THREAD: Started worker thread $i (PID=$!)"
    done
    
    # Wait for workers
    log_msg "THREAD" "MAIN THREAD: Waiting for ${#worker_pids[@]} worker threads to complete"
    local failed=0
    for pid in "${worker_pids[@]}"; do
        if ! wait "$pid"; then
            ((failed++))
            log_msg "THREAD" "MAIN THREAD: Worker thread $pid exited with error"
        else
            log_msg "THREAD" "MAIN THREAD: Worker thread $pid completed successfully"
        fi
    done
    
    # Report results
    if [[ -f "${temp_file}.results" ]]; then
        local success_count=$(grep -c '^SUCCESS:' "${temp_file}.results")
        local failed_count=$(grep -c '^FAILED:' "${temp_file}.results")
        
        echo -e "\n${GREEN}Successfully terminated: $success_count${RESET}"
        [[ $failed_count -gt 0 ]] && echo -e "${RED}Failed to terminate: $failed_count${RESET}"
        log_msg "THREAD" "MAIN THREAD: Results - Success: $success_count, Failed: $failed_count"
    fi
    
    # Cleanup
    log_msg "THREAD" "MAIN THREAD: Cleaning up temporary files"
    rm -f "$temp_file" "${temp_file}.results" "${temp_file}.*.lock"
    [[ "$lock_acquired" == true ]] && release_lock
    log_msg "THREAD" "MAIN THREAD: Threaded execution completed"
    return $failed
}

# Subshell execution mode - runs all operations in a child shell
# Features:
# - Isolated environment
# - Clear signal handling
# - Resource cleanup verification
# - Detailed subshell logging


subshell_execution() {
    log_msg "INFO" "Parent process PID: $$"
    
    (
        # Clear inherited traps
        trap - EXIT INT TERM
        
        # Subshell identification
        echo -e "\n${CYAN}=== SUBSHELL STARTED [PID: $$] ===${RESET}"
        log_msg "SUBSHELL" "Running in subshell PID: $$ (Parent: $PPID)"
        
        # Environment test
        local pre_env=$(printenv | wc -l)
        export SUBSHELL_TEST=1
        log_msg "SUBSHELL" "Environment variables: $pre_env -> $(printenv | wc -l)"
        
        # Main operations
        init_dirs
        load_whitelist
        scan_processes
        
        # Resource test
        temp_file=$(mktemp)
        log_msg "SUBSHELL" "Created temp file: $temp_file"
        
        echo -e "${CYAN}=== SUBSHELL EXITING [PID: $$] ===${RESET}\n"
    )
    
    # Post-execution verification
    log_msg "PARENT" "Subshell completed"
    [[ -z "$SUBSHELL_TEST" ]] && log_msg "VERIFIED" "Environment isolation confirmed"
    [[ ! -f "$temp_file" ]] && log_msg "VERIFIED" "Subshell cleanup confirmed"
}
# ========= Main =========
# Main execution dispatcher
# Determines execution mode based on flags:
# - SUBSHELL (-s): Runs in isolated subshell
# - FORK (-f): Runs in background process
# - THREADS (-t): Uses parallel processing
# - Default: Sequential execution
# Handles high CPU scan mode (-z) when specified

main() {
    if [[ "$SUBSHELL" == true ]]; then
        subshell_execution
    elif [[ "$FORK" == true ]]; then
        fork_execution
    elif [[ "$THREADS" == true ]]; then
        thread_execution
    else
        # Default sequential execution
        init_dirs
        [[ "$FORCE" == false ]] && acquire_lock
        load_whitelist
        detect_vm
        if [[ "$HIGHPROCESSES" == true ]]; then
            scan_high_cpu
        else
            scan_processes
        fi
        [[ "$FORCE" == false ]] && release_lock
    fi
}
# ========= Cleanup on exit =========
# Global cleanup function - releases lock on script exit
# Trapped signals: EXIT, INT (Ctrl-C), TERM

cleanup() {
    release_lock
    exit 0
}

# Set up signal traps for clean exit handling
trap cleanup EXIT INT TERM

# ========= Entry Point =========
# Parse command line arguments then execute main program
parse_arguments "$@"
main